package evaluator

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/config"
)

// notFoundOutput is what's returned if a route isn't found for a policy.
var notFoundOutput = &Output{
	Allow: false,
	Deny: &Denial{
		Status:  http.StatusNotFound,
		Message: "route not found",
	},
	Headers: make(http.Header),
}

// Request contains the inputs needed for evaluation.
type Request struct {
	Policy  *config.Policy
	HTTP    RequestHTTP
	Session RequestSession
}

// Output is the result of evaluation.
type Output struct {
	Allow   bool
	Deny    *Denial
	Headers http.Header
}

// An Evaluator evaluates policies.
type Evaluator struct {
	policyEvaluators  map[uint64]*PolicyEvaluator
	headersEvaluators *HeadersEvaluator
	clientCA          []byte
}

// New creates a new Evaluator.
func New(ctx context.Context, store *Store, options *config.Options) (*Evaluator, error) {
	e := new(Evaluator)
	var err error

	e.headersEvaluators, err = NewHeadersEvaluator(ctx, store)
	if err != nil {
		return nil, err
	}

	e.policyEvaluators = make(map[uint64]*PolicyEvaluator)
	for i := range options.Policies {
		configPolicy := &options.Policies[i]
		id, err := configPolicy.RouteID()
		if err != nil {
			return nil, fmt.Errorf("authorize: error computing policy route id: %w", err)
		}
		policyEvaluator, err := NewPolicyEvaluator(ctx, store, configPolicy)
		if err != nil {
			return nil, err
		}
		e.policyEvaluators[id] = policyEvaluator
	}

	e.clientCA, err = options.GetClientCA()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid client ca: %w", err)
	}

	return e, nil
}

// Evaluate evaluates the rego for the given policy and generates the identity headers.
func (e *Evaluator) Evaluate(ctx context.Context, req *Request) (*Output, error) {
	if req.Policy == nil {
		return notFoundOutput, nil
	}

	id, err := req.Policy.RouteID()
	if err != nil {
		return nil, fmt.Errorf("authorize: error computing policy route id: %w", err)
	}

	policyEvaluator, ok := e.policyEvaluators[id]
	if !ok {
		return notFoundOutput, nil
	}

	clientCA, err := e.getClientCA(req.Policy)
	if err != nil {
		return nil, err
	}

	isValidClientCertificate, err := isValidClientCertificate(clientCA, req.HTTP.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("authorize: error validating client certificate: %w", err)
	}

	policyOutput, err := policyEvaluator.Evaluate(ctx, &PolicyRequest{
		HTTP:                     req.HTTP,
		Session:                  req.Session,
		IsValidClientCertificate: isValidClientCertificate,
	})
	if err != nil {
		return nil, err
	}

	headersReq := NewHeadersRequestFromPolicy(req.Policy)
	headersReq.Session = req.Session
	headersOutput, err := e.headersEvaluators.Evaluate(ctx, headersReq)
	if err != nil {
		return nil, err
	}

	return &Output{
		Allow:   policyOutput.Allow,
		Deny:    policyOutput.Deny,
		Headers: headersOutput.Headers,
	}, nil
}

func (e *Evaluator) getClientCA(policy *config.Policy) (string, error) {
	if policy != nil && policy.TLSDownstreamClientCA != "" {
		bs, err := base64.StdEncoding.DecodeString(policy.TLSDownstreamClientCA)
		if err != nil {
			return "", err
		}
		return string(bs), nil
	}

	return string(e.clientCA), nil
}
