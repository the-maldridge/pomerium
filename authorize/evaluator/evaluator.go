package evaluator

import (
	"context"
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

// Input are the inputs needed for evaluation.
type Input struct {
	Policy   *config.Policy
	HTTP     RequestHTTP
	Session  RequestSession
	ClientCA string // pem-encoded client certificate authority
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

	return e, nil
}

// Evaluate evaluates the rego for the given policy and generates the identity headers.
func (e *Evaluator) Evaluate(ctx context.Context, input *Input) (*Output, error) {
	if input.Policy == nil {
		return notFoundOutput, nil
	}

	id, err := input.Policy.RouteID()
	if err != nil {
		return nil, fmt.Errorf("authorize: error computing policy route id: %w", err)
	}

	policyEvaluator, ok := e.policyEvaluators[id]
	if !ok {
		return notFoundOutput, nil
	}

	isValidClientCertificate, err := isValidClientCertificate(input.ClientCA, input.HTTP.ClientCertificate)
	if err != nil {
		return nil, fmt.Errorf("authorize: error validating client certificate: %w", err)
	}

	policyOutput, err := policyEvaluator.Evaluate(ctx, &PolicyInput{
		HTTP:                     input.HTTP,
		Session:                  input.Session,
		IsValidClientCertificate: isValidClientCertificate,
	})
	if err != nil {
		return nil, err
	}

	headersOutput, err := e.headersEvaluators.Evaluate(ctx, NewHeadersInputFromPolicy(input.Policy))
	if err != nil {
		return nil, err
	}

	return &Output{
		Allow:   policyOutput.Allow,
		Deny:    policyOutput.Deny,
		Headers: headersOutput.IdentityHeaders,
	}, nil
}
