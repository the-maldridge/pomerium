package evaluator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/square/go-jose.v2"

	"github.com/pomerium/pomerium/pkg/cryptutil"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/directory"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

func TestJSONMarshal(t *testing.T) {
	opt := config.NewDefaultOptions()
	opt.AuthenticateURLString = "https://authenticate.example.com"
	e, err := NewOriginalEvaluator(opt, NewStoreFromProtos(0,
		&session.Session{
			UserId: "user1",
		},
		&directory.User{
			Id:       "user1",
			GroupIds: []string{"group1", "group2"},
		},
		&directory.Group{
			Id:    "group1",
			Name:  "admin",
			Email: "admin@example.com",
		},
		&directory.Group{
			Id:   "group2",
			Name: "test",
		},
	))
	require.NoError(t, err)
	bs, _ := json.Marshal(e.newInput(&OriginalRequest{
		HTTP: RequestHTTP{
			Method: "GET",
			URL:    "https://example.com",
			Headers: map[string]string{
				"Accept": "application/json",
			},
			ClientCertificate: "CLIENT_CERTIFICATE",
		},
		Session: RequestSession{
			ID: "SESSION_ID",
		},
	}, true))
	assert.JSONEq(t, `{
		"http": {
			"client_certificate": "CLIENT_CERTIFICATE",
			"headers": {
				"Accept": "application/json"
			},
			"method": "GET",
			"url": "https://example.com"
		},
		"session": {
			"id": "SESSION_ID"
		},
		"is_valid_client_certificate": true
	}`, string(bs))
}

func TestEvaluator(t *testing.T) {
	type A = []interface{}
	type M = map[string]interface{}

	signingKey, err := cryptutil.NewSigningKey()
	require.NoError(t, err)
	encodedSigningKey, err := cryptutil.EncodePrivateKey(signingKey)
	require.NoError(t, err)
	privateJWK, err := cryptutil.PrivateJWKFromBytes(encodedSigningKey, jose.ES256)
	require.NoError(t, err)

	eval := func(t *testing.T, options *config.Options, data []proto.Message, req *Request) (*Output, error) {
		store := NewStoreFromProtos(math.MaxUint64, data...)
		store.UpdateIssuer("authenticate.example.com")
		store.UpdateJWTClaimHeaders(config.NewJWTClaimHeaders("email", "groups", "user", "CUSTOM_KEY"))
		store.UpdateSigningKey(privateJWK)
		e, err := New(context.Background(), store, options)
		require.NoError(t, err)
		return e.Evaluate(context.Background(), req)
	}

	options := &config.Options{
		ClientCA: base64.StdEncoding.EncodeToString([]byte(testCA)),
		Policies: []config.Policy{
			{
				To:                               config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
				AllowPublicUnauthenticatedAccess: true,
			},
			{
				To:                               config.WeightedURLs{{URL: *mustParseURL("https://to.example.com")}},
				AllowPublicUnauthenticatedAccess: true,
				KubernetesServiceAccountToken:    "KUBERNETES",
			},
		},
	}

	t.Run("client certificate", func(t *testing.T) {
		t.Run("invalid", func(t *testing.T) {
			res, err := eval(t, options, nil, &Request{
				Policy: &options.Policies[0],
			})
			require.NoError(t, err)
			assert.True(t, res.Allow)
			assert.Equal(t, &Denial{Status: 495, Message: "invalid client certificate"}, res.Deny)
		})
		t.Run("valid", func(t *testing.T) {
			res, err := eval(t, options, nil, &Request{
				Policy: &options.Policies[0],
				HTTP: RequestHTTP{
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.True(t, res.Allow)
			assert.Nil(t, res.Deny)
		})
	})
	t.Run("identity_headers", func(t *testing.T) {
		t.Run("kubernetes", func(t *testing.T) {
			res, err := eval(t, options, []proto.Message{
				&session.Session{
					Id:                "session1",
					UserId:            "user1",
					ImpersonateGroups: []string{"i1", "i2"},
				},
				&user.User{
					Id:    "user1",
					Email: "a@example.com",
				},
			}, &Request{
				Policy: &options.Policies[1],
				Session: RequestSession{
					ID: "session1",
				},
				HTTP: RequestHTTP{
					Method:            "GET",
					URL:               "https://from.example.com",
					ClientCertificate: testValidCert,
				},
			})
			require.NoError(t, err)
			assert.Equal(t, "a@example.com", res.Headers.Get("Impersonate-User"))
			assert.Equal(t, "i1,i2", res.Headers.Get("Impersonate-Group"))
		})
		//t.Run("google_cloud_serverless", func(t *testing.T) {
		//	withMockGCP(t, func() {
		//		res := eval(t, []config.Policy{{
		//			Source: &config.StringURL{URL: mustParseURL("https://from.example.com")},
		//			To: config.WeightedURLs{
		//				{URL: *mustParseURL("https://to.example.com")},
		//			},
		//			EnableGoogleCloudServerlessAuthentication: true,
		//		}}, []proto.Message{
		//			&session.Session{
		//				Id:                "session1",
		//				UserId:            "user1",
		//				ImpersonateGroups: []string{"i1", "i2"},
		//			},
		//			&user.User{
		//				Id:    "user1",
		//				Email: "a@example.com",
		//			},
		//		}, &OriginalRequest{
		//			Session: RequestSession{
		//				ID: "session1",
		//			},
		//			HTTP: RequestHTTP{
		//				Method: "GET",
		//				URL:    "https://from.example.com",
		//			},
		//		}, true)
		//		headers := res.Bindings["result"].(M)["identity_headers"].(M)
		//		assert.NotEmpty(t, headers["Authorization"])
		//	})
		//})
	})
}

func mustParseURL(str string) *url.URL {
	u, err := url.Parse(str)
	if err != nil {
		panic(err)
	}
	return u
}

func BenchmarkEvaluator_Evaluate(b *testing.B) {
	store := NewStore()

	options := &config.Options{
		AuthenticateURLString: "https://authn.example.com",
		Policies: []config.Policy{
			{
				From: "https://from.example.com",
				To: config.WeightedURLs{
					{URL: *mustParseURL("https://to.example.com")},
				},
				AllowedUsers: []string{"SOMEUSER"},
			},
		},
	}

	e, err := New(context.Background(), store, options)
	if !assert.NoError(b, err) {
		return
	}

	lastSessionID := ""

	for i := 0; i < 100000; i++ {
		sessionID := uuid.New().String()
		lastSessionID = sessionID
		userID := uuid.New().String()
		data, _ := anypb.New(&session.Session{
			Version: fmt.Sprint(i),
			Id:      sessionID,
			UserId:  userID,
			IdToken: &session.IDToken{
				Issuer:   "benchmark",
				Subject:  userID,
				IssuedAt: timestamppb.Now(),
			},
			OauthToken: &session.OAuthToken{
				AccessToken:  "ACCESS TOKEN",
				TokenType:    "Bearer",
				RefreshToken: "REFRESH TOKEN",
			},
		})
		store.UpdateRecord(0, &databroker.Record{
			Version: uint64(i),
			Type:    "type.googleapis.com/session.Session",
			Id:      sessionID,
			Data:    data,
		})
		data, _ = anypb.New(&user.User{
			Version: fmt.Sprint(i),
			Id:      userID,
		})
		store.UpdateRecord(0, &databroker.Record{
			Version: uint64(i),
			Type:    "type.googleapis.com/user.User",
			Id:      userID,
			Data:    data,
		})

		data, _ = anypb.New(&directory.User{
			Version:  fmt.Sprint(i),
			Id:       userID,
			GroupIds: []string{"1", "2", "3", "4"},
		})
		store.UpdateRecord(0, &databroker.Record{
			Version: uint64(i),
			Type:    data.TypeUrl,
			Id:      userID,
			Data:    data,
		})

		data, _ = anypb.New(&directory.Group{
			Version: fmt.Sprint(i),
			Id:      fmt.Sprint(i),
		})
		store.UpdateRecord(0, &databroker.Record{
			Version: uint64(i),
			Type:    data.TypeUrl,
			Id:      fmt.Sprint(i),
			Data:    data,
		})
	}

	b.ResetTimer()
	ctx := context.Background()
	for i := 0; i < b.N; i++ {
		e.Evaluate(ctx, &Request{
			Policy: &options.Policies[0],
			HTTP: RequestHTTP{
				Method:  "GET",
				URL:     "https://example.com/path",
				Headers: map[string]string{},
			},
			Session: RequestSession{
				ID: lastSessionID,
			},
		})
	}
}
