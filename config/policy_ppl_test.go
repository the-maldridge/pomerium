package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/policy"
)

func TestPolicy_ToPPL(t *testing.T) {
	str, err := policy.GenerateRegoFromPolicy((&Policy{
		AllowPublicUnauthenticatedAccess: true,
		CORSAllowPreflight:               true,
		AllowAnyAuthenticatedUser:        true,
		AllowedDomains:                   []string{"a.example.com", "b.example.com"},
		AllowedGroups:                    []string{"group1", "group2"},
		AllowedUsers:                     []string{"user1", "user2"},
		AllowedIDPClaims: map[string][]interface{}{
			"family_name": {"Smith"},
		},
		SubPolicies: []SubPolicy{
			{
				AllowedDomains: []string{"c.example.com", "d.example.com"},
				AllowedGroups:  []string{"group3", "group4"},
				AllowedUsers:   []string{"user3", "user4"},
				AllowedIDPClaims: map[string][]interface{}{
					"given_name": {"John"},
				},
			},
			{
				AllowedDomains: []string{"e.example.com"},
				AllowedGroups:  []string{"group5"},
				AllowedUsers:   []string{"user5"},
				AllowedIDPClaims: map[string][]interface{}{
					"timezone": {"EST"},
				},
			},
		},
	}).ToPPL())
	require.NoError(t, err)
	assert.Equal(t, `package pomerium.policy

default allow = false

default deny = false

pomerium_routes_0 {
	contains(input.http.url, "/.pomerium/")
}

accept_0 = v {
	v := true
}

or_0 {
	pomerium_routes_0
}

else {
	accept_0
}

allow {
	or_0
}

invalid_client_certificate_0 = reason {
	reason = [495, "invalid client certificate"]
	is_boolean(input.is_valid_client_certificate)
	not input.is_valid_client_certificate
}

or_1 {
	invalid_client_certificate_0
}

deny {
	or_1
}
`, str)
}
