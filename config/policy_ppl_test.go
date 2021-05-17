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

cors_preflight_0 {
	input.http.method == "OPTIONS"
	count(object.get(input.http.headers, "Access-Control-Request-Method", [])) > 0
	count(object.get(input.http.headers, "Origin", [])) > 0
}

authenticated_user_0 {
	session := get_session(input.session.id)
	session.user_id != null
	session.user_id != ""
}

domains_0 {
	rule_data := "a.example.com"
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain = rule_data
}

domains_1 {
	rule_data := "b.example.com"
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain = rule_data
}

domains_2 {
	rule_data := "c.example.com"
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain = rule_data
}

domains_3 {
	rule_data := "d.example.com"
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain = rule_data
}

domains_4 {
	rule_data := "e.example.com"
	session := get_session(input.session.id)
	user := get_user(session)
	domain := split(get_user_email(session, user), "@")[1]
	domain = rule_data
}

groups_0 {
	rule_data := "group1"
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	some group
	group = groups[_0]
	group = rule_data
}

groups_1 {
	rule_data := "group2"
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	some group
	group = groups[_0]
	group = rule_data
}

groups_2 {
	rule_data := "group3"
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	some group
	group = groups[_0]
	group = rule_data
}

groups_3 {
	rule_data := "group4"
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	some group
	group = groups[_0]
	group = rule_data
}

groups_4 {
	rule_data := "group5"
	session := get_session(input.session.id)
	directory_user := get_directory_user(session)
	group_ids := get_group_ids(session, directory_user)
	group_names := [directory_group.name |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.name != null
	]
	group_emails := [directory_group.email |
		some i
		group_id := group_ids[i]
		directory_group := get_directory_group(group_id)
		directory_group != null
		directory_group.email != null
	]
	groups = array.concat(group_ids, array.concat(group_names, group_emails))
	some group
	group = groups[_0]
	group = rule_data
}

claims_0 {
	rule_data := {"family_name": null}
	rule_path := ""
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	rule_data == values[_0]
}

claims_1 {
	rule_data := {"given_name": null}
	rule_path := ""
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	rule_data == values[_0]
}

claims_2 {
	rule_data := {"timezone": null}
	rule_path := ""
	session := get_session(input.session.id)
	session_claims := object.get(session, "claims", {})
	user := get_user(session)
	user_claims := object.get(user, "claims", {})
	all_claims := object.union(session_claims, user_claims)
	values := object_get(all_claims, rule_path, [])
	rule_data == values[_0]
}

users_0 {
	rule_data := "user1"
	session := get_session(input.session.id)
	user := get_user(session)
	user_id = rule_data
}

emails_0 {
	rule_data := "user1"
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email = rule_data
}

users_1 {
	rule_data := "user2"
	session := get_session(input.session.id)
	user := get_user(session)
	user_id = rule_data
}

emails_1 {
	rule_data := "user2"
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email = rule_data
}

users_2 {
	rule_data := "user3"
	session := get_session(input.session.id)
	user := get_user(session)
	user_id = rule_data
}

emails_2 {
	rule_data := "user3"
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email = rule_data
}

users_3 {
	rule_data := "user4"
	session := get_session(input.session.id)
	user := get_user(session)
	user_id = rule_data
}

emails_3 {
	rule_data := "user4"
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email = rule_data
}

users_4 {
	rule_data := "user5"
	session := get_session(input.session.id)
	user := get_user(session)
	user_id = rule_data
}

emails_4 {
	rule_data := "user5"
	session := get_session(input.session.id)
	user := get_user(session)
	email := get_user_email(session, user)
	email = rule_data
}

or_0 {
	pomerium_routes_0
}

else {
	accept_0
}

else {
	cors_preflight_0
}

else {
	authenticated_user_0
}

else {
	domains_0
}

else {
	domains_1
}

else {
	domains_2
}

else {
	domains_3
}

else {
	domains_4
}

else {
	groups_0
}

else {
	groups_1
}

else {
	groups_2
}

else {
	groups_3
}

else {
	groups_4
}

else {
	claims_0
}

else {
	claims_1
}

else {
	claims_2
}

else {
	users_0
}

else {
	emails_0
}

else {
	users_1
}

else {
	emails_1
}

else {
	users_2
}

else {
	emails_2
}

else {
	users_3
}

else {
	emails_3
}

else {
	users_4
}

else {
	emails_4
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

get_session(id) = v {
	v := get_databroker_record("type.googleapis.com/user.ServiceAccount", id)
}

else = v {
	v := get_databroker_record("type.googleapis.com/session.Session", id)
}

else = v {
	v := {}
}

get_user(session) = v {
	v := get_databroker_record("type.googleapis.com/user.User", session.impersonate_user_id)
}

else = v {
	v := get_databroker_record("type.googleapis.com/user.User", session.user_id)
}

else = v {
	v := {}
}

get_directory_user(session) = v {
	v := get_databroker_record("type.googleapis.com/directory.User", session.impersonate_user_id)
}

else = v {
	v := get_databroker_record("type.googleapis.com/directory.User", session.user_id)
}

else = v {
	v := {}
}

get_directory_group(id) = v {
	v := get_databroker_record("type.googleapis.com/directory.Group", id)
}

else = v {
	v := {}
}

get_user_email(session, user) = v {
	v := session.impersonate_email
}

else = v {
	v := user.email
}

else = v {
	v := ""
}

get_group_ids(session, directory_user) = v {
	v := session.impersonate_groups
}

else = v {
	v := directory_user.group_ids
}

else = v {
	v := []
}

object_get(obj, key, def) = value {
	segments := split(key, "/")
	count(segments) == 2
	o1 := object.get(obj, segments[0], {})
	value = object.get(o1, segments[1], def)
}

else = value {
	segments := split(key, "/")
	count(segments) == 3
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	value = object.get(o2, segments[2], def)
}

else = value {
	segments := split(key, "/")
	count(segments) == 4
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	value = object.get(o3, segments[3], def)
}

else = value {
	segments := split(key, "/")
	count(segments) == 5
	o1 := object.get(obj, segments[0], {})
	o2 := object.get(o1, segments[1], {})
	o3 := object.get(o2, segments[2], {})
	o4 := object.get(o3, segments[3], {})
	value = object.get(o4, segments[4], def)
}

else = value {
	value = object.get(obj, key, def)
}
`, str)
}
