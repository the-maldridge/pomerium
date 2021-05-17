package rules

import "github.com/open-policy-agent/opa/ast"

// IdentityHeaders defines the identity headers.
//
// data: jwt_claim_headers: array, signing_key: object
// returns: object
//
func IdentityHeaders() *ast.Rule {
	return ast.MustParseRule(`
identity_headers = hs {
	# 5 minutes from now in seconds
	five_minutes := (time.now_ns() / 1e9) + (60 * 5)

	base_jwt_claims := [
		["iss", ` + or(`data.issuer`, `""`) + `],
		["aud", ` + or(`parse_url(input.http.url).hostname`, `""`) + `],
		["jti", ` + or(`session.id`, `""`) + `],
		["exp", ` + or(`min([five_minutes, session.expires_at.seconds])`, or(`five_minutes`, `null`)) + `],
		["iat", ` + or(`session.id_token.issued_at.seconds`, or(`session.issued_at.seconds`, `null`)) + `],
		["sub", ` + or(`user.id`, `""`) + `],
		["user", ` + or(`user.id`, `""`) + `],
		["email", ` + or(`session.impersonate_email`, or(`directory_user.email`, or(`user.email`, `""`))) + `],
		["groups", ` + or(`""`, `""`) + `],
	]

	jwt_headers := {
		"typ": "JWT",
		"alg": data.signing_key.alg,
		"kid": data.signing_key.kid,
	}
	jwt_payload := { k:v | k := jwt_claims[v]; v != null }
	signed_jwt := io.jwt.encode_sign(jwt_headers, jwt_payload, data.signing_key)

	h1 := { k:v | k := "X-Pomerium-Jwt-Assertion"; v := signed_jwt }
	h2 := { k:v |
		claim_value := jwt_claims[claim_key]

		# only include those headers requested by the user
		some header_name
		available := data.jwt_claim_headers[header_name]
		available == claim_key

		# create the header key and value
		k := header_name
		v := ` + headerValue("header_name") + `
	}
	hs := object.union(h1, object.union(h2, other_headers))
}
`)
}

// GetKubernetesHeaders gets the kubernetes headers for the given service account, user and groups.
//
// args: kubernetes_service_account_token: string, user: string, groups: array|string
// returns: object
//
func GetKubernetesHeaders() *ast.Rule {
	return ast.MustParseRule(`
get_kubernetes_headers(kubernetes_service_account_token, user, groups) = hs {
	kubernetes_service_account_token != ""
	h1 := { k:v | k := "Authorization"; v := concat(" ", ["Bearer", kubernetes_service_account_token]) }
	h2 := { k:v | k := "Impersonate-User"; v := user }
	h3 := { k:v |
		k := "Impersonate-Groups"
		v := ` + headerValue("groups") + `
	}
	hs := object.union(h1, object.union(h2, h3))
} else = hs {
	hs := {}
}
`)
}

// headerValue returns a rego expression that returns a comma-concatenated string if the variable is an array, or the
// plain value if not.
func headerValue(variableName string) string {
	c1 := `[x| is_array(` + variableName + `); x := concat(",", ` + variableName + `)]`
	c2 := `[` + variableName + `]`
	return `array.concat(` + c1 + `, ` + c2 + `)[0]`
}

func or(v1, v2 string) string {
	return `array.concat([x|x:=` + v1 + `],[x|x:=` + v2 + `])[0]`
}
