package server

import "testing"

func TestBearerTokenAcceptsTheSchemeInAnyCase(t *testing.T) {
	for _, header := range []string{"Bearer abc", "bearer abc", "BEARER abc", "BeArEr abc", "Bearer  abc "} {
		tok, ok := bearerToken(header)
		if !ok || tok != "abc" {
			t.Fatalf("bearerToken(%q) = %q, %v; want abc, true", header, tok, ok)
		}
	}
}

func TestBearerTokenRefusesOtherSchemesAndMissingTokens(t *testing.T) {
	for _, header := range []string{"", "Basic abc", "Bearerabc", "Bearer", "Digest abc"} {
		if tok, ok := bearerToken(header); ok && tok != "" {
			t.Fatalf("bearerToken(%q) = %q, %v; want no token", header, tok, ok)
		}
	}
}
