package spiffe

import (
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"
)

func TestParseValid(t *testing.T) {
	for _, s := range []string{
		"spiffe://labca.example.com/ns/mtls-demo/sa/demo-client",
		"spiffe://example.org",
		"spiffe://a_b.c-d/X/y.z",
	} {
		id, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if id.String() != s {
			t.Fatalf("round trip %q -> %q", s, id.String())
		}
	}
	id, _ := Parse("spiffe://td/ns/a")
	if id.TrustDomain != "td" || id.Path != "/ns/a" {
		t.Fatalf("bad fields: %+v", id)
	}
}

func TestParseInvalid(t *testing.T) {
	cases := map[string]string{
		"uppercase td":   "spiffe://Example.org/a",
		"empty segment":  "spiffe://example.org/a//b",
		"trailing slash": "spiffe://example.org/a/",
		"dotdot":         "spiffe://example.org/a/../b",
		"dot":            "spiffe://example.org/./b",
		"query":          "spiffe://example.org/a?x=1",
		"fragment":       "spiffe://example.org/a#f",
		"port":           "spiffe://example.org:8443/a",
		"userinfo":       "spiffe://user@example.org/a",
		"too long":       "spiffe://example.org/" + strings.Repeat("a", 2048),
		"wrong scheme":   "https://example.org/a",
		"empty td":       "spiffe:///a",
		"bad seg char":   "spiffe://example.org/a b",
		"empty":          "",
	}
	for name, s := range cases {
		_, err := Parse(s)
		if !errors.Is(err, ErrInvalidID) {
			t.Errorf("%s: want ErrInvalidID, got %v", name, err)
		}
	}
}

func certWith(uris ...string) *x509.Certificate {
	c := &x509.Certificate{}
	for _, s := range uris {
		u, _ := url.Parse(s)
		c.URIs = append(c.URIs, u)
	}
	return c
}

func TestFromCertificate(t *testing.T) {
	got, err := FromCertificate(certWith("spiffe://td/ns/a/sa/b"))
	if err != nil || got != "spiffe://td/ns/a/sa/b" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := FromCertificate(certWith()); err == nil {
		t.Fatal("0 URI SANs must fail")
	}
	if _, err := FromCertificate(certWith("spiffe://td/a", "spiffe://td/b")); err == nil {
		t.Fatal("2 URI SANs must fail")
	}
	if _, err := FromCertificate(certWith("https://td/a")); err == nil {
		t.Fatal("non-spiffe URI must fail")
	}
	if _, err := FromCertificate(certWith("https://td/a", "spiffe://td/b")); err != nil {
		t.Fatalf("one spiffe plus other: %v", err)
	}
	if _, err := FromCertificate(certWith("spiffe://TD/a")); err == nil {
		t.Fatal("invalid spiffe URI must fail")
	}
}
