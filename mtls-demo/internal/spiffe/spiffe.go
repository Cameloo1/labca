// Package spiffe parses and validates SPIFFE IDs.
package spiffe

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidID is returned (wrapped with a reason) for malformed SPIFFE IDs.
var ErrInvalidID = errors.New("spiffe: invalid ID")

const maxIDLen = 2048

// ID is a parsed SPIFFE ID.
type ID struct{ TrustDomain, Path string }

// String renders the ID as spiffe://<trust domain><path>.
func (id ID) String() string { return "spiffe://" + id.TrustDomain + id.Path }

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidID, reason) }

func isTDChar(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
}

func isSegChar(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
}

// Parse validates s and returns the ID.
func Parse(s string) (ID, error) {
	if len(s) > maxIDLen {
		return ID{}, invalid("longer than 2048 bytes")
	}
	rest, ok := strings.CutPrefix(s, "spiffe://")
	if !ok {
		return ID{}, invalid("scheme must be spiffe")
	}
	if strings.ContainsAny(rest, "?#") {
		return ID{}, invalid("query or fragment not allowed")
	}
	td, path := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		td, path = rest[:i], rest[i:]
	}
	if td == "" {
		return ID{}, invalid("empty trust domain")
	}
	if strings.ContainsAny(td, "@:") {
		return ID{}, invalid("userinfo or port not allowed")
	}
	for _, r := range td {
		if !isTDChar(r) {
			return ID{}, invalid("trust domain has invalid character")
		}
	}
	if path != "" {
		for _, seg := range strings.Split(path[1:], "/") {
			if seg == "" {
				return ID{}, invalid("empty path segment")
			}
			if seg == "." || seg == ".." {
				return ID{}, invalid("dot segments not allowed")
			}
			for _, r := range seg {
				if !isSegChar(r) {
					return ID{}, invalid("path segment has invalid character")
				}
			}
		}
	}
	return ID{TrustDomain: td, Path: path}, nil
}

// FromCertificate returns the SPIFFE ID in the certificate's single spiffe URI SAN.
func FromCertificate(c *x509.Certificate) (string, error) {
	var found []string
	for _, u := range c.URIs {
		if u.Scheme == "spiffe" {
			found = append(found, u.String())
		}
	}
	if len(found) != 1 {
		return "", invalid(fmt.Sprintf("expected exactly one spiffe URI SAN, found %d", len(found)))
	}
	if _, err := Parse(found[0]); err != nil {
		return "", err
	}
	return found[0], nil
}
