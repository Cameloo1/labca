package fakelabca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/fakelabca"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
)

func csr(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestSignRevokeAndOwnership(t *testing.T) {
	f := fakelabca.New("labca.test")
	defer f.Close()
	f.AddToken("a", "ns1", "sa1")
	f.AddToken("b", "ns1", "sa2")
	c := &labcaapi.Client{BaseURL: f.URL}
	ctx := context.Background()

	var ae *labcaapi.APIError
	if _, err := c.Sign(ctx, "unknown", csr(t)); !errors.As(err, &ae) || ae.Status != 401 || ae.Code != "unauthenticated" {
		t.Fatalf("unknown token: %v", err)
	}
	if _, err := c.Sign(ctx, "a", []byte("junk")); !errors.As(err, &ae) || ae.Status != 400 || ae.Code != "invalid_csr" {
		t.Fatalf("bad csr: %v", err)
	}
	r, err := c.Sign(ctx, "a", csr(t))
	if err != nil {
		t.Fatal(err)
	}
	if r.SPIFFEID != "spiffe://labca.test/ns/ns1/sa/sa1" || r.SerialHex == "" || r.TrustBundlePEM == "" {
		t.Errorf("sign response %+v", r)
	}
	if _, err := c.Revoke(ctx, "b", r.SerialHex, "keyCompromise"); !errors.As(err, &ae) || ae.Status != 403 || ae.Code != "not_owner" {
		t.Fatalf("non-owner revoke: %v", err)
	}
	if _, err := c.Revoke(ctx, "a", "deadbeef", "keyCompromise"); !errors.As(err, &ae) || ae.Status != 404 {
		t.Fatalf("unknown serial: %v", err)
	}
	if _, err := c.Revoke(ctx, "nope", r.SerialHex, "keyCompromise"); !errors.As(err, &ae) || ae.Status != 401 {
		t.Fatalf("unknown token revoke: %v", err)
	}
	before := f.CRLNumber()
	rr, err := c.Revoke(ctx, "a", r.SerialHex, "keyCompromise")
	if err != nil || !rr.Revoked || rr.CRLNumber != before+1 || f.CRLNumber() != before+1 {
		t.Fatalf("revoke: %+v %v", rr, err)
	}
	list, err := x509.ParseRevocationList(f.CRLDER())
	if err != nil || len(list.RevokedCertificateEntries) != 1 {
		t.Fatalf("crl: %v", err)
	}
	if err := list.CheckSignatureFrom(f.IssuingCA()); err != nil {
		t.Errorf("crl signature: %v", err)
	}
}

func TestFailNextAndTokens(t *testing.T) {
	f := fakelabca.New("labca.test")
	defer f.Close()
	f.AddToken("a", "ns", "sa")
	f.FailNext(429)
	c := &labcaapi.Client{BaseURL: f.URL}
	var ae *labcaapi.APIError
	if _, err := c.Sign(context.Background(), "a", csr(t)); !errors.As(err, &ae) || ae.Status != 429 || ae.Code != "rate_limited" {
		t.Fatalf("got %v", err)
	}
	if _, err := c.Sign(context.Background(), "a", csr(t)); err != nil {
		t.Fatal(err)
	}
	if got := f.Tokens(); len(got) != 2 || got[0] != "a" {
		t.Errorf("tokens %v", got)
	}
}

func TestFakeClock(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := fakelabca.NewFakeClock(start)
	ch := c.After(time.Minute)
	if c.Pending() != 1 {
		t.Fatal("pending")
	}
	c.Advance(30 * time.Second)
	select {
	case <-ch:
		t.Fatal("fired early")
	default:
	}
	c.Advance(31 * time.Second)
	select {
	case <-ch:
	default:
		t.Fatal("did not fire")
	}
	if !c.Now().Equal(start.Add(61*time.Second)) || c.Pending() != 0 {
		t.Error("clock state")
	}
	select {
	case <-c.After(0):
	default:
		t.Error("After(0) should fire immediately")
	}
}
