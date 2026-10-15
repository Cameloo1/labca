package labcaapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSign201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/workload/sign" {
			t.Errorf("bad request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("bad headers: %v", r.Header)
		}
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["csr_pem"] != "CSR" {
			t.Errorf("bad body %v", b)
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"spiffe_id":"spiffe://td/a","serial_hex":"ab","not_before":"x","not_after":"y","certificate_pem":"c","chain_pem":"ch","trust_bundle_pem":"tb"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL + "/", HTTP: srv.Client()}
	r, err := c.Sign(context.Background(), "tok", []byte("CSR"))
	if err != nil {
		t.Fatal(err)
	}
	if r.SPIFFEID != "spiffe://td/a" || r.SerialHex != "ab" || r.CertificatePEM != "c" || r.ChainPEM != "ch" || r.TrustBundlePEM != "tb" {
		t.Fatalf("bad decode: %+v", r)
	}
}

func TestErrors(t *testing.T) {
	cases := []struct {
		status int
		body   string
		code   string
		retry  time.Duration
	}{
		{401, `{"error":"unauthenticated","detail":"bad token"}`, "unauthenticated", 0},
		{403, `{"error":"not_allowlisted","detail":"no"}`, "not_allowlisted", 0},
		{429, `{"error":"rate_limited","detail":"slow","retry_after_s":7}`, "rate_limited", 7 * time.Second},
		{503, `{"error":"issuer_unavailable","detail":"down"}`, "issuer_unavailable", 0},
		{502, `not json`, "", 0},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		c := &Client{BaseURL: srv.URL}
		_, err := c.Sign(context.Background(), "t", []byte("x"))
		srv.Close()
		var ae *APIError
		if !errors.As(err, &ae) {
			t.Fatalf("status %d: want APIError, got %v", tc.status, err)
		}
		if ae.Status != tc.status || ae.Code != tc.code || ae.RetryAfter != tc.retry {
			t.Errorf("status %d: got %+v", tc.status, ae)
		}
		if !strings.Contains(ae.Error(), "HTTP") {
			t.Errorf("Error() text: %q", ae.Error())
		}
	}
}

func TestRevoke(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/workload/revoke" {
			t.Errorf("path %s", r.URL.Path)
		}
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["serial_hex"] != "1f" || b["reason"] != "keyCompromise" {
			t.Errorf("body %v", b)
		}
		_, _ = w.Write([]byte(`{"revoked":true,"crl_number":9}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	r, err := c.Revoke(context.Background(), "t", "1f", "keyCompromise")
	if err != nil || !r.Revoked || r.CRLNumber != 9 {
		t.Fatalf("got %+v, %v", r, err)
	}
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":"not_found","detail":"x"}`))
	}))
	defer srv2.Close()
	_, err = (&Client{BaseURL: srv2.URL}).Revoke(context.Background(), "t", "1f", "superseded")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 404 || ae.Code != "not_found" {
		t.Fatalf("got %v", err)
	}
}

func TestOversizedBodyBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"certificate_pem":"`))
		_, _ = w.Write([]byte(strings.Repeat("a", 3<<20)))
		_, _ = w.Write([]byte(`"}`))
	}))
	defer srv.Close()
	_, err := (&Client{BaseURL: srv.URL}).Sign(context.Background(), "t", []byte("x"))
	if err == nil {
		t.Fatal("oversized body must not decode successfully")
	}
}

func TestTransportError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if _, err := (&Client{BaseURL: url}).Sign(context.Background(), "t", nil); err == nil {
		t.Fatal("want error")
	}
}
