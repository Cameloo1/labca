package crl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Cameloo1/labca/mtls-demo/internal/crl"
	"github.com/Cameloo1/labca/mtls-demo/internal/fakelabca"
	"github.com/Cameloo1/labca/mtls-demo/internal/labcaapi"
)

func newFetcher(t *testing.T, fake *fakelabca.Server, clk *fakelabca.FakeClock, allowStale bool) *crl.Fetcher {
	t.Helper()
	return crl.New(crl.Config{
		URL:        fake.URL + "/pki/issuing/crl.der",
		Issuer:     func() *x509.Certificate { return fake.IssuingCA() },
		Clock:      clk,
		AllowStale: allowStale,
	})
}

func TestValidCRLAndRevokedSerial(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	fake.RevokeSerial("1f")
	clk := fakelabca.NewFakeClock(time.Now())
	f := newFetcher(t, fake, clk, false)
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rev, err := f.IsRevoked(big.NewInt(0x1f)); !rev || err != nil {
		t.Errorf("listed serial: %v %v", rev, err)
	}
	if rev, err := f.IsRevoked(big.NewInt(0x20)); rev || err != nil {
		t.Errorf("unlisted serial: %v %v", rev, err)
	}
	st := f.Status()
	if st.Number != 2 || st.RevokedCount != 1 || !st.Valid || st.NextUpdate.IsZero() || st.ThisUpdate.IsZero() || st.FetchedAt.IsZero() {
		t.Errorf("status %+v", st)
	}
	if !f.Fresh() {
		t.Error("should be fresh")
	}
}

func TestSignatureFromOtherCARejected(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	other := fakelabca.New("labca.test")
	defer other.Close()
	f := crl.New(crl.Config{
		URL:    fake.URL + "/pki/issuing/crl.der",
		Issuer: func() *x509.Certificate { return other.IssuingCA() },
	})
	if err := f.Refresh(context.Background()); err == nil {
		t.Fatal("CRL signed by another CA must be rejected")
	}
	if rev, err := f.IsRevoked(big.NewInt(5)); !rev || !errors.Is(err, crl.ErrNoValidCRL) {
		t.Errorf("got %v %v", rev, err)
	}
}

func TestStaleFailsClosed(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	now := time.Now()
	fake.SetNextUpdate(now.Add(time.Hour))
	clk := fakelabca.NewFakeClock(now)
	f := newFetcher(t, fake, clk, false)
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	rev, err := f.IsRevoked(big.NewInt(5))
	if !rev || !errors.Is(err, crl.ErrStaleCRL) {
		t.Errorf("got %v %v", rev, err)
	}
	if f.Fresh() || f.Status().Valid {
		t.Error("stale CRL must not be fresh")
	}
}

func TestAllowStaleTestFlag(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	now := time.Now()
	fake.SetNextUpdate(now.Add(time.Hour))
	clk := fakelabca.NewFakeClock(now)
	f := newFetcher(t, fake, clk, true)
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	if rev, err := f.IsRevoked(big.NewInt(5)); rev || err != nil {
		t.Errorf("got %v %v", rev, err)
	}
	if !f.Fresh() {
		t.Error("AllowStale should report fresh")
	}
}

func TestNoCRLFailsClosed(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	f := newFetcher(t, fake, fakelabca.NewFakeClock(time.Now()), false)
	rev, err := f.IsRevoked(big.NewInt(1))
	if !rev || !errors.Is(err, crl.ErrNoValidCRL) {
		t.Errorf("got %v %v", rev, err)
	}
	if f.Fresh() || f.Status().Valid {
		t.Error("nothing loaded must not be fresh")
	}
	// No issuer known yet is also an error, not a panic.
	g := crl.New(crl.Config{URL: fake.URL, Issuer: func() *x509.Certificate { return nil }})
	if err := g.Refresh(context.Background()); err == nil {
		t.Error("nil issuer must error")
	}
}

func TestNumberRollbackRejected(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	fake.RevokeSerial("1")
	fake.RevokeSerial("2") // number 3
	f := newFetcher(t, fake, fakelabca.NewFakeClock(time.Now()), false)
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	fake.SetCRLNumber(1)
	if err := f.Refresh(context.Background()); err == nil {
		t.Fatal("rollback must be rejected")
	}
	if got := f.Status().Number; got != 3 {
		t.Errorf("number after rollback attempt: %d", got)
	}
	fake.SetCRLNumber(3) // equal number is accepted
	if err := f.Refresh(context.Background()); err != nil {
		t.Errorf("equal number: %v", err)
	}
}

func TestFailedRefreshKeepsPrevious(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	fake.RevokeSerial("1f")
	var mode atomic.Int32 // 0 ok, 1 server error, 2 garbage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case 1:
			w.WriteHeader(500)
		case 2:
			_, _ = w.Write([]byte("garbage"))
		default:
			_, _ = w.Write(fake.CRLDER())
		}
	}))
	defer srv.Close()
	f := crl.New(crl.Config{URL: srv.URL, Issuer: func() *x509.Certificate { return fake.IssuingCA() }, Clock: fakelabca.NewFakeClock(time.Now())})
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, m := range []int32{1, 2} {
		mode.Store(m)
		if err := f.Refresh(context.Background()); err == nil {
			t.Fatalf("mode %d must fail", m)
		}
		if rev, err := f.IsRevoked(big.NewInt(0x1f)); !rev || err != nil {
			t.Errorf("previous CRL must stay in force: %v %v", rev, err)
		}
	}
}

func TestStartPicksUpNewRevocation(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	clk := fakelabca.NewFakeClock(time.Now())
	f := newFetcher(t, fake, clk, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.Start(ctx)
	waitFor(t, "first load", func() bool { return f.Status().Number == 1 })
	fake.RevokeSerial("abc")
	waitFor(t, "timer", func() bool { return clk.Pending() >= 1 })
	clk.Advance(30 * time.Second)
	waitFor(t, "revocation visible", func() bool {
		rev, err := f.IsRevoked(big.NewInt(0xabc))
		return rev && err == nil
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func issuedLeaf(t *testing.T, fake *fakelabca.Server, issuer *x509.Certificate, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	c, err := fakelabca.IssueLeaf(issuer, key, "spiffe://labca.test/ns/a/sa/b", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return c.Leaf
}

func loadedFetcher(t *testing.T, fake *fakelabca.Server) *crl.Fetcher {
	t.Helper()
	f := newFetcher(t, fake, fakelabca.NewFakeClock(time.Now()), false)
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCheckIssuerMismatch(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	f := loadedFetcher(t, fake)
	sib, sibKey := fake.NewSiblingIssuer()
	leafB := issuedLeaf(t, fake, sib, sibKey)
	if rev, err := f.Check(leafB, sib); !rev || !errors.Is(err, crl.ErrIssuerMismatch) {
		t.Errorf("sibling issuer: %v %v", rev, err)
	}
	if rev, err := f.Check(leafB, nil); !rev || !errors.Is(err, crl.ErrIssuerMismatch) {
		t.Errorf("nil issuer: %v %v", rev, err)
	}
}

func TestCheckLeafNotSignedByIssuer(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	f := loadedFetcher(t, fake)
	sib, sibKey := fake.NewSiblingIssuer()
	leafB := issuedLeaf(t, fake, sib, sibKey)
	if rev, err := f.Check(leafB, fake.IssuingCA()); !rev || !errors.Is(err, crl.ErrIssuerMismatch) {
		t.Errorf("got %v %v", rev, err)
	}
}

func TestCheckHappyAndRevoked(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	f := loadedFetcher(t, fake)
	iss := fake.IssuingCA()
	// The fake keeps the issuing key private, so sign through the sign API.
	fake.AddToken("t", "a", "b")
	res := signViaAPI(t, fake)
	leaf := res
	if rev, err := f.Check(leaf, iss); rev || err != nil {
		t.Fatalf("before revoke: %v %v", rev, err)
	}
	fake.RevokeSerial(leaf.SerialNumber.Text(16))
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rev, err := f.Check(leaf, iss); !rev || err != nil {
		t.Fatalf("after revoke: %v %v", rev, err)
	}
}

func signViaAPI(t *testing.T, fake *fakelabca.Server) *x509.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	r, err := (&labcaapi.Client{BaseURL: fake.URL}).Sign(context.Background(), "t", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode([]byte(r.CertificatePEM))
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCheckFailsClosedWithoutCRL(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	f := newFetcher(t, fake, fakelabca.NewFakeClock(time.Now()), false)
	sib, sibKey := fake.NewSiblingIssuer()
	if rev, err := f.Check(issuedLeaf(t, fake, sib, sibKey), sib); !rev || !errors.Is(err, crl.ErrNoValidCRL) {
		t.Errorf("got %v %v", rev, err)
	}
}

func TestCheckStale(t *testing.T) {
	fake := fakelabca.New("labca.test")
	defer fake.Close()
	now := time.Now()
	fake.SetNextUpdate(now.Add(time.Hour))
	clk := fakelabca.NewFakeClock(now)
	f := newFetcher(t, fake, clk, false)
	if err := f.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	sib, sibKey := fake.NewSiblingIssuer()
	if rev, err := f.Check(issuedLeaf(t, fake, sib, sibKey), sib); !rev || !errors.Is(err, crl.ErrStaleCRL) {
		t.Errorf("got %v %v", rev, err)
	}
}
