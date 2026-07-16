package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeDialer returns a real TCP connection to addr (an in-process HTTP server),
// standing in for a live dnstt tunnel stream so the validator's HTTP E2E logic
// can be exercised without any tunnel runtime. dialErr forces a dial failure.
type fakeDialer struct {
	addr    string
	dialErr error
}

func (d *fakeDialer) Dial(ctx context.Context, resolver string, opts Options) (net.Conn, error) {
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	var dl net.Dialer
	return dl.DialContext(ctx, "tcp", d.addr)
}

func TestDNSTTValidatorHTTPVerdicts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.WriteHeader(http.StatusNoContent) // 204 -> pass
		case "/redir":
			w.WriteHeader(http.StatusMovedPermanently) // 301 -> pass
		default:
			w.WriteHeader(http.StatusInternalServerError) // 500 -> fail
		}
	}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	cases := []struct {
		path       string
		wantOK     bool
		wantStatus int
	}{
		{"/ok", true, 204},
		{"/redir", true, 301},
		{"/boom", false, 500},
	}
	for _, tc := range cases {
		v := NewDNSTTValidator(&fakeDialer{addr: addr})
		opts := Options{Domain: "t.example", PubKey: "deadbeef", E2EURL: "http://" + addr + tc.path}.withDefaults()
		got := v.Validate(context.Background(), "9.9.9.9:53", opts)
		if got.OK != tc.wantOK {
			t.Errorf("%s: OK=%v want %v (reason=%q)", tc.path, got.OK, tc.wantOK, got.Reason)
		}
		if got.HTTPStatus != tc.wantStatus {
			t.Errorf("%s: HTTPStatus=%d want %d", tc.path, got.HTTPStatus, tc.wantStatus)
		}
	}
}

func TestDNSTTValidatorDialFailure(t *testing.T) {
	v := NewDNSTTValidator(&fakeDialer{dialErr: fmt.Errorf("no route to tunnel")})
	opts := Options{Domain: "t.example", PubKey: "deadbeef"}.withDefaults()
	got := v.Validate(context.Background(), "9.9.9.9:53", opts)
	if got.OK {
		t.Fatalf("expected failure when tunnel dial fails, got OK: %+v", got)
	}
	if got.Reason == "" {
		t.Errorf("expected a failure reason")
	}
}

func TestDNSTTValidatorReachabilityOnlyWithoutKey(t *testing.T) {
	// Empty PubKey => no Noise handshake possible, so a completed dial is the
	// verdict (tunnel transport reached the far side); no HTTP fetch is done.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP fetch must not run when PubKey is empty")
	}))
	defer srv.Close()

	v := NewDNSTTValidator(&fakeDialer{addr: srv.Listener.Addr().String()})
	opts := Options{Domain: "t.example"}.withDefaults() // no PubKey
	got := v.Validate(context.Background(), "9.9.9.9:53", opts)
	if !got.OK || got.Reason != "tunnel-reachable" {
		t.Fatalf("expected reachability-only pass, got %+v", got)
	}
	if got.HTTPStatus != 0 {
		t.Errorf("no HTTP fetch expected, got status %d", got.HTTPStatus)
	}
}

func TestDNSTTValidatorNilDialer(t *testing.T) {
	v := NewDNSTTValidator(nil)
	got := v.Validate(context.Background(), "9.9.9.9:53", Options{}.withDefaults())
	if got.OK || got.Reason != "no-tunnel-dialer" {
		t.Fatalf("nil dialer should fail cleanly, got %+v", got)
	}
}
