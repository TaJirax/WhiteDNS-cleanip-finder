package dnsscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestDialUTLSForDoTDoesNotNegotiateHTTP(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := dialUTLS(ctx, "tcp", u.Host, &net.Dialer{Timeout: time.Second}, nil)
	if err != nil {
		t.Fatalf("DoT uTLS handshake failed: %v", err)
	}
	defer conn.Close()

	uconn, ok := conn.(*utls.UConn)
	if !ok {
		t.Fatalf("DoT connection type = %T, want *utls.UConn", conn)
	}
	if got := uconn.ConnectionState().NegotiatedProtocol; got != "" {
		t.Fatalf("DoT negotiated HTTP ALPN %q", got)
	}
}

func TestDoHQueryUsesUTLSHTTP1Transport(t *testing.T) {
	requestOK := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 {
			requestOK <- fmt.Errorf("HTTP version = %s, want HTTP/1.1", r.Proto)
			return
		}
		if r.TLS == nil || r.TLS.NegotiatedProtocol != "http/1.1" {
			requestOK <- fmt.Errorf("negotiated ALPN = %q, want http/1.1", r.TLS.NegotiatedProtocol)
			return
		}
		if got := r.Header.Get("Accept"); got != "application/dns-json" {
			requestOK <- fmt.Errorf("Accept = %q", got)
			return
		}
		requestOK <- nil
		w.Header().Set("Content-Type", "application/dns-json")
		fmt.Fprint(w, `{"Status":0,"Answer":[{"name":"example.com.","type":1,"TTL":60,"data":"192.0.2.1"}]}`)
	}))
	server.TLS = &tls.Config{NextProtos: []string{"http/1.1"}}
	server.StartTLS()
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	client := newDoHClient(3*time.Second, nil)
	resp, _, err := doDoHQuery(context.Background(), host, "example.com", "A", 3*time.Second, client, port)
	if err != nil {
		t.Fatalf("DoH query over uTLS failed: %v", err)
	}
	if err := <-requestOK; err != nil {
		t.Fatal(err)
	}
	if len(resp.Answer) != 1 || resp.Answer[0].Data != "192.0.2.1" {
		t.Fatalf("unexpected DoH response: %+v", resp)
	}
}
