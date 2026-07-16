package dnstt

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"whitedns-go/internal/dnstt/turbotunnel"
)

// TestStreamPacketConnRoundTrip verifies the DNS-over-TCP/53 length-prefixed
// framing: a message written via WriteTo is sent length-prefixed on the wire,
// and a length-prefixed message on the wire is delivered back via ReadFrom.
func TestStreamPacketConnRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Echo server: read one 2-byte-length-prefixed frame, write it back framed.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var n uint16
		if err := binary.Read(br, binary.BigEndian, &n); err != nil {
			return
		}
		p := make([]byte, int(n))
		if _, err := io.ReadFull(br, p); err != nil {
			return
		}
		_ = binary.Write(conn, binary.BigEndian, n)
		_, _ = conn.Write(p)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sp := newStreamPacketConn(conn)
	defer sp.Close()

	payload := []byte("a-formatted-dns-message")
	if _, err := sp.WriteTo(payload, turbotunnel.DummyAddr{}); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	_ = sp.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := sp.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("round-trip mismatch: got %q want %q", buf[:n], payload)
	}
}

func TestEnsurePort(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":      "1.2.3.4:53",
		"1.2.3.4:5300": "1.2.3.4:5300",
		"8.8.8.8":      "8.8.8.8:53",
	}
	for in, want := range cases {
		if got := ensurePort(in); got != want {
			t.Errorf("ensurePort(%q) = %q want %q", in, got, want)
		}
	}
}
