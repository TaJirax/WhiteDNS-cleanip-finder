package antidpi

import (
	"bytes"
	"context"
	"net"
	"testing"
)

type recordConn struct {
	net.Conn
	writes [][]byte
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func TestOnlyClientHelloIsFragmentedAndBytesStayIntact(t *testing.T) {
	base := &recordConn{}
	conn := Wrap(context.Background(), base, Options{Enabled: true, Size: 4})
	plain := []byte("CONNECT example.com:443 HTTP/1.1\r\n\r\n")
	conn.Write(plain)
	hello := []byte{22, 3, 1, 0, 8, 1, 0, 0, 4, 1, 2, 3, 4}
	n, err := conn.Write(hello)
	if err != nil || n != len(hello) || len(base.writes) != 5 {
		t.Fatal(n, err, len(base.writes))
	}
	if !bytes.Equal(bytes.Join(base.writes[1:], nil), hello) {
		t.Fatal("TLS bytes changed")
	}
	conn.Write(hello)
	if len(base.writes) != 6 {
		t.Fatal("application writes were fragmented")
	}
	if Wrap(context.Background(), base, Options{}) != base {
		t.Fatal("disabled transport changed")
	}
}
