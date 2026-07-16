package dnstt

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"

	"whitedns-go/internal/dnstt/turbotunnel"
)

// streamPacketConn is a stream-based (TCP) transport for DNS messages: WriteTo
// and ReadFrom exchange DNS messages over a single byte stream, framing each
// with a two-octet big-endian length prefix as in DNS over TCP (RFC 7766).
// This is what makes DNS-over-TCP/53 tunneling work where UDP/53 is poisoned.
//
// It is adapted from dnstt's DoT TLSPacketConn (dnstt-client/tls.go), minus the
// TLS layer and the infinite redial loop: for a per-resolver probe we dial once
// (the caller supplies the conn so dial errors surface immediately) and tear the
// whole thing down on Close. Like the DoT transport it only moves already-
// formatted DNS messages; DNSPacketConn handles encoding the tunnel payload.
type streamPacketConn struct {
	*turbotunnel.QueuePacketConn
	conn net.Conn
}

// newStreamPacketConn wraps an already-dialed TCP conn as a DNS-over-TCP
// transport and starts its send/recv loops. Closing it (via Close) closes the
// conn, which unblocks both loops.
func newStreamPacketConn(conn net.Conn) *streamPacketConn {
	c := &streamPacketConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
		conn:            conn,
	}
	go c.recvLoop(conn)
	go c.sendLoop(conn)
	return c
}

// Close closes the underlying conn (unblocking recvLoop's Read) and then the
// queue (ending sendLoop's range over the outgoing queue).
func (c *streamPacketConn) Close() error {
	_ = c.conn.Close()
	return c.QueuePacketConn.Close()
}

// recvLoop reads length-prefixed messages from conn and queues them for ReadFrom.
func (c *streamPacketConn) recvLoop(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		var length uint16
		if err := binary.Read(br, binary.BigEndian, &length); err != nil {
			return
		}
		p := make([]byte, int(length))
		if _, err := io.ReadFull(br, p); err != nil {
			return
		}
		c.QueuePacketConn.QueueIncoming(p, turbotunnel.DummyAddr{})
	}
}

// sendLoop writes queued outgoing messages to conn, each length-prefixed.
func (c *streamPacketConn) sendLoop(conn net.Conn) {
	bw := bufio.NewWriter(conn)
	for p := range c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{}) {
		length := uint16(len(p))
		if int(length) != len(p) {
			// Message longer than a DNS-over-TCP frame can express; drop it.
			continue
		}
		if err := binary.Write(bw, binary.BigEndian, &length); err != nil {
			return
		}
		if _, err := bw.Write(p); err != nil {
			return
		}
		if err := bw.Flush(); err != nil {
			return
		}
	}
}
