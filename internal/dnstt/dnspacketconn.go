// Package dnstt vendors the minimal client half of David Fifield's dnstt DNS
// tunnel (https://www.bamsoftware.com/software/dnstt/, public domain) and adapts
// it into a single Dial call that brings up one tunnel stream through a chosen
// resolver. Only the UDP DNS transport is vendored — DoH/DoT would pull in uTLS
// and its transitive crypto stack, which is unnecessary for validating a plain
// UDP/53 resolver and would bloat the Android .aar.
//
// The dns, noise, and turbotunnel subpackages are copied verbatim from upstream;
// this file adapts dnstt-client/dns.go (the DNS-over-UDP packet transport), and
// dial.go adapts dnstt-client/main.go's run() into a stream Dial. Upstream's
// per-packet log.Printf calls are dropped: this runs once per resolver inside a
// bulk scanner, where that logging would be unusable noise.
package dnstt

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"whitedns-go/internal/dnstt/dns"
	"whitedns-go/internal/dnstt/turbotunnel"
)

const (
	// How many bytes of random padding to insert into queries.
	numPadding = 3
	// In an otherwise empty polling query, insert even more random padding,
	// to reduce the chance of a cache hit. Cannot be greater than 31.
	numPaddingForPoll = 8

	// sendLoop's poll timer sends an empty polling query after this much idle
	// time, backing off by pollDelayMultiplier up to maxPollDelay.
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0

	// A limit on the number of empty poll requests we may send in a burst.
	pollLimit = 16
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// DNSPacketConn provides a packet-sending and -receiving interface over DNS. It
// encodes packets + padding as a base32 DNS name in an upstream query's
// Question, and decodes downstream payloads from a TXT RR in the response.
type DNSPacketConn struct {
	clientID turbotunnel.ClientID
	domain   dns.Name
	pollChan chan struct{}
	*turbotunnel.QueuePacketConn
}

// NewDNSPacketConn creates a new DNSPacketConn. transport handles the actual
// sending/receiving of the DNS messages; addr is passed to transport.WriteTo.
func NewDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name) *DNSPacketConn {
	clientID := turbotunnel.NewClientID()
	c := &DNSPacketConn{
		clientID:        clientID,
		domain:          domain,
		pollChan:        make(chan struct{}, pollLimit),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go c.recvLoop(transport)
	go c.sendLoop(transport, addr)
	return c
}

// dnsResponsePayload extracts the downstream payload of a DNS response, encoded
// in the RDATA of a TXT RR. Returns nil unless the message is a well-formed
// response whose Question name is a subdomain of domain and answer is TXT.
func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		return nil
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		return nil
	}
	if len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]
	if _, ok := answer.Name.TrimSuffix(domain); !ok {
		return nil
	}
	if answer.Type != dns.RRTypeTXT {
		return nil
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}
	return payload
}

// nextPacket reads the next length-prefixed packet from r.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

// recvLoop reads DNS responses via transport, decodes their payloads into
// packets, and queues them for ReadFrom. On any data received it pokes pollChan
// so sendLoop can poll immediately. It returns on transport read error.
func (c *DNSPacketConn) recvLoop(transport net.PacketConn) {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			return
		}
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			continue
		}
		payload := dnsResponsePayload(&resp, c.domain)
		r := bytes.NewReader(payload)
		any := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			any = true
			c.QueuePacketConn.QueueIncoming(p, addr)
		}
		if any {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

// chunks breaks p into non-empty subslices of at most n bytes.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

// send encodes p into a DNS query name (ClientID + padding + length-prefixed
// data, base32'd, split into labels, suffixed with domain) and writes it via
// transport. len(p) must be < 224.
func (c *DNSPacketConn) send(transport net.PacketConn, p []byte, addr net.Addr) error {
	var decoded []byte
	{
		if len(p) >= 224 {
			return fmt.Errorf("too long")
		}
		var buf bytes.Buffer
		buf.Write(c.clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
		}
		buf.WriteByte(byte(224 + n))
		io.CopyN(&buf, rand.Reader, int64(n))
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR = 0, RD = 1
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		// EDNS(0)
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}
	_, err = transport.WriteTo(buf, addr)
	return err
}

// sendLoop sends queued outgoing packets via send, and polls with empty queries
// when requested by pollChan or after an idle timeout. It returns on send error
// only for the outgoing transport being closed (send errors are skipped).
func (c *DNSPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		pollTimerExpired := false
		select {
		case p = <-outgoing:
		default:
			select {
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		if err := c.send(transport, p, addr); err != nil {
			// A closed underlying transport surfaces via recvLoop's return and
			// KCP timeouts; transient send errors are skipped, matching upstream.
			continue
		}
	}
}
