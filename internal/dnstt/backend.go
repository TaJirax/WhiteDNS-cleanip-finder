package dnstt

import (
	"context"
	"fmt"
	"net"

	"whitedns-go/internal/dnstt/noise"
	"whitedns-go/internal/e2e"
)

// tunnelDialer adapts dnstt.Dial to the e2e.TunnelDialer seam: it decodes the
// hex public key from Options once per resolver and brings up one tunnel stream.
type tunnelDialer struct{}

func (tunnelDialer) Dial(ctx context.Context, resolver string, opts e2e.Options) (net.Conn, error) {
	pubkey, err := noise.DecodeKey(opts.PubKey)
	if err != nil {
		return nil, fmt.Errorf("bad pubkey: %w", err)
	}
	return Dial(ctx, resolver, opts.Domain, pubkey, string(opts.Transport))
}

// NewValidator returns the DNSTT end-to-end resolver Validator backed by the
// vendored dnstt tunnel runtime, ready to hand to e2e.Run. Requiring a public
// key is enforced by the tunnel handshake; an empty key yields a
// tunnel-reachability-only verdict per e2e's DNSTT backend semantics.
func NewValidator() e2e.Validator {
	return e2e.NewDNSTTValidator(tunnelDialer{})
}
