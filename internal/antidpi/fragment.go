package antidpi

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Options struct {
	Enabled       bool
	Size, DelayMs int
}

func (o Options) Validate() error {
	if o.Enabled && (o.Size < 1 || o.Size > 1024 || o.DelayMs < 0 || o.DelayMs > 20) {
		return fmt.Errorf("Anti-DPI: use 1-1024 bytes and 0-20 ms delay")
	}
	return nil
}

// Wrap changes TCP write boundaries only: TLS bytes, SNI and certificate policy
// stay intact. The operating system may coalesce writes; bypass is best-effort.
func Wrap(ctx context.Context, conn net.Conn, options Options) net.Conn {
	if !options.Enabled {
		return conn
	}
	return &fragmentConn{Conn: conn, ctx: ctx, options: options}
}

type fragmentConn struct {
	net.Conn
	mu      sync.Mutex
	ctx     context.Context
	options Options
	done    bool
}

func (c *fragmentConn) Write(data []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done || len(data) < 6 || data[0] != 22 || data[1] != 3 || data[5] != 1 {
		return c.Conn.Write(data)
	}
	c.done = true
	written := 0
	for len(data) > 0 {
		if err := c.ctx.Err(); err != nil {
			return written, err
		}
		size := min(max(c.options.Size, 1), len(data))
		n, err := c.Conn.Write(data[:size])
		written += n
		if err != nil {
			return written, err
		}
		if n != size {
			return written, io.ErrShortWrite
		}
		data = data[size:]
		if len(data) > 0 && c.options.DelayMs > 0 {
			timer := time.NewTimer(time.Duration(c.options.DelayMs) * time.Millisecond)
			select {
			case <-timer.C:
			case <-c.ctx.Done():
				timer.Stop()
				return written, c.ctx.Err()
			}
		}
	}
	return written, nil
}
