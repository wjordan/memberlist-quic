package memberlistquic

import (
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicStreamConn wraps a quic.Stream to implement net.Conn.
type quicStreamConn struct {
	stream     *quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

var _ net.Conn = (*quicStreamConn)(nil)

func (c *quicStreamConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *quicStreamConn) Write(b []byte) (int, error) { return c.stream.Write(b) }
func (c *quicStreamConn) Close() error                { return c.stream.Close() }
func (c *quicStreamConn) LocalAddr() net.Addr          { return c.localAddr }
func (c *quicStreamConn) RemoteAddr() net.Addr         { return c.remoteAddr }

func (c *quicStreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *quicStreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}
