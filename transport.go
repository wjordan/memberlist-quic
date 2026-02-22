package memberlistquic

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/quic-go/quic-go"
)

const (
	alpn = "memberlist-quic/1"

	defaultMaxIdleTimeout  = 30 * time.Second
	defaultKeepAlivePeriod = 10 * time.Second
	defaultPacketQueueSize = 256
	defaultStreamQueueSize = 16
	defaultSweepInterval   = 30 * time.Second
)

// Config configures the QUIC transport.
type Config struct {
	BindAddr string
	BindPort int

	TLS *tls.Config

	Logger *log.Logger

	MaxIdleTimeout  time.Duration
	KeepAlivePeriod time.Duration

	PacketQueueSize int
	StreamQueueSize int

	MaxConnectionAge  time.Duration
	PoolSweepInterval time.Duration
}

// Transport implements memberlist.Transport and memberlist.NodeAwareTransport
// over QUIC.
type Transport struct {
	config     Config
	logger     *log.Logger
	transport  *quic.Transport
	listener   *quic.Listener
	pool       *ConnPool
	packetCh   chan *memberlist.Packet
	streamCh   chan net.Conn
	shutdownCh chan struct{}
	shutdown   sync.Once
	wg         sync.WaitGroup
}

var _ memberlist.NodeAwareTransport = (*Transport)(nil)

// New creates and starts a QUIC transport.
func New(config Config) (*Transport, error) {
	if config.TLS == nil {
		return nil, fmt.Errorf("TLS config is required")
	}

	if config.Logger == nil {
		config.Logger = log.Default()
	}
	if config.MaxIdleTimeout == 0 {
		config.MaxIdleTimeout = defaultMaxIdleTimeout
	}
	if config.KeepAlivePeriod == 0 {
		config.KeepAlivePeriod = defaultKeepAlivePeriod
	}
	if config.PacketQueueSize == 0 {
		config.PacketQueueSize = defaultPacketQueueSize
	}
	if config.StreamQueueSize == 0 {
		config.StreamQueueSize = defaultStreamQueueSize
	}
	if config.PoolSweepInterval == 0 {
		config.PoolSweepInterval = defaultSweepInterval
	}

	// Set ALPN protocol
	tlsConf := config.TLS.Clone()
	tlsConf.NextProtos = []string{alpn}

	// Bind UDP socket
	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP(config.BindAddr),
		Port: config.BindPort,
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind UDP: %w", err)
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:  config.MaxIdleTimeout,
		KeepAlivePeriod: config.KeepAlivePeriod,
		EnableDatagrams: true,
	}

	qTransport := &quic.Transport{Conn: udpConn}

	listener, err := qTransport.Listen(tlsConf, quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to start QUIC listener: %w", err)
	}

	t := &Transport{
		config:     config,
		logger:     config.Logger,
		transport:  qTransport,
		listener:   listener,
		packetCh:   make(chan *memberlist.Packet, config.PacketQueueSize),
		streamCh:   make(chan net.Conn, config.StreamQueueSize),
		shutdownCh: make(chan struct{}),
	}

	t.pool = newConnPool(qTransport, tlsConf, quicConfig, config.Logger, config.MaxConnectionAge, config.PoolSweepInterval, t.startConnHandlers)

	t.wg.Add(1)
	go t.acceptLoop()

	return t, nil
}

// FinalAdvertiseAddr returns the IP and port to advertise.
func (t *Transport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	advertiseIP := net.ParseIP(ip)
	if advertiseIP == nil {
		// Use the bound address
		addr := t.listener.Addr().(*net.UDPAddr)
		if addr.IP.IsUnspecified() {
			// Pick a private IP
			var err error
			advertiseIP, err = getPrivateIP()
			if err != nil {
				return nil, 0, fmt.Errorf("failed to get private IP: %w", err)
			}
		} else {
			advertiseIP = addr.IP
		}
	}
	if port == 0 {
		port = t.listener.Addr().(*net.UDPAddr).Port
	}
	return advertiseIP, port, nil
}

// WriteTo sends a packet to the given address.
func (t *Transport) WriteTo(b []byte, addr string) (time.Time, error) {
	return t.WriteToAddress(b, memberlist.Address{Addr: addr})
}

// WriteToAddress sends a packet to the given address.
func (t *Transport) WriteToAddress(b []byte, addr memberlist.Address) (time.Time, error) {
	conn, err := t.pool.GetOrDial(t.dialContext(), addr.Addr)
	if err != nil {
		return time.Time{}, err
	}
	return sendDatagram(conn, b)
}

// PacketCh returns the channel for inbound packets.
func (t *Transport) PacketCh() <-chan *memberlist.Packet {
	return t.packetCh
}

// DialTimeout opens a stream to the given address.
func (t *Transport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	return t.DialAddressTimeout(memberlist.Address{Addr: addr}, timeout)
}

// DialAddressTimeout opens a stream to the given address.
func (t *Transport) DialAddressTimeout(addr memberlist.Address, timeout time.Duration) (net.Conn, error) {
	conn, err := t.pool.GetOrDial(t.dialContext(), addr.Addr)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStream()
	if err != nil {
		return nil, err
	}

	sc := &quicStreamConn{
		stream:     stream,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}

	if timeout > 0 {
		_ = sc.SetDeadline(time.Now().Add(timeout))
	}

	return sc, nil
}

// StreamCh returns the channel for inbound streams.
func (t *Transport) StreamCh() <-chan net.Conn {
	return t.streamCh
}

// Shutdown closes the transport.
func (t *Transport) Shutdown() error {
	t.shutdown.Do(func() {
		close(t.shutdownCh)
		t.listener.Close()
		t.pool.close()
		t.transport.Close()
	})
	t.wg.Wait()
	return nil
}

// ConnPool returns the underlying connection pool.
func (t *Transport) ConnPool() *ConnPool {
	return t.pool
}

// RawTransport returns the underlying QUIC transport. This is needed for
// hole punching — outgoing dials must originate from the same UDP socket
// as the listener so the NAT mapping is preserved.
func (t *Transport) RawTransport() *quic.Transport {
	return t.transport
}

// startConnHandlers starts the receive goroutines for a newly dialed
// outbound connection. This is also called for inbound connections via acceptLoop.
func (t *Transport) startConnHandlers(conn *quic.Conn) {
	t.wg.Add(3)
	go t.receiveDatagrams(conn)
	go t.acceptStreams(conn)
	go t.acceptUniStreams(conn)
}

func (t *Transport) dialContext() context.Context {
	return shutdownContext{t.shutdownCh}
}

// shutdownContext implements context.Context, cancelling when the shutdown
// channel is closed.
type shutdownContext struct {
	ch <-chan struct{}
}

var _ context.Context = shutdownContext{}

func (c shutdownContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c shutdownContext) Done() <-chan struct{}        { return c.ch }
func (c shutdownContext) Value(any) any               { return nil }
func (c shutdownContext) Err() error {
	select {
	case <-c.ch:
		return fmt.Errorf("transport shutdown")
	default:
		return nil
	}
}

// getPrivateIP returns a private IP address.
func getPrivateIP() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil {
			continue
		}
		if ip[0] == 10 ||
			(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
			(ip[0] == 192 && ip[1] == 168) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("no private IP address found")
}
