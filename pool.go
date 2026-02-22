package memberlistquic

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

type poolEntry struct {
	mu        sync.Mutex
	conn      *quic.Conn
	createdAt time.Time
}

func (e *poolEntry) setConn(conn *quic.Conn) {
	e.conn = conn
	e.createdAt = time.Now()
}

// ConnPool manages QUIC connections to peers.
type ConnPool struct {
	transport  *quic.Transport
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	entries    sync.Map // addr string → *poolEntry
	logger     *log.Logger

	// onNewConn is called when a new outbound connection is dialed.
	// The Transport uses this to start receive goroutines.
	onNewConn func(conn *quic.Conn)

	maxAge        time.Duration
	sweepInterval time.Duration

	shutdownCh chan struct{}
	wg         sync.WaitGroup
}

func newConnPool(transport *quic.Transport, tlsConfig *tls.Config, quicConfig *quic.Config, logger *log.Logger, maxAge, sweepInterval time.Duration, onNewConn func(*quic.Conn)) *ConnPool {
	p := &ConnPool{
		transport:     transport,
		tlsConfig:     tlsConfig,
		quicConfig:    quicConfig,
		logger:        logger,
		maxAge:        maxAge,
		sweepInterval: sweepInterval,
		onNewConn:     onNewConn,
		shutdownCh:    make(chan struct{}),
	}

	if sweepInterval > 0 {
		p.wg.Add(1)
		go p.sweepLoop()
	}

	return p
}

// getAliveConn returns the connection from an entry if it's alive, or nil.
// Caller must hold entry.mu.
func getAliveConn(entry *poolEntry) *quic.Conn {
	if entry.conn != nil && entry.conn.Context().Err() == nil {
		return entry.conn
	}
	return nil
}

// GetConnection returns an existing connection to the given address, or nil.
func (p *ConnPool) GetConnection(addr string) *quic.Conn {
	val, ok := p.entries.Load(addr)
	if !ok {
		return nil
	}
	entry := val.(*poolEntry)
	entry.mu.Lock()
	conn := getAliveConn(entry)
	entry.mu.Unlock()
	if conn == nil {
		p.entries.Delete(addr)
	}
	return conn
}

// GetOrDial returns an existing connection or dials a new one.
func (p *ConnPool) GetOrDial(ctx context.Context, addr string) (*quic.Conn, error) {
	// Fast path: existing live connection
	if conn := p.GetConnection(addr); conn != nil {
		return conn, nil
	}

	// Ensure an entry exists for dedup
	newEntry := &poolEntry{}
	val, _ := p.entries.LoadOrStore(addr, newEntry)
	entry := val.(*poolEntry)

	// Lock the entry to serialize dialing
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Double-check under lock
	if conn := getAliveConn(entry); conn != nil {
		return conn, nil
	}

	// Dial
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	tlsConf := p.tlsConfig.Clone()
	tlsConf.ServerName = udpAddr.IP.String()

	conn, err := p.transport.Dial(ctx, udpAddr, tlsConf, p.quicConfig)
	if err != nil {
		return nil, err
	}

	entry.setConn(conn)

	if p.onNewConn != nil {
		p.onNewConn(conn)
	}

	return conn, nil
}

// CloseConnection closes and removes the connection to addr.
func (p *ConnPool) CloseConnection(addr string) {
	val, ok := p.entries.LoadAndDelete(addr)
	if !ok {
		return
	}
	entry := val.(*poolEntry)
	entry.mu.Lock()
	if entry.conn != nil {
		_ = entry.conn.CloseWithError(0, "connection closed")
	}
	entry.mu.Unlock()
}

// Range iterates over all live connections.
func (p *ConnPool) Range(fn func(addr string, conn *quic.Conn) bool) {
	p.entries.Range(func(key, value any) bool {
		entry := value.(*poolEntry)
		entry.mu.Lock()
		conn := getAliveConn(entry)
		entry.mu.Unlock()
		if conn == nil {
			return true
		}
		return fn(key.(string), conn)
	})
}

// Len returns the number of active connections.
func (p *ConnPool) Len() int {
	count := 0
	p.entries.Range(func(_, value any) bool {
		entry := value.(*poolEntry)
		entry.mu.Lock()
		if getAliveConn(entry) != nil {
			count++
		}
		entry.mu.Unlock()
		return true
	})
	return count
}

// AddInbound registers an inbound (or externally established) connection in the pool.
func (p *ConnPool) AddInbound(conn *quic.Conn) {
	addr := conn.RemoteAddr().String()
	entry := &poolEntry{}
	entry.setConn(conn)

	val, loaded := p.entries.LoadOrStore(addr, entry)
	if !loaded {
		return
	}
	// Entry already exists — check if its connection is still alive
	existing := val.(*poolEntry)
	existing.mu.Lock()
	if getAliveConn(existing) == nil {
		existing.setConn(conn)
	}
	existing.mu.Unlock()
}

func (p *ConnPool) sweep() {
	now := time.Now()
	p.entries.Range(func(key, value any) bool {
		entry := value.(*poolEntry)
		entry.mu.Lock()
		if entry.conn == nil || entry.conn.Context().Err() != nil {
			entry.mu.Unlock()
			p.entries.Delete(key)
			return true
		}
		if p.maxAge > 0 && now.Sub(entry.createdAt) > p.maxAge {
			_ = entry.conn.CloseWithError(0, "max connection age exceeded")
			entry.mu.Unlock()
			p.entries.Delete(key)
			return true
		}
		entry.mu.Unlock()
		return true
	})
}

func (p *ConnPool) sweepLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(p.sweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.sweep()
		case <-p.shutdownCh:
			return
		}
	}
}

func (p *ConnPool) close() {
	close(p.shutdownCh)
	p.entries.Range(func(key, value any) bool {
		entry := value.(*poolEntry)
		entry.mu.Lock()
		if entry.conn != nil {
			_ = entry.conn.CloseWithError(0, "transport shutdown")
		}
		entry.mu.Unlock()
		p.entries.Delete(key)
		return true
	})
	p.wg.Wait()
}
