package memberlistquic

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/quic-go/quic-go"
)

func (t *Transport) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.Accept(context.Background())
		if err != nil {
			select {
			case <-t.shutdownCh:
				return
			default:
				t.logger.Printf("[ERR] memberlist-quic: accept error: %v", err)
				continue
			}
		}
		t.pool.addInbound(conn)
		t.startConnHandlers(conn)
	}
}

func (t *Transport) receiveDatagrams(conn *quic.Conn) {
	defer t.wg.Done()
	for {
		msg, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		select {
		case t.packetCh <- &memberlist.Packet{
			Buf:       msg,
			From:      conn.RemoteAddr(),
			Timestamp: time.Now(),
		}:
		case <-t.shutdownCh:
			return
		}
	}
}

func (t *Transport) acceptStreams(conn *quic.Conn) {
	defer t.wg.Done()
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		sc := &quicStreamConn{
			stream:     stream,
			localAddr:  conn.LocalAddr(),
			remoteAddr: conn.RemoteAddr(),
		}
		select {
		case t.streamCh <- sc:
		case <-t.shutdownCh:
			stream.Close()
			return
		}
	}
}

func (t *Transport) acceptUniStreams(conn *quic.Conn) {
	defer t.wg.Done()
	for {
		stream, err := conn.AcceptUniStream(context.Background())
		if err != nil {
			return
		}
		go t.handleUniStream(stream, conn.RemoteAddr())
	}
}

func (t *Transport) handleUniStream(stream *quic.ReceiveStream, remoteAddr net.Addr) {
	defer stream.CancelRead(0)

	var hdr [4]byte
	if _, err := io.ReadFull(stream, hdr[:]); err != nil {
		return
	}
	size := binary.BigEndian.Uint32(hdr[:])
	if size > 65536 {
		return
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(stream, buf); err != nil {
		return
	}

	select {
	case t.packetCh <- &memberlist.Packet{
		Buf:       buf,
		From:      remoteAddr,
		Timestamp: time.Now(),
	}:
	case <-t.shutdownCh:
	}
}
