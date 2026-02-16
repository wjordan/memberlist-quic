package memberlistquic

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/quic-go/quic-go"
)

// sendDatagram sends a packet via QUIC datagram if possible, falling back
// to a unidirectional stream if the payload exceeds the datagram MTU or
// if the peer doesn't support datagrams.
func sendDatagram(conn *quic.Conn, payload []byte) (time.Time, error) {
	now := time.Now()

	if !conn.ConnectionState().SupportsDatagrams.Remote {
		return now, sendViaStream(conn, payload)
	}

	err := conn.SendDatagram(payload)
	if err != nil {
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			return now, sendViaStream(conn, payload)
		}
		return now, err
	}
	return now, nil
}

// sendViaStream sends a packet-like message over a unidirectional stream.
// Used as fallback when datagrams are unavailable or payload exceeds MTU.
// Format: [4B length BE][payload]
func sendViaStream(conn *quic.Conn, payload []byte) error {
	stream, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
	defer stream.Close()

	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := stream.Write(hdr[:]); err != nil {
		return err
	}
	_, err = stream.Write(payload)
	return err
}
