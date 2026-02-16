package tlsutil

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

func TestGenerateCA(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected non-empty PEM output")
	}
}

func TestGenerateNodeCert(t *testing.T) {
	caCert, caKey, err := GenerateCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := GenerateNodeCert(caCert, caKey, "node-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected non-empty PEM output")
	}

	// Verify the cert can be loaded
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
}

func TestMutualTLSConfig(t *testing.T) {
	caCert, caKey, err := GenerateCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	nodeCert, nodeKey, err := GenerateNodeCert(caCert, caKey, "node-1", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tlsConf, err := MutualTLSConfig(nodeCert, nodeKey, caCert)
	if err != nil {
		t.Fatal(err)
	}

	if tlsConf.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("expected RequireAndVerifyClientCert")
	}
	if len(tlsConf.Certificates) != 1 {
		t.Fatal("expected 1 certificate")
	}
	if tlsConf.RootCAs == nil || tlsConf.ClientCAs == nil {
		t.Fatal("expected non-nil CA pools")
	}
}

func TestNodeIDFromConn(t *testing.T) {
	caCert, caKey, err := GenerateCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	serverCert, serverKey, err := GenerateNodeCertWithIPs(caCert, caKey, "server-node", []net.IP{net.IPv4(127, 0, 0, 1)}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	clientCert, clientKey, err := GenerateNodeCertWithIPs(caCert, caKey, "client-node", []net.IP{net.IPv4(127, 0, 0, 1)}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	serverTLS, err := MutualTLSConfig(serverCert, serverKey, caCert)
	if err != nil {
		t.Fatal(err)
	}

	clientTLS, err := MutualTLSConfig(clientCert, clientKey, caCert)
	if err != nil {
		t.Fatal(err)
	}

	// Set up QUIC listener
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()

	tr := &quic.Transport{Conn: udpConn}
	defer tr.Close()

	listener, err := tr.Listen(serverTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Connect from client
	clientTLS.ServerName = "127.0.0.1"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	var serverConn *quic.Conn
	go func() {
		var err error
		serverConn, err = listener.Accept(ctx)
		errCh <- err
	}()

	clientConn, err := tr.Dial(ctx, listener.Addr(), clientTLS, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientConn.CloseWithError(0, "") }()

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	defer func() { _ = serverConn.CloseWithError(0, "") }()

	// Verify NodeIDFromConn
	nodeID, err := NodeIDFromConn(serverConn)
	if err != nil {
		t.Fatal(err)
	}
	if nodeID != "client-node" {
		t.Fatalf("expected client-node, got %s", nodeID)
	}

	nodeID, err = NodeIDFromConn(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	if nodeID != "server-node" {
		t.Fatalf("expected server-node, got %s", nodeID)
	}
}
