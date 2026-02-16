package memberlistquic

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/quic-go/quic-go"
	"github.com/wjordan/memberlist-quic/tlsutil"
)

func createTestTransport(t *testing.T, caCert, caKey []byte, nodeName string) (*Transport, *memberlist.Config) {
	t.Helper()

	nodeCert, nodeKey, err := tlsutil.GenerateNodeCertWithIPs(caCert, caKey, nodeName, []net.IP{net.IPv4(127, 0, 0, 1)}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tlsConf, err := tlsutil.MutualTLSConfig(nodeCert, nodeKey, caCert)
	if err != nil {
		t.Fatal(err)
	}

	transport, err := New(Config{
		BindAddr:          "127.0.0.1",
		BindPort:          0,
		TLS:               tlsConf,
		MaxIdleTimeout:    10 * time.Second,
		KeepAlivePeriod:   5 * time.Second,
		PoolSweepInterval: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { transport.Shutdown() })

	mlConfig := memberlist.DefaultLANConfig()
	mlConfig.Name = nodeName
	mlConfig.BindAddr = "127.0.0.1"
	mlConfig.BindPort = 0
	mlConfig.AdvertisePort = 0
	mlConfig.Transport = transport
	mlConfig.LogOutput = nil
	// Reduce probe interval for faster tests while allowing enough time for QUIC
	mlConfig.ProbeInterval = 1 * time.Second
	mlConfig.ProbeTimeout = 500 * time.Millisecond
	mlConfig.SuspicionMult = 2
	mlConfig.RetransmitMult = 2

	return transport, mlConfig
}

func advertiseAddr(t *testing.T, ml *memberlist.Memberlist) string {
	t.Helper()
	cfg := ml.LocalNode()
	return fmt.Sprintf("%s:%d", cfg.Addr.String(), cfg.Port)
}

func TestTwoNodeCluster(t *testing.T) {
	caCert, caKey, err := tlsutil.GenerateCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, cfg1 := createTestTransport(t, caCert, caKey, "node-1")
	_, cfg2 := createTestTransport(t, caCert, caKey, "node-2")

	ml1, err := memberlist.Create(cfg1)
	if err != nil {
		t.Fatal(err)
	}
	defer ml1.Shutdown()

	ml2, err := memberlist.Create(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	defer ml2.Shutdown()

	n, err := ml2.Join([]string{advertiseAddr(t, ml1)})
	if err != nil {
		t.Fatalf("join failed: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 successful join, got %d", n)
	}

	// Wait for convergence
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(ml1.Members()) == 2 && len(ml2.Members()) == 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if len(ml1.Members()) != 2 {
		t.Fatalf("node-1 expected 2 members, got %d", len(ml1.Members()))
	}
	if len(ml2.Members()) != 2 {
		t.Fatalf("node-2 expected 2 members, got %d", len(ml2.Members()))
	}
}

func TestThreeNodeCluster(t *testing.T) {
	caCert, caKey, err := tlsutil.GenerateCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, cfg1 := createTestTransport(t, caCert, caKey, "node-1")
	_, cfg2 := createTestTransport(t, caCert, caKey, "node-2")
	_, cfg3 := createTestTransport(t, caCert, caKey, "node-3")

	ml1, err := memberlist.Create(cfg1)
	if err != nil {
		t.Fatal(err)
	}
	defer ml1.Shutdown()

	ml2, err := memberlist.Create(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	defer ml2.Shutdown()

	ml3, err := memberlist.Create(cfg3)
	if err != nil {
		t.Fatal(err)
	}
	defer ml3.Shutdown()

	// Join node-2 and node-3 to node-1
	if _, err := ml2.Join([]string{advertiseAddr(t, ml1)}); err != nil {
		t.Fatalf("join node-2 failed: %v", err)
	}
	if _, err := ml3.Join([]string{advertiseAddr(t, ml1)}); err != nil {
		t.Fatalf("join node-3 failed: %v", err)
	}

	// Wait for full convergence
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(ml1.Members()) == 3 && len(ml2.Members()) == 3 && len(ml3.Members()) == 3 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	for _, ml := range []*memberlist.Memberlist{ml1, ml2, ml3} {
		if len(ml.Members()) != 3 {
			t.Fatalf("%s expected 3 members, got %d", ml.LocalNode().Name, len(ml.Members()))
		}
	}
}

func TestLeaveDetection(t *testing.T) {
	caCert, caKey, err := tlsutil.GenerateCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, cfg1 := createTestTransport(t, caCert, caKey, "node-1")
	_, cfg2 := createTestTransport(t, caCert, caKey, "node-2")

	ml1, err := memberlist.Create(cfg1)
	if err != nil {
		t.Fatal(err)
	}
	defer ml1.Shutdown()

	ml2, err := memberlist.Create(cfg2)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ml2.Join([]string{advertiseAddr(t, ml1)}); err != nil {
		t.Fatalf("join failed: %v", err)
	}

	// Wait for full membership
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(ml1.Members()) == 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Leave
	if err := ml2.Leave(5 * time.Second); err != nil {
		t.Fatalf("leave failed: %v", err)
	}
	ml2.Shutdown()

	// Wait for node-1 to detect leave
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		members := ml1.Members()
		if len(members) == 1 && members[0].Name == "node-1" {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("node-1 expected 1 member after leave, got %d", len(ml1.Members()))
}

func TestConnPoolSharing(t *testing.T) {
	caCert, caKey, err := tlsutil.GenerateCA("test-org", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	tr1, cfg1 := createTestTransport(t, caCert, caKey, "node-1")
	tr2, cfg2 := createTestTransport(t, caCert, caKey, "node-2")

	ml1, err := memberlist.Create(cfg1)
	if err != nil {
		t.Fatal(err)
	}
	defer ml1.Shutdown()

	ml2, err := memberlist.Create(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	defer ml2.Shutdown()

	if _, err := ml2.Join([]string{advertiseAddr(t, ml1)}); err != nil {
		t.Fatalf("join failed: %v", err)
	}

	// Wait for convergence
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(ml1.Members()) == 2 && len(ml2.Members()) == 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Verify the connection pool has connections
	pool1 := tr1.ConnPool()
	pool2 := tr2.ConnPool()

	if pool1.Len() == 0 {
		t.Fatal("node-1 pool should have connections")
	}
	if pool2.Len() == 0 {
		t.Fatal("node-2 pool should have connections")
	}

	// Open an application-level stream on the existing connection
	var conn *quic.Conn
	pool2.Range(func(addr string, c *quic.Conn) bool {
		conn = c
		return false
	})

	if conn == nil {
		t.Fatal("expected a connection in pool")
	}

	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatalf("failed to open application stream: %v", err)
	}
	stream.Close()
}
