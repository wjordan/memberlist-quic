# memberlist-quic

QUIC transport for [hashicorp/memberlist](https://github.com/hashicorp/memberlist), replacing the default UDP+TCP transport with [quic-go](https://github.com/quic-go/quic-go).

All traffic runs over a single UDP socket using TLS 1.3 mutual authentication, QUIC datagrams (RFC 9221) for probe packets, and multiplexed streams for state sync.

## Features

- Drop-in `memberlist.Transport` and `NodeAwareTransport` implementation
- TLS 1.3 mutual authentication on all connections
- QUIC datagrams for packet operations, with automatic stream fallback when payloads exceed the datagram MTU
- Multiplexed bidirectional streams for push-pull state sync
- Connection pool with dial-on-demand, idle eviction, and duplicate connection tiebreaking
- Pool exposed for application-level multiplexing on the same peer connections

## Quick Start

```go
import (
    memberlistquic "github.com/wjordan/memberlist-quic"
    "github.com/wjordan/memberlist-quic/tlsutil"
    "github.com/hashicorp/memberlist"
)

// Generate a CA and node certificate
caCert, caKey, _ := tlsutil.GenerateCA("my-cluster", 365*24*time.Hour)
nodeCert, nodeKey, _ := tlsutil.GenerateNodeCert(caCert, caKey, "node-1", 365*24*time.Hour)
tlsCfg, _ := tlsutil.MutualTLSConfig(nodeCert, nodeKey, caCert)

// Create the QUIC transport
transport, _ := memberlistquic.New(memberlistquic.Config{
    BindAddr: "0.0.0.0",
    BindPort: 7946,
    TLS:      tlsCfg,
})

// Use it with memberlist
cfg := memberlist.DefaultLANConfig()
cfg.Transport = transport
cfg.Name = "node-1"
list, _ := memberlist.Create(cfg)
defer list.Shutdown()
defer transport.Shutdown()
```

## TLS Setup

The `tlsutil` package provides helpers for generating certificates suitable for mutual TLS:

```go
// Generate a self-signed CA
caCert, caKey, err := tlsutil.GenerateCA("my-org", 365*24*time.Hour)

// Generate a node certificate signed by the CA
// The node ID is set as the certificate Common Name
nodeCert, nodeKey, err := tlsutil.GenerateNodeCert(caCert, caKey, "node-1", 365*24*time.Hour)

// Build a mutual TLS config from the node cert and CA
tlsCfg, err := tlsutil.MutualTLSConfig(nodeCert, nodeKey, caCert)
```

In production, use your own CA and certificate management instead of the built-in helpers.

## Connection Pool Sharing

The underlying QUIC connection pool is exposed so applications can open additional streams on the same peer connections:

```go
pool := transport.ConnPool()

// Get an existing connection to a peer (does not dial)
conn := pool.GetConnection("10.0.0.2:7946")

// Or get-or-dial
conn, err := pool.GetOrDial(ctx, "10.0.0.2:7946")

// Open an application-level stream
stream, err := conn.OpenStream()
```

## Configuration

| Field | Default | Description |
|---|---|---|
| `BindAddr` | *(required)* | UDP address to listen on |
| `BindPort` | *(required)* | UDP port for listening and advertising |
| `TLS` | *(required)* | TLS config with mutual authentication |
| `Logger` | `log.Default()` | Logger for transport messages |
| `MaxIdleTimeout` | 30s | QUIC connection idle timeout |
| `KeepAlivePeriod` | 10s | QUIC keep-alive interval |
| `PacketQueueSize` | 256 | Inbound packet channel buffer size |
| `StreamQueueSize` | 16 | Inbound stream channel buffer size |
| `MaxConnectionAge` | 0 (no limit) | Max lifetime for pooled connections |
| `PoolSweepInterval` | 30s | How often idle/dead connections are reaped |

## Requirements

- Go 1.24+
- QUIC datagram support (RFC 9221) is used when available but not required — the transport falls back to streams automatically
