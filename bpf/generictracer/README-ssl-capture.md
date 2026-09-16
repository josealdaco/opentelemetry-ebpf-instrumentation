# How OBI Captures Plaintext Data on SSL/TLS Connections

This document explains how this eBPF instrumentation captures the **raw (plaintext) payload** of SSL/TLS-encrypted connections — such as HTTPS calls to Elasticsearch or SSL-enabled MySQL sessions — **without ever decrypting traffic and without access to certificates or keys**.

## TL;DR

The eBPF programs never decrypt anything. They intercept application data at the **SSL library API boundary** in userspace, where the data is still (or already) plaintext:

- **Before encryption**: hooking `SSL_write` on entry — the app hands OpenSSL a plaintext buffer to encrypt; the uprobe reads it first.
- **After decryption**: hooking `SSL_read` on return — OpenSSL has already decrypted the wire data into the app's buffer; the uretprobe reads it.

No certificates, private keys, or session keys are ever read or needed.

## Why Not Capture Packets?

Kernel-side probes (`kprobe/tcp_sendmsg`, `kprobe/tcp_recvmsg`, socket filters) see only **ciphertext** for TLS connections. Decrypting it would require the session keys, which is neither practical nor desirable. Instead, the interception point is moved up the stack to where the data is plaintext by definition:

```
  Application
      │  plaintext
      ▼
 ┌─────────────────────────────┐
 │  SSL_write / SSL_read       │ ◀── uprobes capture HERE (plaintext)
 │  (libssl.so / OpenSSL)      │
 └─────────────────────────────┘
      │  ciphertext
      ▼
 ┌─────────────────────────────┐
 │  tcp_sendmsg / tcp_recvmsg  │ ◀── kprobes see ciphertext; used for
 │  (kernel)                   │     connection identity, not payload
 └─────────────────────────────┘
      │
      ▼
    network
```

## The Uprobes (`bpf/generictracer/libssl.c`)

The generic tracer attaches user-space probes to the OpenSSL API of the target process (shared `libssl.so`, or the same symbols statically linked into the binary):

| Hook | Direction | What is captured |
|---|---|---|
| `uprobe/SSL_write`, `SSL_write_ex`, `SSL_write_ex2` | send | Plaintext buffer **before** encryption |
| `uprobe/SSL_read`, `SSL_read_ex` (entry) | receive | Saves the destination buffer pointer |
| `uretprobe/SSL_read`, `SSL_read_ex` (return) | receive | Plaintext **after** decryption, using the saved pointer + return length |
| `uprobe/SSL_shutdown`, `SSL_free` | — | Session teardown / map cleanup |
| `uprobe/SSL_set_bio`, `uprobe/libcrypto.so:BIO_write` | — | BIO-based correlation (see memory BIO section) |

This works because of OpenSSL's calling convention:

```c
int SSL_read (SSL *ssl, void *buf, int num);        // buf receives PLAINTEXT
int SSL_write(SSL *ssl, const void *buf, int num);  // buf contains PLAINTEXT
```

For reads, the entry uprobe stashes the `buf` pointer in the `active_ssl_read_args` map (keyed by pid_tgid); the uretprobe then does `bpf_probe_read` of `ret` bytes from that user-space address — which by then holds decrypted data.

## Correlating the SSL Session to a TCP Connection

The plaintext buffer alone isn't enough — it must be attributed to the right connection (peer address, ports, PID). The `SSL *` pointer serves as the correlation key:

- **`ssl_to_conn`**: maps `SSL *` → `ssl_pid_connection_info_t` (the socket 5-tuple + PID).
- **`pid_tid_to_conn`**: populated by the kernel-side probes (`sys_connect`, `sys_accept4`, `tcp_sendmsg`, `tcp_recvmsg` in `k_tracer.c`) so an in-flight SSL call on a thread can find its socket.
- **`ssl_to_pid_tid`**: handles reads/writes happening on different threads (thread pools) than the one that established the session.

`connect_ssl_to_connection()` / `connect_ssl_to_sock()` (in `bpf/common/ssl_helpers.h`) bind an "unconnected" SSL session — one seen by an SSL uprobe but not yet tied to a socket — to the connection observed by the concurrently-firing kernel probe. The trick: while a thread is inside `SSL_read`/`SSL_write`, any `tcp_recvmsg`/`tcp_sendmsg` it triggers belongs to the same logical operation, so the pid_tgid links the two layers.

`handle_ssl_buf()` (`bpf/generictracer/ssl_defs.h`) walks this fallback chain and finally calls `handle_buf_with_connection(..., WITH_SSL, ...)` — the **same protocol-parsing pipeline** used for plaintext traffic (HTTP, HTTP/2, MySQL, Postgres, Redis, Kafka, ...). This is why TLS-wrapped protocols get the same span quality as unencrypted ones.

Conversely, once a connection is known to be SSL (`active_ssl_connections`), the kernel probes **skip payload parsing** for it (`is_ssl_connection()` checks in `tcp_sendmsg`/`return_recvmsg`) — the ciphertext they see would only pollute protocol detection.

## The Memory BIO Case (`tls_prefix.h`)

Some frameworks (e.g. event-loop servers) don't let OpenSSL write to the socket directly. They use **memory BIOs**: `SSL_write` encrypts into a memory buffer, and the event loop later writes that ciphertext to the socket on a *different* call path, breaking the pid_tgid-based correlation.

The fix is ciphertext fingerprinting:

1. `uprobe/libcrypto.so:BIO_write` records a **prefix of the ciphertext record** just produced by OpenSSL (`tls_prefix_register_egress`), keyed to the `SSL *`.
2. When `kprobe/tcp_sendmsg` later sees an outgoing buffer, `tls_prefix_try_bind()` compares its leading bytes against recorded prefixes. On a match, the connection is bound to the `SSL *` and marked as TLS — so subsequent uprobe-captured plaintext lands on the right connection.

## STARTTLS-style Protocols (MySQL)

Unlike HTTPS (TLS from byte zero), MySQL upgrades mid-stream:

1. Handshake/capability negotiation happens in **plaintext** — the kernel probes see it and establish connection identity.
2. After the client's SSL Request packet, the socket switches to TLS — from then on, queries and results are captured by the `SSL_read`/`SSL_write` uprobes and parsed by the MySQL protocol parser.

The connection info from phase 1 carries over to phase 2 through the `ssl_to_conn`/`pid_tid_to_conn` binding described above.

## Runtime Coverage

| Client stack | Mechanism |
|---|---|
| C/C++, Python, Node.js, PHP, Ruby (OpenSSL-based) | `libssl.so` uprobes (this document) |
| Go (`crypto/tls`) | Separate Go uprobes in the `gotracer` on `crypto/tls.(*Conn).Read/Write` — same plaintext-boundary principle |
| Java (JSSE) | Not OpenSSL; covered by a separate mechanism |
| Statically-linked/stripped exotic TLS | May not be hookable |

## Key Takeaways

1. **No decryption ever happens** — data is read where it is naturally plaintext.
2. **No key material is touched** — the `SSL *` pointer is used only as an opaque correlation key.
3. **Kernel probes provide identity, uprobes provide payload** — the two layers are joined via pid_tgid and the SSL pointer maps.
4. **One parsing pipeline** — TLS and non-TLS traffic converge into `handle_buf_with_connection`, so span quality is identical.
