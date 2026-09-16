// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>
#include <common/preempt_guard.h>
#include <common/ssl_helpers.h>

#include <generictracer/ssl_defs.h>
#include <generictracer/tls_prefix.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_read_args.h>
#include <maps/active_ssl_write_args.h>
#include <maps/fd_to_connection.h>

#include <pid/pid.h>

static __always_inline int ssl_size_to_int(size_t size) {
    return (int)min((size_t)__INT_MAX__, size);
}

// SSL read and read_ex are more less the same, but some frameworks use one or the other.
// SSL_read_ex sets an argument pointer with the number of bytes read, while SSL_read returns
// the number of bytes read.
SEC("uprobe/libssl.so:SSL_read")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_read, void *ssl, const void *buf, int num) {
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_read id=%d tid=%d ssl=%llx ===", id, (u32)id, ssl);

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn);
    }

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_to_pid_tid,
                        &args.ssl,
                        &id,
                        BPF_NOEXIST); // we must not overwrite here, remember the original thread

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read")
int BPF_URETPROBE_GUARDED(obi_uretprobe_ssl_read, int ret) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_read id=%d tid=%d ===", id, (u32)id);

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);

    bpf_map_delete_elem(&active_ssl_read_args, &id);

    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, args, ret, TCP_RECV);
    return 0;
}

SEC("uprobe/libssl.so:SSL_read_ex")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_read_ex,
                       void *ssl,
                       const void *buf,
                       int num,
                       size_t *readbytes) { //NOLINT(readability-non-const-parameter)
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_read_ex id=%d tid=%d ssl=%llx ===", id, (u32)id, ssl);

    ssl_pid_connection_info_t *s_conn = bpf_map_lookup_elem(&ssl_to_conn, &ssl);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn);
    }

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = (u64)readbytes;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_read_args, &id, &args, BPF_ANY);
    bpf_map_update_elem(&ssl_to_pid_tid,
                        &args.ssl,
                        &id,
                        BPF_NOEXIST); // we must not overwrite here, remember the original thread

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read_ex")
int BPF_URETPROBE_GUARDED(obi_uretprobe_ssl_read_ex, int ret) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_read_ex id=%d tid=%d ===", id, (u32)id);

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);

    if (!args) {
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        return 0;
    }

    if (ret != 1) {
        const u64 ssl = args->ssl;
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        bpf_map_delete_elem(&ssl_to_pid_tid, &ssl);
        return 0;
    }

    size_t read_len = 0;
    bpf_probe_read_user(&read_len, sizeof(read_len), (void *)args->len_ptr);

    bpf_map_delete_elem(&active_ssl_read_args, &id);
    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, args, ssl_size_to_int(read_len), TCP_RECV);
    return 0;
}

// SSL write and write_ex are more less the same, but some frameworks use one or the other.
// SSL_write_ex sets an argument pointer with the number of bytes written, while SSL_write returns
// the number of bytes written.
SEC("uprobe/libssl.so:SSL_write")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_write, void *ssl, const void *buf, int num) {
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_write id=%d tid=%d ssl=%llx ===", id, (u32)id, ssl);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write")
int BPF_URETPROBE_GUARDED(obi_uretprobe_ssl_write, int ret) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);

    bpf_dbg_printk("=== uretprobe SSL_write id=%d tid=%d args %llx ===", id, (u32)id, args);

    if (args) {
        ssl_args_t saved = {};
        __builtin_memcpy(&saved, args, sizeof(ssl_args_t));
        bpf_map_delete_elem(&active_ssl_write_args, &id);
        // must be last in the function, doesn't return
        handle_ssl_buf(ctx, id, &saved, ret, TCP_SEND);
    }

    return 0;
}

SEC("uprobe/libssl.so:SSL_write_ex")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_write_ex,
                       void *ssl,
                       const void *buf,
                       size_t num,
                       size_t *written) { //NOLINT(readability-non-const-parameter)
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_write_ex id=%d tid=%d ssl=%llx ===", id, (u32)id, ssl);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = (u64)written;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("uprobe/libssl.so:SSL_write_ex2")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_write_ex2,
                       void *ssl,
                       const void *buf,
                       size_t num,
                       u64 flags,
                       size_t *written) { //NOLINT(readability-non-const-parameter)
    (void)ctx;
    (void)num;
    (void)flags;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_write_ex2 id=%d tid=%d ssl=%llx ===", id, (u32)id, ssl);

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = (u64)written;
    args.flags = 0;

    bpf_map_update_elem(&active_ssl_write_args, &id, &args, BPF_ANY);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex")
int BPF_URETPROBE_GUARDED(obi_uretprobe_ssl_write_ex, int ret) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);

    bpf_dbg_printk("=== uretprobe SSL_write_ex id=%d tid=%d args %llx ===", id, (u32)id, args);

    if (ret != 1 || !args) {
        bpf_map_delete_elem(&active_ssl_write_args, &id);
        return 0;
    }

    size_t write_len = 0;
    bpf_probe_read_user(&write_len, sizeof(write_len), (void *)args->len_ptr);

    ssl_args_t saved = {};
    __builtin_memcpy(&saved, args, sizeof(ssl_args_t));
    bpf_map_delete_elem(&active_ssl_write_args, &id);
    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, &saved, ssl_size_to_int(write_len), TCP_SEND);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex2")
int BPF_URETPROBE_GUARDED(obi_uretprobe_ssl_write_ex2, int ret) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_write_args, &id);

    bpf_dbg_printk("=== uretprobe SSL_write_ex2 id=%d tid=%d args %llx ===", id, (u32)id, args);

    if (ret != 1 || !args) {
        bpf_map_delete_elem(&active_ssl_write_args, &id);
        return 0;
    }

    size_t write_len = 0;
    bpf_probe_read_user(&write_len, sizeof(write_len), (void *)args->len_ptr);

    ssl_args_t saved = {};
    __builtin_memcpy(&saved, args, sizeof(ssl_args_t));
    bpf_map_delete_elem(&active_ssl_write_args, &id);
    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, &saved, ssl_size_to_int(write_len), TCP_SEND);

    return 0;
}

SEC("uprobe/libssl.so:SSL_shutdown")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_shutdown, void *s) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_shutdown id=%d tid=%d ssl=%llx ===", id, (u32)id, s);

    ssl_release_connection_state(id, s);
    ssl_release_thread_state(id);

    return 0;
}

// Records which BIOs this SSL reads from and writes to.
//
// CPython (_ssl.c) and Node (crypto_tls.cc) both call this when building the
// connection. It names the connection's own BIOs, separating them from
// OpenSSL's internal staging BIOs, and identifies the SSL behind a BIO level
// write during the handshake, while SSL_write is off the stack.
SEC("uprobe/libssl.so:SSL_set_bio")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_set_bio, void *ssl, void *rbio, void *wbio) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    // Split in two: bpf_trace_printk takes at most three arguments, and clang
    // silently switches to bpf_trace_vprintk beyond that, which needs 5.16.
    bpf_dbg_printk("=== SSL_set_bio id=%d tid=%d ssl=%llx ===", id, (u32)id, ssl);
    bpf_dbg_printk("SSL_set_bio rbio=%llx wbio=%llx", rbio, wbio);

    ssl_bios_track(pid_from_pid_tgid(id), ssl, rbio, wbio);

    return 0;
}

// Associates an SSL with the connection behind a raw file descriptor.
//
// CPython 2.7 (_ssl.c) wires its SSL objects with SSL_set_fd — memory BIO
// support (and with it SSL_set_bio usage) only arrived in Python 3.5 — so the
// SSL_set_bio probe above never fires there. The fd was already mapped to its
// connection at socket setup time (fd_to_connection, populated by both
// kretprobe/sys_accept4 and kretprobe/sys_connect), which lets us bind
// ssl_to_conn here instead of waiting for the lazy kprobe correlation during
// the first SSL_read/SSL_write.
SEC("uprobe/libssl.so:SSL_set_fd")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_set_fd, void *ssl, int fd) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }

    // Split in two: bpf_trace_printk takes at most three arguments
    bpf_dbg_printk("=== SSL_set_fd id=%d tid=%d ===", id, (u32)id);
    bpf_dbg_printk("SSL_set_fd ssl=%llx fd=%d", ssl, fd);

    // Resolve strictly through the fd being wired. A thread-keyed lookup
    // (pid_tid_to_conn) must not be used here: event-loop servers like nginx
    // multiplex many connections on one thread, and that entry holds the most
    // recently accepted connection, not necessarily the one behind this fd.
    const fd_key key = {.pid_tgid = id, .fd = fd};
    connection_info_t *conn = bpf_map_lookup_elem(&fd_to_connection, &key);

    if (!conn) {
        bpf_dbg_printk("SSL_set_fd: no connection known for fd=%d yet tid=%d", fd, (u32)id);
        return 0;
    }

    // Don't clobber an association already established elsewhere (handshake
    // or read/write correlation), which carries an accurate orig_dport.
    if (bpf_map_lookup_elem(&ssl_to_conn, &ssl)) {
        bpf_dbg_printk("SSL_set_fd: ssl=%llx already bound, keeping it", ssl);
        return 0;
    }

    ssl_pid_connection_info_t ssl_conn = {0};
    ssl_conn.p_conn.pid = pid_from_pid_tgid(id);
    __builtin_memcpy(&ssl_conn.p_conn.conn, conn, sizeof(connection_info_t));
    ssl_conn.orig_dport = ssl_conn.p_conn.conn.d_port;
    sort_connection_info(&ssl_conn.p_conn.conn);

    // Bind only ssl_to_conn (payload attribution for the SSL path). Do NOT
    // insert into active_ssl_connections here: fd_to_connection entries
    // outlive closed sockets, so a reused fd number could mark an unrelated,
    // possibly plaintext connection as TLS, making is_ssl_connection()
    // suppress the kprobe parsers for it and dropping its spans entirely.
    // The active flag is set by connect_ssl_to_connection() once real TLS
    // I/O is observed on the socket during SSL_read/SSL_write.
    bpf_dbg_printk("SSL_set_fd: binding ssl=%llx to fd connection", ssl);
    bpf_map_update_elem(&ssl_to_conn, &ssl, &ssl_conn, BPF_ANY);

    return 0;
}

// Drops the BIO associations of an SSL that is going away.
//
// Allocators reuse BIO pointers, and a reused pointer may next serve as an
// internal BIO that SSL_set_bio never names.
SEC("uprobe/libssl.so:SSL_free")
int BPF_UPROBE_GUARDED(obi_uprobe_ssl_free, void *ssl) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_free id=%d tid=%d ssl=%llx ===", id, (u32)id, ssl);

    // Node can free an SSL without shutting it down first, so this is the
    // reliable release point. Only SSL-keyed state goes here: this thread may
    // still be serving other connections through pid_tid_to_conn.
    ssl_release_connection_state(id, ssl);

    return 0;
}

// The seam where ciphertext becomes observable for every TLS stack.
//
// OpenSSL writes a finished record out through the BIO the same way for a
// socket BIO and a memory BIO, whatever the application does with the buffer
// afterwards. It is a libcrypto symbol.
SEC("uprobe/libcrypto.so:BIO_write")
int BPF_UPROBE_GUARDED(obi_uprobe_bio_write, void *bio, const void *buf, int len) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    tls_prefix_register_egress(bio, buf, len);

    return 0;
}
