// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/utils.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <pid/types/pid_key.h>

// Registry of threads whose operations must be grouped under their own trace
// (feature-gated by g_thread_trace_grouping, see OTEL_EBPF_BPF_THREAD_TRACE_GROUPING).
//
// Scenario: a main process creates a long-lived daemon thread that performs
// background work (same user-space pid, different OS tid). No server request
// ever runs on that thread, so the normal parent lookups find nothing and
// every operation becomes a disconnected single-span trace. Entries here are
// written at sys_clone time, keyed by the new thread's OWN namespaced
// identity {pid, tid, ns} — the exact key the thread rebuilds from its own
// task info at lookup time. A hit makes find_thread_group_trace get-or-create
// a root context in server_traces under that same key, so all spans from the
// thread join a single trace grouped by the owning pid/tid/ns.
//
// The value is the creating thread's namespaced key, kept for debugging and
// potential future linking; the grouping itself only relies on key presence.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);   // key: the created thread's own {pid, tid, ns}
    __type(value, pid_key_t); // value: the creating thread's namespaced key
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} thread_trace_map SEC(".maps");
