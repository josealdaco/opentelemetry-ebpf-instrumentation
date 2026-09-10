// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/trace_key.h>

// Pending map cleanup for an exited thread. kprobes cannot sleep and
// cannot use bpf_timer, so the delayed cleanup is implemented as a FIFO
// queue drained by subsequent sys_exit invocations once the deadline
// (exit time + delay) has passed.
typedef struct exit_pending {
    trace_key_t task;
    u64 id;
    u64 deadline_ns;
} exit_pending_t;

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, exit_pending_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} exit_pending_queue SEC(".maps");
