// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

#include <pid/types/pid_key.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} parent_thread_traces SEC(".maps");
