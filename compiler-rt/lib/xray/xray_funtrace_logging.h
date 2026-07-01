//===-- xray_funtrace_logging.h ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of XRay, a dynamic runtime instrumentation system.
//
// A fast, funtrace-inspired ring buffer logging mode for XRay. Key design
// differences from FDR/basic modes that provide ~5x better performance:
//
// 1. Inline ring buffer writes in the trampoline (no function call dispatch)
// 2. Hardware timestamp counter (cntvct_el0 on aarch64) instead of syscall
// 3. Minimal register saves (only registers the trampoline clobbers)
// 4. Simple power-of-2 ring buffer with bitmask wraparound (no locks)
// 5. No recursion guard, no atomic fences in the hot path
//
//===----------------------------------------------------------------------===//
#ifndef XRAY_FUNTRACE_LOGGING_H
#define XRAY_FUNTRACE_LOGGING_H

#include "xray_defs.h"
#include <cstdint>

namespace __xray {

// Ring buffer entry: 16 bytes, matching funtrace's trace_entry layout.
// Kept simple for fast inline writes from assembly trampolines.
struct alignas(16) FuntraceEntry {
  uint64_t FuncData; // Function ID | (EntryType << 32) | flags
  uint64_t Timestamp; // Raw hardware counter value (cntvct_el0 / rdtsc)
};

static_assert(sizeof(FuntraceEntry) == 16,
              "FuntraceEntry must be 16 bytes for assembly trampoline");

// Per-thread trace data, accessed from the fast trampoline via TLS.
// Layout must stay in sync with assembly trampolines.
//
// The first two fields (Pos, WraparoundMask) are loaded as a pair
// by the trampoline using `ldp`. Pos is ANDed with WraparoundMask
// to implement ring buffer wraparound and enable/disable:
//   - WraparoundMask == ~BufSize for enabled (clears wraparound bit)
//   - WraparoundMask == 0 for disabled (AND yields 0 -> early exit)
struct FuntraceThreadData {
  FuntraceEntry *Pos;        // offset 0: current write position
  uint64_t WraparoundMask;   // offset 8: mask for ring buffer wraparound
  FuntraceEntry *Buf;        // offset 16: buffer base pointer
  uint64_t BufSize;          // offset 24: buffer size in bytes (power of 2)
};

// Flag bits for FuncData field
constexpr uint64_t kFuntraceExitBit = 1ULL << 63;
constexpr uint64_t kFuntraceTailExitBit = 1ULL << 62;

bool funtraceLogDynamicInitializer() XRAY_NEVER_INSTRUMENT;

} // namespace __xray

#endif // XRAY_FUNTRACE_LOGGING_H
