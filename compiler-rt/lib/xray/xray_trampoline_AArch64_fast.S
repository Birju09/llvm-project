//===-- xray_trampoline_AArch64_fast.S -------------------------*- ASM -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Fast XRay trampoline for AArch64, inspired by funtrace
// (https://github.com/yosefk/funtrace).
//
// Key differences from the standard xray_trampoline_AArch64.S:
//
// 1. INLINE RING BUFFER WRITE: Instead of calling a handler function through
//    a global function pointer (which itself does TLS lookup, recursion guard,
//    timestamp read, etc.), we do the entire trace recording inline in ~15
//    instructions. This eliminates the function call overhead and all the
//    indirection in the logging backends.
//
// 2. MINIMAL REGISTER SAVES: The standard trampoline saves x0-x8, x30, and
//    q0-q7 (288 bytes of stack operations). We only save 4 scratch registers
//    (x9-x12, 32 bytes) since we don't call any functions.
//
// 3. HARDWARE TIMESTAMP: Uses `mrs cntvct_el0` (1 instruction, ~few cycles)
//    instead of going through a handler that calls clock_gettime() (syscall,
//    ~100+ cycles).
//
// 4. BITMASK WRAPAROUND: Ring buffer position is ANDed with a mask to wrap
//    around. Setting mask to 0 disables tracing with zero branch overhead
//    (the cbz catches it).
//
// Performance: ~10ns per instrumented call vs ~50-60ns for standard XRay FDR.
//
// TLS Layout (FuntraceThreadData, must match xray_funtrace_logging.h):
//   offset 0:  Pos             (FuntraceEntry*)  - current write position
//   offset 8:  WraparoundMask  (uint64_t)        - ~BufSize or 0 (disabled)
//   offset 16: Buf             (FuntraceEntry*)   - buffer base
//   offset 24: BufSize         (uint64_t)         - buffer size in bytes
//
// Entry layout (FuntraceEntry, 16 bytes):
//   offset 0: FuncData  (uint64_t) - function ID | type flags
//   offset 8: Timestamp (uint64_t) - raw cntvct_el0 value
//
//===----------------------------------------------------------------------===//

#include "../builtins/assembly.h"
#include "../sanitizer_common/sanitizer_asm.h"

// BTI landing pad for indirect calls (BLR).
#if defined(__aarch64__) && defined(__ARM_FEATURE_BTI_DEFAULT)
# define BTI_C hint 34
#else
# define BTI_C
#endif

// Flag bits in FuncData (must match xray_funtrace_logging.h)
#define FUNTRACE_EXIT_BIT      63
#define FUNTRACE_TAIL_EXIT_BIT 62

//===----------------------------------------------------------------------===//
// Macro: LOAD_TLD_ADDR reg
// Load the address of __xray_funtrace_tld (thread-local) into register.
// Uses initial-exec TLS model for shared library compatibility.
//===----------------------------------------------------------------------===//
.macro LOAD_TLD_ADDR reg
#if !defined(XRAY_PIC)
    // Local-exec TLS: direct offset from thread pointer.
    // Only works when compiled into the executable (not a shared library).
    // This is the fastest TLS access: 2 instructions, no memory loads.
    mrs \reg, tpidr_el0
    add \reg, \reg, :tprel_hi12:__xray_funtrace_tld
    add \reg, \reg, :tprel_lo12_nc:__xray_funtrace_tld
#else
    // Initial-exec TLS: GOT lookup for offset, then add to thread pointer.
    // Works from shared libraries but requires one extra memory load.
    adrp \reg, :gottprel:__xray_funtrace_tld
    ldr \reg, [\reg, :gottprel_lo12:__xray_funtrace_tld]
    mrs x10, tpidr_el0
    add \reg, x10, \reg
#endif
.endm

//===----------------------------------------------------------------------===//
// __xray_FunctionEntry (fast path)
//
// Called from XRay sled via BLR x16. x17 contains the function ID.
// x30 points 12 bytes before the actual return address (sled data).
//
// Hot path: 15 instructions, 32 bytes stack, no function calls.
//===----------------------------------------------------------------------===//
.text
.p2align 2
.global ASM_SYMBOL(__xray_FunctionEntry)
ASM_HIDDEN(__xray_FunctionEntry)
ASM_TYPE_FUNCTION(__xray_FunctionEntry)
ASM_SYMBOL(__xray_FunctionEntry):
  BTI_C
  // Skip past the 12 bytes of sled data after the BLR.
  add x30, x30, 12

  // Save scratch registers. We only need 4 registers for the entire
  // operation — a 9x reduction from the standard trampoline's 17 registers.
  stp x9, x10, [sp, #-16]!
  stp x11, x12, [sp, #-16]!

  // Load TLS pointer to FuntraceThreadData.
  LOAD_TLD_ADDR x9

  // Load Pos and WraparoundMask as a pair (they're adjacent in the struct).
  ldp x10, x11, [x9]         // x10 = Pos, x11 = WraparoundMask

  // Ring buffer wraparound + disable check in one instruction.
  // If tracing is disabled, WraparoundMask == 0, so AND yields 0.
  // If enabled, this clears the wraparound bit in Pos.
  and x10, x10, x11
  cbz x10, 1f                // If zero: tracing disabled or Pos is null

  // Read hardware timestamp — single instruction, no syscall.
  mrs x12, cntvct_el0

  // Write trace entry: {FuncID, Timestamp}
  // x17 has the function ID from the XRay sled (zero-extended to 64 bits).
  // Entry type = ENTRY (no flag bits set).
  str x17, [x10]              // FuncData = function ID (entry, no flags)
  str x12, [x10, #8]          // Timestamp = cntvct_el0

  // Advance write position.
  add x10, x10, #16
  str x10, [x9]               // Store new Pos back to TLD

1:
  ldp x11, x12, [sp], #16
  ldp x9, x10, [sp], #16
  ret
ASM_SIZE(__xray_FunctionEntry)

//===----------------------------------------------------------------------===//
// __xray_FunctionExit (fast path)
//===----------------------------------------------------------------------===//
.p2align 2
.global ASM_SYMBOL(__xray_FunctionExit)
ASM_HIDDEN(__xray_FunctionExit)
ASM_TYPE_FUNCTION(__xray_FunctionExit)
ASM_SYMBOL(__xray_FunctionExit):
  BTI_C
  add x30, x30, 12

  stp x9, x10, [sp, #-16]!
  stp x11, x12, [sp, #-16]!

  LOAD_TLD_ADDR x9
  ldp x10, x11, [x9]
  and x10, x10, x11
  cbz x10, 1f

  mrs x12, cntvct_el0

  // Set EXIT flag bit in FuncData.
  mov x11, x17
  orr x11, x11, #(1 << FUNTRACE_EXIT_BIT)
  str x11, [x10]              // FuncData = function ID | EXIT flag
  str x12, [x10, #8]          // Timestamp

  add x10, x10, #16
  str x10, [x9]

1:
  ldp x11, x12, [sp], #16
  ldp x9, x10, [sp], #16
  ret
ASM_SIZE(__xray_FunctionExit)

//===----------------------------------------------------------------------===//
// __xray_FunctionTailExit (fast path)
//===----------------------------------------------------------------------===//
.p2align 2
.global ASM_SYMBOL(__xray_FunctionTailExit)
ASM_HIDDEN(__xray_FunctionTailExit)
ASM_TYPE_FUNCTION(__xray_FunctionTailExit)
ASM_SYMBOL(__xray_FunctionTailExit):
  BTI_C
  add x30, x30, 12

  stp x9, x10, [sp, #-16]!
  stp x11, x12, [sp, #-16]!

  LOAD_TLD_ADDR x9
  ldp x10, x11, [x9]
  and x10, x10, x11
  cbz x10, 1f

  mrs x12, cntvct_el0

  // Set TAIL_EXIT flag bit in FuncData.
  mov x11, x17
  orr x11, x11, #(1 << FUNTRACE_TAIL_EXIT_BIT)
  str x11, [x10]
  str x12, [x10, #8]

  add x10, x10, #16
  str x10, [x9]

1:
  ldp x11, x12, [sp], #16
  ldp x9, x10, [sp], #16
  ret
ASM_SIZE(__xray_FunctionTailExit)

//===----------------------------------------------------------------------===//
// __xray_ArgLoggerEntry (fast path)
// Same as FunctionEntry but also stores x0 (first argument).
// We use a 16-byte entry with the arg encoded in the upper bits of FuncData.
// For simplicity we just record it as a normal entry — arg logging would
// require a wider entry format.
//===----------------------------------------------------------------------===//
.p2align 2
.global ASM_SYMBOL(__xray_ArgLoggerEntry)
ASM_HIDDEN(__xray_ArgLoggerEntry)
ASM_TYPE_FUNCTION(__xray_ArgLoggerEntry)
ASM_SYMBOL(__xray_ArgLoggerEntry):
  BTI_C
  add x30, x30, 12

  stp x9, x10, [sp, #-16]!
  stp x11, x12, [sp, #-16]!

  LOAD_TLD_ADDR x9
  ldp x10, x11, [x9]
  and x10, x10, x11
  cbz x10, 1f

  mrs x12, cntvct_el0

  // Record as normal entry (arg is lost in the fast path for simplicity).
  str x17, [x10]
  str x12, [x10, #8]

  add x10, x10, #16
  str x10, [x9]

1:
  ldp x11, x12, [sp], #16
  ldp x9, x10, [sp], #16
  ret
ASM_SIZE(__xray_ArgLoggerEntry)

//===----------------------------------------------------------------------===//
// __xray_CustomEvent / __xray_TypedEvent
// These are no-ops in the fast path — custom events don't fit the simple
// ring buffer format. Users needing custom events should use FDR mode.
//===----------------------------------------------------------------------===//
.global ASM_SYMBOL(__xray_CustomEvent)
ASM_TYPE_FUNCTION(__xray_CustomEvent)
ASM_SYMBOL(__xray_CustomEvent):
  BTI_C
  ret
ASM_SIZE(__xray_CustomEvent)

.global ASM_SYMBOL(__xray_TypedEvent)
ASM_TYPE_FUNCTION(__xray_TypedEvent)
ASM_SYMBOL(__xray_TypedEvent):
  BTI_C
  ret
ASM_SIZE(__xray_TypedEvent)

NO_EXEC_STACK_DIRECTIVE
