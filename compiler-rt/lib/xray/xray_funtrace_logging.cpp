//===-- xray_funtrace_logging.cpp --------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of XRay, a dynamic runtime instrumentation system.
//
// A fast, funtrace-inspired ring buffer logging mode. The hot path (recording
// trace entries) is done entirely inline in the assembly trampoline with no
// function call overhead. This file provides:
//   - Thread-local ring buffer allocation/management
//   - Initialization, finalization, and flushing (cold path)
//   - Snapshot/export of trace data
//
// Based on concepts from https://github.com/yosefk/funtrace
//
//===----------------------------------------------------------------------===//

#include "xray_funtrace_logging.h"
#include "sanitizer_common/sanitizer_allocator_internal.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "xray/xray_interface.h"
#include "xray/xray_log_interface.h"
#include "xray_defs.h"
#include "xray_flags.h"
#include "xray_interface_internal.h"
#include "xray_tsc.h"
#include "xray_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace __xray {

// Default ring buffer size: 2^20 bytes = 1MB = 65536 entries of 16 bytes each.
// This matches funtrace's default and provides ~65K function call history.
static constexpr int kDefaultLogBufSizeLog2 = 20;

// The thread-local trace data. This is accessed from the assembly trampoline
// via TLS. It MUST be compiled into the executable (not a shared library) to
// get efficient local-exec TLS access (single register+offset instruction).
//
// When compiled into a shared library, TLS access requires a function call
// to locate the library's TLS area, which defeats the purpose of inlining.
SANITIZER_INTERFACE_ATTRIBUTE
thread_local FuntraceThreadData __xray_funtrace_tld = {nullptr, 0, nullptr, 0};

static pthread_key_t TLSKey;
static atomic_uint8_t Initialized{0};

// Track all thread buffers for snapshot/flush.
static SpinMutex ThreadListMutex;
struct ThreadBufferNode {
  FuntraceThreadData *TLD;
  FuntraceEntry *Buf;
  uint64_t BufSize;
  uint64_t Tid;
  ThreadBufferNode *Next;
};
static ThreadBufferNode *ThreadList = nullptr;

static void threadCleanup(void *Arg) XRAY_NEVER_INSTRUMENT {
  auto *TLD = reinterpret_cast<FuntraceThreadData *>(Arg);
  // Disable tracing for this thread (trampoline will early-exit).
  TLD->WraparoundMask = 0;
  // We don't free the buffer here — it stays alive for snapshot collection.
  // A GC thread or finalization will clean it up.
}

static int getLogBufSizeLog2() XRAY_NEVER_INSTRUMENT {
  const char *Env = GetEnv("XRAY_FUNTRACE_LOG_BUF_SIZE");
  if (Env)
    return atoi(Env);
  return kDefaultLogBufSizeLog2;
}

// Called once per thread on first instrumented function call.
// The trampoline checks if Pos == nullptr and calls this.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__xray_funtrace_init_thread() XRAY_NEVER_INSTRUMENT {
  if (!atomic_load(&Initialized, memory_order_acquire))
    return;

  int LogSize = getLogBufSizeLog2();
  if (LogSize < 5) // Minimum 32 bytes = 2 entries
    return;

  uint64_t BufSize = 1ULL << LogSize;
  // Align to 2x buffer size for bitmask wraparound trick (from funtrace):
  // After incrementing Pos, ANDing with ~BufSize clears the wraparound bit
  // without worrying about carry propagation to higher bits.
  void *Mem = nullptr;
  int Ret = posix_memalign(&Mem, BufSize * 2, BufSize);
  if (Ret != 0 || Mem == nullptr)
    return;

  // Zero last entry's timestamp to detect wraparound (from funtrace).
  auto *Entries = reinterpret_cast<FuntraceEntry *>(Mem);
  Entries[BufSize / sizeof(FuntraceEntry) - 1].Timestamp = 0;

  auto *TLD = &__xray_funtrace_tld;
  TLD->Buf = Entries;
  TLD->Pos = Entries;
  TLD->BufSize = BufSize;
  TLD->WraparoundMask = ~BufSize; // Enable tracing

  // Register for thread cleanup.
  pthread_setspecific(TLSKey, TLD);

  // Add to global thread list for snapshots.
  auto *Node = reinterpret_cast<ThreadBufferNode *>(
      InternalAlloc(sizeof(ThreadBufferNode)));
  Node->TLD = TLD;
  Node->Buf = Entries;
  Node->BufSize = BufSize;
  Node->Tid = GetTid();
  {
    SpinMutexLock L(&ThreadListMutex);
    Node->Next = ThreadList;
    ThreadList = Node;
  }
}

// The handler function — called from the standard (non-fast) trampoline.
// This provides a fallback path that still uses the ring buffer but goes
// through the normal XRay handler dispatch mechanism.
static void funtraceHandleArg0(int32_t FuncId,
                               XRayEntryType Type) XRAY_NEVER_INSTRUMENT {
  auto *TLD = &__xray_funtrace_tld;

  // Lazy init on first call.
  if (UNLIKELY(TLD->Pos == nullptr)) {
    __xray_funtrace_init_thread();
    if (TLD->Pos == nullptr)
      return;
  }

  auto *Entry = TLD->Pos;
  Entry = reinterpret_cast<FuntraceEntry *>(
      reinterpret_cast<uint64_t>(Entry) & TLD->WraparoundMask);
  if (!Entry)
    return;

  // Read hardware timestamp.
  uint8_t CPU;
  uint64_t TSC = readTSC(CPU);

  // Encode function ID and entry type into FuncData.
  uint64_t FuncData = static_cast<uint64_t>(static_cast<uint32_t>(FuncId));
  switch (Type) {
  case XRayEntryType::EXIT:
    FuncData |= kFuntraceExitBit;
    break;
  case XRayEntryType::TAIL:
    FuncData |= kFuntraceTailExitBit;
    break;
  default:
    break;
  }

  Entry->FuncData = FuncData;
  Entry->Timestamp = TSC;
  TLD->Pos = Entry + 1;
}

// XRay log interface implementation.

static void funtraceAtExit() XRAY_NEVER_INSTRUMENT {
  __xray_log_finalize();
  __xray_log_flushLog();
}

static XRayLogInitStatus
funtraceLoggingInit(size_t, size_t, void *, size_t) XRAY_NEVER_INSTRUMENT {
  pthread_key_create(&TLSKey, threadCleanup);
  atomic_store(&Initialized, 1, memory_order_release);

  // Set the handler for the standard trampoline path.
  __xray_set_handler(funtraceHandleArg0);

  // Flush trace data on program exit.
  atexit(funtraceAtExit);

  return XRayLogInitStatus::XRAY_LOG_INITIALIZED;
}

static XRayLogInitStatus funtraceLoggingFinalize() XRAY_NEVER_INSTRUMENT {
  atomic_store(&Initialized, 0, memory_order_release);
  __xray_remove_handler();

  // Disable all threads.
  {
    SpinMutexLock L(&ThreadListMutex);
    for (auto *N = ThreadList; N; N = N->Next) {
      if (N->TLD)
        N->TLD->WraparoundMask = 0;
    }
  }

  return XRayLogInitStatus::XRAY_LOG_FINALIZED;
}

static XRayLogFlushStatus funtraceLoggingFlush() XRAY_NEVER_INSTRUMENT {
  // Write all thread buffers to a file.
  int Fd = -1;
  {
    // Create output file.
    auto *Filename = GetEnv("XRAY_FUNTRACE_OUTPUT");
    if (!Filename)
      Filename = "xray-funtrace.raw";
    Fd = open(Filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (Fd == -1)
      return XRayLogFlushStatus::XRAY_LOG_NOT_FLUSHING;
  }

  // Write header: magic, version, TSC frequency.
  struct {
    uint64_t Magic;
    uint64_t Version;
    uint64_t TSCFrequency;
  } Header;
  Header.Magic = 0x46554E5452414345ULL; // "FUNTRACE"
  Header.Version = 1;
  Header.TSCFrequency = getTSCFrequency();
  write(Fd, &Header, sizeof(Header));

  // Write each thread's buffer.
  {
    SpinMutexLock L(&ThreadListMutex);
    for (auto *N = ThreadList; N; N = N->Next) {
      struct {
        uint64_t Tid;
        uint64_t BufSize;
        uint64_t PosOffset; // Offset of current write position from buf start
      } ThreadHeader;
      ThreadHeader.Tid = N->Tid;
      ThreadHeader.BufSize = N->BufSize;
      auto *TLD = N->TLD;
      if (TLD && TLD->Buf) {
        ThreadHeader.PosOffset =
            reinterpret_cast<uint64_t>(TLD->Pos) -
            reinterpret_cast<uint64_t>(TLD->Buf);
      } else {
        ThreadHeader.PosOffset = 0;
      }
      write(Fd, &ThreadHeader, sizeof(ThreadHeader));
      if (N->Buf && N->BufSize)
        write(Fd, N->Buf, N->BufSize);
    }
  }

  close(Fd);

  // Free all buffers.
  {
    SpinMutexLock L(&ThreadListMutex);
    auto *N = ThreadList;
    while (N) {
      auto *Next = N->Next;
      if (N->Buf)
        free(N->Buf);
      if (N->TLD) {
        N->TLD->Pos = nullptr;
        N->TLD->Buf = nullptr;
        N->TLD->WraparoundMask = 0;
      }
      InternalFree(N);
      N = Next;
    }
    ThreadList = nullptr;
  }

  pthread_key_delete(TLSKey);

  return XRayLogFlushStatus::XRAY_LOG_FLUSHED;
}

static void funtraceHandleArg0Empty(int32_t,
                                    XRayEntryType) XRAY_NEVER_INSTRUMENT {}

bool funtraceLogDynamicInitializer() XRAY_NEVER_INSTRUMENT {
  XRayLogImpl Impl{
      funtraceLoggingInit,
      funtraceLoggingFinalize,
      funtraceHandleArg0Empty,
      funtraceLoggingFlush,
  };
  auto RegistrationResult =
      __xray_log_register_mode("xray-funtrace", Impl);
  if (RegistrationResult != XRayLogRegisterStatus::XRAY_REGISTRATION_OK &&
      Verbosity())
    Report("Cannot register XRay Funtrace Mode to 'xray-funtrace'; "
           "error = %d\n",
           RegistrationResult);

  if (!internal_strcmp(flags()->xray_mode, "xray-funtrace")) {
    auto SelectResult = __xray_log_select_mode("xray-funtrace");
    if (SelectResult != XRayLogRegisterStatus::XRAY_REGISTRATION_OK) {
      if (Verbosity())
        Report("Failed selecting XRay Funtrace Mode; error = %d\n",
               SelectResult);
      return false;
    }
    auto InitResult = __xray_log_init_mode("xray-funtrace", "");
    if (InitResult != XRayLogInitStatus::XRAY_LOG_INITIALIZED) {
      if (Verbosity())
        Report("Failed initializing XRay Funtrace Mode; error = %d\n",
               InitResult);
      return false;
    }
    __xray_patch();
    return true;
  }
  return false;
}

// Static initializer to register the mode.
static bool UNUSED Unused = funtraceLogDynamicInitializer();

} // namespace __xray
