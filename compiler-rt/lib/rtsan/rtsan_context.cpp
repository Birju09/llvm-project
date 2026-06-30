//===--- rtsan_context.cpp - Realtime Sanitizer -----------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//===----------------------------------------------------------------------===//

#include "rtsan/rtsan_context.h"
#include "rtsan/rtsan.h"

#include "sanitizer_common/sanitizer_allocator_internal.h"

#include <new>
#include <pthread.h>

using namespace __sanitizer;

namespace __rtsan {

static pthread_key_t context_key;
static pthread_once_t key_once = PTHREAD_ONCE_INIT;

// InternalFree cannot be passed directly to pthread_key_create
// because it expects a signature with only one arg
static void InternalFreeWrapper(void *ptr) { __sanitizer::InternalFree(ptr); }

// Re-entrancy guard: set to true while this thread is initializing its
// per-thread context. Accessed via raw TLS (not pthread_getspecific), so it
// does NOT trigger RTSAN interceptors, breaking the initialization cycle.
//
// Initialization cycle on QNX (and some other platforms):
//   GetContextForThisThread()
//     -> pthread_once() / pthread_key_create()  [intercepted]
//       -> interceptor calls GetContextForThisThread()
//         -> pthread_once() again -> deadlock / infinite recursion
//
// When re-entrancy is detected we return a static fallback context that is
// never in realtime mode, so the intercepted init calls are silently allowed.
static __thread bool g_initializing_context = false;

// Constructor defined before the static instance so it is available.
Context::Context() = default;

// Fallback context returned during re-entrant initialization. It is never
// in realtime mode and never bypassed, so intercepted calls during init pass
// through without triggering violations.
static Context g_init_fallback_context;

static Context &GetContextForThisThreadImpl() {
  // Fast re-entrancy check: if we are already setting up the context for this
  // thread, return the fallback to avoid infinite recursion.
  if (g_initializing_context)
    return g_init_fallback_context;

  g_initializing_context = true;

  auto MakeThreadLocalContextKey = []() {
    CHECK_EQ(pthread_key_create(&context_key, InternalFreeWrapper), 0);
  };

  pthread_once(&key_once, MakeThreadLocalContextKey);
  Context *current_thread_context =
      static_cast<Context *>(pthread_getspecific(context_key));
  if (current_thread_context == nullptr) {
    current_thread_context =
        static_cast<Context *>(InternalAlloc(sizeof(Context)));
    new (current_thread_context) Context();
    pthread_setspecific(context_key, current_thread_context);
  }

  g_initializing_context = false;
  return *current_thread_context;
}

void Context::RealtimePush() { realtime_depth_++; }

void Context::RealtimePop() { realtime_depth_--; }

void Context::BypassPush() { bypass_depth_++; }

void Context::BypassPop() { bypass_depth_--; }

bool Context::InRealtimeContext() const { return realtime_depth_ > 0; }

bool Context::IsBypassed() const { return bypass_depth_ > 0; }

Context &GetContextForThisThread() { return GetContextForThisThreadImpl(); }

} // namespace __rtsan
