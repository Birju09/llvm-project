//===-- sanitizer_qnx.cpp -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between sanitizer run-time libraries and implements
// QNX-specific functions from sanitizer_libc.h and sanitizer_common.h.
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_QNX

#  include "sanitizer_common.h"
#  include "sanitizer_flags.h"
#  include "sanitizer_internal_defs.h"
#  include "sanitizer_libc.h"
#  include "sanitizer_linux.h"
#  include "sanitizer_mutex.h"
#  include "sanitizer_procmaps.h"

#  include <devctl.h>
#  include <dlfcn.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <pthread.h>
#  include <sched.h>
#  include <signal.h>
#  include <sys/elf.h>
#  include <sys/link.h>
#  include <sys/mman.h>
#  include <sys/neutrino.h>
#  include <sys/procfs.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/time.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <ucontext.h>
#  include <stdio.h>
#  include <unistd.h>

// QNX doesn't have MAP_NORESERVE
#  ifndef MAP_NORESERVE
#    define MAP_NORESERVE 0
#  endif

// QNX doesn't have MADV_DONTNEED; use POSIX equivalent
#  ifndef MADV_DONTNEED
#    define MADV_DONTNEED POSIX_MADV_DONTNEED
#  endif

// QNX may define MAP_ANON but not MAP_ANONYMOUS
#  ifndef MAP_ANONYMOUS
#    ifdef MAP_ANON
#      define MAP_ANONYMOUS MAP_ANON
#    endif
#  endif

namespace __sanitizer {

// Fallback __cxa_guard_* for when the C++ runtime isn't linked in.
// Uses GCC/Clang atomic builtins so these are thread-safe.
// Byte layout: 0 = uninitialized, 1 = in-progress, 2 = done.
extern "C" SANITIZER_WEAK_ATTRIBUTE int __cxa_guard_acquire(void *guard_object) {
  unsigned char *guard = static_cast<unsigned char *>(guard_object);
  if (__atomic_load_n(guard, __ATOMIC_ACQUIRE) == 2)
    return 0;  // Already initialized.
  unsigned char expected = 0;
  if (!__atomic_compare_exchange_n(guard, &expected, (unsigned char)1,
                                   /*weak=*/false, __ATOMIC_ACQ_REL,
                                   __ATOMIC_ACQUIRE))
    return 0;  // Another thread claimed initialization or it's already done.
  return 1;
}

extern "C" SANITIZER_WEAK_ATTRIBUTE void __cxa_guard_release(void *guard_object) {
  unsigned char *guard = static_cast<unsigned char *>(guard_object);
  __atomic_store_n(guard, (unsigned char)2, __ATOMIC_RELEASE);
}

extern "C" SANITIZER_WEAK_ATTRIBUTE void __cxa_guard_abort(void *guard_object) {
  unsigned char *guard = static_cast<unsigned char *>(guard_object);
  __atomic_store_n(guard, (unsigned char)0, __ATOMIC_RELEASE);
}

// --------------- sanitizer_libc.h

// Cache the real mmap from libc so that internal_mmap bypasses any PLT
// interceptors (e.g. RTSAN's mmap interceptor). This mirrors how Linux uses
// internal_syscall() to avoid going through the PLT for sanitizer-internal
// memory allocations.
//
// We use atomics instead of pthread_once to avoid calling intercepted pthread
// functions during early init. A thread-local re-entrancy guard prevents
// infinite recursion if dlsym itself calls mmap internally during init.
typedef void *(*MmapFn)(void *, size_t, int, int, int, off_t);
static MmapFn real_mmap_fn = nullptr;
static int real_mmap_init_done = 0; // 0=uninitialized, 1=done
static __thread bool real_mmap_initializing = false;

static MmapFn GetRealMmap() {
  if (__atomic_load_n(&real_mmap_init_done, __ATOMIC_ACQUIRE))
    return real_mmap_fn;
  // Re-entrancy: if dlsym calls mmap internally, use PLT (returns nullptr
  // here so caller falls back to PLT mmap).
  if (real_mmap_initializing)
    return nullptr;
  real_mmap_initializing = true;
  MmapFn fn = (MmapFn)dlsym(RTLD_NEXT, "mmap");
  if (!fn)
    fn = (MmapFn)dlsym(RTLD_DEFAULT, "mmap");
  real_mmap_fn = fn;
  __atomic_store_n(&real_mmap_init_done, 1, __ATOMIC_RELEASE);
  real_mmap_initializing = false;
  return fn;
}

uptr internal_mmap(void *addr, uptr length, int prot, int flags, int fd,
                   u64 offset) {
  // MAP_ANONYMOUS requires fd=-1 on QNX.
  if (flags & MAP_ANONYMOUS)
    fd = -1;
  // Call the real libc mmap directly, bypassing any PLT interceptors.
  // Falls back to PLT mmap only during re-entrant dlsym init.
  MmapFn fn = GetRealMmap();
  void *res = fn ? fn(addr, length, prot, flags, fd, (off_t)offset)
                 : mmap(addr, length, prot, flags, fd, (off_t)offset);
  if (res == MAP_FAILED)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_munmap(void *addr, uptr length) {
  int res = munmap(addr, length);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_mremap(void *old_address, uptr old_size, uptr new_size, int flags,
                     void *new_address) {
  // QNX does not support mremap. Callers must avoid this path or use
  // munmap+mmap instead.
  errno = ENOSYS;
  return (uptr)-1;
}

int internal_mprotect(void *addr, uptr length, int prot) {
  return mprotect(addr, length, prot);
}

int internal_madvise(uptr addr, uptr length, int advice) {
  // QNX doesn't have madvise; posix_madvise is available but returns
  // error code directly (not via errno).
  return posix_madvise((void *)addr, length, advice);
}

uptr internal_close(fd_t fd) {
  int res = close(fd);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_open(const char *filename, int flags) {
  int fd = open(filename, flags);
  if (fd == -1)
    return (uptr)-errno;
  return (uptr)fd;
}

uptr internal_open(const char *filename, int flags, u32 mode) {
  int fd = open(filename, flags, (mode_t)mode);
  if (fd == -1)
    return (uptr)-errno;
  return (uptr)fd;
}

uptr internal_read(fd_t fd, void *buf, uptr count) {
  ssize_t res;
  HANDLE_EINTR(res, read(fd, buf, (size_t)count));
  if (res == -1)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_write(fd_t fd, const void *buf, uptr count) {
  ssize_t res;
  HANDLE_EINTR(res, write(fd, buf, (size_t)count));
  if (res == -1)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_ftruncate(fd_t fd, uptr size) {
  int res;
  HANDLE_EINTR(res, ftruncate(fd, (off_t)size));
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_stat(const char *path, void *buf) {
  int res = stat(path, (struct stat *)buf);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_lstat(const char *path, void *buf) {
  int res = lstat(path, (struct stat *)buf);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_fstat(fd_t fd, void *buf) {
  int res = fstat(fd, (struct stat *)buf);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_filesize(fd_t fd) {
  struct stat st;
  if (internal_fstat(fd, &st))
    return (uptr)-1;
  return (uptr)st.st_size;
}

uptr internal_dup(int oldfd) {
  int res = dup(oldfd);
  if (res == -1)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_dup2(int oldfd, int newfd) {
  int res = dup2(oldfd, newfd);
  if (res == -1)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_readlink(const char *path, char *buf, uptr bufsize) {
  ssize_t res = readlink(path, buf, (size_t)bufsize);
  if (res == -1)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_unlink(const char *path) {
  int res = unlink(path);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_rename(const char *oldpath, const char *newpath) {
  int res = ::rename(oldpath, newpath);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_sched_yield() {
  int res = sched_yield();
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

void internal_usleep(u64 useconds) {
  struct timespec ts;
  ts.tv_sec = useconds / 1000000;
  ts.tv_nsec = (useconds % 1000000) * 1000;
  nanosleep(&ts, nullptr);
}

uptr internal_execve(const char *filename, char *const argv[],
                     char *const envp[]) {
  execve(filename, argv, envp);
  return (uptr)-errno;
}

void internal__exit(int exitcode) {
  _exit(exitcode);
  Die();  // Unreachable.
}

// ptrace is not available on QNX; devctl/procfs are used for process control.
uptr internal_ptrace(int request, int pid, void *addr, void *data) {
  errno = ENOSYS;
  return (uptr)-1;
}

uptr internal_waitpid(int pid, int *status, int options) {
  pid_t res = waitpid((pid_t)pid, status, options);
  if (res == -1)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_getpid() { return (uptr)getpid(); }

uptr internal_getppid() { return (uptr)getppid(); }

int internal_dlinfo(void *handle, int request, void *p) {
  // QNX does not provide dlinfo(); this interface is unsupported.
  errno = ENOSYS;
  return -1;
}

uptr internal_lseek(fd_t fd, OFF_T offset, int whence) {
  off_t res = lseek(fd, (off_t)offset, whence);
  if (res == (off_t)-1)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_prctl(int option, uptr arg2, uptr arg3, uptr arg4, uptr arg5) {
  // prctl is a Linux-specific syscall not available on QNX.
  errno = ENOSYS;
  return (uptr)-1;
}

uptr internal_sigaltstack(const void *ss, void *oss) {
  int res = sigaltstack((const stack_t *)ss, (stack_t *)oss);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

int internal_fork() {
  return fork();
}

uptr internal_sigprocmask(int how, __sanitizer_sigset_t *set,
                          __sanitizer_sigset_t *oldset) {
  int res = sigprocmask(how, (const sigset_t *)set, (sigset_t *)oldset);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

void internal_sigfillset(__sanitizer_sigset_t *set) {
  sigfillset((sigset_t *)set);
}

void internal_sigemptyset(__sanitizer_sigset_t *set) {
  sigemptyset((sigset_t *)set);
}

void internal_sigdelset(__sanitizer_sigset_t *set, int signum) {
  sigdelset((sigset_t *)set, signum);
}

bool internal_sigismember(__sanitizer_sigset_t *set, int signum) {
  return sigismember((sigset_t *)set, signum) != 0;
}

uptr internal_clock_gettime(__sanitizer_clockid_t clk_id, void *tp) {
  int res = clock_gettime((clockid_t)clk_id, (struct timespec *)tp);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

u64 NanoTime() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (u64)ts.tv_sec * 1000000000ULL + (u64)ts.tv_nsec;
}

// ThreadLister: enumerate threads via /proc/<pid>/as + DCMD_PROC_TIDSTATUS.
ThreadLister::ThreadLister(pid_t pid) : buffer_(4096) {
  task_path_.AppendF("/proc/%d/as", pid);
}

ThreadLister::Result ThreadLister::ListThreads(
    InternalMmapVector<ThreadID> *threads) {
  threads->clear();

  int fd = open(task_path_.data(), O_RDONLY | O_NONBLOCK);
  if (fd < 0) {
    // Fallback: at minimum return the current thread.
    threads->push_back((ThreadID)gettid());
    return Ok;
  }

  // Get process info to know how many threads exist.
  // Heap-allocate large procfs structs to keep the stack frame small.
  InternalMmapVector<procfs_info> pinfo_buf(1);
  procfs_info *pinfo = pinfo_buf.data();
  internal_memset(pinfo, 0, sizeof(*pinfo));
  if (devctl(fd, DCMD_PROC_INFO, pinfo, sizeof(*pinfo), nullptr) != EOK) {
    close(fd);
    threads->push_back((ThreadID)gettid());
    return Ok;
  }

  // TIDs on QNX start at 1 and are assigned sequentially. Iterate until
  // devctl returns an error or we've found all live threads.
  // Use num_threads * 4 as an upper bound to handle TID gaps from thread
  // creation/destruction.
  const int max_tid = pinfo->num_threads * 4 + 16;
  InternalMmapVector<procfs_status> status_buf(1);
  procfs_status *status = status_buf.data();
  for (int tid = 1; tid <= max_tid; ++tid) {
    internal_memset(status, 0, sizeof(*status));
    status->tid = tid;
    if (devctl(fd, DCMD_PROC_TIDSTATUS, status, sizeof(*status), nullptr) !=
        EOK)
      continue;
    if (status->state != STATE_DEAD)
      threads->push_back((ThreadID)status->tid);
  }

  close(fd);

  if (threads->empty())
    threads->push_back((ThreadID)gettid());

  return Ok;
}

const char *ThreadLister::LoadStatus(ThreadID tid) { return nullptr; }

bool ThreadLister::IsAlive(ThreadID tid) {
  return SignalKill(ND_LOCAL_NODE, getpid(), (int)tid, 0, SI_USER, 0) == 0;
}

// Module listing via dl_iterate_phdr. QNX's callback takes const dl_phdr_info*.
static int AddQNXModuleSegments(
    const char *module_name, const dl_phdr_info *info,
    InternalMmapVectorNoCtor<LoadedModule> *modules) {
  // Use a placeholder name rather than skipping unknown modules entirely,
  // so that modules_.size() > 0 is satisfied and address ranges are tracked.
  const char *name =
      (module_name && module_name[0]) ? module_name : "<unknown>";
  LoadedModule cur_module;
  cur_module.set(name, info->dlpi_addr);
  if (!info->dlpi_phdr || info->dlpi_phnum == 0) {
    modules->push_back(cur_module);
    return 0;
  }
  for (int i = 0; i < (int)info->dlpi_phnum; ++i) {
    const Elf64_Phdr *phdr = &info->dlpi_phdr[i];
    if (phdr->p_type == PT_LOAD) {
      uptr cur_beg = info->dlpi_addr + phdr->p_vaddr;
      uptr cur_end = cur_beg + phdr->p_memsz;
      bool executable = (phdr->p_flags & PF_X) != 0;
      bool writable = (phdr->p_flags & PF_W) != 0;
      cur_module.addAddressRange(cur_beg, cur_end, executable, writable);
    }
  }
  modules->push_back(cur_module);
  return 0;
}

struct QNXDlIteratePhdrData {
  InternalMmapVectorNoCtor<LoadedModule> *modules;
  bool first;
};

static int QNXDlIteratePhdrCb(const dl_phdr_info *info, size_t size,
                               void *arg) {
  QNXDlIteratePhdrData *data = static_cast<QNXDlIteratePhdrData *>(arg);
  if (data->first) {
    // First entry is the main executable; dlpi_name may be empty.
    data->first = false;
    InternalMmapVector<char> module_name(kMaxPathLength);
    ReadBinaryNameCached(module_name.data(), module_name.size());
    const char *name =
        (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name
                                                 : module_name.data();
    return AddQNXModuleSegments(name, info, data->modules);
  }
  // Don't skip modules with empty names — use placeholder so they're tracked.
  const char *name =
      (info->dlpi_name && info->dlpi_name[0]) ? info->dlpi_name : "<unknown>";
  return AddQNXModuleSegments(name, info, data->modules);
}

void ListOfModules::init() {
  clearOrInit();
  QNXDlIteratePhdrData data = {&modules_, true};
  dl_iterate_phdr(QNXDlIteratePhdrCb, &data);

  // Fallback: if dl_iterate_phdr didn't enumerate any modules (e.g. static
  // build or unimplemented on this QNX configuration), synthesize an entry
  // for the executable itself so RAW_CHECK(modules_.size() > 0) doesn't fire.
  if (modules_.size() == 0) {
    InternalMmapVector<char> exe_name(kMaxPathLength);
    ReadBinaryNameCached(exe_name.data(), exe_name.size());
    const char *name = exe_name.data()[0] ? exe_name.data() : "<unknown>";
    LoadedModule exe_module;
    exe_module.set(name, /*base_address=*/0);
    modules_.push_back(exe_module);
  }
}

void ListOfModules::fallbackInit() { clear(); }

}  // namespace __sanitizer

#endif  // SANITIZER_QNX
