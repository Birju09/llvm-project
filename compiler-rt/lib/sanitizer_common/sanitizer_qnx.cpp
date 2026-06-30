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

#  include <dlfcn.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <pthread.h>
#  include <sched.h>
#  include <signal.h>
#  include <sys/mman.h>
#  include <sys/neutrino.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/time.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <ucontext.h>
#  include <unistd.h>

// QNX may define MAP_ANON but not MAP_ANONYMOUS
#  ifndef MAP_ANONYMOUS
#    ifdef MAP_ANON
#      define MAP_ANONYMOUS MAP_ANON
#    endif
#  endif

namespace __sanitizer {

// --------------- sanitizer_libc.h

uptr internal_mmap(void *addr, uptr length, int prot, int flags, int fd,
                   u64 offset) {
  // MAP_ANONYMOUS requires fd=-1 on QNX
  if (flags & MAP_ANONYMOUS)
    fd = -1;
  uptr res = (uptr)mmap(addr, length, prot, flags, fd, (off_t)offset);
  if (res == (uptr)MAP_FAILED)
    return (uptr)-errno;
  return res;
}

uptr internal_munmap(void *addr, uptr length) {
  int res = munmap(addr, length);
  if (res == -1)
    return (uptr)-errno;
  return 0;
}

uptr internal_mremap(void *old_address, uptr old_size, uptr new_size, int flags,
                     void *new_address) {
  // QNX does not support mremap.
  CHECK(false && "internal_mremap is not supported on QNX");
  return (uptr)-ENOSYS;
}

int internal_mprotect(void *addr, uptr length, int prot) {
  return mprotect(addr, length, prot);
}

int internal_madvise(uptr addr, uptr length, int advice) {
  return madvise((void *)addr, length, advice);
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
  int res = rename(oldpath, newpath);
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
  int res = execve(filename, argv, envp);
  return (uptr)-errno;
}

void internal__exit(int exitcode) {
  _exit(exitcode);
  Die();  // Unreachable.
}

// Ptrace is not available on QNX — devctl/procfs are used instead.
uptr internal_ptrace(int request, int pid, void *addr, void *data) {
  UNIMPLEMENTED();
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
  return dlinfo(handle, request, p);
}

uptr internal_lseek(fd_t fd, OFF_T offset, int whence) {
  off_t res = lseek(fd, (off_t)offset, whence);
  if (res == (off_t)-1)
    return (uptr)-errno;
  return (uptr)res;
}

uptr internal_prctl(int option, uptr arg2, uptr arg3, uptr arg4, uptr arg5) {
  // prctl is not available on QNX.
  UNIMPLEMENTED();
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

// ThreadLister: QNX enumerates threads via /proc/<pid>/as + devctl.
// Provide a minimal stub that returns the current thread only.
// Full implementation is in sanitizer_procmaps_qnx.cpp.
ThreadLister::ThreadLister(pid_t pid) : buffer_(4096) {
  task_path_.AppendF("/proc/%d", pid);
}

ThreadLister::Result ThreadLister::ListThreads(
    InternalMmapVector<ThreadID> *threads) {
  // QNX thread enumeration via /proc/<pid>/as + devctl(DCMD_PROC_TIDSTATUS)
  // For now, return just the current thread as a fallback.
  threads->clear();
  threads->push_back((ThreadID)gettid());
  return Ok;
}

const char *ThreadLister::LoadStatus(ThreadID tid) {
  return nullptr;
}

bool ThreadLister::IsAlive(ThreadID tid) {
  // Check if the thread exists by sending signal 0.
  return tgkill(getpid(), (int)tid, 0) == 0;
}

}  // namespace __sanitizer

#endif  // SANITIZER_QNX
