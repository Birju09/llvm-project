//===-- sanitizer_platform_limits_qnx.cpp ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of Sanitizer common code.
//
// Sizes and layouts of QNX-specific data structures.
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_QNX || defined(__QNXNTO__) || defined(__QNX__) || \
    defined(QNX_OS_SAFETY)

#  include "sanitizer_internal_defs.h"
#  include "sanitizer_platform_limits_posix.h"

#  include <dirent.h>
#  include <grp.h>
#  include <limits.h>
#  include <pthread.h>
#  include <pwd.h>
#  include <regex.h>
#  include <signal.h>
#  include <stddef.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/time.h>
#  include <sys/times.h>
#  include <sys/types.h>
#  include <sys/utsname.h>
#  include <time.h>
#  include <unistd.h>
#  include <wchar.h>

namespace __sanitizer {

unsigned struct_utsname_sz = sizeof(struct utsname);
unsigned struct_stat_sz = sizeof(struct stat);
unsigned struct_rusage_sz = sizeof(struct rusage);
unsigned struct_tm_sz = sizeof(struct tm);
unsigned struct_passwd_sz = sizeof(struct passwd);
unsigned struct_group_sz = sizeof(struct group);
unsigned siginfo_t_sz = sizeof(siginfo_t);
unsigned struct_sigaction_sz = sizeof(struct sigaction);
unsigned struct_stack_t_sz = sizeof(stack_t);
unsigned struct_itimerval_sz = sizeof(struct itimerval);
unsigned pthread_t_sz = sizeof(pthread_t);
unsigned pthread_mutex_t_sz = sizeof(pthread_mutex_t);
unsigned pthread_cond_t_sz = sizeof(pthread_cond_t);
unsigned pid_t_sz = sizeof(pid_t);
unsigned timeval_sz = sizeof(struct timeval);
unsigned uid_t_sz = sizeof(uid_t);
unsigned gid_t_sz = sizeof(gid_t);
unsigned mbstate_t_sz = sizeof(mbstate_t);
unsigned sigset_t_sz = sizeof(sigset_t);
unsigned struct_timezone_sz = sizeof(struct timezone);
unsigned struct_tms_sz = sizeof(struct tms);
unsigned struct_sigevent_sz = sizeof(struct sigevent);
unsigned struct_sched_param_sz = sizeof(struct sched_param);
unsigned struct_regex_sz = sizeof(regex_t);
unsigned struct_regmatch_sz = sizeof(regmatch_t);
unsigned struct_dirent_sz = sizeof(struct dirent);

const int si_SEGV_MAPERR = SEGV_MAPERR;
const int si_SEGV_ACCERR = SEGV_ACCERR;

const uptr sig_ign = (uptr)SIG_IGN;
const uptr sig_dfl = (uptr)SIG_DFL;
const uptr sig_err = (uptr)SIG_ERR;
const uptr sa_siginfo = (uptr)SA_SIGINFO;

}  // namespace __sanitizer

#endif  // SANITIZER_QNX
