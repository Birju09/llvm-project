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

#if SANITIZER_QNX

#  include "sanitizer_internal_defs.h"
#  include "sanitizer_platform_limits_posix.h"

#  include <dirent.h>
#  include <limits.h>
#  include <pthread.h>
#  include <pwd.h>
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
unsigned siginfo_t_sz = sizeof(siginfo_t);
unsigned struct_itimerval_sz = sizeof(struct itimerval);
unsigned pthread_t_sz = sizeof(pthread_t);
unsigned pthread_mutex_t_sz = sizeof(pthread_mutex_t);
unsigned pthread_cond_t_sz = sizeof(pthread_cond_t);
unsigned pid_t_sz = sizeof(pid_t);
unsigned timeval_sz = sizeof(struct timeval);
unsigned uid_t_sz = sizeof(uid_t);
unsigned gid_t_sz = sizeof(gid_t);
unsigned mbstate_t_sz = sizeof(mbstate_t);
unsigned struct_timezone_sz = sizeof(struct timezone);
unsigned struct_tms_sz = sizeof(struct tms);
unsigned struct_sigevent_sz = sizeof(struct sigevent);
unsigned struct_sched_param_sz = sizeof(struct sched_param);
unsigned struct_dirent_sz = sizeof(struct dirent);

}  // namespace __sanitizer

#endif  // SANITIZER_QNX
