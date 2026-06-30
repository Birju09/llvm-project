//===-- sanitizer_procmaps_qnx.cpp ----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Information about the process mappings (QNX-specific parts).
// Uses /proc/self/as with DCMD_PROC_MAPINFO devctl to enumerate mappings.
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_QNX

#  include "sanitizer_common.h"
#  include "sanitizer_linux.h"
#  include "sanitizer_procmaps.h"

#  include <devctl.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <sys/mman.h>
#  include <sys/procfs.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <unistd.h>

namespace __sanitizer {

// Build a text buffer in Linux /proc/self/maps format from QNX procfs.
// Format: "start-end rwxp offset devmaj:devmin inode [name]\n"
void ReadProcMaps(ProcSelfMapsBuff *proc_maps) {
  proc_maps->data = nullptr;
  proc_maps->mmaped_size = 0;
  proc_maps->len = 0;

  int fd = open("/proc/self/as", O_RDONLY | O_NONBLOCK);
  if (fd < 0)
    return;

  // First call with zero count to find number of entries.
  int num_maps = 0;
  int status = devctl(fd, DCMD_PROC_MAPINFO, nullptr, 0, &num_maps);
  if (status != EOK && num_maps == 0) {
    close(fd);
    return;
  }

  uptr mapinfo_size = (uptr)num_maps * sizeof(procfs_mapinfo);
  procfs_mapinfo *mapinfo =
      (procfs_mapinfo *)MmapOrDie(mapinfo_size, "ReadProcMaps mapinfo");

  int actual = 0;
  status = devctl(fd, DCMD_PROC_MAPINFO, mapinfo, (int)mapinfo_size, &actual);
  close(fd);

  if (status != EOK || actual == 0) {
    UnmapOrDie(mapinfo, mapinfo_size);
    return;
  }

  // Each line is at most ~128 bytes. Allocate conservatively.
  uptr buf_size = (uptr)actual * 128;
  char *buf = (char *)MmapOrDie(buf_size, "ReadProcMaps buf");
  uptr pos = 0;

  for (int i = 0; i < actual; i++) {
    const procfs_mapinfo &m = mapinfo[i];
    uptr vaddr = (uptr)m.vaddr;
    uptr end_addr = vaddr + (uptr)m.size;

    char rwxp[5] = "----";
    if (m.flags & PROT_READ)
      rwxp[0] = 'r';
    if (m.flags & PROT_WRITE)
      rwxp[1] = 'w';
    if (m.flags & PROT_EXEC)
      rwxp[2] = 'x';
    // MAP_SHARED
    if (m.flags & MAP_SHARED)
      rwxp[3] = 's';
    else
      rwxp[3] = 'p';

    // Format: start-end rwxp offset 00:00 0 \n
    // We don't have inode/device info easily; use zeros.
    uptr written = internal_snprintf(buf + pos, buf_size - pos,
                                     "%zx-%zx %s %zx 00:00 0\n", vaddr,
                                     end_addr, rwxp, (uptr)m.offset);
    pos += written;

    // Safety: stop if we're running out of buffer.
    if (pos + 256 >= buf_size)
      break;
  }

  UnmapOrDie(mapinfo, mapinfo_size);

  proc_maps->data = buf;
  proc_maps->mmaped_size = buf_size;
  proc_maps->len = pos;
}

static bool IsOneOf(char c, char c1, char c2) { return c == c1 || c == c2; }

bool MemoryMappingLayout::Next(MemoryMappedSegment *segment) {
  if (Error())
    return false;
  char *last = data_.proc_self_maps.data + data_.proc_self_maps.len;
  if (data_.current >= last)
    return false;
  char *next_line =
      (char *)internal_memchr(data_.current, '\n', last - data_.current);
  if (next_line == nullptr)
    next_line = last;

  // Format: start-end rwxp offset 00:00 0 [name]
  segment->start = ParseHex(&data_.current);
  CHECK_EQ(*data_.current++, '-');
  segment->end = ParseHex(&data_.current);
  CHECK_EQ(*data_.current++, ' ');
  CHECK(IsOneOf(*data_.current, '-', 'r'));
  segment->protection = 0;
  if (*data_.current++ == 'r')
    segment->protection |= kProtectionRead;
  CHECK(IsOneOf(*data_.current, '-', 'w'));
  if (*data_.current++ == 'w')
    segment->protection |= kProtectionWrite;
  CHECK(IsOneOf(*data_.current, '-', 'x'));
  if (*data_.current++ == 'x')
    segment->protection |= kProtectionExecute;
  CHECK(IsOneOf(*data_.current, 's', 'p'));
  if (*data_.current++ == 's')
    segment->protection |= kProtectionShared;
  CHECK_EQ(*data_.current++, ' ');
  segment->offset = ParseHex(&data_.current);
  // Skip remaining fields (device, inode, name).
  while (data_.current < next_line && *data_.current != ' ')
    data_.current++;
  while (data_.current < next_line && *data_.current == ' ')
    data_.current++;
  // Fill filename if provided.
  if (segment->filename) {
    uptr len =
        Min((uptr)(next_line - data_.current), segment->filename_size - 1);
    internal_strncpy(segment->filename, data_.current, len);
    segment->filename[len] = 0;
  }

  data_.current = next_line + 1;
  return true;
}

}  // namespace __sanitizer

#endif  // SANITIZER_QNX
