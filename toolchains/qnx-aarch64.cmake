# ---------------------------------------------------------------------------
# Locate QNX SDP directories
# ---------------------------------------------------------------------------
if(NOT DEFINED QNX_HOST_DIR)
  if(DEFINED ENV{QNX_HOST})
    set(QNX_HOST_DIR "$ENV{QNX_HOST}")
  else()
    message(FATAL_ERROR
      "QNX_HOST_DIR is not set. Either export QNX_HOST or pass "
      "-DQNX_HOST_DIR=<path> on the cmake command line.")
  endif()
endif()

if(NOT DEFINED QNX_TARGET_DIR)
  if(DEFINED ENV{QNX_TARGET})
    set(QNX_TARGET_DIR "$ENV{QNX_TARGET}")
  else()
    message(FATAL_ERROR
      "QNX_TARGET_DIR is not set. Either export QNX_TARGET or pass "
      "-DQNX_TARGET_DIR=<path> on the cmake command line.")
  endif()
endif()

# ---------------------------------------------------------------------------
# Locate host LLVM build (for clang, clang++, llvm-config, lld)
# ---------------------------------------------------------------------------
if(NOT DEFINED LLVM_HOST_BUILD)
  # Default: assume build-host sibling of the repo root
  get_filename_component(_repo_root "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
  set(LLVM_HOST_BUILD "${_repo_root}/build-host")
endif()

set(_host_bin "${LLVM_HOST_BUILD}/bin")

# ---------------------------------------------------------------------------
# System / target identification
# ---------------------------------------------------------------------------
set(CMAKE_SYSTEM_NAME      QNX)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# Target triple used by Clang
set(QNX_TARGET_TRIPLE "aarch64-unknown-qnx")

# ---------------------------------------------------------------------------
# Sysroot
# ---------------------------------------------------------------------------
set(CMAKE_SYSROOT "${QNX_TARGET_DIR}/aarch64le")

# Only look for libraries/headers in the sysroot, not the host
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# ---------------------------------------------------------------------------
# Compilers
# ---------------------------------------------------------------------------
set(CMAKE_C_COMPILER   "${_host_bin}/clang"   CACHE FILEPATH "C compiler")
set(CMAKE_CXX_COMPILER "${_host_bin}/clang++" CACHE FILEPATH "C++ compiler")
set(CMAKE_ASM_COMPILER "${_host_bin}/clang"   CACHE FILEPATH "ASM compiler")

# Tell Clang to target QNX aarch64
set(CMAKE_C_COMPILER_TARGET   "${QNX_TARGET_TRIPLE}")
set(CMAKE_CXX_COMPILER_TARGET "${QNX_TARGET_TRIPLE}")
set(CMAKE_ASM_COMPILER_TARGET "${QNX_TARGET_TRIPLE}")

# ---------------------------------------------------------------------------
# Linker — use ld.lld via clang driver
# ---------------------------------------------------------------------------
set(CMAKE_LINKER "${_host_bin}/ld.lld" CACHE FILEPATH "Linker")

# -fuse-ld=lld tells the clang driver to invoke lld
# --no-rosegment: do not create a read-only segment (required for QNX)
# -m aarch64elf:  lld ELF emulation for aarch64
set(_lld_flags "-fuse-ld=lld -Wl,--no-rosegment -Wl,-m,aarch64elf")

set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_lld_flags}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_lld_flags}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_lld_flags}")

# ---------------------------------------------------------------------------
# AR / ranlib / objcopy (use LLVM tools from host build)
# ---------------------------------------------------------------------------
set(CMAKE_AR      "${_host_bin}/llvm-ar"      CACHE FILEPATH "ar")
set(CMAKE_RANLIB  "${_host_bin}/llvm-ranlib"  CACHE FILEPATH "ranlib")
set(CMAKE_NM      "${_host_bin}/llvm-nm"      CACHE FILEPATH "nm")
set(CMAKE_OBJCOPY "${_host_bin}/llvm-objcopy" CACHE FILEPATH "objcopy")
set(CMAKE_STRIP   "${_host_bin}/llvm-strip"   CACHE FILEPATH "strip")

# ---------------------------------------------------------------------------
# QNX-specific compiler flags
# ---------------------------------------------------------------------------
# -D_QNX_SOURCE enables QNX extensions
# -D__QNXNTO__ is normally predefined by the compiler when targeting QNX,
#   but set it explicitly as a safety net.
set(_qnx_defs "-D_QNX_SOURCE -D__QNXNTO__")

# Include paths: QNX SDK headers
set(_qnx_includes
  "-I${QNX_TARGET_DIR}/usr/include"
  "-I${QNX_TARGET_DIR}/usr/include/c++/v1"
)

set(CMAKE_C_FLAGS_INIT   "${_qnx_defs} ${_qnx_includes}")
set(CMAKE_CXX_FLAGS_INIT "${_qnx_defs} ${_qnx_includes}")
set(CMAKE_ASM_FLAGS_INIT "--target=${QNX_TARGET_TRIPLE}")

# ---------------------------------------------------------------------------
# Library search paths
# ---------------------------------------------------------------------------
set(CMAKE_C_STANDARD_LIBRARIES   "-lc -lm" CACHE STRING "C standard libs")
set(CMAKE_CXX_STANDARD_LIBRARIES "-lc -lm -lc++ -lc++abi" CACHE STRING "C++ standard libs")

# ---------------------------------------------------------------------------
# compiler-rt / LLVM-specific hints
# ---------------------------------------------------------------------------
# These are used when configuring compiler-rt standalone.
set(COMPILER_RT_DEFAULT_TARGET_ONLY   ON  CACHE BOOL "")
set(COMPILER_RT_BUILD_BUILTINS        OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_LIBFUZZER       OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_PROFILE         OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_MEMPROF         OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_ORC             OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_GWP_ASAN        OFF CACHE BOOL "")
set(COMPILER_RT_INCLUDE_TESTS         OFF CACHE BOOL "")

# Enable what we actually want
set(COMPILER_RT_BUILD_SANITIZERS ON  CACHE BOOL "")
set(COMPILER_RT_BUILD_XRAY       ON  CACHE BOOL "")

set(COMPILER_RT_SANITIZERS_TO_BUILD "rtsan;ubsan_minimal" CACHE STRING "")
