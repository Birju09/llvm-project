//===--- QNX.cpp - QNX ToolChain Implementations --------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "QNX.h"
#include "clang/Config/config.h"
#include "clang/Driver/CommonArgs.h"
#include "clang/Driver/Compilation.h"
#include "clang/Driver/SanitizerArgs.h"
#include "llvm/Support/Path.h"

using namespace clang::driver;
using namespace clang::driver::tools;
using namespace clang::driver::toolchains;
using namespace clang;
using namespace llvm::opt;

void tools::QNX::Linker::ConstructJob(Compilation &C, const JobAction &JA,
                                      const InputInfo &Output,
                                      const InputInfoList &Inputs,
                                      const ArgList &Args,
                                      const char *LinkingOutput) const {

  const auto &ToolChain = static_cast<const toolchains::QNX &>(getToolChain());
  const Driver &D = ToolChain.getDriver();
  const bool Shared = Args.hasArg(options::OPT_shared);
  const bool Static = Args.hasArg(options::OPT_static);
  ArgStringList CmdArgs;
  bool isLLD = false;
  const bool IsPIE = !Shared && (Args.hasArg(options::OPT_pie) || ToolChain.isPIEDefault(Args));

  ToolChain.GetLinkerPath(&isLLD);
  // Silence warning for "clang -g foo.o -o foo"
  Args.ClaimAllArgs(options::OPT_g_Group);
  // and "clang -emit-llvm foo.o -o foo"
  Args.ClaimAllArgs(options::OPT_emit_llvm);
  // and for "clang -w foo.o -o foo". Other warning options are already
  // handled somewhere else.
  Args.ClaimAllArgs(options::OPT_w);
  // libgcc_s is determine by -static
  Args.ClaimAllArgs(options::OPT_shared_libgcc);

  // Silence warning for "clang -pie foo.o -o foo"
  Args.ClaimAllArgs(options::OPT_pie);

  if (!D.SysRoot.empty()) {
    CmdArgs.push_back(Args.MakeArgString("--sysroot=" + D.SysRoot));
  }

  if (IsPIE) {
    CmdArgs.push_back("-pie");
  }

  CmdArgs.push_back("--warn-shared-textrel");
  CmdArgs.push_back("-zrelro");
  CmdArgs.push_back("-znow");
  CmdArgs.push_back("--eh-frame-hdr");

  // enforce 8mb stack size, the default size for QNX is too small at 256/512K
  CmdArgs.push_back("-z");
  CmdArgs.push_back("stack-size=8388608");

  if (Static) {
    CmdArgs.push_back("-Bstatic");
  } else {
    if (Shared) {
      CmdArgs.push_back("-shared");
    } else if (!Args.hasArg(options::OPT_r)) {
      CmdArgs.push_back("-dynamic-linker");
      CmdArgs.push_back("/usr/lib/ldqnx-64.so.2");
    }
  }

  assert((Output.isFilename() || Output.isNothing()) && "Invalid output.");
  if (Output.isFilename()) {
    CmdArgs.push_back("-o");
    CmdArgs.push_back(Output.getFilename());
  }

  if (!Args.hasArg(options::OPT_nostdlib, options::OPT_nostartfiles,
                   options::OPT_r)) {
    const char *crt1 = "crt1.o";
    if (Args.hasArg(options::OPT_pg)) {
      crt1 = "mcrt1.o";
    }

    if (!Shared) {
      CmdArgs.push_back(Args.MakeArgString(ToolChain.GetFilePath(crt1)));
    }
    CmdArgs.push_back(Args.MakeArgString(ToolChain.GetFilePath("crti.o")));
    CmdArgs.push_back(Args.MakeArgString(ToolChain.GetFilePath("crtbegin.o")));
  }

  Args.addAllArgs(CmdArgs, {options::OPT_L, options::OPT_T_Group,
                            options::OPT_s, options::OPT_t});
  ToolChain.AddFilePathLibArgs(Args, CmdArgs);

  if (D.isUsingLTO() && isLLD) {
    addLTOOptions(ToolChain, Args, CmdArgs, Output, Inputs,
                  D.getLTOMode() == LTOK_Thin);
  }

  addLinkerCompressDebugSectionsOption(ToolChain, Args, CmdArgs);

  bool NeedsSanitizerDeps = addSanitizerRuntimes(ToolChain, Args, CmdArgs);
  bool NeedsXRayDeps = addXRayRuntime(ToolChain, Args, CmdArgs);

  AddLinkerInputs(ToolChain, Inputs, Args, CmdArgs, JA);

  if (!Args.hasArg(options::OPT_nostdlib, options::OPT_nodefaultlibs,
                   options::OPT_r)) {
    CmdArgs.push_back("-lc");
    CmdArgs.push_back("-lm");
    CmdArgs.push_back("-lregex");

    if (Static) {
      CmdArgs.push_back("-lgcc");
    } else {
      CmdArgs.push_back("-lgcc_s");
    }

    // Use the static OpenMP runtime with -static-openmp
    bool StaticOpenMP = Args.hasArg(options::OPT_static_openmp) && !Static;
    addOpenMPRuntime(C, CmdArgs, ToolChain, Args, StaticOpenMP);

    if (D.CCCIsCXX() && ToolChain.ShouldLinkCXXStdlib(Args)) {
      ToolChain.AddCXXStdlibLibArgs(Args, CmdArgs);

      if (Static) {
        // These are required for static linking
        CmdArgs.push_back("-llocale");
        CmdArgs.push_back("-lcatalog");
      }
    }

    CmdArgs.push_back("-lgcc_eh");

    // Silence warnings when linking C code with a C++ '-stdlib' argument.
    Args.ClaimAllArgs(options::OPT_stdlib_EQ);

    // Additional linker set-up and flags for Fortran. This is required in order
    // to generate executables. As Fortran runtime depends on the C runtime,
    // these dependencies need to be listed before the C runtime below (i.e.
    // AddRunTimeLibs).
    if (D.IsFlangMode() &&
        !Args.hasArg(options::OPT_nostdlib, options::OPT_nodefaultlibs)) {
      ToolChain.addFortranRuntimeLibraryPath(Args, CmdArgs);
      ToolChain.addFortranRuntimeLibs(Args, CmdArgs);
    }
  }

  Args.claimAllArgs(options::OPT_pthread, options::OPT_pthreads);

  if (!Args.hasArg(options::OPT_nostdlib, options::OPT_nostartfiles,
                   options::OPT_r)) {
    CmdArgs.push_back(Args.MakeArgString(ToolChain.GetFilePath("crtend.o")));
    CmdArgs.push_back(Args.MakeArgString(ToolChain.GetFilePath("crtn.o")));
  }

  if (NeedsSanitizerDeps)
    linkSanitizerRuntimeDeps(ToolChain, Args, CmdArgs);
  if (NeedsXRayDeps)
    linkXRayRuntimeDeps(ToolChain, Args, CmdArgs);

  ToolChain.addProfileRTLibs(Args, CmdArgs);

  const char *Exec = Args.MakeArgString(getToolChain().GetLinkerPath());
  C.addCommand(std::make_unique<Command>(JA, *this,
                                         ResponseFileSupport::AtFileCurCP(),
                                         Exec, CmdArgs, Inputs, Output));
}

toolchains::QNX::QNX(const Driver &D, const llvm::Triple &Triple,
                     const ArgList &Args)
    : Generic_ELF(D, Triple, Args) {
  GCCInstallation.init(Triple, Args);

  getFilePaths().push_back(concat(getDriver().SysRoot, "/usr/lib"));

  if (GCCInstallation.isValid())
    getFilePaths().push_back(GCCInstallation.getInstallPath().str());
}

void toolchains::QNX::AddClangSystemIncludeArgs(
    const llvm::opt::ArgList &DriverArgs,
    llvm::opt::ArgStringList &CC1Args) const {
  const Driver &D = getDriver();

  if (DriverArgs.hasArg(clang::driver::options::OPT_nostdinc)) {
    return;
  }

  if (!DriverArgs.hasArg(options::OPT_nobuiltininc)) {
    SmallString<128> Dir(D.ResourceDir);
    llvm::sys::path::append(Dir, "include");
    addSystemInclude(DriverArgs, CC1Args, Dir.str());
  }

  if (DriverArgs.hasArg(options::OPT_nostdlibinc)) {
    return;
  }

  // Check for configure-time C include directories.
  StringRef CIncludeDirs(C_INCLUDE_DIRS);
  if (CIncludeDirs != "") {
    SmallVector<StringRef, 5> dirs;
    CIncludeDirs.split(dirs, ":");
    for (StringRef dir : dirs) {
      StringRef Prefix =
          llvm::sys::path::is_absolute(dir) ? StringRef(D.SysRoot) : "";
      addExternCSystemInclude(DriverArgs, CC1Args, Prefix + dir);
    }
    return;
  }

  addSystemInclude(DriverArgs, CC1Args,
                   concat(D.SysRoot, "/usr/include/shims"));
  addSystemInclude(DriverArgs, CC1Args, concat(D.SysRoot, "/usr/include"));
}

void clang::driver::toolchains::QNX::addLibCxxIncludePaths(
    const llvm::opt::ArgList &DriverArgs,
    llvm::opt::ArgStringList &CC1Args) const {
  std::string inclxx = concat(getDriver().SysRoot, "/usr/include/c++/v1");
  addSystemInclude(DriverArgs, CC1Args, inclxx);
}

SanitizerMask clang::driver::toolchains::QNX::getSupportedSanitizers() const {
  SanitizerMask Res = ToolChain::getSupportedSanitizers();
  Res |= SanitizerKind::Address;
  Res |= SanitizerKind::PointerCompare;
  Res |= SanitizerKind::PointerSubtract;
  Res |= SanitizerKind::Memory;
  Res |= SanitizerKind::Leak;
  Res |= SanitizerKind::Thread;
  Res |= SanitizerKind::Undefined;
  Res |= SanitizerKind::Realtime;
  return Res;
}

Tool *clang::driver::toolchains::QNX::buildLinker() const {
  return new tools::QNX::Linker(*this);
}