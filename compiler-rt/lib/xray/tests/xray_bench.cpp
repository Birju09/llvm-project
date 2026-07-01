//===-- xray_bench.cpp - XRay mode performance benchmark ---------*- C++ -*-===//
//
// Measures per-call overhead of XRay in different logging modes.
// Compile and run with each mode to compare:
//
//   # Build (cross-compile for QNX aarch64 or native):
//   clang++ -fxray-instrument -fxray-instruction-threshold=1 \
//     -O2 -o xray_bench xray_bench.cpp -lxray -lxray-fdr -lpthread
//
//   # Run with FDR mode:
//   XRAY_OPTIONS="xray_mode=xray-fdr verbosity=0" ./xray_bench
//
//   # Run with basic mode:
//   XRAY_OPTIONS="xray_mode=xray-basic verbosity=0" ./xray_bench
//
//   # Run with funtrace mode:
//   XRAY_OPTIONS="xray_mode=xray-funtrace verbosity=0" ./xray_bench
//
//   # Run with patching disabled (measures baseline overhead of nop sleds):
//   XRAY_OPTIONS="xray_mode=xray-fdr patch_premain=false" ./xray_bench --nopatch
//
//===----------------------------------------------------------------------===//

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>

// Get high-resolution timestamp.
static inline uint64_t now_ns() {
#if defined(__aarch64__)
  // Use cntvct_el0 + cntfrq_el0 for aarch64 (same as our optimized xray_tsc.h)
  uint64_t count, freq;
  asm volatile("mrs %0, cntvct_el0" : "=r"(count));
  asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
  // Convert to nanoseconds: count * 1e9 / freq
  // Use 128-bit math to avoid overflow
  __uint128_t ns = (__uint128_t)count * 1000000000ULL / freq;
  return (uint64_t)ns;
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

// These functions are the workload. They're trivial so we measure
// pure instrumentation overhead. XRay will patch their entry/exit.
[[clang::xray_always_instrument]] void target_leaf() {
  asm volatile("" ::: "memory"); // prevent optimization
}

[[clang::xray_always_instrument]] void target_depth2() {
  target_leaf();
}

[[clang::xray_always_instrument]] void target_depth3() {
  target_depth2();
}

// Calibration: same function without XRay instrumentation.
[[clang::xray_never_instrument]] void baseline_leaf() {
  asm volatile("" ::: "memory");
}

[[clang::xray_never_instrument]] void baseline_depth2() {
  baseline_leaf();
}

[[clang::xray_never_instrument]] void baseline_depth3() {
  baseline_depth2();
}

struct BenchResult {
  double ns_per_call;
  double total_ms;
  uint64_t iterations;
};

template <typename Fn>
[[clang::xray_never_instrument]]
BenchResult bench(const char *name, Fn fn, uint64_t iterations) {
  // Warmup
  for (uint64_t i = 0; i < 1000; ++i)
    fn();

  uint64_t start = now_ns();
  for (uint64_t i = 0; i < iterations; ++i)
    fn();
  uint64_t end = now_ns();

  uint64_t elapsed = end - start;
  double ns_per = (double)elapsed / (double)iterations;
  double total_ms = (double)elapsed / 1e6;

  printf("  %-30s %8.2f ns/call  (%lu iters, %.1f ms total)\n",
         name, ns_per, (unsigned long)iterations, total_ms);

  return {ns_per, total_ms, iterations};
}

[[clang::xray_never_instrument]]
int main(int argc, char **argv) {
  uint64_t N = 10000000; // 10M iterations default

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "-n") == 0 && i + 1 < argc)
      N = strtoull(argv[++i], nullptr, 10);
  }

  printf("XRay Performance Benchmark\n");
  printf("==========================\n");
  printf("Iterations: %lu\n\n", (unsigned long)N);

  // --- Baseline (no XRay instrumentation) ---
  printf("Baseline (no instrumentation):\n");
  auto bl = bench("baseline_leaf()", baseline_leaf, N);
  auto bd2 = bench("baseline_depth2()", baseline_depth2, N);
  auto bd3 = bench("baseline_depth3()", baseline_depth3, N);

  printf("\n");

  // --- Instrumented ---
  printf("Instrumented (current XRay mode):\n");
  auto il = bench("target_leaf()", target_leaf, N);
  auto id2 = bench("target_depth2()", target_depth2, N);
  auto id3 = bench("target_depth3()", target_depth3, N);

  printf("\n");

  // --- Overhead calculation ---
  printf("Per-call overhead (instrumented - baseline):\n");
  // leaf: 1 entry + 1 exit = 2 XRay events per call
  double leaf_overhead = il.ns_per_call - bl.ns_per_call;
  // depth2: 2 functions * 2 events = 4 XRay events per call
  double d2_overhead = id2.ns_per_call - bd2.ns_per_call;
  // depth3: 3 functions * 2 events = 6 XRay events per call
  double d3_overhead = id3.ns_per_call - bd3.ns_per_call;

  printf("  %-30s %8.2f ns  (2 events -> %.2f ns/event)\n",
         "leaf overhead", leaf_overhead, leaf_overhead / 2.0);
  printf("  %-30s %8.2f ns  (4 events -> %.2f ns/event)\n",
         "depth2 overhead", d2_overhead, d2_overhead / 4.0);
  printf("  %-30s %8.2f ns  (6 events -> %.2f ns/event)\n",
         "depth3 overhead", d3_overhead, d3_overhead / 6.0);

  double avg_per_event = (leaf_overhead / 2.0 + d2_overhead / 4.0 + d3_overhead / 6.0) / 3.0;
  printf("\n  ** Average: %.2f ns per XRay event **\n", avg_per_event);

  return 0;
}
