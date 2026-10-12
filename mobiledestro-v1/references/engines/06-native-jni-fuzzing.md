# Engine 06: Native code, JNI, parsers, and bounded fuzzing

Research reviewed: 2026-10-13. Fuzz only isolated local harnesses or explicitly approved disposable app instances. No exploit weaponization, persistence, kernel targeting, or production denial of service is required to establish an application defect.

## Trust model

| Stage | Record |
| --- | --- |
| Entry | Import, media/document parser, JNI call, native network decoder, framework FFI |
| Source | External byte buffer, string, length, file descriptor, callback, compressed archive |
| Transform | Decode/decompress, size arithmetic, copy, allocation, JNI conversion, object lifetime |
| Check | Format/schema, length and capacity, integer range, ownership, exception state, path boundary |
| Sink | Memory access, file write, native load, returned data, persistent parser state |

Map all shipped ABIs and splits. A native symbol or dangerous function name is a hypothesis; prioritize paths where untrusted bytes actually arrive with insufficient constraints.

## Source-backed facts

JNI references, threads, string encodings, exception handling, and explicit method registration have specific ownership rules. Follow the actual Java/native boundary instead of assuming C-style string or reference semantics. [JNI tips](https://developer.android.com/ndk/guides/jni-tips)

HWASan support depends on build and device setup; Android 14 onward supports a simpler path for debuggable applications, while older releases may need a suitable system image. Preserve these instrumentation prerequisites in the finding. [HWAddress Sanitizer](https://developer.android.com/ndk/guides/hwasan)

Coverage-guided fuzzing uses a dedicated target and corpus; AOSP documents target construction and execution with libFuzzer. The harness must reflect production input constraints. [AOSP libFuzzer guide](https://source.android.com/docs/security/test/libfuzzer)

## Decisive tests

1. Inventory native libraries with ABI, hash, build ID, symbols, packaged version, and load site. Inspect `JNI_OnLoad`, `RegisterNatives`, static JNI exports, Dart FFI, Unity entry points, and dynamically loaded modules.
2. Build a reachability slice from an ordinary app entry to a native parser. Record every length/type transform, decoder, truncation, and earlier guard. Associate file descriptors with their actual open mode and source.
3. Review integer conversions before allocations/copies, buffer capacity checks, direct-buffer lifetime, Java array releases, callback lifetime, reference ownership, and error paths after failed JNI calls. Separate decompiler ambiguity from proven source behavior.
4. With source, isolate one parser and compile a sanitizer-enabled harness. With binaries only, use an approved developer harness or constrained entry-point replay and explicitly label coverage limits. Do not invent source or symbol names.
5. Seed valid minimal inputs and add bounded structural mutations at the specific boundary. Define maximum input size, CPU time, memory, total executions, disk artifacts, and crash count before running. Disable network and unrelated filesystem access in the harness.
6. Use oracles for memory safety, parser invariant violations, unexpected writes, and nontermination. Deduplicate by normalized stack plus root cause, then minimize the input while retaining the failure.
7. Reproduce the minimized case through the real application entry and a clean process. Compare a valid neighboring input and a repaired guard. Capture whether behavior is an out-of-bounds read/write, use-after-free, controlled assertion, ordinary parse rejection, or unclassified crash.
8. For archive extraction or library loading, use a lab directory and harmless sentinel only. Show the actual resolved destination or loaded artifact and required write capability; do not overwrite operational app code.

## Negative controls and disqualifiers

- Missing RELRO/canaries, exported symbols, obfuscation, or strings containing keys are contextual leads, not a memory-corruption proof.
- A crash caused only by a harness violating a production precondition is not demonstrated application reachability.
- An out-of-memory kill, sanitizer-only setup failure, deliberate abort on invalid input, or unsupported ABI must be distinguished from memory corruption.
- A crash is not proof of code execution, sensitive-memory disclosure, or exploitable register control. Report exactly the observed primitive.
- Repeated crashes from the same root cause are one issue; preserve different prerequisites without inflating count.

## Version and precondition caveats

Record compiler/NDK, ABI, sanitizer, operating system, library version/build ID, symbol source, optimized versus diagnostic build, and harness modifications. Recompilation can change layout and timing. An emulator result does not establish every shipped ABI's behavior.

## Chain edges and artifacts

Candidate edges: external file to reachable native parser; bridge argument to invalid buffer state; import path escape to controlled sentinel write; native return to downstream trust error. Require ordinary entry reachability separately from harness capability.

Save the reachability map, minimized corpus, hashes, harness and resource limits, seed, exact tool versions, sanitizer report, symbolized stack/build IDs, clean-run reproduction, controls, and explicit impact ceiling. Do not package user data or unnecessary memory dumps.
