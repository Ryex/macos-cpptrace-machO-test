# macos_mach_trace

Throw-away C++/CMake demo that generates a fatal failure, catches it through a
Mach exception port, and prints a symbolized stack trace captured from the
exception-watching thread while the faulting thread is paused.

## Build

```sh
git submodule update --init --recursive
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j
```

The project builds on both Intel (`x86_64`) and Apple Silicon (`arm64`) macOS.
To produce a universal binary:

```sh
cmake -S . -B build-universal -DCMAKE_BUILD_TYPE=Debug -DMACOS_TRACE_UNIVERSAL=ON
cmake --build build-universal -j
```

`cpptrace` is vendored as a git submodule (`third_party/cpptrace`).  On macOS
cpptrace uses libdwarf for symbolization; its default CMake configuration
fetches and builds libdwarf and zstd via `FetchContent`.  The generated `dSYM`
is created as a post-build step so line numbers are available.

## Run

```sh
./build/macos_mach_trace
```

or pass the failure directly:

```sh
./build/macos_mach_trace segfault
./build/macos_mach_trace stack_overflow
./build/macos_mach_trace abort
```

The program intentionally exits with status 0 after printing the trace, so the
process does not die from the fault it just caught.

Set `MACOS_TRACE_DEBUG=1` to dump the raw frame-pointer links as they are read
from the paused thread.

Run the binary directly rather than under a debugger: LLDB installs its own
task/thread exception ports, and this demo replaces them with its own.

## What it does

1. Allocates a receive right and registers it with
   `task_set_exception_ports` for `EXC_BAD_ACCESS`, `EXC_BAD_INSTRUCTION`,
   `EXC_ARITHMETIC`, `EXC_BREAKPOINT`, `EXC_SOFTWARE`, `EXC_CRASH`, and
   `EXC_GUARD`, using `EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES`.
   That behavior gives the server both the faulting thread/task ports and the
   saved register state.
2. Runs a dedicated exception thread in `mach_msg_server(mach_exc_server, ...)`.
3. When an exception arrives, the server thread reads the register state from
   the Mach message.  It then unwinds the **paused** thread:

   - Primary path: libunwind is initialized with a local context, but all
     relevant registers are overwritten from the exception state.  libunwind
     therefore reads the remote thread's stack through DWARF/compact-unwind
     CFI even though it is running on another thread.
   - Fallback: a frame-pointer walk over the target task, using
     `mach_vm_read_overwrite` so an invalid frame link cannot crash the
     exception thread.

4. Builds a `cpptrace::raw_trace` from the captured PCs and calls
   `raw_trace::resolve()` to symbolize and print the frames.

## Abort / SIGABRT caveat

`abort()` raises `SIGABRT`, a BSD signal, not a hardware Mach exception.  xnu
also refuses to deliver an `EXC_CRASH` notification to a task exception port
that lives in the exiting task itself (see `check_exc_receiver_dependency` in
`osfmk/kern/exception.c`), to avoid a deadlock.  Consequently an in-process
Mach exception port cannot directly observe `abort()`.

To keep the same capture path, the program installs a `SA_SIGINFO`/`SA_ONSTACK`
handler for `SIGABRT`.  The handler copies the interrupted `ucontext_t` state
and sends it to the Mach exception port with a real
`mach_exception_raise_state_identity` RPC.  The exception-watching thread then
unwinds that saved state while the aborting thread is blocked waiting for the
RPC reply.  This is the only synthetic part of the demo; segfault and stack
overflow arrive from the kernel through the normal Mach exception mechanism.

## arm64e / signed frame records (PAC)

Plain `arm64` code on macOS does not sign return addresses, so the normal
`arm64` build needs no special handling.

`arm64e` code uses pointer authentication.  In the arm64e ABI a function starts
with `pacibsp` and saves the signed LR in its frame record:

```asm
pacibsp
stp x29, x30, [sp, #-16]!
mov x29, sp
...
ldp x29, x30, [sp], #16
retab
```

The frame-pointer walk handles this by stripping the PAC bits before
symbolization:

- saved LR: `ptrauth_strip(..., ptrauth_key_return_address)` (`xpaci`)
- frame-pointer links: `ptrauth_strip(..., ptrauth_key_frame_pointer)` (`xpacd`)
- thread-state PC/LR: the `arm_thread_state64_get_*` accessors handle the
  kernel's signature, then the same strip is applied.

Plain arm64 built with `-mbranch-protection=pac-ret` (`paciasp`/`retaa`) is
also handled: Clang's ptrauth intrinsics are no-ops in that mode, so the code
emits the `xpaci`/`xpacd` instructions directly.

On arm64e the program deliberately uses the frame-pointer walk instead of the
libunwind synthetic-context path.  libunwind has its own arm64e support, but its
authenticated-unwinding `setIP` path expects a return address signed with the
current SP; handing it a synthesized/stripped context can be unsafe.

An `arm64e` build can be produced with:

```sh
cmake -S . -B build-arm64e -DCMAKE_BUILD_TYPE=Debug -DCMAKE_OSX_ARCHITECTURES=arm64e
cmake --build build-arm64e -j
```

The arm64e build was compile-verified here; the test VM is Intel, so its runtime
behavior has not been exercised on an Apple Silicon machine.

## CI

`.github/workflows/build-macos-universal.yml` is macOS-only.  It runs on a
single `macos-14` runner, cross-builds the universal `x86_64 + arm64` binary
with static cpptrace/libdwarf/zstd, verifies both slices and the absence of
dynamic cpptrace/libdwarf/libzstd dependencies, and uploads the
`macos-mach-trace-universal` artifact containing the binary, dSYM, tarball,
and checksums.

## Dependencies

- C++17 STL
- macOS SDK headers (`mach`, `pthread`, `signal`, `ucontext`)
- `cpptrace` (git submodule)
- libdwarf/zstd (built automatically by cpptrace's CMake)
- `mig` and `dsymutil` from Xcode command line tools
