// Throw-away demo: catch a fatal failure through a Mach exception port and
// unwind the *paused* faulting thread from the exception-watching thread.
//
// Supported failures:
//   1. segfault          (EXC_BAD_ACCESS)
//   2. stack_overflow    (EXC_BAD_ACCESS, guard page)
//   3. abort             (SIGABRT bridged into a Mach EXC_CRASH message)
//
// The stack trace is produced by:
//   * libunwind, driven with the register context taken from the Mach
//     exception message, so it walks the paused thread rather than the
//     current thread, and
//   * a frame-pointer walk over the remote thread's memory as a fallback.
// The resulting PCs are handed to cpptrace for symbolization/printing.

#include <cpptrace/cpptrace.hpp>
#include <cpptrace/formatting.hpp>

#include <libunwind.h>

#if defined(__aarch64__) && defined(__has_feature)
 #if __has_feature(ptrauth_calls)
  #include <ptrauth.h>
  #define MACOS_TRACE_HAS_PTRAUTH 1
 #endif
#endif
#ifndef MACOS_TRACE_HAS_PTRAUTH
 #define MACOS_TRACE_HAS_PTRAUTH 0
#endif

// Plain arm64 code can also be built with -mbranch-protection=pac-ret
// (paciasp/retaa).  Clang's ptrauth intrinsics are no-ops in that mode, so use
// the xpaci/xpacd instructions directly.
#if !MACOS_TRACE_HAS_PTRAUTH && defined(__aarch64__) && defined(__ARM_FEATURE_PAC_DEFAULT)
 #define MACOS_TRACE_HAS_PAC_RET 1
#else
 #define MACOS_TRACE_HAS_PAC_RET 0
#endif

#include <mach/exception.h>
#include <mach/exception_types.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach/thread_act.h>
#include <mach/thread_status.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ucontext.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

extern "C" {
#include "mach_exc.h"
#include "mach_excServer.h"
}

namespace {

constexpr std::size_t kMaxFrames = 64;
constexpr std::size_t kAltStackSize = 64 * 1024;

#if MACOS_TRACE_HAS_PTRAUTH
// On arm64e prefer the explicitly PAC-stripped frame-pointer walk.  libunwind
// has arm64e support too, but driving it with a synthesized context is harder
// to validate without an arm64e machine.
constexpr bool kPreferFramePointers = true;
#else
constexpr bool kPreferFramePointers = false;
#endif

#if defined(__x86_64__)
using thread_state = x86_thread_state64_t;
constexpr int kThreadFlavor = x86_THREAD_STATE64;
constexpr mach_msg_type_number_t kThreadCount = x86_THREAD_STATE64_COUNT;
#elif defined(__aarch64__)
using thread_state = arm_thread_state64_t;
constexpr int kThreadFlavor = ARM_THREAD_STATE64;
constexpr mach_msg_type_number_t kThreadCount = ARM_THREAD_STATE64_COUNT;
#else
#error "This program supports x86_64 and arm64 macOS only."
#endif

mach_port_t g_exception_port = MACH_PORT_NULL;
std::atomic<bool> g_reported{false};
char g_alt_stack[kAltStackSize];

// ---------------------------------------------------------------------------
// A few small architecture helpers.
// ---------------------------------------------------------------------------

// On arm64e, return addresses are signed with ptrauth key IB and the frame's
// entry SP as the discriminator.  For unwinding/symbolization we only need the
// canonical address, so stripping the signature is sufficient.  On plain
// arm64 (and x86_64) these are no-ops.
std::uintptr_t strip_code_pointer(std::uintptr_t value) {
#if MACOS_TRACE_HAS_PTRAUTH
    return reinterpret_cast<std::uintptr_t>(
        ptrauth_strip(reinterpret_cast<void*>(value), ptrauth_key_return_address)
    );
#elif MACOS_TRACE_HAS_PAC_RET
    asm volatile("xpaci %0" : "+r"(value));
    return value;
#else
    return value;
#endif
}

std::uintptr_t strip_data_pointer(std::uintptr_t value) {
#if MACOS_TRACE_HAS_PTRAUTH
    // ptrauth.h defines this as a process-dependent data key and documents
    // that frame pointers use the storage address + 16 as the discriminator.
    return reinterpret_cast<std::uintptr_t>(
        ptrauth_strip(reinterpret_cast<void*>(value), ptrauth_key_frame_pointer)
    );
#elif MACOS_TRACE_HAS_PAC_RET
    asm volatile("xpacd %0" : "+r"(value));
    return value;
#else
    return value;
#endif
}

std::uintptr_t state_pc(const thread_state& s) {
#if defined(__x86_64__)
    return static_cast<std::uintptr_t>(s.__rip);
#else
    return strip_code_pointer(static_cast<std::uintptr_t>(arm_thread_state64_get_pc(s)));
#endif
}

std::uintptr_t state_sp(const thread_state& s) {
#if defined(__x86_64__)
    return static_cast<std::uintptr_t>(s.__rsp);
#else
    return strip_data_pointer(static_cast<std::uintptr_t>(arm_thread_state64_get_sp(s)));
#endif
}

std::uintptr_t state_fp(const thread_state& s) {
#if defined(__x86_64__)
    return static_cast<std::uintptr_t>(s.__rbp);
#else
    return strip_data_pointer(static_cast<std::uintptr_t>(arm_thread_state64_get_fp(s)));
#endif
}

std::uintptr_t state_lr(const thread_state& s) {
#if defined(__x86_64__)
    (void)s;
    return 0;
#else
    return strip_code_pointer(static_cast<std::uintptr_t>(arm_thread_state64_get_lr(s)));
#endif
}

const char* exception_name(exception_type_t exception) {
    switch(exception) {
        case EXC_BAD_ACCESS: return "EXC_BAD_ACCESS";
        case EXC_BAD_INSTRUCTION: return "EXC_BAD_INSTRUCTION";
        case EXC_ARITHMETIC: return "EXC_ARITHMETIC";
        case EXC_EMULATION: return "EXC_EMULATION";
        case EXC_SOFTWARE: return "EXC_SOFTWARE";
        case EXC_BREAKPOINT: return "EXC_BREAKPOINT";
        case EXC_SYSCALL: return "EXC_SYSCALL";
        case EXC_MACH_SYSCALL: return "EXC_MACH_SYSCALL";
        case EXC_RPC_ALERT: return "EXC_RPC_ALERT";
        case EXC_CRASH: return "EXC_CRASH";
        case EXC_RESOURCE: return "EXC_RESOURCE";
        case EXC_GUARD: return "EXC_GUARD";
        default: return "UNKNOWN";
    }
}

bool safe_read(mach_port_t task, std::uintptr_t address, void* out, std::size_t size) {
    mach_vm_size_t bytes_read = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        task,
        static_cast<mach_vm_address_t>(address),
        static_cast<mach_vm_size_t>(size),
        reinterpret_cast<mach_vm_address_t>(out),
        &bytes_read
    );
    return kr == KERN_SUCCESS && bytes_read == size;
}

// ---------------------------------------------------------------------------
// libunwind with a synthetic context.
//
// libunwind's local backend in libSystem is normally used for the calling
// thread.  It only needs a register context, though.  We initialize a cursor
// from a context created on this thread and then overwrite every relevant
// register with the state that the kernel/exception message reports for the
// suspended thread.  Because both threads share an address space, libunwind's
// DWARF/compact-unwind CFI reader can walk the paused thread's stack.
// ---------------------------------------------------------------------------

void set_libunwind_registers(unw_cursor_t& cursor, const thread_state& s) {
    using u = unw_word_t;
#if defined(__x86_64__)
    unw_set_reg(&cursor, UNW_REG_IP, static_cast<u>(s.__rip));
    unw_set_reg(&cursor, UNW_REG_SP, static_cast<u>(s.__rsp));
    unw_set_reg(&cursor, UNW_X86_64_RAX, static_cast<u>(s.__rax));
    unw_set_reg(&cursor, UNW_X86_64_RDX, static_cast<u>(s.__rdx));
    unw_set_reg(&cursor, UNW_X86_64_RCX, static_cast<u>(s.__rcx));
    unw_set_reg(&cursor, UNW_X86_64_RBX, static_cast<u>(s.__rbx));
    unw_set_reg(&cursor, UNW_X86_64_RSI, static_cast<u>(s.__rsi));
    unw_set_reg(&cursor, UNW_X86_64_RDI, static_cast<u>(s.__rdi));
    unw_set_reg(&cursor, UNW_X86_64_RBP, static_cast<u>(s.__rbp));
    unw_set_reg(&cursor, UNW_X86_64_R8, static_cast<u>(s.__r8));
    unw_set_reg(&cursor, UNW_X86_64_R9, static_cast<u>(s.__r9));
    unw_set_reg(&cursor, UNW_X86_64_R10, static_cast<u>(s.__r10));
    unw_set_reg(&cursor, UNW_X86_64_R11, static_cast<u>(s.__r11));
    unw_set_reg(&cursor, UNW_X86_64_R12, static_cast<u>(s.__r12));
    unw_set_reg(&cursor, UNW_X86_64_R13, static_cast<u>(s.__r13));
    unw_set_reg(&cursor, UNW_X86_64_R14, static_cast<u>(s.__r14));
    unw_set_reg(&cursor, UNW_X86_64_R15, static_cast<u>(s.__r15));
#else
    for(int i = 0; i <= 28; ++i) {
        unw_set_reg(&cursor, UNW_AARCH64_X0 + i, static_cast<u>(s.__x[i]));
    }
    unw_set_reg(&cursor, UNW_REG_IP, static_cast<u>(state_pc(s)));
    unw_set_reg(&cursor, UNW_REG_SP, static_cast<u>(state_sp(s)));
    unw_set_reg(&cursor, UNW_AARCH64_X29, static_cast<u>(state_fp(s)));
    unw_set_reg(&cursor, UNW_AARCH64_X30, static_cast<u>(state_lr(s)));
    unw_set_reg(&cursor, UNW_AARCH64_RA_SIGN_STATE, 0);
#endif
}

std::vector<cpptrace::frame_ptr> unwind_with_libunwind(const thread_state& state) {
    std::vector<cpptrace::frame_ptr> frames;

    unw_context_t context;
    if(unw_getcontext(&context) != 0) {
        return frames;
    }

    unw_cursor_t cursor;
    if(unw_init_local(&cursor, &context) != 0) {
        return frames;
    }

    set_libunwind_registers(cursor, state);

    for(std::size_t i = 0; i < kMaxFrames; ++i) {
        unw_word_t ip = 0;
        if(unw_get_reg(&cursor, UNW_REG_IP, &ip) != 0 || ip == 0) {
            break;
        }

        // libunwind on arm64e may return a PC still signed with the frame SP.
        // Strip the signature before symbolization.
        cpptrace::frame_ptr frame =
            static_cast<cpptrace::frame_ptr>(strip_code_pointer(static_cast<std::uintptr_t>(ip)));
        // Frame 0 is the faulting PC itself.  Later frames are return
        // addresses (one past the call site), so step back into the call.
        if(i > 0 && frame > 1) {
            frame -= 1;
        }
        frames.push_back(frame);

        if(unw_step(&cursor) <= 0) {
            break;
        }
    }

    return frames;
}

// ---------------------------------------------------------------------------
// Frame-pointer fallback.  Reads the paused thread's stack through
// mach_vm_read_overwrite so a bad link cannot kill the watching thread.
// ---------------------------------------------------------------------------

std::vector<cpptrace::frame_ptr> unwind_with_frame_pointers(
    const thread_state& state,
    mach_port_t task
) {
    std::vector<cpptrace::frame_ptr> frames;
    const std::uintptr_t pc = state_pc(state);
    const std::uintptr_t sp = state_sp(state);
    const std::uintptr_t upper = sp + (256ull << 20); // sanity bound
    const bool debug = std::getenv("MACOS_TRACE_DEBUG") != nullptr;

    frames.push_back(static_cast<cpptrace::frame_ptr>(pc));

#if defined(__x86_64__)
    std::uintptr_t fp = state_fp(state);
    while(frames.size() < kMaxFrames) {
        if(fp == 0 || (fp & 7) != 0 || fp < sp || fp >= upper) {
            break;
        }

        std::uintptr_t words[2] = {0, 0};
        if(!safe_read(task, fp, words, sizeof(words))) {
            break;
        }

        const std::uintptr_t next_fp = words[0];
        const std::uintptr_t return_address = words[1];
        if(debug) {
            std::fprintf(stderr, "fp[%zu] fp=0x%llx next=0x%llx ret=0x%llx\n",
                frames.size(),
                static_cast<unsigned long long>(fp),
                static_cast<unsigned long long>(next_fp),
                static_cast<unsigned long long>(return_address));
        }
        if(return_address == 0) {
            break;
        }

        frames.push_back(static_cast<cpptrace::frame_ptr>(return_address - 1));

        if(next_fp <= fp || next_fp >= upper) {
            break;
        }
        fp = next_fp;
    }
#else
    // On arm64 the link register is the immediate return address if the
    // fault happened inside a callee (e.g. a stack-probe helper).  The frame
    // record then supplies the caller chain: [fp] = previous fp and
    // [fp + 8] = saved lr.
    const std::uintptr_t lr = state_lr(state);
    const bool lr_added = lr != 0 && lr != pc;
    if(lr_added) {
        frames.push_back(static_cast<cpptrace::frame_ptr>(lr - 1));
    }

    bool first_frame_record = true;
    std::uintptr_t fp = state_fp(state);
    while(frames.size() < kMaxFrames) {
        if(fp == 0 || (fp & 15) != 0 || fp < sp || fp >= upper) {
            break;
        }

        std::uintptr_t words[2] = {0, 0};
        if(!safe_read(task, fp, words, sizeof(words))) {
            break;
        }

        const std::uintptr_t next_fp = strip_data_pointer(words[0]);
        const std::uintptr_t saved_lr = strip_code_pointer(words[1]);
        if(saved_lr == 0) {
            break;
        }

        cpptrace::frame_ptr frame = static_cast<cpptrace::frame_ptr>(saved_lr - 1);
        // The first frame record can contain the same return address we just
        // added from LR.  Do not suppress later repeated addresses, though:
        // recursive functions legitimately have many equal return addresses.
        if(!(first_frame_record && lr_added && frames.back() == frame)) {
            frames.push_back(frame);
        }
        first_frame_record = false;

        if(next_fp <= fp || next_fp >= upper) {
            break;
        }
        fp = next_fp;
    }
#endif

    return frames;
}

// ---------------------------------------------------------------------------
// Reporting / unwinding on the exception thread.
// ---------------------------------------------------------------------------

cpptrace::stacktrace make_unsymbolized_trace(const std::vector<cpptrace::frame_ptr>& frames) {
    cpptrace::stacktrace trace;
    trace.frames.reserve(frames.size());
    for(cpptrace::frame_ptr address : frames) {
        cpptrace::stacktrace_frame frame{};
        frame.raw_address = address;
        frame.object_address = address;
        frame.symbol = "<unresolved>";
        frame.is_inline = false;
        trace.frames.push_back(std::move(frame));
    }
    return trace;
}

void report_and_exit(
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    const int64_t* codes,
    mach_msg_type_number_t code_count,
    const thread_state& state
) {
    if(g_reported.exchange(true)) {
        std::fprintf(stderr, "Unexpected second exception while reporting; exiting.\n");
        std::fflush(nullptr);
        _exit(1);
    }

    mach_port_t memory_task = task;
    if(memory_task == MACH_PORT_NULL) {
        memory_task = mach_task_self();
    }

    std::fprintf(stderr, "\n");
    std::fprintf(stderr, "=== Mach exception caught ===\n");
    std::fprintf(stderr, "exception : %s (%d)\n", exception_name(exception), exception);
    for(mach_msg_type_number_t i = 0; i < code_count; ++i) {
        std::fprintf(stderr, "code[%u]   : 0x%llx (%lld)\n", i,
            static_cast<unsigned long long>(codes[i]),
            static_cast<long long>(codes[i]));
    }

    std::fprintf(stderr, "thread    : 0x%x\n", thread);
    std::fprintf(stderr, "task      : 0x%x\n", memory_task);
    std::fprintf(stderr, "pc        : 0x%llx\n",
        static_cast<unsigned long long>(state_pc(state)));
    std::fprintf(stderr, "sp        : 0x%llx\n",
        static_cast<unsigned long long>(state_sp(state)));
    std::fprintf(stderr, "fp        : 0x%llx\n",
        static_cast<unsigned long long>(state_fp(state)));
#if defined(__aarch64__)
    std::fprintf(stderr, "lr        : 0x%llx\n",
        static_cast<unsigned long long>(state_lr(state)));
#endif
    std::fflush(stderr);

    // On arm64e we deliberately use the PAC-aware frame-pointer walk only:
    // driving libunwind's authenticated-unwinding path with a synthesized
    // context can be unsafe because its setIP path expects a value signed with
    // the current SP.  Plain arm64 and x86_64 use libunwind first.
    std::vector<cpptrace::frame_ptr> libunwind_frames;
    if(!kPreferFramePointers) {
        libunwind_frames = unwind_with_libunwind(state);
    }
    std::vector<cpptrace::frame_ptr> frame_pointer_frames =
        unwind_with_frame_pointers(state, memory_task);

    const std::size_t libunwind_count = libunwind_frames.size();
    const std::size_t frame_pointer_count = frame_pointer_frames.size();
    const bool use_frame_pointers =
        kPreferFramePointers || frame_pointer_count > libunwind_count;
    std::vector<cpptrace::frame_ptr> frames =
        use_frame_pointers ? std::move(frame_pointer_frames) : std::move(libunwind_frames);

    std::fprintf(stderr, "unwinder  : %s (%zu frames; libunwind=%zu, fp=%zu)\n",
        use_frame_pointers
            ? (kPreferFramePointers
                ? "frame-pointer (arm64e PAC-aware)"
                : "frame-pointer fallback")
            : "libunwind (synthetic remote context)",
        frames.size(),
        libunwind_count,
        frame_pointer_count);
    std::fprintf(stderr, "note      : unwound on the exception-watching thread; the failing "
                         "thread was stopped (Mach suspension or blocked in the abort RPC).\n");
    if(frames.size() >= kMaxFrames) {
        std::fprintf(stderr, "note      : frame capture capped at %zu frames.\n", kMaxFrames);
    }
    std::fprintf(stderr, "\n");
    std::fflush(stderr);

    if(frames.empty()) {
        std::fprintf(stderr, "No frames could be captured.\n");
        std::fflush(nullptr);
        _exit(1);
    }

    cpptrace::raw_trace raw;
    raw.frames = std::move(frames);

    cpptrace::formatter formatter;
    formatter.colors(cpptrace::formatter::color_mode::none);

    try {
        cpptrace::stacktrace trace = raw.resolve();
        if(!trace.empty()) {
            formatter.print(std::cout, trace);
        } else {
            std::fprintf(stderr, "cpptrace returned an empty trace; raw frames:\n");
            formatter.print(std::cout, make_unsymbolized_trace(raw.frames));
        }
    } catch(const std::exception& e) {
        std::fprintf(stderr, "cpptrace failed to symbolize frames: %s\n", e.what());
        std::fprintf(stderr, "raw frames:\n");
        formatter.print(std::cout, make_unsymbolized_trace(raw.frames));
    }

    std::cout.flush();
    std::fflush(nullptr);
    _exit(0);
}

// ---------------------------------------------------------------------------
// MIG exception server callbacks.
// ---------------------------------------------------------------------------

extern "C" kern_return_t catch_mach_exception_raise(
    mach_port_t,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count
) {
    thread_state state{};
    mach_msg_type_number_t state_count = kThreadCount;
    kern_return_t kr = thread_get_state(
        thread,
        kThreadFlavor,
        reinterpret_cast<thread_state_t>(&state),
        &state_count
    );
    if(kr != KERN_SUCCESS) {
        std::fprintf(stderr, "thread_get_state failed: %s\n", mach_error_string(kr));
        _exit(1);
    }
    report_and_exit(thread, task, exception, code, code_count, state);
    return KERN_SUCCESS;
}

extern "C" kern_return_t catch_mach_exception_raise_state(
    mach_port_t,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int* flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t,
    mach_msg_type_number_t*
) {
    thread_state state{};
    if(*flavor != kThreadFlavor || old_state_count < kThreadCount) {
        std::fprintf(stderr, "Unsupported exception state flavor %d\n", *flavor);
        _exit(1);
    }
    std::memcpy(&state, old_state, sizeof(state));
    report_and_exit(MACH_PORT_NULL, MACH_PORT_NULL, exception, code, code_count, state);
    return KERN_SUCCESS;
}

extern "C" kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int* flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t,
    mach_msg_type_number_t*
) {
    thread_state state{};
    if(*flavor != kThreadFlavor || old_state_count < kThreadCount) {
        std::fprintf(stderr, "Unsupported exception state flavor %d\n", *flavor);
        _exit(1);
    }
    std::memcpy(&state, old_state, sizeof(state));
    report_and_exit(thread, task, exception, code, code_count, state);
    return KERN_SUCCESS;
}

void* exception_thread(void*) {
    // Dispatch Mach exception RPCs until the process exits.  The callbacks
    // above run on this thread, never on the faulting thread.
    kern_return_t kr = mach_msg_server(
        mach_exc_server,
        sizeof(union __RequestUnion__mach_exc_subsystem),
        g_exception_port,
        0
    );
    std::fprintf(stderr, "mach_msg_server stopped: %s\n", mach_error_string(kr));
    return nullptr;
}

// ---------------------------------------------------------------------------
// SIGABRT -> Mach exception bridge.
//
// An in-process task exception port cannot receive the kernel's EXC_CRASH
// notification: xnu deliberately refuses to deliver EXC_CRASH to a port that
// lives in the exiting task (to avoid a deadlock).  SIGABRT is a BSD signal,
// not a hardware fault, so abort() does not produce EXC_BAD_ACCESS either.
//
// To keep the same code path, the SIGABRT handler captures the interrupted
// thread state and sends it to our Mach exception port as a real 64-bit Mach
// exception RPC.  The handler thread then unwinds the (blocked) aborting
// thread exactly like it does for hardware faults.
// ---------------------------------------------------------------------------

void sigabrt_handler(int, siginfo_t*, void* ucontext_ptr) {
    if(g_reported.load()) {
        _exit(1);
    }

    auto* uc = static_cast<ucontext_t*>(ucontext_ptr);
    thread_state state{};
    std::memcpy(&state, &uc->uc_mcontext->__ss, sizeof(state));

    int flavor = kThreadFlavor;
    mach_msg_type_number_t new_state_count = kThreadCount;
    thread_state new_state{};
    int64_t codes[2] = {
        static_cast<int64_t>((SIGABRT & 0xff) << 24),
        0
    };

    kern_return_t kr = mach_exception_raise_state_identity(
        g_exception_port,
        mach_thread_self(),
        mach_task_self(),
        EXC_CRASH,
        codes,
        2,
        &flavor,
        reinterpret_cast<thread_state_t>(&state),
        kThreadCount,
        reinterpret_cast<thread_state_t>(&new_state),
        &new_state_count
    );

    if(kr != KERN_SUCCESS) {
        char message[256];
        std::snprintf(message, sizeof(message),
            "sigabrt: mach_exception_raise_state_identity failed: %s\n",
            mach_error_string(kr));
        (void)write(STDERR_FILENO, message, std::strlen(message));
    }
    _exit(1);
}

// ---------------------------------------------------------------------------
// Failure generators.
// ---------------------------------------------------------------------------

__attribute__((noinline)) void trigger_segfault() {
    volatile int* null_pointer = reinterpret_cast<int*>(0x10);
    *null_pointer = 42;
}

__attribute__((noinline)) void trigger_stack_overflow(int depth) {
    // 1 KiB per frame avoids the compiler's stack-probe helper on both
    // architectures, so the faulting frame has a normal frame pointer.
    volatile unsigned char buffer[1024];
    buffer[0] = static_cast<unsigned char>(depth);
    buffer[sizeof(buffer) - 1] = static_cast<unsigned char>(depth);
    trigger_stack_overflow(depth + 1);
    asm volatile("" : : "r"(buffer) : "memory");
}

__attribute__((noinline)) void trigger_abort() {
    std::abort();
}

// ---------------------------------------------------------------------------
// Setup.
// ---------------------------------------------------------------------------

bool install_exception_port() {
    mach_port_t task = mach_task_self();

    kern_return_t kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &g_exception_port);
    if(kr != KERN_SUCCESS) {
        std::fprintf(stderr, "mach_port_allocate failed: %s\n", mach_error_string(kr));
        return false;
    }

    kr = mach_port_insert_right(task, g_exception_port, g_exception_port, MACH_MSG_TYPE_MAKE_SEND);
    if(kr != KERN_SUCCESS) {
        std::fprintf(stderr, "mach_port_insert_right failed: %s\n", mach_error_string(kr));
        return false;
    }

    exception_mask_t mask =
        EXC_MASK_BAD_ACCESS |
        EXC_MASK_BAD_INSTRUCTION |
        EXC_MASK_ARITHMETIC |
        EXC_MASK_BREAKPOINT |
        EXC_MASK_SOFTWARE |
        EXC_MASK_CRASH |
        EXC_MASK_GUARD;

    // STATE_IDENTITY gives us both the thread/task ports and the register
    // state at the time of the exception.
    kr = task_set_exception_ports(
        task,
        mask,
        g_exception_port,
        EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES,
        kThreadFlavor
    );
    if(kr != KERN_SUCCESS) {
        std::fprintf(stderr, "task_set_exception_ports failed: %s\n", mach_error_string(kr));
        return false;
    }

    return true;
}

void install_sigabrt_handler() {
    stack_t alt_stack{};
    alt_stack.ss_sp = g_alt_stack;
    alt_stack.ss_size = sizeof(g_alt_stack);
    alt_stack.ss_flags = 0;
    if(sigaltstack(&alt_stack, nullptr) != 0) {
        std::perror("sigaltstack");
    }

    struct sigaction action{};
    action.sa_sigaction = sigabrt_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if(sigaction(SIGABRT, &action, nullptr) != 0) {
        std::perror("sigaction(SIGABRT)");
    }
}

void print_usage(const char* argv0) {
    std::cerr
        << "Usage: " << argv0 << " [segfault|stack_overflow|abort]\n"
        << "With no argument an interactive prompt is shown.\n";
}

} // namespace

int main(int argc, char** argv) {
    std::string choice;

    if(argc > 1) {
        choice = argv[1];
    } else {
        std::cout
            << "Choose a failure to generate:\n"
            << "  1) segfault\n"
            << "  2) stack_overflow\n"
            << "  3) abort (raise SIGABRT)\n"
            << "> " << std::flush;
        if(!std::getline(std::cin, choice)) {
            return 1;
        }
    }

    enum class Failure { segfault, stack_overflow, abort };
    Failure failure;
    if(choice == "1" || choice == "segfault" || choice == "segv") {
        failure = Failure::segfault;
    } else if(choice == "2" || choice == "stack_overflow" || choice == "stack-overflow" ||
              choice == "overflow") {
        failure = Failure::stack_overflow;
    } else if(choice == "3" || choice == "abort" || choice == "raise abort" ||
              choice == "raise_abort" || choice == "raise-abort" || choice == "sigabrt") {
        failure = Failure::abort;
    } else {
        std::cerr << "Unknown failure type: " << choice << "\n";
        print_usage(argv[0]);
        return 1;
    }

    if(!install_exception_port()) {
        return 1;
    }

    pthread_t thread;
    int rc = pthread_create(&thread, nullptr, exception_thread, nullptr);
    if(rc != 0) {
        std::fprintf(stderr, "pthread_create failed: %s\n", std::strerror(rc));
        return 1;
    }
    pthread_detach(thread);

    install_sigabrt_handler();

    // Give the exception server thread a moment to enter mach_msg().
    usleep(100 * 1000);

    switch(failure) {
        case Failure::segfault:
            std::cerr << "Generating SIGSEGV (EXC_BAD_ACCESS)...\n";
            trigger_segfault();
            break;
        case Failure::stack_overflow:
            std::cerr << "Generating stack overflow...\n";
            trigger_stack_overflow(0);
            break;
        case Failure::abort:
            std::cerr << "Generating abort()/SIGABRT...\n";
            trigger_abort();
            break;
    }

    std::cerr << "Failure generator returned unexpectedly; no fault was delivered.\n";
    return 1;
}
