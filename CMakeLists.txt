cmake_minimum_required(VERSION 3.21)

option(MACOS_TRACE_UNIVERSAL "Build a universal x86_64 + arm64 binary" OFF)
if(MACOS_TRACE_UNIVERSAL)
  set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "Target architectures" FORCE)
endif()

if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
  set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum macOS version")
endif()

project(macos_mach_trace LANGUAGES C CXX)

if(NOT APPLE)
  message(FATAL_ERROR "This project only builds on macOS.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# cpptrace (git submodule).  cpptrace uses libdwarf for symbolization on macOS;
# by default it fetches and builds libdwarf/zstd through FetchContent.
# ---------------------------------------------------------------------------
set(CPPTRACE_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CPPTRACE_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(CPPTRACE_UNWIND_WITH_EXECINFO ON CACHE BOOL "" FORCE)
set(CPPTRACE_GET_SYMBOLS_WITH_LIBDWARF ON CACHE BOOL "" FORCE)
set(CPPTRACE_USE_EXTERNAL_LIBDWARF OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/cpptrace EXCLUDE_FROM_ALL)

# ---------------------------------------------------------------------------
# Machine-generated MIG stubs for the 64-bit Mach exception protocol.
# ---------------------------------------------------------------------------
find_program(MIG_EXECUTABLE mig REQUIRED)

execute_process(
  COMMAND xcrun --show-sdk-path
  OUTPUT_VARIABLE MACOS_SDK_PATH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT MACOS_SDK_PATH)
  message(FATAL_ERROR "Could not locate the macOS SDK with xcrun")
endif()

set(MACH_EXC_DEFS "${MACOS_SDK_PATH}/usr/include/mach/mach_exc.defs")
set(MIG_DIR "${CMAKE_CURRENT_BINARY_DIR}/mig")
file(MAKE_DIRECTORY "${MIG_DIR}")

add_custom_command(
  OUTPUT
    "${MIG_DIR}/mach_exc.h"
    "${MIG_DIR}/mach_excUser.c"
    "${MIG_DIR}/mach_excServer.h"
    "${MIG_DIR}/mach_excServer.c"
  COMMAND "${MIG_EXECUTABLE}"
          -header mach_exc.h
          -user mach_excUser.c
          -sheader mach_excServer.h
          -server mach_excServer.c
          "${MACH_EXC_DEFS}"
  DEPENDS "${MACH_EXC_DEFS}"
  WORKING_DIRECTORY "${MIG_DIR}"
  COMMENT "Generating Mach exception MIG stubs"
  VERBATIM
)

set(MIG_SOURCES
  "${MIG_DIR}/mach_excUser.c"
  "${MIG_DIR}/mach_excServer.c"
)

add_executable(macos_mach_trace
  src/main.cpp
  ${MIG_SOURCES}
)

target_include_directories(macos_mach_trace PRIVATE "${MIG_DIR}")

# Frame pointers and no sibling-call optimization make the faulting stacks
# deterministic and also give the frame-pointer fallback unwinder a chance.
target_compile_options(macos_mach_trace PRIVATE
  -g
  -O0
  -fno-omit-frame-pointer
  -fno-optimize-sibling-calls
)

target_link_libraries(macos_mach_trace PRIVATE cpptrace::cpptrace)

# cpptrace's libdwarf resolver looks for <exe>.dSYM first.  Generate one for
# line-number information in Debug builds.
find_program(DSYMUTIL_EXECUTABLE dsymutil)
if(DSYMUTIL_EXECUTABLE)
  add_custom_command(TARGET macos_mach_trace POST_BUILD
    COMMAND "${DSYMUTIL_EXECUTABLE}" "$<TARGET_FILE:macos_mach_trace>"
            -o "$<TARGET_FILE:macos_mach_trace>.dSYM"
    COMMENT "Generating dSYM"
    VERBATIM
  )
endif()
