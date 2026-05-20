#pragma once

// =====================================================
// shared.h  –  EDR AMSI Bridge
// Shared between AMSI Provider DLL and C++ Agent EXE
// =====================================================

// Suppress windows.h min/max macros — they conflict with std::min / std::max
#ifndef NOMINMAX
#  define NOMINMAX
#endif

#include <windows.h>

// Named pipe connecting Provider → Agent
#define EDR_PIPE_NAME          "\\\\.\\pipe\\EdrAmsiPipe"
#define EDR_PIPE_NAME_W       L"\\\\.\\pipe\\EdrAmsiPipe"

// Maximum number of simultaneous pipe instances (= max concurrent PS sessions)
#define EDR_PIPE_MAX_INSTANCES  16

// Maximum script payload stored in one message (bytes, UTF-8)
static const size_t MAX_SCRIPT_CHARS = 16384;

// -------------------------------------------------------
// Wire format – keep layout identical in provider + agent.
// pragma pack(push,1) ensures no padding even across
// compiler / platform differences.
// -------------------------------------------------------
#pragma pack(push, 1)
struct ScanMessage
{
    DWORD  pid;                        // Scanning process PID
    DWORD  parentPid;                  // Parent PID

    char   process[260];               // Image name (UTF-8)
    char   parentProcess[260];         // Parent image name (UTF-8)

    char   sha256[65];                 // Hex SHA-256 of the final script
    char   script[MAX_SCRIPT_CHARS];   // UTF-8 script content (null-terminated)
};
#pragma pack(pop)

static_assert(sizeof(ScanMessage) > 0, "ScanMessage must be non-empty");