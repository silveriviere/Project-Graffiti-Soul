// Common type definitions matching Xbox SDK and Ghidra output
#pragma once

#include <cstdint>

// Basic types matching Ghidra naming
using byte = uint8_t;
using word = uint16_t;
using dword = uint32_t;
using qword = uint64_t;

using sbyte = int8_t;
using sword = int16_t;
using sdword = int32_t;
using sqword = int64_t;

// Pointer types
using pvoid = void*;
using uintptr_t = std::uintptr_t;

// Xbox-specific types (stubbed for now)
// TODO: Replace with proper implementations as needed
struct XTHREAD;
struct XD3DDEVICE;
struct XFILE;

// Function pointer types
using LPTHREAD_START_ROUTINE = dword (*)(void*);

// Common macros
#define NULL 0

// Address annotations for tracking original XBE locations
#define ADDR(x) [[maybe_unused]] static constexpr dword ORIGINAL_ADDR = x
