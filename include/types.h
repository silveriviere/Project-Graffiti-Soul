#pragma once

#include <cstdint>

using byte = uint8_t;
using word = uint16_t;
using dword = uint32_t;
using qword = uint64_t;
using ulonglong = uint64_t;

using sbyte = int8_t;
using sword = int16_t;
using sdword = int32_t;
using sqword = int64_t;

using pvoid = void*;
using uintptr_t = std::uintptr_t;

struct XTHREAD;
struct XD3DDEVICE;
struct XFILE;

using LPTHREAD_START_ROUTINE = dword (*)(void*);

#define NULL 0
#define ADDR(x) [[maybe_unused]] static constexpr dword ORIGINAL_ADDR = x
