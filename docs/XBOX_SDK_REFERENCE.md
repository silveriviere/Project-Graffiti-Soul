# Xbox SDK Function Reference

Reference for identifying Xbox SDK functions in decompiled code.

## Sources

- **nxdk**: https://github.com/XboxDev/nxdk (Open-source Xbox SDK)
- **xbox-includes**: https://github.com/mborgerson/xbox-includes (GPL headers from Cxbx-Reloaded/Wine/OpenXDK)
- **XbSymbolDatabase**: https://github.com/Cxbx-Reloaded/XbSymbolDatabase (Function patterns)

## Common Xbox SDK Functions Found in Games

### Memory Management (xboxkrnl.exe)

```cpp
VOID RtlZeroMemory(VOID *Destination, SIZE_T Length);
VOID RtlFillMemory(VOID *Destination, SIZE_T Length, BYTE Fill);
VOID RtlMoveMemory(VOID *Destination, CONST VOID *Source, SIZE_T Length);
SIZE_T RtlCompareMemory(CONST VOID *Source1, CONST VOID *Source2, SIZE_T Length);
```

### Timing & Performance (xboxkrnl.exe)

```cpp
BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
VOID KeDelayExecutionThread(KPROCESSOR_MODE WaitMode, BOOLEAN Alertable, PLARGE_INTEGER Interval);
```

**Note**: In your decompiled code, `QueryPerformanceCounter` at 0x00145560 uses `rdtsc` instruction.

### Thread Management (xboxkrnl.exe)

```cpp
NTSTATUS PsCreateSystemThread(
    PHANDLE ThreadHandle,
    ULONG ThreadExtraSize,
    ULONG KernelStackSize,
    ULONG TlsDataSize,
    PKSTART_ROUTINE StartRoutine,
    PVOID StartContext,
    BOOLEAN CreateSuspended
);

VOID PsTerminateSystemThread(NTSTATUS ExitStatus);
NTSTATUS NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
NTSTATUS NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
```

### Synchronization (xboxkrnl.exe)

```cpp
NTSTATUS NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
NTSTATUS NtWaitForMultipleObjectsEx(
    ULONG Count,
    PHANDLE Handles,
    WAIT_TYPE WaitType,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);
NTSTATUS NtSetEvent(HANDLE EventHandle, PLONG PreviousState);
NTSTATUS NtCreateEvent(PHANDLE EventHandle, POBJECT_ATTRIBUTES ObjectAttributes, EVENT_TYPE EventType, BOOLEAN InitialState);
```

### Graphics (D3D8.lib / XGraphics.lib)

Graphics functions are typically accessed through COM-style vtables (virtual function tables).

**Common patterns:**
- Device at `DAT_00251d70` - Likely IDirect3DDevice8
- Device at `DAT_00251d6c` - Another graphics-related interface

**IDirect3DDevice8 vtable indices** (approximate):
- `vtable[0x0c]` - Commit/Apply state
- `vtable[0x14]` - Set render state
- `vtable[0x60]` - Set texture
- `vtable[0x78]` - Set something
- `vtable[0xa8]` - Set shader
- `vtable[0xb0]` - Begin scene
- `vtable[0xb4]` - End scene
- `vtable[0xb8]` - Present/Swap buffers
- `vtable[0x124]` - Set render target
- `vtable[0x138]` - Set depth stencil
- `vtable[0x144]` - Set texture stage state
- `vtable[0x148]` - Set transform
- `vtable[0x14c]` - Set material

### Standard Library (MSVCRT.lib)

```cpp
void* malloc(size_t size);
void free(void* ptr);
void* memset(void* dest, int value, size_t count);
void* memcpy(void* dest, const void* src, size_t count);
```

### Math Library Helpers

Your decompiled code shows these at specific addresses:

- `__allmul` (0x0017ca70) - 64-bit multiply
- `__alldiv` (0x0017c9c0) - 64-bit divide

These are MSVC runtime helper functions for 64-bit integer arithmetic on x86.

## Identifying Xbox SDK Functions

### Method 1: Pattern Matching
Look for characteristic code patterns:

**QueryPerformanceCounter**:
```c
// Uses rdtsc instruction
uVar1 = rdtsc();
*param_1 = (int)uVar1;
param_1[1] = (int)((ulonglong)uVar1 >> 0x20);
return 1;
```

**malloc/free**:
```c
// Look for calls to addresses like 0x0004a8f0 (_malloc in your binary)
void *ptr = _malloc(0x8840);
```

### Method 2: Import Analysis
Check your XBE imports in Ghidra:
- Functions imported from XBOXKRNL.EXE
- Functions imported from D3D8.LIB
- Functions imported from XAPILIB.LIB

### Method 3: Symbol Database
Use XbSymbolDatabase patterns to auto-identify functions:
https://github.com/Cxbx-Reloaded/XbSymbolDatabase

## Global Pointers in Your Binary

Based on analysis of FUN_00013a80:

```cpp
// Graphics/Rendering
DAT_00251d70  // Graphics device (IDirect3DDevice8?)
DAT_00251d6c  // Another graphics device
DAT_00251d68  // Debug overlay/text system

// Input/Hardware
DAT_00251f5c  // Hardware device (controller or peripheral)
              // Accessed via FUN_000694a0(device, index) -> returns float

// Game State
DAT_0022fce0  // Global GameState pointer (g_GameState)

// Matrix Stack
DAT_00264c04  // Matrix stack pointer (used by FUN_001ba9c0/FUN_001baa50)

// Flags/State
DAT_001fa1d0  // Some render state flag
DAT_00251d88  // Another state flag
DAT_00251d44  // State flag
DAT_00251d54  // State flag
DAT_00251d58  // State flag
DAT_00251d40  // Object counter
DAT_00251d80  // State flag
DAT_00251d84  // State flag
DAT_00265174  // Performance counter (returned by FUN_0015fa10)
```

## Next Steps

1. Use Ghidra's import list to identify known SDK functions
2. Use XbSymbolDatabase to pattern-match unknown functions
3. Cross-reference with nxdk headers for function signatures
4. Document all identified functions in kb.json
5. Only mark as "complete" after verification in xemu
