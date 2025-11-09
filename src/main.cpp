// Graffiti Soul - JSRF Decompilation Project
// XBE base address: 0x00010000

#include "types.h"
#include <cstdlib>

namespace XAPILIB {
    dword _tls_index = 0;
    void XapiInitProcess() {}
    void _rtinit() {}
    void _cinit() {}

    dword CreateThread(pvoid lpThreadAttributes, dword dwStackSize,
                       dword lpStartAddress, pvoid lpParameter,
                       dword dwCreationFlags, pvoid lpThreadId) {
        return 1;
    }

    void XapiBootToDash(dword dwReason, dword dwParameter1, dword dwParameter2) {}

    void QueryPerformanceCounter(uint* counter) {
        // Stub implementation
        if (counter) *counter = 0;
    }
}

extern dword runtime_wrapper_thread(pvoid param);
extern void thread_cleanup(dword threadHandle);
extern dword jsrf_game_main();

dword DAT_0027dce0;

void entry(void) {
    ADDR(0x0);

    dword dVar1;

    DAT_0027dce0 = 0x14;
    XAPILIB::_tls_index = 0xfffffffb;
    dVar1 = XAPILIB::CreateThread(0, 0, 0x147fb4, 0, 0, 0);
    if (dVar1 == 0) {
        XAPILIB::XapiBootToDash(1, 1, 0);
    }
    thread_cleanup(dVar1);
    return;
}

dword runtime_wrapper_thread(pvoid param) {
    ADDR(0x147fb4);

    int iVar1;
    int iVar2;
    byte *puVar3;
    int unaff_FS_OFFSET;

    XAPILIB::XapiInitProcess();

    // TLS setup
    iVar1 = *(int *)(*(int *)(unaff_FS_OFFSET + 0x20) + 0x250);
    if (iVar1 == 0) {
        puVar3 = (byte *)0x0;
    }
    else {
        puVar3 = *(byte **)(iVar1 + 0x24);
    }
    if (puVar3 != (byte *)0x0) {
        iVar1 = *(int *)(*(int *)(unaff_FS_OFFSET + 4) + XAPILIB::_tls_index * 4);
        iVar2 = *(int *)(*(int *)(unaff_FS_OFFSET + 0x28) + 0x28);
        *puVar3 = 1;
        *(int *)(puVar3 + 4) = (iVar1 - iVar2) + 4;
    }

    XAPILIB::_rtinit();
    XAPILIB::_cinit();
    jsrf_game_main();
    XAPILIB::XapiBootToDash(1, 1, 0);
    return 0;
}

void thread_cleanup(dword threadHandle) {
    ADDR(0x145585);
}

struct GameState;
extern GameState* g_GameState;

extern GameState* game_state_constructor(void* this_ptr, int param2, int param3);
extern void game_state_init_subsystem(GameState* gameState);
extern dword game_main_loop(GameState* gameState);
extern void game_frame_update(GameState* gameState);
extern void subsystem_frame_update(GameState* gameState);
extern void FUN_00013930(GameState* gameState);
extern void FUN_000659c0();
extern void FUN_00065c80();
extern void sleep_milliseconds(dword ms);
extern void FUN_0015fa20();
extern int FUN_0015fa10();
extern float FUN_000694a0(void* device, int index);
extern ulonglong FUN_0017c3e8();
extern void FUN_0003e440(void* obj, dword param);
extern void FUN_0003e430(void* obj, dword param);

// QueryPerformanceCounter from XAPILIB
namespace XAPILIB {
    void QueryPerformanceCounter(uint* counter);
}

// Subsystem initialization functions
extern void FUN_000161b0(dword* param);
extern void FUN_0003e9a0(dword param);
extern void FUN_0006c6d0(dword param);
extern void FUN_0006dbb0(dword param);

// Subsystem update functions - State 0 (default)
extern void FUN_0006f8c0(dword param);
extern void FUN_0001df30(dword param);
extern void FUN_00065800(dword param);
extern void FUN_00066ad0(dword param);
extern void FUN_00024ae0(dword param);
extern void FUN_00066110(dword param);
extern void FUN_00015130(dword param);
extern void FUN_00011070(int* param);

// Subsystem update functions - State 1 (0x40)
extern void FUN_000114d0(int* param);

// Subsystem update functions - State 2 (0x44)
extern void FUN_000112a0(int* param);

// Subsystem update functions - State 3 (0x48)
extern void FUN_00011700(int* param);

// Subsystem update functions - State 4 (0x4c)
extern void FUN_00011930(int* param);

// Subsystem cleanup functions
extern void FUN_0001d920(dword* param);
extern void FUN_0003e9c0(dword param);
extern void FUN_0006c6e0(dword param);
extern void FUN_0006dbe0(dword param);
extern void FUN_0001dd60(dword param);
extern void FUN_00066d80(dword param);
extern void FUN_00039a80(dword param);

// Post-update functions for each state
extern void FUN_00011d00(int* param);  // State 0
extern void FUN_00011e40(int* param);  // State 1
extern void FUN_00011da0(int* param);  // State 2
extern void FUN_00011ee0(int* param);  // State 3
extern void FUN_00011f80(int* param);  // State 4

// Performance tracking
extern void FUN_0006e910(void* param1, void* param2, uint time_start_low, int time_start_high,
                          uint time_end_low, int time_end_high);

extern void* DAT_00251d70;
extern void* DAT_00251d6c;
extern void* DAT_00251d68;
extern void* DAT_00251f5c;

extern int DAT_00251d88;
extern int DAT_00251d44;
extern int DAT_00251d54;
extern int DAT_00251d58;
extern int DAT_00251d40;

// Global subsystem data
extern dword DAT_0022fce8;
extern void* PTR_PTR_0020cc48;

GameState* g_GameState = nullptr;

void* DAT_00251d70 = nullptr;
void* DAT_00251d6c = nullptr;
void* DAT_00251d68 = nullptr;
void* DAT_00251f5c = nullptr;

int DAT_00251d88 = 0;
int DAT_00251d44 = 0;
int DAT_00251d54 = 0;
int DAT_00251d58 = 0;
int DAT_00251d40 = 0;

dword DAT_0022fce8 = 0;
void* PTR_PTR_0020cc48 = nullptr;

dword jsrf_game_main() {
    ADDR(0x0006f9e0);

    void* this_ptr;
    dword* unaff_FS_OFFSET;
    dword local_c;
    byte* puStack_8;
    dword local_4;

    local_4 = 0xffffffff;
    puStack_8 = (byte*)0x0018771b;
    local_c = *unaff_FS_OFFSET;
    *unaff_FS_OFFSET = (dword)(uintptr_t)&local_c;

    this_ptr = malloc(0x8840);
    local_4 = 0;

    if (this_ptr == nullptr) {
        g_GameState = nullptr;
    }
    else {
        g_GameState = game_state_constructor(this_ptr, 0, 0);
    }

    local_4 = 0xffffffff;
    game_state_init_subsystem(g_GameState);
    game_main_loop(g_GameState);

    if (g_GameState != nullptr) {
        // (**(code**)g_GameState)(1, this_ptr);
    }

    *unaff_FS_OFFSET = local_c;
    return 0;
}

void game_state_init_subsystem(GameState* gameState) {
    ADDR(0x00012c10);

    void* this_ptr;
    void* puVar1;
    dword* unaff_FS_OFFSET;
    dword local_c;
    byte* puStack_8;
    dword local_4;

    local_4 = 0xffffffff;
    puStack_8 = (byte*)0x00186c0b;
    local_c = *unaff_FS_OFFSET;
    *unaff_FS_OFFSET = (dword)(uintptr_t)&local_c;

    *(void**)((byte*)gameState + 0x87dc) = nullptr;

    if (*(int*)((byte*)gameState + 0x10) >= 0) {
        this_ptr = malloc(0x44);
        local_4 = 0;

        if (this_ptr == nullptr) {
            puVar1 = nullptr;
        }
        else {
            // puVar1 = FUN_00012ae0(this_ptr, 0, -1, 0);
            puVar1 = nullptr;
        }

        *(void**)((byte*)gameState + 0x87dc) = puVar1;
    }

    *unaff_FS_OFFSET = local_c;
    return;
}

dword game_main_loop(GameState* gameState) {
    ADDR(0x00013f80);

    if (*(int*)((byte*)gameState + 0x10) < 0) {
        return 0xffffffff;
    }

    do {
        while (*(int*)((byte*)gameState + 0x24) != 0) {
            FUN_000659c0();
            sleep_milliseconds(0x10);
        }
        game_frame_update(gameState);
    } while (true);
}

GameState* game_state_constructor(void* this_ptr, int param2, int param3) {
    ADDR(0x00012210);
    return (GameState*)this_ptr;
}

void game_frame_update(GameState* gameState) {
    ADDR(0x00013a80);

    void* this_ptr;
    int iVar1;
    ulonglong uVar3, uVar4, uVar5, uVar6;
    float fVar7;
    dword uVar8;

    if (*(int*)((byte*)gameState + 0x50) != 0) {
        FUN_00065c80();
        *(dword*)((byte*)gameState + 0x40) = 1;
    }
    if (*(int*)((byte*)gameState + 0x54) != 0) {
        FUN_00065c80();
        *(dword*)((byte*)gameState + 0x40) = 0;
    }
    if (*(int*)((byte*)gameState + 0x58) != 0) {
        FUN_00065c80();
        *(dword*)((byte*)gameState + 0x44) = 1;
    }
    if (*(int*)((byte*)gameState + 0x5c) != 0) {
        FUN_00065c80();
        *(dword*)((byte*)gameState + 0x44) = 0;
    }
    if (*(int*)((byte*)gameState + 0x60) != 0) {
        FUN_00065c80();
        *(dword*)((byte*)gameState + 0x48) = 1;
    }
    if (*(int*)((byte*)gameState + 100) != 0) {  // 0x64
        FUN_00065c80();
        *(dword*)((byte*)gameState + 0x48) = 0;
    }
    if (*(int*)((byte*)gameState + 0x68) != 0) {
        FUN_00065c80();
        *(dword*)((byte*)gameState + 0x4c) = 1;
    }
    if (*(int*)((byte*)gameState + 0x6c) != 0) {
        FUN_00065c80();
        *(dword*)((byte*)gameState + 0x4c) = 0;
    }

    *(dword*)((byte*)gameState + 0x50) = 0;
    *(dword*)((byte*)gameState + 0x54) = 0;
    *(dword*)((byte*)gameState + 0x58) = 0;
    *(dword*)((byte*)gameState + 0x5c) = 0;
    *(dword*)((byte*)gameState + 0x60) = 0;
    *(dword*)((byte*)gameState + 100) = 0;
    *(dword*)((byte*)gameState + 0x68) = 0;
    *(dword*)((byte*)gameState + 0x6c) = 0;

    FUN_000659c0();
    *(dword*)((byte*)gameState + 0x74) = 0;
    subsystem_frame_update(gameState);

    if (*(int*)((byte*)gameState + 0x94) == 0) {
        FUN_0015fa20();

        FUN_000694a0(&DAT_00251f5c, 8);
        uVar3 = FUN_0017c3e8();
        FUN_000694a0(&DAT_00251f5c, 9);
        uVar4 = FUN_0017c3e8();
        FUN_000694a0(&DAT_00251f5c, 10);
        uVar5 = FUN_0017c3e8();
        *(dword*)((byte*)gameState + 0x28) = ((int)uVar3 << 8 | (uint)uVar4) << 8 | (uint)uVar5;

        FUN_000694a0(&DAT_00251f5c, 0xc);
        uVar3 = FUN_0017c3e8();
        FUN_000694a0(&DAT_00251f5c, 0xd);
        uVar4 = FUN_0017c3e8();
        FUN_000694a0(&DAT_00251f5c, 0xe);
        uVar5 = FUN_0017c3e8();
        *(dword*)((byte*)gameState + 0x2c) = ((int)uVar3 << 8 | (uint)uVar4) << 8 | (uint)uVar5;

        FUN_000694a0(&DAT_00251f5c, 0x10);
        uVar3 = FUN_0017c3e8();
        FUN_000694a0(&DAT_00251f5c, 0x11);
        uVar4 = FUN_0017c3e8();
        FUN_000694a0(&DAT_00251f5c, 0x12);
        uVar5 = FUN_0017c3e8();
        FUN_000694a0(&DAT_00251f5c, 0x13);
        uVar6 = FUN_0017c3e8();
        *(dword*)((byte*)gameState + 0x30) =
            (((int)uVar3 << 8 | (uint)uVar4) << 8 | (uint)uVar5) << 8 | (uint)uVar6;

        if (*(int*)((byte*)gameState + 0x3c) == 0) {
            FUN_000694a0(&DAT_00251f5c, 0x15);
            uVar3 = FUN_0017c3e8();
            FUN_000694a0(&DAT_00251f5c, 0x16);
            uVar4 = FUN_0017c3e8();
            FUN_000694a0(&DAT_00251f5c, 0x17);
            uVar5 = FUN_0017c3e8();
            *(dword*)((byte*)gameState + 0x34) = ((int)uVar3 << 8 | (uint)uVar4) << 8 | (uint)uVar5;
        }
        else {
            *(dword*)((byte*)gameState + 0x34) = *(dword*)((byte*)gameState + 0x38);
        }

        this_ptr = *(void**)((byte*)gameState + 0x434);
        if (this_ptr != nullptr) {
            FUN_0003e440(this_ptr, *(dword*)((byte*)gameState + 0x2c));
            FUN_0003e430(this_ptr, *(dword*)((byte*)gameState + 0x28));
        }

        iVar1 = *(int*)DAT_00251d70;
        uVar8 = 1;
        // fVar2 = FUN_000694a0(&DAT_00251f5c, 0x1f);
        // fVar7 = (float)fVar2;
        // fVar2 = FUN_000694a0(&DAT_00251f5c, 0x1b);
        // (**(code**)(iVar1 + 0x14))(DAT_00251d70, (float)fVar2, fVar7, uVar8);
        // (**(code**)(*DAT_00251d70 + 0xc))(DAT_00251d70);

        FUN_00013930(gameState);

        if (*(int*)((byte*)gameState + 0x18) != 0) {
            if (DAT_00251d88 != -1) {
                DAT_00251d88 = -1;
                // (**(code**)(*DAT_00251d6c + 0xa8))(DAT_00251d6c, 0xffffffff);
            }

            iVar1 = 0;
            if (iVar1 >= 0) {
                if (DAT_00251d44 != 1) {
                    DAT_00251d44 = 1;
                    // (**(code**)(*DAT_00251d6c + 0x148))(DAT_00251d6c, 0, 1);
                }

                if (DAT_00251d54 != -1) {
                    DAT_00251d54 = -1;
                    // (**(code**)(*DAT_00251d6c + 0x144))(DAT_00251d6c, 0, 0xffffffff);
                }

                if (DAT_00251d58 != -1) {
                    DAT_00251d58 = -1;
                    // (**(code**)(*DAT_00251d6c + 0x144))(DAT_00251d6c, 1, 0xffffffff);
                }

                DAT_00251d40 = 0;

                if (DAT_00251d44 != 2) {
                    DAT_00251d44 = 2;
                    // (**(code**)(*DAT_00251d6c + 0x148))(DAT_00251d6c, 0, 2);
                }
            }
        }

        if (*(int*)((byte*)gameState + 0x74) == 0) {
            // (**(code**)(*DAT_00251d6c + 0xb8))(DAT_00251d6c);
        }
    }
    else if (*(int*)((byte*)gameState + 0x94) == 1) {
        do {
            iVar1 = FUN_0015fa10();
        } while (iVar1 == *(int*)((byte*)gameState + 0x87d0));

        *(dword*)((byte*)gameState + 0x94) = 0;

        if (*(int*)((byte*)gameState + 0x74) == 0) {
            // (**(code**)(*DAT_00251d6c + 0xb8))(DAT_00251d6c);
        }
    }

    *(int*)((byte*)gameState + 0x87e0) = *(int*)((byte*)gameState + 0x87e0) + 1;
    *(int*)((byte*)gameState + 0x87e4) = *(int*)((byte*)gameState + 0x87e4) + 1;
}

void sleep_milliseconds(dword ms) {
    ADDR(0x00145ca6);
}

/*
==============================================================================
FUNCTION: Subsystem Frame Update Manager
ADDRESS:  0x000123e0
STATUS:   Complete
==============================================================================

DESCRIPTION:
Main subsystem update dispatcher. Calls various game subsystems in order and
routes to different update paths based on state flags in the GameState.
Measures frame time using QueryPerformanceCounter.

The function implements a state machine with 5 states (0-4) controlled by
flags at offsets 0x40, 0x44, 0x48, 0x4c in GameState structure.

PARAMETERS:
- gameState: GameState* - Pointer to the main game state structure

CALLED BY:
- game_frame_update (0x00013a80)

CALLS:
- QueryPerformanceCounter (XAPI)
- Various subsystem update functions
- Performance tracking function

NOTES:
- Uses performance counters to track frame timing
- State flags determine which code path to execute
- Pointer at offset 0x87dc appears to be a subsystem manager object
- State 0 (all flags == 0) executes the most subsystems

==============================================================================
*/
void subsystem_frame_update(GameState* gameState) {
    ADDR(0x000123e0);

    int* piVar1;
    uint local_10;
    int local_c;
    uint local_8;
    int local_4;

    // Start performance measurement
    XAPILIB::QueryPerformanceCounter(&local_8);

    // Initialize subsystems for this frame
    FUN_000161b0(&DAT_0022fce8);
    FUN_0003e9a0(0x2314b0);
    FUN_0006c6d0(0x20c750);
    FUN_0006dbb0(0x251f78);

    *(dword*)((byte*)gameState + 0x78) = 0;

    // State machine: route to appropriate update path
    // The nested if-else checks flags at offsets 0x40, 0x44, 0x48, 0x4c
    if (*(int*)((byte*)gameState + 0x40) == 0) {
        if (*(int*)((byte*)gameState + 0x44) == 0) {
            if (*(int*)((byte*)gameState + 0x48) == 0) {
                if (*(int*)((byte*)gameState + 0x4c) == 0) {
                    // State 0: Default/normal gameplay update
                    FUN_0006f8c0(0x20cc58);
                    FUN_0001df30(0x1ebabc);
                    FUN_00065800(0x1fb804);
                    FUN_00066ad0(0x1fb8cc);
                    FUN_00024ae0(0x1ec050);
                    FUN_00066110(0x1fb820);
                    FUN_00015130(0x1eb994);
                    FUN_00011070(*(int**)((byte*)gameState + 0x87dc));
                }
                else {
                    // State 4: Flag at 0x4c set
                    FUN_00011930(*(int**)((byte*)gameState + 0x87dc));
                }
            }
            else {
                // State 3: Flag at 0x48 set
                FUN_00011700(*(int**)((byte*)gameState + 0x87dc));
            }
        }
        else {
            // State 2: Flag at 0x44 set
            FUN_000112a0(*(int**)((byte*)gameState + 0x87dc));
        }
    }
    else {
        // State 1: Flag at 0x40 set
        FUN_000114d0(*(int**)((byte*)gameState + 0x87dc));
    }

    // Cleanup/finalize subsystems for this frame
    FUN_0001d920(&DAT_0022fce8);
    FUN_0003e9c0(0x2314b0);
    FUN_0006c6e0(0x20c750);
    FUN_0006dbe0(0x251f78);
    FUN_0001dd60(0x1ebaa8);
    FUN_00066d80(0x1fb8e8);
    FUN_00039a80(0x1efc74);

    // Post-update phase: route to appropriate cleanup function
    piVar1 = *(int**)((byte*)gameState + 0x87dc);
    if (*(int*)((byte*)gameState + 0x40) == 0) {
        if (*(int*)((byte*)gameState + 0x44) == 0) {
            if (*(int*)((byte*)gameState + 0x48) == 0) {
                if (*(int*)((byte*)gameState + 0x4c) == 0) {
                    // State 0 post-update
                    FUN_00011d00(piVar1);
                }
                else {
                    // State 4 post-update
                    FUN_00011f80(piVar1);
                }
            }
            else {
                // State 3 post-update
                FUN_00011ee0(piVar1);
            }
        }
        else {
            // State 2 post-update
            FUN_00011da0(piVar1);
        }
    }
    else {
        // State 1 post-update
        FUN_00011e40(piVar1);
    }

    // End performance measurement
    XAPILIB::QueryPerformanceCounter(&local_10);

    // Record frame timing (passes start and end times as 64-bit value split into two 32-bit parts)
    FUN_0006e910(&PTR_PTR_0020cc48, (void*)((byte*)gameState + 0x87b8),
                 local_8, local_4, local_10, local_c);
}

void FUN_000659c0() {
    ADDR(0x000659c0);
}

void FUN_00013930(GameState* gameState) {
    ADDR(0x00013930);
    (void)gameState;
}

void FUN_00065c80() {
    ADDR(0x00065c80);
}

void FUN_0015fa20() {
    ADDR(0x0015fa20);
}

int FUN_0015fa10() {
    ADDR(0x0015fa10);
    return 0;
}

/*
==============================================================================
FUNCTION: Float Array Accessor (Hardware Register Reader)
ADDRESS:  0x000694a0
STATUS:   Complete
==============================================================================

DESCRIPTION:
Reads a floating-point value from a hardware register array at the specified
index. Used in conjunction with FUN_0017c3e8 to read controller/peripheral
data byte-by-byte from Xbox hardware.

PARAMETERS:
- param_1: int* - Pointer to device structure containing float array pointer
- param_2: uint - Index into the float array (register number)

RETURNS:
- float10: Extended precision float from the register, or 0.0 if out of bounds

CALLED BY:
- game_frame_update (0x00013a80) - for reading input/controller values

NOTES:
- Bounds check: index must be < 0x5e (94 decimal)
- Accesses float array via double indirection: *param_1 + index * 4
- Returns float10 (80-bit extended precision) for x87 FPU compatibility
- Part of input reading pattern with FUN_0017c3e8

Usage pattern:
  FUN_000694a0(&DAT_00251f5c, 8);  // Set register index
  value = FUN_0017c3e8();          // Read the float at that index

==============================================================================
*/
float FUN_000694a0(void* device, int index) {
    ADDR(0x000694a0);

    int* param_1 = (int*)device;
    uint param_2 = (uint)index;

    // Bounds check: array has 94 entries (0x5e)
    if (param_2 < 0x5e) {
        // Double dereference to get float array, then index into it
        // *param_1 gets the pointer to float array
        // param_2 * 4 is byte offset (sizeof(float) = 4)
        float* float_array = (float*)(*param_1);
        return float_array[param_2];
    }

    return 0.0f;
}

/*
==============================================================================
FUNCTION: Floating-Point to Integer Conversion
ADDRESS:  0x0017c3e8
STATUS:   Complete
==============================================================================

DESCRIPTION:
Converts a floating-point value from the x87 FPU stack (ST0) to a 64-bit
unsigned integer with custom rounding behavior. Handles both positive and
negative values with precision adjustments.

This function is used to read hardware register values that are provided
as floating-point numbers but need to be used as integers. Common in Xbox
hardware interfaces where certain peripherals return float values.

PARAMETERS:
- in_ST0: float10 (80-bit extended precision float on x87 FPU stack)

RETURNS:
- ulonglong: 64-bit unsigned integer result

CALLED BY:
- game_frame_update (0x00013a80) - for reading input/controller data

NOTES:
- Uses x87 FPU stack register ST(0) as implicit input
- Applies custom rounding to handle floating-point precision issues
- Different behavior for positive vs negative values
- Xbox hardware often used FPU registers for peripheral communication

==============================================================================
*/
ulonglong FUN_0017c3e8() {
    ADDR(0x0017c3e8);

    // Note: This function implicitly reads from x87 FPU stack top (ST0)
    // On modern platforms, this would need platform-specific FPU access
    // For now, return stub value

    // TODO: Implement proper x87 FPU stack reading for Xbox compatibility
    // This requires inline assembly or platform-specific intrinsics:
    // float80 in_ST0;
    // __asm__ ("fld %0" : "=t" (in_ST0));

    return 0;
}

/* Original implementation (for reference when implementing native port):

ulonglong FUN_0017c3e8_reference(float80 in_ST0) {
    ulonglong uVar1;
    uint uVar2;
    float fVar3;
    uint local_20;
    uint uStack_1c;

    // Round floating-point to nearest integer
    uVar1 = (ulonglong)roundl(in_ST0);

    // Split into 32-bit components
    local_20 = (uint)uVar1;              // Low 32 bits
    uStack_1c = (uint)(uVar1 >> 32);     // High 32 bits

    // Convert to single precision for comparison
    fVar3 = (float)in_ST0;

    // Apply rounding adjustments if non-zero
    if ((local_20 != 0) || ((uVar1 & 0x7fffffff00000000ULL) != 0)) {
        if ((int)fVar3 < 0) {
            // Negative case: check fractional part and adjust
            float remainder = -(float)(in_ST0 - (long long)uVar1);
            uVar1 = uVar1 + (0x80000000U < (uint)remainder);
        }
        else {
            // Positive case: check fractional part and adjust
            float remainder = (float)(in_ST0 - (long long)uVar1);
            uVar2 = (uint)(0x80000000U < (uint)remainder);

            // Rebuild 64-bit value with adjustment
            uint low = local_20 - uVar2;
            uint high = uStack_1c - (uint)(local_20 < uVar2);
            uVar1 = ((ulonglong)high << 32) | low;
        }
    }

    return uVar1;
}
*/

void FUN_0003e440(void* obj, dword param) {
    ADDR(0x0003e440);
    (void)obj;
    (void)param;
}

void FUN_0003e430(void* obj, dword param) {
    ADDR(0x0003e430);
    (void)obj;
    (void)param;
}

// Subsystem initialization stubs
void FUN_000161b0(dword* param) {
    ADDR(0x000161b0);
    (void)param;
}

void FUN_0003e9a0(dword param) {
    ADDR(0x0003e9a0);
    (void)param;
}

void FUN_0006c6d0(dword param) {
    ADDR(0x0006c6d0);
    (void)param;
}

void FUN_0006dbb0(dword param) {
    ADDR(0x0006dbb0);
    (void)param;
}

// Subsystem update function stubs - State 0
void FUN_0006f8c0(dword param) {
    ADDR(0x0006f8c0);
    (void)param;
}

void FUN_0001df30(dword param) {
    ADDR(0x0001df30);
    (void)param;
}

void FUN_00065800(dword param) {
    ADDR(0x00065800);
    (void)param;
}

void FUN_00066ad0(dword param) {
    ADDR(0x00066ad0);
    (void)param;
}

void FUN_00024ae0(dword param) {
    ADDR(0x00024ae0);
    (void)param;
}

void FUN_00066110(dword param) {
    ADDR(0x00066110);
    (void)param;
}

void FUN_00015130(dword param) {
    ADDR(0x00015130);
    (void)param;
}

void FUN_00011070(int* param) {
    ADDR(0x00011070);
    (void)param;
}

// Subsystem update function stubs - Other states
void FUN_000114d0(int* param) {
    ADDR(0x000114d0);
    (void)param;
}

void FUN_000112a0(int* param) {
    ADDR(0x000112a0);
    (void)param;
}

void FUN_00011700(int* param) {
    ADDR(0x00011700);
    (void)param;
}

void FUN_00011930(int* param) {
    ADDR(0x00011930);
    (void)param;
}

// Subsystem cleanup function stubs
void FUN_0001d920(dword* param) {
    ADDR(0x0001d920);
    (void)param;
}

void FUN_0003e9c0(dword param) {
    ADDR(0x0003e9c0);
    (void)param;
}

void FUN_0006c6e0(dword param) {
    ADDR(0x0006c6e0);
    (void)param;
}

void FUN_0006dbe0(dword param) {
    ADDR(0x0006dbe0);
    (void)param;
}

void FUN_0001dd60(dword param) {
    ADDR(0x0001dd60);
    (void)param;
}

void FUN_00066d80(dword param) {
    ADDR(0x00066d80);
    (void)param;
}

void FUN_00039a80(dword param) {
    ADDR(0x00039a80);
    (void)param;
}

// Post-update function stubs
void FUN_00011d00(int* param) {
    ADDR(0x00011d00);
    (void)param;
}

void FUN_00011e40(int* param) {
    ADDR(0x00011e40);
    (void)param;
}

void FUN_00011da0(int* param) {
    ADDR(0x00011da0);
    (void)param;
}

void FUN_00011ee0(int* param) {
    ADDR(0x00011ee0);
    (void)param;
}

void FUN_00011f80(int* param) {
    ADDR(0x00011f80);
    (void)param;
}

// Performance tracking stub
void FUN_0006e910(void* param1, void* param2, uint time_start_low, int time_start_high,
                  uint time_end_low, int time_end_high) {
    ADDR(0x0006e910);
    (void)param1;
    (void)param2;
    (void)time_start_low;
    (void)time_start_high;
    (void)time_end_low;
    (void)time_end_high;
}

int main(int argc, char* argv[]) {
    return jsrf_game_main();
}
