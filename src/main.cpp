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
extern void FUN_000123e0(uintptr_t gameState);
extern void FUN_00013930(GameState* gameState);
extern void FUN_000659c0();
extern void FUN_00065c80();
extern void sleep_milliseconds(dword ms);
extern void FUN_0015fa20();
extern int FUN_0015fa10();
extern void FUN_000694a0(void* device, int index);
extern ulonglong FUN_0017c3e8();
extern void FUN_0003e440(void* obj, dword param);
extern void FUN_0003e430(void* obj, dword param);

extern void* DAT_00251d70;
extern void* DAT_00251d6c;
extern void* DAT_00251d68;
extern void* DAT_00251f5c;

extern int DAT_00251d88;
extern int DAT_00251d44;
extern int DAT_00251d54;
extern int DAT_00251d58;
extern int DAT_00251d40;

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
    FUN_000123e0((uintptr_t)gameState);

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

void FUN_000123e0(uintptr_t gameState) {
    ADDR(0x000123e0);
    (void)gameState;
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

void FUN_000694a0(void* device, int index) {
    ADDR(0x000694a0);
    (void)device;
    (void)index;
}

ulonglong FUN_0017c3e8() {
    ADDR(0x0017c3e8);
    return 0;
}

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

int main(int argc, char* argv[]) {
    return jsrf_game_main();
}
