// Project: Graffiti Soul
// Decompiled from Jet Set Radio Future XBE

#include "types.h"

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

// Xbox API stubs (these would normally come from Xbox SDK)
// For now, we provide empty implementations so the code links
namespace XAPILIB {
    dword _tls_index = 0;

    void XapiInitProcess() {
        // TODO: Replace with PC equivalent initialization
    }

    void _rtinit() {
        // C runtime init - handled automatically on PC
    }

    void _cinit() {
        // C++ constructor init - handled automatically on PC
    }

    dword CreateThread(pvoid lpThreadAttributes, dword dwStackSize,
                       dword lpStartAddress, pvoid lpParameter,
                       dword dwCreationFlags, pvoid lpThreadId) {
        // TODO: Replace with std::thread or platform-specific threading
        return 1; // Fake success for now
    }

    void XapiBootToDash(dword dwReason, dword dwParameter1, dword dwParameter2) {
        // Xbox-specific - boots back to dashboard
        // On PC, we just exit
    }
}

// Decompiled game functions
extern dword runtime_wrapper_thread(pvoid param);  // 0x147fb4
extern void thread_cleanup(dword threadHandle);    // 0x145585
extern dword jsrf_game_main();                     // 0x0006f9e0 - THE ACTUAL GAME!

// Global variables from XBE
dword DAT_0027dce0;  // Global at 0x0027dce0

// ============================================================================
// DECOMPILED FUNCTIONS FROM GHIDRA
// ============================================================================

// XBE Entry Point
// This is the first function that runs when the XBE loads
void entry(void) {
    ADDR(0x0); // TODO: Find actual entry address

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

// C/C++ Runtime Initialization Wrapper (0x147fb4)
// This function initializes the C runtime and calls the actual game
// Think of this as the Xbox equivalent of mainCRTStartup
dword runtime_wrapper_thread(pvoid param) {
    ADDR(0x147fb4);

    int iVar1;
    int iVar2;
    byte *puVar3;
    int unaff_FS_OFFSET;  // FS segment register offset (x86 TLS)

    // Initialize Xbox API
    XAPILIB::XapiInitProcess();

    // TLS (Thread Local Storage) setup - this is accessing thread-specific data
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

    // Initialize C runtime
    XAPILIB::_rtinit();

    // Initialize C++ global constructors
    XAPILIB::_cinit();

    // *** CALL THE ACTUAL GAME! ***
    jsrf_game_main();

    // When game exits, boot back to Xbox dashboard
    XAPILIB::XapiBootToDash(1, 1, 0);
    return 0;
}

// Thread cleanup/wait handler (0x145585)
void thread_cleanup(dword threadHandle) {
    ADDR(0x145585);

    // TODO: Fill in decompiled code from Ghidra
    // This likely calls WaitForSingleObject or similar to wait for thread completion
}

// ============================================================================
// THE ACTUAL GAME STARTS HERE
// ============================================================================

// JSRF Game Main Function (0x0006f9e0)
// This is where the actual game code begins!
dword jsrf_game_main() {
    ADDR(0x0006f9e0);

    // TODO: Decompile this next!
    // This is the real game entry point
    // Expected to contain:
    // - Game initialization
    // - Main game loop
    // - Cleanup on exit

    return 0;
}

// ============================================================================
// PC PORT ENTRY POINT
// ============================================================================

int main(int argc, char* argv[]) {
    // For the PC port, we skip the Xbox-specific threading
    // and call the game directly after minimal initialization

    // TODO: Replace Xbox API calls with PC equivalents
    // For now, just call the game main
    return jsrf_game_main();
}
