# Project: Graffiti Soul - XBE Memory Map

Track original addresses from Ghidra analysis to maintain correspondence with the original binary.

## Entry Points

| Address    | Function Name           | Description                          | Status    |
|------------|-------------------------|--------------------------------------|-----------|
| (TBD)      | entry                   | XBE entry point (launches thread)    | Decompiled|
| 0x147fb4   | runtime_wrapper_thread  | C/C++ runtime init wrapper           | Decompiled|
| 0x145585   | thread_cleanup          | Thread cleanup/wait handler          | Stub      |
| **0x0006f9e0** | **jsrf_game_main**  | **ACTUAL GAME ENTRY POINT**          | **Decompiled** |

## Core Game Functions

| Address    | Function Name           | Description                          | Status    |
|------------|-------------------------|--------------------------------------|-----------|
| 0x00012210 | game_state_constructor  | GameState constructor (0x8840 bytes) | Stub      |
| 0x00012c10 | game_state_init_subsystem | Initialize game subsystems         | Decompiled|
| 0x00012ae0 | subsystem_constructor   | Subsystem constructor (0x44 bytes)   | TODO      |
| 0x00013f80 | game_main_loop          | Main game loop (infinite)            | Decompiled|
| 0x00013a80 | game_frame_update       | Per-frame game update                | TODO      |
| 0x000659c0 | unknown_func_659c0      | Unknown function in loop             | TODO      |
| 0x00145ca6 | sleep_milliseconds      | Sleep function (~16ms for 60fps)     | Stub      |

## Initialization Functions

| Address    | Function Name           | Description                          | Status |
|------------|-------------------------|--------------------------------------|--------|
| (TBD)      | d3d_init                | Direct3D device initialization       | TODO   |
| (TBD)      | filesystem_init         | File system setup                    | TODO   |
| (TBD)      | audio_init              | Audio system initialization          | TODO   |

## Core Game Systems

| Address    | Function Name           | Description                          | Status |
|------------|-------------------------|--------------------------------------|--------|
| (TBD)      | player_update           | Player state update                  | TODO   |
| (TBD)      | trick_system            | Trick handling                       | TODO   |
| (TBD)      | graffiti_system         | Graffiti mechanics                   | TODO   |

## Graphics/Rendering

| Address    | Function Name           | Description                          | Status |
|------------|-------------------------|--------------------------------------|--------|
| (TBD)      | render_frame            | Main render loop                     | TODO   |
| (TBD)      | camera_update           | Camera system                        | TODO   |

## Data Structures

### Important Global Variables

| Address    | Name                    | Type            | Description           |
|------------|-------------------------|-----------------|-----------------------|
| 0x0027dce0 | (unknown)               | dword           | Set to 0x14 at entry  |
| 0x0022fce0 | g_GameState             | GameState*      | Main game state (0x8840 bytes) |

### GameState Structure (0x8840 bytes)

| Offset     | Type                    | Description                          |
|------------|-------------------------|--------------------------------------|
| 0x0000     | vtable*                 | Virtual function table pointer       |
| 0x0010     | int                     | Initialization flag (-1 = not init)  |
| 0x0024     | int                     | Loop control flag (checked in main loop) |
| 0x87dc     | void*                   | Subsystem pointer (0x44 bytes)       |

## Notes

- Add addresses as you discover them in Ghidra
- Mark status as: TODO, Stub, Partial, Complete
- Include notes about calling conventions, parameters, etc.
- Link to related functions
