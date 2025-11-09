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
| 0x000123e0 | FUN_000123e0            | Major update function (called each frame) | Stub   |
| 0x00012ae0 | subsystem_constructor   | Subsystem constructor (0x44 bytes)   | TODO      |
| 0x00012c10 | game_state_init_subsystem | Initialize game subsystems         | Decompiled|
| 0x00013930 | FUN_00013930            | Major per-frame update function      | Stub      |
| 0x00013a80 | **game_frame_update**   | **Per-frame game update (MAIN LOOP BODY)** | **Decompiled** |
| 0x00013f80 | game_main_loop          | Infinite game loop                   | Decompiled|

## Input System

| Address    | Function Name           | Description                          | Status    |
|------------|-------------------------|--------------------------------------|-----------|
| 0x000659c0 | FUN_000659c0            | Unknown function (called in loop)    | Stub      |
| 0x00065c80 | FUN_00065c80            | Input callback (button events)       | Stub      |
| 0x000694a0 | FUN_000694a0            | Read from input device by index      | Stub      |
| 0x0017c3e8 | FUN_0017c3e8            | Read byte from input device          | Stub      |

## Subsystem Functions

| Address    | Function Name           | Description                          | Status    |
|------------|-------------------------|--------------------------------------|-----------|
| 0x0003e430 | FUN_0003e430            | Subsystem update function            | Stub      |
| 0x0003e440 | FUN_0003e440            | Subsystem update function            | Stub      |
| 0x0015fa10 | FUN_0015fa10            | Returns frame/time value             | Stub      |
| 0x0015fa20 | FUN_0015fa20            | Initialization function              | Stub      |
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

### Global Subsystems

| Address    | Name                    | Type            | Description           |
|------------|-------------------------|-----------------|-----------------------|
| 0x00251d70 | DAT_00251d70            | void*           | Audio or camera system (has vtable) |
| 0x00251d6c | DAT_00251d6c            | void*           | Major subsystem (rendering/scene?) |
| 0x00251d68 | DAT_00251d68            | void*           | Debug/UI text system |
| 0x00251f5c | DAT_00251f5c            | void*           | Input device interface |

### Global State Flags

| Address    | Name                    | Type            | Description           |
|------------|-------------------------|-----------------|-----------------------|
| 0x00251d88 | DAT_00251d88            | int             | State flag            |
| 0x00251d44 | DAT_00251d44            | int             | State flag            |
| 0x00251d54 | DAT_00251d54            | int             | State flag            |
| 0x00251d58 | DAT_00251d58            | int             | State flag            |
| 0x00251d40 | DAT_00251d40            | int             | Object counter (for debug display) |

### GameState Structure (0x8840 bytes = 34,880 bytes)

| Offset     | Type                    | Description                          |
|------------|-------------------------|--------------------------------------|
| 0x0000     | vtable*                 | Virtual function table pointer       |
| 0x0010     | int                     | Initialization flag (-1 = not init)  |
| 0x0018     | int                     | Debug mode flag                      |
| 0x0024     | int                     | Loop control flag (checked in main loop) |
| 0x0028     | dword                   | Input data (3 bytes combined)        |
| 0x002c     | dword                   | Input data (3 bytes combined)        |
| 0x0030     | dword                   | Input data (4 bytes combined)        |
| 0x0034     | dword                   | Input data (3 bytes combined)        |
| 0x0038     | dword                   | Input data backup                    |
| 0x003c     | int                     | Input mode flag                      |
| 0x0040     | dword                   | Button state flag 1                  |
| 0x0044     | dword                   | Button state flag 2                  |
| 0x0048     | dword                   | Button state flag 3                  |
| 0x004c     | dword                   | Button state flag 4                  |
| 0x0050     | int                     | Button pressed flag 1                |
| 0x0054     | int                     | Button pressed flag 2                |
| 0x0058     | int                     | Button pressed flag 3                |
| 0x005c     | int                     | Button pressed flag 4                |
| 0x0060     | int                     | Button pressed flag 5                |
| 0x0064     | int                     | Button pressed flag 6                |
| 0x0068     | int                     | Button pressed flag 7                |
| 0x006c     | int                     | Button pressed flag 8                |
| 0x0074     | dword                   | Render control flag                  |
| 0x007c     | dword                   | FPS counter (frames per second)      |
| 0x0080     | dword                   | TPS counter (ticks per second?)      |
| 0x0084     | dword                   | TPF counter (ticks per frame?)       |
| 0x0094     | int                     | Update mode (0=normal, 1=paused?)    |
| 0x0434     | void*                   | Subsystem pointer                    |
| 0x87b8     | dword                   | Execution time (microseconds) - low  |
| 0x87bc     | dword                   | Execution time (microseconds) - high |
| 0x87c0     | dword                   | Draw time (microseconds) - low       |
| 0x87c4     | dword                   | Draw time (microseconds) - high      |
| 0x87d0     | int                     | Frame sync value                     |
| 0x87dc     | void*                   | Subsystem pointer (0x44 bytes)       |
| 0x87e0     | int                     | Frame counter 1                      |
| 0x87e4     | int                     | Frame counter 2                      |

## Notes

- **Input System**: Uses byte-reading pattern - likely reading controller analog sticks and button states
- **Debug System**: Has built-in debug overlay showing FPS, object count, execution/draw times
- **Frame Timing**: Game runs at ~60 FPS (16ms sleep between frames)
- **Virtual Functions**: Heavy use of C++ polymorphism via vtables
- **Performance Metrics**: Tracks execution time and draw time in microseconds

- Add addresses as you discover them in Ghidra
- Mark status as: TODO, Stub, Partial, Complete, Decompiled
- Include notes about calling conventions, parameters, etc.
- Link to related functions
