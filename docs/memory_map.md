# Project: Graffiti Soul - XBE Memory Map

Track original addresses from Ghidra analysis to maintain correspondence with the original binary.

## Entry Points

| Address    | Function Name           | Description                          | Status    |
|------------|-------------------------|--------------------------------------|-----------|
| (TBD)      | entry                   | XBE entry point (launches thread)    | Decompiled|
| 0x147fb4   | runtime_wrapper_thread  | C/C++ runtime init wrapper           | Decompiled|
| 0x145585   | thread_cleanup          | Thread cleanup/wait handler          | Stub      |
| **0x0006f9e0** | **jsrf_game_main**  | **ACTUAL GAME ENTRY POINT**          | **TODO**  |

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

## Notes

- Add addresses as you discover them in Ghidra
- Mark status as: TODO, Stub, Partial, Complete
- Include notes about calling conventions, parameters, etc.
- Link to related functions
