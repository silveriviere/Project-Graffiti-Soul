# Project Structure

Based on the Halo decompilation project methodology.

## Directory Layout

```
graffiti-soul/
├── src/
│   ├── core/           # Core game systems (main loop, initialization)
│   ├── subsystems/     # Game subsystems (documented in kb.json)
│   ├── rendering/      # Graphics, camera, scene graph
│   ├── input/          # Controller input handling
│   └── utils/          # Helper functions, math, timing
├── include/
│   ├── types.h         # Xbox SDK types
│   ├── gamestate.h     # GameState structure definition
│   └── globals.h       # Global variables
├── docs/
│   ├── kb.json         # Knowledge base (function tracking)
│   ├── STRUCTURE.md    # This file
│   └── analysis/       # Decompiled function analysis
├── tools/
│   ├── patch.py                        # XBE patcher
│   └── ExtractDecompiledFunctions.py   # Ghidra extraction script
└── build/              # Build artifacts
```

## Verification Workflow

1. **Extract** - Use Ghidra script to extract decompiled functions
2. **Document** - Add to kb.json with status "stub"
3. **Analyze** - Study the decompiled code, understand purpose
4. **Implement** - Write C++ implementation
5. **Update Status** - Mark as "partial" in kb.json
6. **Build & Patch** - Compile and patch into XBE
7. **Test** - Verify in xemu emulator
8. **Complete** - Mark as "complete" in kb.json only after verification

## Status Levels

- `stub` - Not implemented, placeholder only
- `partial` - Implemented but not verified in xemu
- `complete` - Implemented AND verified to match original behavior

**Important**: Only mark as `complete` after testing in xemu!

## Function Organization

Place functions in the appropriate directory based on purpose:

### core/
- Entry point (`entry`)
- Main game loop (`runtime_wrapper_thread`, `jsrf_game_main`, `game_main_loop`)
- Frame update (`game_frame_update`)

### subsystems/
- Subsystem dispatcher (`subsystem_frame_update`)
- Individual subsystem updates (FUN_000161b0, FUN_0003e9a0, etc.)

### rendering/
- Graphics device management
- Scene graph traversal (FUN_00011450, FUN_00011220)
- Matrix operations (FUN_001ba8a0, FUN_001ba9c0, FUN_001baa50)
- Rendering pipeline (FUN_000131f0)

### input/
- Controller input reading
- Input state processing

### utils/
- Hardware register reads (FUN_000694a0)
- Float to int conversion (FUN_0017c3e8)
- Performance timing (QueryPerformanceCounter, FUN_0006e910)
- Math operations (__allmul, __alldiv)

## Analysis Organization

Store decompiled function extractions in `docs/analysis/` with descriptive names:

- `docs/analysis/main_execution_flow.md` - Entry point through main loop
- `docs/analysis/frame_update.md` - Frame update functions
- `docs/analysis/rendering_pipeline.md` - Rendering-related functions
- `docs/analysis/input_system.md` - Input handling
- `docs/analysis/subsystems.md` - Subsystem analysis

This helps track understanding without cluttering the repo.
