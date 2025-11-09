# Quick Start Guide

Get started with Graffiti Soul decompilation.

## What You Have

✅ **Ghidra extraction script** - `tools/ExtractDecompiledFunctions.py`
✅ **XBE patcher** - `tools/patch.py`
✅ **Knowledge base** - `docs/kb.json`
✅ **Project structure** - See `docs/STRUCTURE.md`
✅ **Xbox SDK reference** - `docs/XBOX_SDK_REFERENCE.md`
✅ **Extraction guide** - `docs/EXTRACTION_GUIDE.md`

## Your First Analysis Session

### 1. Extract Functions from Ghidra

```
1. Open default.xbe in Ghidra
2. Run ExtractDecompiledFunctions.py
3. Choose "Call Graph (Execution Order)"
4. Start address: 0x6f9e0 (or leave empty for entry point)
5. Max depth: 5
6. Max functions: 50
7. Save to: docs/analysis/session_01.md
```

### 2. Analyze the Output

Open `docs/analysis/session_01.md` and look for:

- Simple utility functions (getters, setters)
- Math helpers (__allmul, __alldiv)
- Xbox SDK functions (QueryPerformanceCounter, malloc, etc.)
- Game-specific logic

### 3. Document in kb.json

For each new function found, add:

```json
{
  "decl": "ReturnType function_name(params)",
  "addr": "0xABCDEF",
  "status": "stub",
  "notes": "Brief description"
}
```

### 4. Understand the Architecture

Read your analysis and identify:

- **GameState structure** - What offsets are used? What do they mean?
- **Global pointers** - What systems are referenced? (graphics, input, etc.)
- **Call patterns** - Which functions call which?
- **Execution flow** - What happens each frame?

## Next Steps

### Study Phase (Current)

1. Extract more functions (different starting points)
2. Build understanding of game architecture
3. Document structures in `include/gamestate.h`
4. Identify all global pointers
5. Map out subsystem relationships

### Implementation Phase (Later)

1. Start with simple utilities
2. Implement incrementally
3. Test constantly in xemu
4. Only mark "complete" when verified

## Important Rules

❌ **DO NOT** implement functions without testing
❌ **DO NOT** mark as "complete" without xemu verification
❌ **DO NOT** commit without updating kb.json
✅ **DO** extract and analyze first
✅ **DO** document everything
✅ **DO** test frequently

## Resources

- **Discord**: https://discord.gg/cy6jxUu72N
- **Halo Decompilation** (same approach): https://github.com/halo-re/halo
- **Xbox SDK Headers**: https://github.com/XboxDev/nxdk
- **XbSymbolDatabase**: https://github.com/Cxbx-Reloaded/XbSymbolDatabase

## Current Understanding

Based on your first extraction (20 functions):

### Execution Flow
```
FUN_0006f9e0 (jsrf_game_main)
    └─> FUN_00013f80 (game_main_loop)
            └─> FUN_00013a80 (game_frame_update)
                    ├─> Input processing
                    ├─> Hardware reading
                    ├─> Subsystem update (FUN_000123e0)
                    ├─> Rendering (FUN_000131f0)
                    └─> Performance tracking
```

### Key Discoveries

- **GameState size**: 0x8840 bytes (34,880 bytes)
- **Global pointer**: DAT_0022fce0 (g_GameState)
- **Graphics devices**: DAT_00251d70, DAT_00251d6c
- **Input device**: DAT_00251f5c
- **Matrix stack**: DAT_00264c04

### Functions Already Complete (per kb.json)

1. `FUN_000694a0` - Hardware register read (bounds-checked)
2. `FUN_0017c3e8` - Float to int conversion
3. `subsystem_frame_update` - Main subsystem dispatcher

These are marked complete - verify they actually work!

## What to Do Now

**Recommended order:**

1. **Extract more** - Get 100+ functions to understand the full picture
2. **Study patterns** - Look for common code structures
3. **Map globals** - Document all global variables and their purposes
4. **Define structures** - Create header files with struct definitions
5. **Start simple** - Implement only trivial functions first
6. **Test early** - Build and patch as soon as you have something

Good luck! 🎮
