# Testing Guide for Graffiti Soul

This guide explains how to test your decompiled functions by patching them into the original JSRF XBE and running in xemu (Xbox emulator).

## Overview

**Progressive Decompilation** is a technique where you gradually replace functions in the original game binary with your decompiled versions and test them to verify correctness. This approach:

- Allows incremental testing of individual functions
- Verifies that decompiled code matches original behavior
- Catches errors early in the decompilation process
- Enables you to see your code running in the actual game

## Prerequisites

### Required Files

You **MUST** legally own a copy of Jet Set Radio Future. You will need:

1. **Original JSRF XBE** (`default.xbe`) - Extracted from your legally owned game disc
2. **Game assets** - All data files from your retail JSRF disc

**We do not condone piracy.** Do not proceed unless you own the game.

### Required Software

1. **xemu** - Original Xbox emulator
   - Download: https://xemu.app/
   - Documentation: https://xemu.app/docs/

2. **Python 3.8+** with dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. **Build tools** (one of):
   - **Clang/LLVM** (recommended for Xbox builds)
   - **Visual Studio** (Windows only)
   - **GCC** (for host builds only, not Xbox-compatible)

4. **extract-xiso** (optional, for creating ISOs):
   ```bash
   # Linux/macOS
   git clone https://github.com/XboxDev/extract-xiso.git
   cd extract-xiso
   mkdir build && cd build
   cmake .. && make
   sudo make install
   ```

## Setup

### 1. Extract Your Game Files

Extract files from your legally owned JSRF disc:

```bash
# Create directory for original files
mkdir -p jsrf-original

# Extract ISO (if you have ISO file)
extract-xiso -d jsrf-original/ your-jsrf.iso

# Or manually copy files from disc
cp /path/to/disc/* jsrf-original/
```

Your `jsrf-original/` directory should contain:
- `default.xbe` - The game executable
- Game data files (textures, models, sounds, etc.)

### 2. Configure Build for Xbox

The default build creates a native executable for testing compilation. For Xbox testing, enable Xbox mode:

```bash
# Create build directory for Xbox
mkdir build-xbox && cd build-xbox

# Configure for Xbox with Clang
cmake .. \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DBUILD_FOR_XBOX=ON \
  -DENABLE_PATCHING=ON \
  -DORIGINAL_XBE=../jsrf-original/default.xbe

# Build
cmake --build .
```

### 3. Knowledge Base (kb.json)

The `kb.json` file tracks all discovered functions and their addresses. When you decompile a new function:

1. Add its entry to `kb.json`
2. Mark its status (`stub`, `partial`, or `complete`)
3. The build system uses this to know which functions to patch

Example entry:
```json
{
  "decl": "void subsystem_frame_update(GameState* gameState)",
  "addr": "0x123e0",
  "status": "complete",
  "notes": "Main subsystem dispatcher"
}
```

## Testing Workflow

### Standard Testing Process

```bash
# 1. Build the project
cd build-xbox
cmake --build .

# 2. Patch the XBE
cmake --build . --target patch-xbe

# 3. The patched XBE is created at:
#    build-xbox/jsrf-patched/default.xbe

# 4. Copy game data to patched directory
cp -r ../jsrf-original/* jsrf-patched/
# (This copies all game assets but overwrites default.xbe with our patched version)

# 5. Run in xemu
xemu -dvd_path jsrf-patched/
```

### What Happens During Patching

The `tools/patch.py` script:

1. **Loads original XBE** - Reads the retail game executable
2. **Loads your compiled code** - Reads functions you've decompiled
3. **Embeds new code** - Adds your compiled functions to the XBE
4. **Creates redirects** - Patches original function addresses to jump to your code
5. **Writes patched XBE** - Outputs the modified executable

### Function Status Levels

Functions in `kb.json` can have these statuses:

- **`stub`** - Function exists but has no implementation (just returns/empty)
  - Not worth patching, will crash if called

- **`partial`** - Function partially implemented, may have some TODOs
  - Can be patched for basic testing
  - May not handle all edge cases

- **`complete`** - Function fully decompiled and verified
  - Safe to patch and test
  - Should match original behavior

**Only `partial` and `complete` functions are patched by default.**

## Debugging with xemu

### Enable Debug Logging

```bash
# Run xemu with debug output
xemu -dvd_path jsrf-patched/ -full_boot -s -S
```

Flags:
- `-s` - Enable GDB server on port 1234
- `-S` - Pause at startup (wait for debugger)
- `-full_boot` - Boot through Xbox BIOS (more accurate)

### Using GDB

```bash
# In another terminal
gdb build-xbox/bin/graffiti-soul

# Connect to xemu
(gdb) target remote localhost:1234

# Set breakpoints
(gdb) break subsystem_frame_update

# Continue execution
(gdb) continue
```

### xemu Debugging Features

- **Monitor** - Press `` ` `` (backtick) to open debug monitor
- **Disassembly** - View assembly of your patched functions
- **Memory inspector** - Examine game memory in real-time
- **Performance profiling** - Measure function execution times

## Verification Strategies

### 1. Binary Comparison

Compare your compiled function against the original:

```bash
# Disassemble original function
objdump -D jsrf-original/default.xbe | grep -A 50 "123e0:"

# Disassemble your implementation
objdump -D build-xbox/bin/graffiti-soul | grep -A 50 "subsystem_frame_update"

# Compare side-by-side
diff original.asm yours.asm
```

### 2. Behavioral Testing

- Does the game boot?
- Does it reach the main menu?
- Can you start a level?
- Are there graphical glitches?
- Does it crash?

### 3. Incremental Approach

**Start small:**
1. Decompile a single, simple function
2. Mark it as `complete` in kb.json
3. Patch and test
4. If it works, move to next function
5. If it breaks, you know exactly which function is wrong

### 4. Logging

Add logging to your functions (remove before finalizing):

```cpp
void subsystem_frame_update(GameState* gameState) {
    // Debug output (Xbox has debug serial port)
    debug_printf("subsystem_frame_update called\n");

    // ... rest of function
}
```

## Common Issues

### Patching Fails

**Problem**: `patch.py` fails with error

**Solutions**:
- Verify original XBE path is correct
- Check that compiled exe exists
- Ensure kb.json is valid JSON
- Install Python dependencies: `pip install -r requirements.txt`

### Game Crashes Immediately

**Problem**: XBE crashes on startup in xemu

**Possible causes**:
- Function signature mismatch (wrong parameters/return type)
- Incorrect function address in kb.json
- Stack corruption
- Calling convention mismatch (stdcall vs cdecl)

**Debug**:
1. Check xemu console output for crash address
2. Compare against kb.json to identify which function
3. Review that function's decompilation

### Game Freezes

**Problem**: Game loads but freezes/hangs

**Possible causes**:
- Infinite loop in your code
- Missing function call
- Incorrect state machine logic

**Debug**:
1. Use GDB to pause and check call stack
2. Add debug output to trace execution
3. Compare your control flow against Ghidra decompilation

### Visual Glitches

**Problem**: Game runs but has graphical corruption

**Possible causes**:
- Graphics subsystem function incorrectly decompiled
- Incorrect data structure offsets
- Floating-point precision issues

**Debug**:
1. Disable patching of graphics functions
2. Binary search: disable half, test, narrow down
3. Review GameState structure offsets

## Creating an ISO for Testing

Once your patched XBE works, you can create an ISO:

```bash
# Create ISO from patched directory
extract-xiso -c jsrf-patched/ -o jsrf-patched.iso

# Boot ISO in xemu
xemu -dvd_path jsrf-patched.iso
```

## Advanced: Testing on Real Hardware

⚠️ **DANGER: Can brick your Xbox if done incorrectly**

If you have a modded Xbox:

1. FTP the `jsrf-patched` directory to your Xbox
2. Boot using a dashboard (UnleashX, XBMC, etc.)
3. Launch `default.xbe`

**Only do this if you know what you're doing and accept the risk.**

## CI/CD Testing

The project can be configured for automated testing:

```yaml
# .github/workflows/test.yml
name: Test Build

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install dependencies
        run: |
          sudo apt-get install -y clang lld
          pip install -r requirements.txt

      - name: Build for Xbox
        run: |
          mkdir build && cd build
          cmake .. -DBUILD_FOR_XBOX=ON
          cmake --build .

      - name: Verify compilation
        run: |
          ls -lh build/bin/graffiti-soul
          file build/bin/graffiti-soul
```

Note: Actual XBE patching and xemu testing in CI requires the original XBE, which cannot be distributed.

## Resources

- **xemu Documentation**: https://xemu.app/docs/
- **Xbox Development Wiki**: https://xboxdevwiki.net/
- **Original Xbox Toolchain**: https://github.com/XboxDev/
- **dplewis/jsrf** (reference implementation): https://github.com/dplewis/jsrf

## Next Steps

Once you have the testing workflow set up:

1. Start with simple functions (getters, setters, utility functions)
2. Gradually work up to complex functions
3. Test frequently - after every function or two
4. Document any quirks or discoveries in kb.json notes
5. Share your findings with the community

Remember: The goal is a **matching decompilation** - your code should produce identical assembly to the original when compiled with the same compiler settings.

Happy decompiling! 🎮
