# Function Extraction & Analysis Guide

How to systematically extract and analyze decompiled functions.

## Step 1: Extract Functions in Execution Order

### Using the Ghidra Script

1. **Open your XBE in Ghidra**
2. **Add the script directory**:
   - Window → Script Manager
   - Click "Manage Script Directories" (folder icon)
   - Add: `<project-root>/tools/`

3. **Run ExtractDecompiledFunctions.py**
4. **Select "Call Graph (Execution Order)"**
5. **Choose starting point**:
   - For main execution flow: `0x6f9e0` (jsrf_game_main)
   - For subsystems: `0x123e0` (subsystem_frame_update)
   - Or leave empty to start from entry point

6. **Set extraction parameters**:
   - **Max depth**:
     - 3-4 for focused analysis
     - 5-6 for broader view
     - 7+ for comprehensive extraction
   - **Max functions**:
     - 20-30 for quick analysis
     - 50-100 for thorough understanding
     - 200+ for complete subsystem analysis

7. **Save output** to `docs/analysis/<descriptive-name>.md`

### Recommended Extraction Sessions

Create separate extractions for different areas:

```bash
# Session 1: Core execution flow
Start: 0x6f9e0 (jsrf_game_main)
Depth: 5
Max: 50
Output: docs/analysis/01_main_execution_flow.md

# Session 2: Subsystem dispatcher
Start: 0x123e0 (subsystem_frame_update)
Depth: 4
Max: 30
Output: docs/analysis/02_subsystem_dispatcher.md

# Session 3: Rendering pipeline
Start: 0x131f0 (rendering function)
Depth: 6
Max: 100
Output: docs/analysis/03_rendering_pipeline.md

# Session 4: Input system
Start: 0x65c80 or similar input function
Depth: 4
Max: 40
Output: docs/analysis/04_input_system.md

# Session 5: Scene graph traversal
Start: 0x11450 or 0x11220
Depth: 5
Max: 60
Output: docs/analysis/05_scene_graph.md
```

## Step 2: Analyze Extracted Functions

For each extracted markdown file:

### A. Identify Function Types

Look for patterns to categorize functions:

#### **1. Utility Functions** (Simple, self-contained)
```c
// Example: Simple getter
return DAT_00265174;

// Example: Simple setter
*(object + 0x44) = value;

// Example: Bounds check
if (index < 0x5e) return array[index];
return 0.0;
```
→ **Action**: Implement immediately, mark as "partial"

#### **2. Math/Helper Functions** (Library functions)
```c
// 64-bit multiply
longlong __allmul(uint param_1, int param_2, uint param_3, int param_4)

// Float to int
ulonglong FUN_0017c3e8(void)  // Custom rounding
```
→ **Action**: Match to MSVC runtime, document signature

#### **3. Xbox SDK Functions** (Known APIs)
```c
// QueryPerformanceCounter
rdtsc()  // Uses specific CPU instruction

// malloc
_malloc(0x8840)  // Standard library
```
→ **Action**: Cross-reference with XBOX_SDK_REFERENCE.md

#### **4. Game Logic Functions** (Complex, game-specific)
```c
// Large functions with multiple conditionals
// State machines
// Object management
```
→ **Action**: Document thoroughly, implement later

### B. Document in kb.json

For each function, add or update entry:

```json
{
  "decl": "ReturnType function_name(ParamType param)",
  "addr": "0xABCDEF",
  "status": "stub",  // or "partial" or "complete"
  "notes": "Brief description of what it does"
}
```

**Status guidelines**:
- `stub` - Not implemented yet, just signature
- `partial` - Implemented but not tested in xemu
- `complete` - Implemented AND verified in xemu

### C. Look for Common Patterns

#### **Pattern 1: Virtual Function Calls**
```c
(**(code **)(*object + 0xc))(param);
          ^        ^      ^
          |        |      └─ vtable offset
          |        └──────── vtable pointer
          └───────────────── dereference to get function
```
→ Indicates object-oriented design, COM interfaces

#### **Pattern 2: Linked List/Tree Traversal**
```c
while (node != NULL) {
    // Process node
    node = node->next;  // or node->sibling
}
```
→ Scene graph, object list, etc.

#### **Pattern 3: State Machine**
```c
if (state == 0) {
    // State 0 logic
} else if (state == 1) {
    // State 1 logic
}
```
→ Game state management

#### **Pattern 4: Input Debouncing**
```c
if (button_pressed_flag != 0) {
    clear_flag();
    set_processed_state();
}
```
→ Input handling

#### **Pattern 5: Matrix Stack Operations**
```c
// Push: Copy matrix forward
*stack_ptr = *(stack_ptr + 0x40);
stack_ptr += 0x40;

// Pop: Move pointer back
stack_ptr -= 0x40;

// Load identity
matrix[0][0] = 1.0; matrix[0][1] = 0.0; ...
```
→ 3D graphics transform stack

### D. Cross-Reference Analysis

Look at **"Calls"** and **"Called By"** sections:

1. **If many functions call this**: Likely a utility or common operation
2. **If this calls many functions**: Likely a dispatcher or manager
3. **If recursive**: Tree/graph traversal or divide-and-conquer algorithm
4. **If called once**: Likely specific initialization or special case

### E. Data Type Inference

From offset usage, infer structure layouts:

```c
// If you see:
*(int *)((int)gameState + 0x10) < 0     // Exit flag (int)
*(int *)((int)gameState + 0x18) != 0    // Debug flag (int)
*(int *)((int)gameState + 0x7c)         // FPS counter (int)

// Document in include/gamestate.h:
struct GameState {
    // ...
    int exit_flag;      // 0x10
    int debug_enabled;  // 0x18
    // ...
    int fps;            // 0x7c
};
```

## Step 3: Priority Order for Implementation

### Phase 1: Foundational Utilities (Implement First)
- Math helpers (__allmul, __alldiv)
- Simple getters/setters
- Bounds-checked array access
- Memory utilities (if not using SDK directly)

### Phase 2: Xbox SDK Wrappers (Match to SDK)
- QueryPerformanceCounter
- Thread functions
- Memory allocation
- Synchronization primitives

### Phase 3: Game Utilities (Implement & Test)
- Performance timing calculations
- Matrix stack operations
- Input debouncing
- Debug overlay

### Phase 4: Core Systems (Complex, Test Thoroughly)
- Main game loop
- Frame update
- Subsystem dispatcher
- Scene graph traversal

### Phase 5: Rendering (Most Complex)
- Object rendering
- State management
- Shader management
- Scene rendering

## Step 4: Verification Workflow

For EVERY function marked as "partial" or "complete":

1. **Implement** in appropriate source file
2. **Add to build system** (CMakeLists.txt)
3. **Build** for Xbox target
4. **Patch** using tools/patch.py
5. **Test** in xemu emulator
6. **Verify** behavior matches original
7. **Update kb.json** status only if verified

### Testing Checklist

- [ ] Game boots without crashing
- [ ] Function executes without errors
- [ ] Output matches expected behavior
- [ ] No regressions in other systems
- [ ] Frame rate is maintained
- [ ] Memory usage is similar

Only mark as "complete" when ALL boxes are checked!

## Step 5: Documentation

For each implemented function, document:

1. **What it does** (high-level purpose)
2. **How it works** (algorithm/approach)
3. **Where it's called** (call graph context)
4. **Related functions** (what it calls/callers)
5. **Verification notes** (how you tested it)

Keep notes in:
- Code comments (inline documentation)
- kb.json (status and brief notes)
- CHANGELOG.md (track progress)

## Tips

### Finding Related Functions

Use Ghidra's cross-reference features:
- Right-click function → References → Find references to <function>
- Right-click data → References → Find references to <address>

### Understanding Complex Functions

1. Start with the **call depth = 3+** functions (the leaf nodes)
2. Work your way **backwards** up the call graph
3. Once you understand helpers, the higher-level functions make more sense

### When Stuck

1. Extract more context (increase depth/max functions)
2. Look at assembly in Ghidra (sometimes clearer than decompiled C)
3. Compare with similar games (Halo, other Xbox games)
4. Ask for help on Discord: https://discord.gg/cy6jxUu72N

## Example Workflow

```bash
# 1. Extract functions
# (Run Ghidra script: Call Graph mode, start 0x6f9e0, depth 5, max 50)

# 2. Analyze output
# Read docs/analysis/01_main_execution_flow.md
# Identify 10 simple functions to implement

# 3. Document in kb.json
# Add/update entries for those 10 functions

# 4. Create header
# Define structures in include/gamestate.h

# 5. Implement
# Write C++ in src/core/timing.cpp (example)

# 6. Build (when ready)
# mkdir build-xbox && cd build-xbox
# cmake .. -DBUILD_FOR_XBOX=ON ...

# 7. Test (when ready)
# python tools/patch.py original.xbe build/graffiti-soul.exe patched.xbe
# xemu -dvd_path patched.xbe

# 8. Verify & Update
# If works correctly → mark "complete" in kb.json
# If not → debug, fix, repeat
```

## Summary

**Key Principles:**
1. **Extract systematically** (by execution order, not random)
2. **Analyze before implementing** (understand first)
3. **Document everything** (kb.json, headers, comments)
4. **Implement incrementally** (small pieces at a time)
5. **Verify constantly** (test in xemu frequently)
6. **Only mark complete when tested** (partial until verified)

Good luck!
