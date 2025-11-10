# Graffiti Soul

A decompilation project for **Jet Set Radio Future** (JSRF) for the original Xbox.

## Important Legal Notice

### Game Preservation and Educational Use Only

This project exists for game preservation, research, and educational purposes. This repository does not contain and will never distribute:

- Game ROMs, ISOs, or executables
- Original game assets (textures, models, sounds, music, etc.)
- Copyrighted game data of any kind
- Any material that would allow you to play the game without owning it

### You Must Own a Legal Copy of the Game

This project requires you to own a legitimate copy of Jet Set Radio Future.

To use this project, you must:
1. Purchase or own an original physical copy of Jet Set Radio Future for Xbox
2. Legally extract the executable from your own game disc
3. Use your own legally obtained game assets

We do not condone, support, or facilitate piracy in any form.

### Copyright and Trademark Notice

Jet Set Radio Future, all related characters, logos, and intellectual property are © SEGA Corporation. This project is not affiliated with, endorsed by, or connected to SEGA in any way. All trademarks and copyrights belong to their respective owners.

This is a fan-made preservation project created to:
- Document the technical implementation of a historic game
- Preserve gaming history for future generations
- Enable the game to run on modern hardware for those who legally own it
- Provide educational insights into Xbox game development

---

## About This Project

Graffiti Soul is a reverse engineering and decompilation effort for Jet Set Radio Future, one of the original Xbox's most beloved titles. The goal is to create a matching decompilation that accurately reconstructs the original code.

Checkout the Discord server here: https://discord.gg/8784r9FG

## Building

### Prerequisites

**For development builds:**
- CMake 3.15 or higher
- C++17 compatible compiler (GCC, Clang, or MSVC)
- Git

**For Xbox testing builds:**
- Clang/LLVM toolchain
- Python 3.8+ with dependencies (`pip install -r requirements.txt`)
- Original JSRF XBE file (from your legally owned copy)
- xemu or equivalent emulator (https://xemu.app/)

### Build Instructions

**Standard development build** (compiles on your platform for verification):

```bash
# Clone the repository
git clone https://github.com/yourusername/graffiti-soul.git
cd graffiti-soul

# Create build directory
mkdir build && cd build

# Configure and build
cmake ..
cmake --build .

# The executable will be in build/bin/graffiti-soul
```

**Xbox testing build** (creates patchable XBE for testing in xemu):

```bash
# Install Python dependencies
pip install -r requirements.txt

# Create Xbox build directory
mkdir build-xbox && cd build-xbox

# Configure for Xbox with patching enabled
cmake .. \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DBUILD_FOR_XBOX=ON \
  -DENABLE_PATCHING=ON \
  -DORIGINAL_XBE=../jsrf-original/default.xbe

# Build and patch
cmake --build .
cmake --build . --target patch-xbe

# Patched XBE is created at build-xbox/jsrf-patched/default.xbe
```

**For complete testing instructions**, see [TESTING.md](TESTING.md).

## Project Structure

```
graffiti-soul/
├── src/
│   └── main.cpp              # Entry point, main game loop, subsystems
├── include/
│   └── types.h               # Type definitions matching Xbox SDK
├── docs/
│   ├── function_template.cpp # Template for decompiled functions
│   └── kb.json               # Knowledge base - tracks all functions and addresses
├── tools/
│   └── patch.py              # XBE patching tool for testing
├── MEMORY_MAP.md             # XBE memory map with function addresses
├── requirements.txt          # Python dependencies
├── CMakeLists.txt            # Build configuration
├── TESTING.md                # Testing guide with xemu
└── README.md                 # This file
```

## Contributing

Contributions are welcome! If you're interested in helping with this preservation effort:

1. You must own a legitimate copy of JSRF
2. Use tools like Ghidra or IDA Pro to analyze your legally obtained executable
3. Document your findings and create matching C++ implementations
4. Submit pull requests with clear documentation of what you've decompiled

### Decompilation Guidelines

- All function addresses should be documented using the `ADDR()` macro
- Match the original assembly as closely as possible
- Use descriptive names when the original symbols are unknown
- Document any assumptions or uncertainties
- Do not include any copyrighted assets or data
- Add function entries to `docs/kb.json` with status (`stub`, `partial`, or `complete`)
- Test your decompiled functions using the XBE patching workflow (see [TESTING.md](TESTING.md))
- Verify that patched functions work correctly in xemu before marking as `complete`


## Disclaimer

This software is provided "as is" without warranty of any kind. The developers and contributors assume no liability for any misuse of this code. This project is for educational and preservation purposes only.

If you love Jet Set Radio Future, please support SEGA by purchasing their games. The original developers created something special, and they deserve to be compensated for their work.

## Resources

- [Jet Set Radio Future on Wikipedia](https://en.wikipedia.org/wiki/Jet_Set_Radio_Future)
- [Original Xbox Technical Documentation](https://xboxdevwiki.net/)

