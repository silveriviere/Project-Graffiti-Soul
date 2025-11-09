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

### Why Decompile?

- **Preservation**: Original Xbox hardware is aging and failing. Preserving these games in a documented, understandable form helps ensure they aren't lost to time.
- **Education**: Understanding how commercial games were actually built provides valuable insights into game development techniques from that era.
- **Modding**: A complete decompilation allows the community to fix bugs, add features, and create mods (assuming you own the game legally).
- **Portability**: Eventually, this could enable the game to run on modern hardware for people who own legitimate copies.

### Project Status

This project is in early development and very much a work in progress.

Currently implemented:
- Basic XBE entry point structure
- Thread initialization framework
- Game state initialization stubs
- Main game loop skeleton

Much work remains to fully decompile all game systems.

## Building

### Prerequisites

- CMake 3.15 or higher
- C++17 compatible compiler (GCC, Clang, or MSVC)
- Git

### Build Instructions

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

Or use the build script:

```bash
./build.sh
```

## Project Structure

```
graffiti-soul/
├── src/
│   └── main.cpp           # Entry point and main game loop
├── include/
│   └── types.h            # Type definitions matching Xbox SDK
├── docs/
│   └── function_template.cpp  # Template for decompiled functions
├── CMakeLists.txt         # Build configuration
└── README.md              # This file
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

## Legal FAQ

**Q: Is this legal?**

A: Reverse engineering for interoperability, preservation, and educational purposes is generally protected under fair use in many jurisdictions. That said, you must own a legal copy of the game to use this project ethically and legally.

**Q: Can I play the game with just this code?**

A: No. This decompilation is just code - it doesn't include any of the actual game content like graphics, sounds, music, or levels. You would need the original game assets from your legally owned copy.

**Q: Will you ever distribute game files?**

A: No. We will never distribute copyrighted game files, assets, or executable code from the original game. This repository only contains our reverse-engineered recreation of the code structure.

**Q: Is this an emulator?**

A: No. This is a native reimplementation of the game code. It's more like a port that would still require access to the original game's data files.

## Disclaimer

This software is provided "as is" without warranty of any kind. The developers and contributors assume no liability for any misuse of this code. This project is for educational and preservation purposes only.

If you love Jet Set Radio Future, please support SEGA by purchasing their games. The original developers created something special, and they deserve to be compensated for their work.

## Resources

- [Jet Set Radio Future on Wikipedia](https://en.wikipedia.org/wiki/Jet_Set_Radio_Future)
- [Original Xbox Technical Documentation](https://xboxdevwiki.net/)

## License

This decompilation project is released for educational and preservation purposes. The original game code and assets remain the property of SEGA Corporation. See LICENSE for details on the decompilation code itself.

---

Remember: This project is only legal and ethical if you own a legitimate copy of the game. Please support game preservation by purchasing games legally.
