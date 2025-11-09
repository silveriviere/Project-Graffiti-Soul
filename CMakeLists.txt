cmake_minimum_required(VERSION 3.15)
project(GraffitiSoul VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(BUILD_FOR_XBOX "Build for Xbox hardware (i386, freestanding)" OFF)
option(ENABLE_PATCHING "Enable XBE patching target" OFF)

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find Python3 for tools
if(ENABLE_PATCHING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
endif()

# Source files
set(SOURCES
    src/main.cpp
)

# Include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
)

# Create executable
add_executable(graffiti-soul ${SOURCES})

# Xbox-specific compilation settings
if(BUILD_FOR_XBOX)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # Clang targeting i386 Win32 (Xbox-compatible)
        target_compile_options(graffiti-soul PRIVATE
            -target i386-pc-win32
            -march=pentium3
            -nostdlib
            -ffreestanding
        )
        target_link_options(graffiti-soul PRIVATE
            -target i386-pc-win32
            -nostdlib
        )
    elseif(MSVC)
        # MSVC 32-bit compilation
        target_compile_options(graffiti-soul PRIVATE
            /arch:IA32
            /GS-  # Disable stack protection
        )
    endif()
    message(STATUS "Building for Xbox (i386 freestanding)")
endif()

# Compiler warnings
if(MSVC)
    target_compile_options(graffiti-soul PRIVATE /W4)
else()
    target_compile_options(graffiti-soul PRIVATE -Wall -Wextra -Wpedantic)
endif()

# XBE Patching target
if(ENABLE_PATCHING)
    set(ORIGINAL_XBE "${CMAKE_SOURCE_DIR}/jsrf-original/default.xbe"
        CACHE FILEPATH "Path to original JSRF XBE file")
    set(PATCHED_XBE "${CMAKE_BINARY_DIR}/jsrf-patched/default.xbe")

    add_custom_target(patch-xbe
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/jsrf-patched"
        COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_SOURCE_DIR}/tools/patch.py"
            "${ORIGINAL_XBE}"
            "$<TARGET_FILE:graffiti-soul>"
            "${PATCHED_XBE}"
            --kb "${CMAKE_SOURCE_DIR}/kb.json"
        DEPENDS graffiti-soul
        COMMENT "Patching XBE with decompiled functions..."
        VERBATIM
    )

    message(STATUS "XBE patching enabled. Run 'make patch-xbe' to create patched XBE")
    message(STATUS "  Original XBE: ${ORIGINAL_XBE}")
    message(STATUS "  Patched XBE:  ${PATCHED_XBE}")
endif()

# Add subsystem libraries as you decompile them
# add_subdirectory(src/engine)
# add_subdirectory(src/graphics)
# add_subdirectory(src/physics)
# add_subdirectory(src/game)
