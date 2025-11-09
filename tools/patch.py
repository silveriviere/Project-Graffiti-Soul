#!/usr/bin/env python3
"""
XBE Patcher for Graffiti Soul (JSRF Decompilation)

This script patches a retail JSRF XBE file with our decompiled functions.
Based on the approach from https://github.com/dplewis/jsrf

Usage:
    python patch.py <original_xbe> <compiled_exe> <output_xbe>

Process:
    1. Load the original JSRF XBE file
    2. Load our compiled PE executable with decompiled functions
    3. Embed the PE into the XBE as new sections
    4. Patch function calls to redirect to our implementations
    5. Write the patched XBE

Requirements:
    - Original JSRF default.xbe file (from retail disc)
    - Compiled executable from our CMake build
    - Python packages: pefile, construct
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import pefile
except ImportError:
    print("Error: pefile module not found. Install with: pip install pefile")
    sys.exit(1)


class XBEPatcher:
    """Patches an XBE file with re-implemented functions from a PE executable."""

    def __init__(self, xbe_path: str, exe_path: str, kb_path: str):
        self.xbe_path = Path(xbe_path)
        self.exe_path = Path(exe_path)
        self.kb_path = Path(kb_path)

        # Load files
        self.xbe_data = self.xbe_path.read_bytes()
        self.exe_data = self.exe_path.read_bytes()

        # Load knowledge base
        with open(self.kb_path) as f:
            self.kb = json.load(f)

        # Parse PE
        self.pe = pefile.PE(data=self.exe_data)

        # XBE base address (from kb.json)
        self.xbe_base = int(self.kb.get('xbe_base', '0x10000'), 16)

    def get_implemented_functions(self) -> List[Dict]:
        """Get list of functions that have been implemented (not stubs)."""
        implemented = []
        for obj in self.kb.get('objects', []):
            for func in obj.get('functions', []):
                status = func.get('status', 'stub')
                if status in ['complete', 'partial']:
                    implemented.append({
                        'name': func.get('decl', '').split('(')[0].split()[-1],
                        'addr': int(func['addr'], 16),
                        'decl': func.get('decl', ''),
                        'status': status
                    })
        return implemented

    def create_redirect_stub(self, target_addr: int) -> bytes:
        """
        Create x86 redirect code: push addr; ret
        This jumps to the target address.

        push imm32    = 0x68 [4 bytes]
        ret           = 0xC3
        """
        return struct.pack('<BI', 0x68, target_addr) + b'\xC3'

    def patch_function_redirects(self, xbe_data: bytearray) -> int:
        """
        Patch functions in the XBE to redirect to our implementations.
        Returns the number of functions patched.
        """
        implemented = self.get_implemented_functions()
        patched_count = 0

        print(f"\nPatching {len(implemented)} implemented functions:")

        for func in implemented:
            # Calculate absolute address in XBE
            xbe_offset = func['addr']

            # For now, we'll just log what would be patched
            # Full implementation would calculate the PE function address
            # and create the redirect stub
            print(f"  [{func['status']}] {func['decl'][:60]}... @ 0x{func['addr']:08x}")

            # TODO: Implement actual patching
            # redirect_code = self.create_redirect_stub(new_function_addr)
            # xbe_data[xbe_offset:xbe_offset+len(redirect_code)] = redirect_code
            # patched_count += 1

        return patched_count

    def embed_pe_sections(self, xbe_data: bytearray) -> Tuple[bytearray, int]:
        """
        Embed PE sections into the XBE.
        Returns updated XBE data and the base address where PE was loaded.
        """
        print("\nEmbedding PE sections into XBE...")

        # Find the end of existing XBE sections
        # This is a simplified version - real implementation needs to parse XBE header

        # For now, just append at the end
        pe_base = len(xbe_data)
        xbe_data.extend(self.exe_data)

        print(f"  PE embedded at offset 0x{pe_base:08x}")
        return xbe_data, pe_base

    def patch(self, output_path: str) -> bool:
        """
        Main patching routine.
        """
        print("=" * 70)
        print("Graffiti Soul XBE Patcher")
        print("=" * 70)
        print(f"Original XBE: {self.xbe_path}")
        print(f"Compiled EXE: {self.exe_path}")
        print(f"Knowledge Base: {self.kb_path}")
        print(f"Output: {output_path}")

        # Create mutable copy of XBE
        patched_xbe = bytearray(self.xbe_data)

        # Embed our PE
        patched_xbe, pe_base = self.embed_pe_sections(patched_xbe)

        # Patch function redirects
        num_patched = self.patch_function_redirects(patched_xbe)

        # Write output
        output_path = Path(output_path)
        output_path.write_bytes(patched_xbe)

        # Calculate MD5
        md5 = hashlib.md5(patched_xbe).hexdigest()

        print("\n" + "=" * 70)
        print(f"Patching complete!")
        print(f"  Functions patched: {num_patched}")
        print(f"  Output size: {len(patched_xbe):,} bytes")
        print(f"  MD5: {md5}")
        print("=" * 70)

        print("\nNOTE: This is a basic implementation. Full XBE patching requires:")
        print("  - Proper XBE header parsing")
        print("  - Section alignment and rebasing")
        print("  - Import table resolution")
        print("  - Entry point modification")
        print("  - Certificate regeneration")
        print("\nRefer to https://github.com/dplewis/jsrf for a complete implementation.")

        return True


def main():
    parser = argparse.ArgumentParser(
        description='Patch JSRF XBE with decompiled functions'
    )
    parser.add_argument('xbe', help='Original JSRF default.xbe file')
    parser.add_argument('exe', help='Compiled executable with our implementations')
    parser.add_argument('output', help='Output patched XBE file')
    parser.add_argument('--kb', default='kb.json', help='Knowledge base JSON file')

    args = parser.parse_args()

    # Validate inputs
    if not Path(args.xbe).exists():
        print(f"Error: XBE file not found: {args.xbe}")
        return 1

    if not Path(args.exe).exists():
        print(f"Error: EXE file not found: {args.exe}")
        return 1

    if not Path(args.kb).exists():
        print(f"Error: Knowledge base not found: {args.kb}")
        return 1

    # Create patcher and run
    patcher = XBEPatcher(args.xbe, args.exe, args.kb)
    success = patcher.patch(args.output)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
