# Extract decompiled functions to markdown for Claude AI analysis
# @author Graffiti Soul Team
# @category Analysis
# @keybinding
# @menupath Tools.Graffiti Soul.Extract Decompiled Functions
# @toolbar

"""
Ghidra Script: Extract Decompiled Functions for Claude AI

This script extracts decompiled C code from selected functions or address ranges
and formats them as markdown for analysis with Claude AI.

Usage:
1. Open your XBE in Ghidra
2. Select one or more functions in the listing or decompiler
3. Run this script from Script Manager
4. Choose output options in the dialog
5. Copy the output or save to file

The output includes:
- Function signatures
- Decompiled C code
- Cross-references (calls made and callers)
- Data references
- Address information
"""

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet
from java.io import File, FileWriter
from java.util import Date
from java.text import SimpleDateFormat


class FunctionExtractor:
    """Extracts and formats decompiled functions."""

    def __init__(self):
        self.decompiler = None
        self.monitor = ConsoleTaskMonitor()

    def initialize_decompiler(self):
        """Initialize the decompiler interface."""
        self.decompiler = DecompInterface()
        self.decompiler.openProgram(currentProgram)

        # Set decompiler options for better output
        options = DecompileOptions()
        self.decompiler.setOptions(options)

    def cleanup(self):
        """Cleanup decompiler resources."""
        if self.decompiler:
            self.decompiler.dispose()

    def decompile_function(self, func):
        """Decompile a function and return C code."""
        if not func:
            return None

        results = self.decompiler.decompileFunction(func, 30, self.monitor)

        if not results or not results.decompileCompleted():
            return None

        decomp = results.getDecompiledFunction()
        if decomp:
            return decomp.getC()

        return None

    def get_function_calls(self, func):
        """Get all functions called by this function."""
        calls = []
        for called in func.getCalledFunctions(self.monitor):
            calls.append({
                'name': called.getName(),
                'addr': called.getEntryPoint().toString()
            })
        return calls

    def get_calling_functions(self, func):
        """Get all functions that call this function."""
        callers = []
        for caller in func.getCallingFunctions(self.monitor):
            callers.append({
                'name': caller.getName(),
                'addr': caller.getEntryPoint().toString()
            })
        return callers

    def extract_function_info(self, func):
        """Extract comprehensive information about a function."""
        print("Decompiling {} @ {}...".format(func.getName(), func.getEntryPoint()))

        info = {
            'name': func.getName(),
            'address': func.getEntryPoint().toString(),
            'signature': func.getPrototypeString(False, False),
        }

        # Decompile
        decompiled = self.decompile_function(func)
        if decompiled:
            info['decompiled_code'] = decompiled
            info['code_lines'] = len(decompiled.split('\n'))
        else:
            info['error'] = 'Decompilation failed'

        # Get cross-references
        info['calls'] = self.get_function_calls(func)
        info['called_by'] = self.get_calling_functions(func)

        # Get parameters
        params = []
        for param in func.getParameters():
            params.append({
                'name': param.getName(),
                'type': str(param.getDataType())
            })
        info['parameters'] = params
        info['return_type'] = str(func.getReturnType())

        return info


def format_as_markdown(functions_info, title="Decompiled Functions"):
    """Format extracted functions as markdown."""

    timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(Date())

    md = "# {}\n\n".format(title)
    md += "Extracted: {}\n".format(timestamp)
    md += "Program: {}\n".format(currentProgram.getName())
    md += "Base Address: {}\n\n".format(currentProgram.getImageBase())
    md += "Total functions: {}\n\n".format(len(functions_info))
    md += "---\n\n"

    for idx, info in enumerate(functions_info, 1):
        md += "## {}. {}\n\n".format(idx, info['name'])
        md += "**Address:** `{}`\n\n".format(info['address'])
        md += "**Signature:** `{}`\n\n".format(info['signature'])

        # Add type information
        md += "**Return Type:** `{}`\n\n".format(info['return_type'])

        if info['parameters']:
            md += "**Parameters:**\n"
            for param in info['parameters']:
                md += "- `{} {}`\n".format(param['type'], param['name'])
            md += "\n"

        # Add cross-references
        if info['calls']:
            md += "**Calls:** ({} functions)\n".format(len(info['calls']))
            for call in info['calls'][:15]:  # Limit to 15
                md += "- `{}` @ `{}`\n".format(call['name'], call['addr'])
            if len(info['calls']) > 15:
                md += "- ... and {} more\n".format(len(info['calls']) - 15)
            md += "\n"

        if info['called_by']:
            md += "**Called By:** ({} functions)\n".format(len(info['called_by']))
            for caller in info['called_by'][:15]:
                md += "- `{}` @ `{}`\n".format(caller['name'], caller['addr'])
            if len(info['called_by']) > 15:
                md += "- ... and {} more\n".format(len(info['called_by']) - 15)
            md += "\n"

        # Add decompiled code
        if 'decompiled_code' in info:
            md += "**Decompiled Code:**\n\n"
            md += "```c\n"
            md += info['decompiled_code']
            md += "\n```\n\n"
        elif 'error' in info:
            md += "**Error:** {}\n\n".format(info['error'])

        md += "---\n\n"

    return md


def get_selected_functions():
    """Get functions selected in the listing or decompiler."""
    functions = []

    # Try to get selected function in listing
    if currentSelection:
        func_manager = currentProgram.getFunctionManager()
        for addr in currentSelection.getAddresses(True):
            func = func_manager.getFunctionContaining(addr)
            if func and func not in functions:
                functions.append(func)

    # If no selection, try current location
    if not functions and currentLocation:
        func = getFunctionContaining(currentLocation.getAddress())
        if func:
            functions.append(func)

    return functions


def extract_all_functions_in_range(start_addr, end_addr):
    """Extract all functions in an address range."""
    addr_set = AddressSet(start_addr, end_addr)
    func_manager = currentProgram.getFunctionManager()

    functions = []
    for func in func_manager.getFunctions(addr_set, True):
        functions.append(func)

    return functions


def main():
    # Ask user for extraction mode
    from javax.swing import JOptionPane

    options = ["Selected Functions", "Address Range", "All Functions"]
    choice = askChoice(
        "Extract Decompiled Functions",
        "Choose extraction mode:",
        options,
        options[0]
    )

    if not choice:
        print("Cancelled by user")
        return

    functions_to_extract = []

    if choice == "Selected Functions":
        functions_to_extract = get_selected_functions()
        if not functions_to_extract:
            popup("No functions selected! Please select one or more functions in the listing.")
            return

    elif choice == "Address Range":
        start_str = askString("Start Address", "Enter start address (hex):")
        end_str = askString("End Address", "Enter end address (hex):")

        if not start_str or not end_str:
            print("Cancelled by user")
            return

        try:
            start_addr = currentProgram.getAddressFactory().getAddress(start_str)
            end_addr = currentProgram.getAddressFactory().getAddress(end_str)
            functions_to_extract = extract_all_functions_in_range(start_addr, end_addr)
        except:
            popup("Invalid address format! Use format like: 0x6f9e0")
            return

    elif choice == "All Functions":
        confirm = askYesNo(
            "Confirm",
            "Extract ALL functions? This may take a long time!"
        )
        if not confirm:
            return

        func_manager = currentProgram.getFunctionManager()
        functions_to_extract = list(func_manager.getFunctions(True))

    if not functions_to_extract:
        popup("No functions found!")
        return

    print("Extracting {} functions...".format(len(functions_to_extract)))

    # Initialize extractor
    extractor = FunctionExtractor()
    extractor.initialize_decompiler()

    try:
        # Extract function info
        functions_info = []
        for func in functions_to_extract:
            info = extractor.extract_function_info(func)
            functions_info.append(info)

        # Format as markdown
        markdown = format_as_markdown(functions_info)

        # Ask user what to do with output
        output_choice = askChoice(
            "Output",
            "What would you like to do with the output?",
            ["Save to File", "Print to Console", "Both"],
            "Save to File"
        )

        if not output_choice:
            print("Cancelled by user")
            return

        # Save to file if requested
        if output_choice in ["Save to File", "Both"]:
            default_name = "decompiled_{}.md".format(
                SimpleDateFormat("yyyyMMdd_HHmmss").format(Date())
            )
            output_file = askFile("Save Output", "Save")

            if output_file:
                writer = FileWriter(output_file)
                writer.write(markdown)
                writer.close()
                print("Output saved to: {}".format(output_file.getAbsolutePath()))
                popup("Extraction complete!\n\nSaved to: {}".format(output_file.getAbsolutePath()))

        # Print to console if requested
        if output_choice in ["Print to Console", "Both"]:
            print("\n" + "="*70)
            print(markdown)
            print("="*70)
            popup("Extraction complete!\n\nCheck the console for output.")

    finally:
        extractor.cleanup()

    print("Extraction complete!")


# Run the script
if __name__ == '__main__':
    main()
