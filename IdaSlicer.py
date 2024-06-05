import os
import re
from idaapi import *
from idc import *
from idautils import *
import ida_hexrays
import ida_bytes

# Function to get the decompiled code
def decompile_function(ea):
    try:
        decomp = ida_hexrays.decompile(ea)
        if decomp:
            return str(decomp)
    except Exception as e:
        print(f"Failed to decompile function at {ea:#x}: {e}")
    return None

# Function to collect all called functions recursively
def collect_called_functions(func_ea, collected_functions):
    if func_ea in collected_functions:
        return
    collected_functions.add(func_ea)
    
    func = get_func(func_ea)
    if func is None:
        return
    
    for block in FlowChart(func):
        for head in Heads(block.start_ea, block.end_ea):
            refs = CodeRefsFrom(head, False)
            for ref in refs:
                if ida_bytes.is_code(get_full_flags(ref)):
                    collect_called_functions(ref, collected_functions)

# Function to sanitize file names
def sanitize_filename(name):
    return re.sub(r'[\\/*?:"<>|]', "_", name)

# Main function to slice exported functions and save decompiled code
def slice_exported_functions():
    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    
    # Iterate over all segments
    for seg in Segments():
        # Iterate over all functions in the segment
        for func_ea in Functions(get_segm_start(seg), get_segm_end(seg)):
            if is_public_name(func_ea):
                function_name = get_func_name(func_ea)
                sanitized_name = sanitize_filename(function_name)
                
                # Collect all called functions
                called_functions = set()
                collect_called_functions(func_ea, called_functions)
                
                # Decompile the collected functions
                decompiled_code = ""
                for called_ea in called_functions:
                    code = decompile_function(called_ea)
                    if code:
                        decompiled_code += f"// Decompiled code for function at {hex(called_ea)}:\n"
                        decompiled_code += code + "\n\n"
                
                # Write the decompiled code to a file
                file_path = os.path.join(desktop_path, "slice_{}.txt".format(sanitized_name))
                with open(file_path, 'w') as file:
                    file.write(decompiled_code)

# Ensure Hex-Rays decompiler is available
if ida_hexrays.init_hexrays_plugin():
    # Run the main function
    slice_exported_functions()
else:
    print("Hex-Rays decompiler is not available.")
