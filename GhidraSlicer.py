# Import necessary Ghidra modules
from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os

# Function to get decompiled code
def decompile_function(func):
    decomp_interface = DecompInterface()
    options = DecompileOptions()
    decomp_interface.setOptions(options)
    decomp_interface.openProgram(currentProgram)
    
    decomp_result = decomp_interface.decompileFunction(func, 60, ConsoleTaskMonitor())
    if decomp_result and decomp_result.decompileCompleted():
        return decomp_result.getDecompiledFunction().getC()
    return None

# Function to collect all called functions recursively
def collect_called_functions(func, collected_functions):
    if func in collected_functions:
        return
    collected_functions.add(func)
    
    # Iterate over all code units in the function body
    for code_unit in currentProgram.getListing().getCodeUnits(func.getBody(), True):
        for reference in currentProgram.getReferenceManager().getReferencesFrom(code_unit.getAddress()):
            if reference.getReferenceType().isCall():
                called_func = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress())
                if called_func:
                    collect_called_functions(called_func, collected_functions)

# Main function to slice exported functions and save decompiled code
def slice_exported_functions():
    desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop')
    symbol_table = currentProgram.getSymbolTable()
    
    # Iterate over all symbols and select exported functions
    for symbol in symbol_table.getAllSymbols(True):
        if symbol.getSymbolType() == SymbolType.FUNCTION and symbol.isExternalEntryPoint():
            function_name = symbol.getName()
            exported_func = symbol.getObject()
            
            # Collect all called functions
            called_functions = set()
            collect_called_functions(exported_func, called_functions)
            
            # Decompile the collected functions
            decompiled_code = ""
            for func in called_functions:
                code = decompile_function(func)
                if code:
                    decompiled_code += code.strip()
            
            # Write the decompiled code to a file
            file_path = os.path.join(desktop_path, "slice_{}.txt".format(function_name))
            with open(file_path, 'w') as file:
                file.write(decompiled_code.strip())

# Run the main function
slice_exported_functions()
