#--------------------------------------
# PAL VIRII
#--------------------------------------
import traceback

from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import FunctionManager



import PALsplash
import PALDecompilerPipeline as Dispacher

#print("ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")

def print_pal_debug(pal_func):
    """
    Enhanced PAL Printer with dividers, spacing, and C-code listing.
    """
    width = 100
    divider = "=" * width
    sub_divider = "-" * width
    
    # 1. Header Section
    print(f"\n{divider}")
    print(f"║ PAL FUNCTION OBJECT: {pal_func.func_name:<68} ║")
    print(f"║ Entry: {hex(pal_func.function_address):<18} | Range: {hex(pal_func.range[0])}-{hex(pal_func.range[1]):<22} ║")
    print(f"{divider}")

    # 2. Decompiled C-Code Section
    print("\n[ DECOMPILED C-CODE ]")
    print(sub_divider)
    # Add line numbers to C-code for reference
    for i, line in enumerate(pal_func.c_code.split('\n')):
        print(f"{i+1:3} | {line}")
    print(sub_divider)

    # 3. Execution Sequence (Blocks & P-Code)
    print("\n[ P-CODE EXECUTION SEQUENCE ]")
    for block in pal_func.blocks:
        print(f"\n┌── BLOCK {block.block_id} ──────────────────────────────────────────────────────────")
        print(f"│ Address: {hex(block.addr)}")
        print(f"│ Ops:     {len(block.ops)}")
        print(f"├{'─'*20}┬{'─'*30}┬{'─'*43}")
        print(f"│ {'OPCODE':<18} │ {'OUTPUT = INPUTS':<28} │ {'ASSEMBLY REFERENCE'}")
        print(f"├{'─'*20}┼{'─'*30}┼{'─'*43}")
        
        for op in block.ops:
            # Format SSA variables
            out_str = f"{op.output.ssa_id} = " if op.output else ""
            in_str = ", ".join([i.ssa_id for i in op.inputs])
            logic_str = f"{out_str}{in_str}"
            
            # Print the row with vertical dividers
            print(f"│ {op.opcode:<18} │ {logic_str:<28} │ {op.assembly}")
            
        print(f"└{'─'*20}┴{'─'*30}┴{'─'*43}")

    # 4. SSA Map Summary (Variables discovered)
    print(f"\n[ SSA VARIABLE MAP ({len(pal_func.ssa_map)} variables) ]")
    print(sub_divider)
    # Print in columns to save vertical space
    vars_list = list(pal_func.ssa_map.values())
    for i in range(0, len(vars_list), 2):
        row = vars_list[i:i+2]
        line = ""
        for v in row:
            line += f"ID: {v.ssa_id:<8} Space: {v.space:<10} Offset: {hex(v.offset):<12} | "
        print(line)
    print(f"{divider}\n")

def main():
   
    PALsplash.logo_print()

    # Get the Function Manager for the current program
    
    fm = currentProgram.getFunctionManager()

    decompiler_interface = DecompInterface()
    monitor = ConsoleTaskMonitor()


    # Iterate over all non-external functions
    
    # fm.getFunctions(True) returns an iterator in address order
    functions = fm.getFunctions(True)

    for func in functions:
        # "mutate", "feedback", "transform_a", "transform_b", "check_bit"
        #if func.getName() in ["FUN_00102740"]:
        
        #if func.getName() in ["PAL_indirect_gauntlet"]:
        if func.getName() in ["FUN_00106d80"]:
      
        #if func.getName() in ["process_payload_block", "PALexec"]: #, "main"]:
            
            dispach = Dispacher.PALDecompilerPipeline(func, currentProgram, decompiler_interface, monitor)
            pycode_read, pycode_exec = dispach.run_all()
            
            
            print("\n===== PAL PYTHON READABLE OUTPUT =====\n")
            print("\n".join(pycode_read), "\n-----------------------------------------\n")
            
            print("\n===== PAL PYTHON EXECUTABLE OUTPUT =====\n")
            print("\n".join(pycode_exec), "\n-----------------------------------------\n")






            #dispach.debug_print(verbose=True)
        
           
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("\n=== UNHANDLED EXCEPTION ===")
        traceback.print_exc()
        sys.stderr.flush()
        raise
