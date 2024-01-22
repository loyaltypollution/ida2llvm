import ida_pro
import ida_ida
import ida_nalt
import logging

from llvmlite import ir
from os.path import basename

import ida2llvm

logger = logging.getLogger(__name__)
filename = basename(ida_nalt.get_input_file_path())
logging.basicConfig(filename=f".\\tests\\log\\{filename}.log",
                    format='%(levelname)s (%(name)s.py) %(message)s',
                    filemode='a',
                    level=logging.DEBUG)

module = ir.Module(filename)
logger.info(f"declared ir module of name {filename}")

# def generate_graph():
#     callees = dict()
#     # loop through all functions
#     for function_ea in idautils.Functions():
#         f_name = idc.get_func_name(function_ea)
#         # For each of the incoming references
#         for ref_ea in idautils.CodeRefsTo(function_ea, 0):
#             # Get the name of the referring function
#             caller_name = idc.get_func_name(ref_ea)
#             # Add the current function to the list of functions
#             # called by the referring function
#             callees[str(caller_name)] = callees.get(str(caller_name), set())
#             callees[str(caller_name)].add(str(f_name))
#     return callees

# def recursive_decompile():
#     # recurisvely decompile
#     pass

# function_graph = generate_graph()
# print(function_graph)

try:
    func_name = 'main'
    ida2llvm.function.lift_function(module, func_name, False)
except Exception as e:
    logger.exception(e)

with open(f'.\\tests\\ll\\{filename}.ll', 'w') as f:
    f.write(str(module))

ida_pro.qexit(ida_ida.IDB_PACKED)