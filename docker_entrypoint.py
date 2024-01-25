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

try:
    func_name = 'main'
    ida2llvm.function.lift_function(module, func_name, False)
except Exception as e:
    logger.exception(e)

with open(f'.\\tests\\ll\\{filename}.ll', 'w') as f:
    f.write(str(module))

ida_pro.qexit(ida_ida.IDB_PACKED)