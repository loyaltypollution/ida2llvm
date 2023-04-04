import ida_pro
import ida_ida

from llvmgen.module import LLVMModule

import sys
with open('stdout', 'w') as sys.stdout:
    # declare llvm function
    LLVMModule().define_function("main")

    with open('.ll', 'w+') as f:
        f.write(str(LLVMModule().module))

ida_pro.qexit(ida_ida.IDB_PACKED)