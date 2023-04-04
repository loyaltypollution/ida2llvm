from llvmlite import ir
import llvmgen.function
from llvmgen.singleton import Singleton, SingletonParent

class LLVMModule(SingletonParent, metaclass=Singleton):
    def __init__(self):
        self.module = ir.Module('module')

    def declare_function(self, func_name, llvm_func_type=None):
        import ida_typeinf
        import ida_idaapi
        import ida_nalt
        import ida_name
        
        # rename all function args to arg0, arg1, arg2, if does not exist
        func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
        tif = ida_typeinf.tinfo_t()
        ida_nalt.get_tinfo(tif, func_ea)

        ida_func_details = ida_typeinf.func_type_data_t()
        tif.get_func_details(ida_func_details)

        ida_args = (ida_func_details.at(i) for i in range(ida_func_details.size()))
        for i, arg in enumerate(ida_args):
            arg.name = f"arg{i}"
        function_tinfo = ida_typeinf.tinfo_t()
        function_tinfo.create_func(ida_func_details)
        ida_typeinf.apply_tinfo(func_ea, function_tinfo, ida_typeinf.TINFO_DEFINITE)

        return llvmgen.function.Function(func_name, self, llvm_func_type)
    
    def define_function(self, func_name, is_define=True):
        function = self.declare_function(func_name)
        if is_define:
            function.define_function()
        return function
    
    def intrinsics(self, intrinsic):
        match intrinsic:
            case "strcpy":
                # ida_pro: (dest, src)
                # llvmintrinsic: (dest, src, length, isvolatile=True)
                llvm_func_type = ir.FunctionType(ir.VoidType(), (ir.IntType(8).as_pointer(), ir.IntType(8).as_pointer()))
                f = self.declare_function("_h_strcpy", llvm_func_type)

                if not f.is_defined():
                    f.llvm_f.append_basic_block('head')
                    f.builder = ir.IRBuilder(f.llvm_f.entry_basic_block)

                    memcpy = self.module.declare_intrinsic('llvm.memcpy', [ir.IntType(8).as_pointer(), ir.IntType(8).as_pointer(), ir.IntType(64)])

                    dest, src = f.llvm_f.args

                    # TODO
                    # TODO
                    # TODO
                    # TODO
                    # TODO
                    # TODO
                    # TODO

                    length = ir.Constant(ir.IntType(64), 45)
                    volatile = ir.Constant(ir.IntType(1), True)
                    f.builder.call(memcpy, (dest, src, length, volatile))
                    f.builder.ret_void()
                return f.llvm_f

            case "memset":
                # ida_pro: (dest, src, length)
                # llvmintrinsic: (dest, src, length, isvolatile=True)
                llvm_func_type = ir.FunctionType(ir.VoidType(), (ir.IntType(8).as_pointer(), ir.IntType(8), ir.IntType(64)))
                f = self.declare_function("_h_memset", llvm_func_type)

                if not f.is_defined():
                    f.llvm_f.append_basic_block('head')
                    f.builder = ir.IRBuilder(f.llvm_f.entry_basic_block)

                    memset = self.module.declare_intrinsic('llvm.memset', [ir.IntType(8).as_pointer(), ir.IntType(64)])

                    dest, src, length = f.llvm_f.args
                    volatile = ir.Constant(ir.IntType(1), True)
                    f.builder.call(memset, (dest, src, length, volatile))
                    f.builder.ret_void()
                return f.llvm_f
