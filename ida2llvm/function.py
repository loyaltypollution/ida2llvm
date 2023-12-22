import ida_typeinf
import ida_name
import ida_idaapi
import ida_segment
import logging

from llvmlite import ir
from contextlib import suppress

import ida2llvm

logger = logging.getLogger(__name__)

def lift_intrinsic_function(module: ir.Module, func_name: str):
    """
    Lifts IDA macros to corresponding LLVM intrinsics.

    Hexray's decompiler recognises higher-level functions at the Microcode level.
        Such ida_hexrays:mop_t objects are typed as ida_hexrays.mop_h (auxillary function member)
        
        This improves decompiler output, representing operations that cannot be mapped to nice C code
        (https://hex-rays.com/blog/igors-tip-of-the-week-67-decompiler-helpers/).

        For relevant #define macros, refer to IDA SDK: `defs.h` and `pro.h`.

    LLVM intrinsics have well known names and semantics and are required to follow certain restrictions.

    :param module: _description_
    :type module: ir.Module
    :param func_name: _description_
    :type func_name: str
    :raises NotImplementedError: _description_
    :return: _description_
    :rtype: _type_
    """
    # retrieve intrinsic function if it already exists
    with suppress(KeyError):
        return module.get_global(f"_h_{func_name}")

    match func_name:
        case "strcpy":
            typ = ir.FunctionType(ir.VoidType(), (ir.IntType(8).as_pointer(), ir.IntType(8).as_pointer()))
            f = ir.Function(module, typ, "_h_strcpy")
            if f.is_declaration:
                f.append_basic_block('head')
                builder = ir.IRBuilder(f.entry_basic_block)

                memcpy = module.declare_intrinsic('llvm.memcpy', [ir.IntType(8).as_pointer(), ir.IntType(8).as_pointer(), ir.IntType(64)])

                logger.debug("TODO: fix strcpy naieve assumptions")
                dest, src = f.llvm_f.args
                length = ir.Constant(ir.IntType(64), 45)
                volatile = ir.Constant(ir.IntType(1), True)

                builder.call(memcpy, (dest, src, length, volatile))
                builder.ret_void()
            return f
    
        case "__halt":
            fty = ir.FunctionType(ir.VoidType(), [])
            f = ir.Function(module, fty, "_h_halt")
            if f.is_declaration:
                f.append_basic_block('head')
                builder = ir.IRBuilder(f.entry_basic_block)
                builder.asm(fty, "hlt", "", (), True)
                builder.ret_void()
            return f

        # case "memset":
        #     # ida_pro: (dest, src, length)
        #     # llvmintrinsic: (dest, src, length, isvolatile=True)
        #     typ = ir.FunctionType(ir.VoidType(), (ir.IntType(8).as_pointer(), ir.IntType(8), ir.IntType(64)))
        #     f = declare_function("_h_memset", typ)

        #     if not f.is_defined():
        #         f.llvm_f.append_basic_block('head')
        #         f.builder = ir.IRBuilder(f.llvm_f.entry_basic_block)

        #         memset = module.declare_intrinsic('llvm.memset', [ir.IntType(8).as_pointer(), ir.IntType(64)])

        #         dest, src, length = f.llvm_f.args
        #         volatile = ir.Constant(ir.IntType(1), True)
        #         f.builder.call(memset, (dest, src, length, volatile))
        #         f.builder.ret_void()
        #     return f.llvm_f

        # case "__ROL8__":
        #     # ida_pro: (item, shiftamount)
        #     # llvmintrinsic: (left, right, shiftamount) funnelshiftright is equal to rotateright iff left and right operands are equal.
        #     typ = ir.FunctionType(ir.IntType(64), (ir.IntType(64), ir.IntType(8)))
        #     f = declare_function("_h_rol8", typ)

        #     if not f.is_defined():
        #         f.llvm_f.append_basic_block('head')
        #         f.builder = ir.IRBuilder(f.llvm_f.entry_basic_block)
        #         rol_func_type = ir.FunctionType(ir.IntType(64), (ir.IntType(64), ir.IntType(64), ir.IntType(64)))
        #         rol8 = module.declare_intrinsic('llvm.fshl.i64', [ir.IntType(64), ir.IntType(64), ir.IntType(64)], rol_func_type)

        #         item, shiftamount = f.llvm_f.args
        #         shiftamount = llvmgen.ida2llvm.type.change_type(f.builder, shiftamount, ir.IntType(64))
        #         return_val = f.builder.call(rol8, (item, item, shiftamount))
        #         f.builder.ret(return_val)
        #     return f.llvm_f
            
        # case "_byteswap_uint64":
        #     # ida_pro: (item)
        #     # llvmintrinsic: (item)
        #     typ = ir.FunctionType(ir.IntType(64), (ir.IntType(64),))
        #     f = declare_function("_h_byteswap_uint64", typ)

        #     if not f.is_defined():
        #         f.llvm_f.append_basic_block('head')
        #         f.builder = ir.IRBuilder(f.llvm_f.entry_basic_block)
        #         byteswap_func_type = ir.FunctionType(ir.IntType(64), (ir.IntType(64),))
        #         byteswap64 = module.declare_intrinsic('llvm.bswap.i64', [ir.IntType(64),], byteswap_func_type)

        #         item, = f.llvm_f.args
        #         return_val = f.builder.call(byteswap64, (item,))
        #         f.builder.ret(return_val)
        #     return f.llvm_f

        # case "_byteswap_ulong":
        #     # ida_pro: (item)
        #     # llvmintrinsic: (item)
        #     typ = ir.FunctionType(ir.IntType(32), (ir.IntType(32),))
        #     f = declare_function("_h_byteswap_uint32", typ)

        #     if not f.is_defined():
        #         f.llvm_f.append_basic_block('head')
        #         f.builder = ir.IRBuilder(f.llvm_f.entry_basic_block)
        #         byteswap_func_type = ir.FunctionType(ir.IntType(32), (ir.IntType(32),))
        #         byteswap32 = module.declare_intrinsic('llvm.bswap.i32', [ir.IntType(32),], byteswap_func_type)

        #         item, = f.llvm_f.args
        #         return_val = f.builder.call(byteswap32, (item,))
        #         f.builder.ret(return_val)
        #     return f.llvm_f

        case _:
            raise NotImplementedError(f"NotImplementedError {func_name}")

def lift_function(module: ir.Module, func_name: str, is_declare: bool, tif: ida_typeinf.tinfo_t = None):
    """
    Declares function given its name. 
    If `is_declare` is False, also define the function by recursively.
    If `tif` is given, enforce function type as given.
    lifting its instructions in IDA decompiler output.
    Heavylifting is done in `lift_from_address`.

    :param module: parent module of function
    :type module: ir.Module
    :param func_name: name of function to lift
    :type func_name: str
    :param is_declare: is the function declare only?
    :type is_declare: bool
    :param tif: function type, defaults to None
    :type tif: ida_typeinf.tinfo_t, optional
    :return: lifted function
    :rtype: ir.Function
    """
    from contextlib import suppress
    with suppress(NotImplementedError):
        return lift_intrinsic_function(module, func_name)

    with suppress(KeyError):
        return module.get_global(func_name)

    func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
    if ida_segment.segtype(func_ea) & ida_segment.SEG_XTRN:
        is_declare = True

    assert func_ea != ida_idaapi.BADADDR
    if tif is None:
        tif = ida2llvm.address.lift_type_from_address(func_ea)
    typ = ida2llvm.type.lift_tif(tif)
    res = ir.Function(module, typ, func_name)
    logger.debug(f"lifting function {func_name} at {hex(func_ea)}, type: {typ} from {tif}")

    # rename all function args to arg0, arg1, arg2, if does not exist
    ida_func_details = ida_typeinf.func_type_data_t()
    tif.get_func_details(ida_func_details)

    ida_args = (ida_func_details.at(i) for i in range(ida_func_details.size()))
    for i, arg in enumerate(ida_args):
        arg.name = f"arg{i}"
    function_tinfo = ida_typeinf.tinfo_t()
    function_tinfo.create_func(ida_func_details)
    if func_ea != 0xffffffffffffffff:
        ida_typeinf.apply_tinfo(func_ea, function_tinfo, ida_typeinf.TINFO_DEFINITE)

    if is_declare:
        return res
    return ida2llvm.address.lift_from_address(module, func_ea)
