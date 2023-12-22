import ida_typeinf
import ida_idaapi
import logging

from llvmlite import ir

logger = logging.getLogger(__name__)

def lift_tif(tif: ida_typeinf.tinfo_t) -> ir.Type:
    """
    Lifts the given IDA type to corresponding LLVM type.
    If IDA type is an array/struct/tif, type lifting is performed recursively.

    :param tif: the type to lift, in IDA
    :type tif: ida_typeinf.tinfo_t
    :raises NotImplementedError: variadic structs
    :return: lifted LLVM type
    :rtype: ir.Type
    """
    match tif:
        case tif if tif.is_func():
            # a function type is composed of:
            ## return type, argument types, variadic
            ida_rettype = tif.get_rettype()
            ida_args = (tif.get_nth_arg(i) for i in range(tif.get_nargs()))
            is_vararg = tif.is_vararg_cc()

            llvm_rettype = lift_tif(ida_rettype)
            llvm_args = (lift_tif(arg) for arg in ida_args)
            return ir.FunctionType(llvm_rettype, llvm_args, var_arg = is_vararg)

        case tif if tif.is_ptr():
            child_tif = tif.get_ptrarr_object()

            # clang compiles C void * to LLVM IR i8*
            if child_tif.is_void():
                return ir.IntType(8).as_pointer()

            return lift_tif(child_tif).as_pointer()

        case tif if tif.is_array():
            child_tif = tif.get_ptrarr_object()
            element = lift_tif(child_tif)

            count = tif.get_array_nelems()
            if count == 0:
                # an array with an indeterminate number of elements = type pointer
                tif.convert_array_to_ptr()
                return lift_tif(tif)

            return ir.ArrayType(element, count)

        case tif if tif.is_void():
            return ir.VoidType()

        case tif if tif.is_udt():
            udt_data = ida_typeinf.udt_type_data_t()
            tif.get_udt_details(udt_data)
            type_name = tif.get_type_name()
            context = ir.context.global_context

            if type_name not in context.identified_types:
                struct_t = context.get_identified_type(type_name)
                elementTypes = []
                for idx in range(udt_data.size()):
                    udt_member = udt_data.at(idx)
                    element = lift_tif(udt_member.type)
                    elementTypes.append(element)
                if tif.is_varstruct():
                    raise NotImplementedError(f"variadic structs not implemented: {tif}")
                struct_t.set_body(*elementTypes)
            return context.get_identified_type(type_name)

        case tif if tif.is_bool():
            return ir.IntType(1)

        case tif if tif.is_float():
            return ir.FloatType()

        case tif if tif.is_double():
            return ir.DoubleType()

        case _:
            byte_size = tif.get_size()
            # naieve assumption that system is either 32 bit or 64 bit
            bitness = 32
            if ida_idaapi.get_inf_structure().is_64bit():
                bitness = 64
            if byte_size == (1 << bitness) - 1:
                byte_size = 1
            return ir.IntType(byte_size * 8)

def typecast(src: ir.Value, dst_type: ir.Type, builder: ir.IRBuilder, signed: bool = False) -> ir.Value:
    """
    Given some `src`, convert it to type `dst_type`.
    Instructions are emitted into `builder`.

    :param src: value to convert
    :type src: ir.Value
    :param dst_type: destination type
    :type dst_type: ir.Type
    :param builder: builds instructions
    :type builder: ir.IRBuilder
    :param signed: whether to preserve signness, defaults to True
    :type signed: bool, optional
    :raises NotImplementedError: type conversion not supported
    :return: value after typecast
    :rtype: ir.Value   
    """
    if src.type != dst_type:
        match (src, dst_type):
            case (src, dst_type) if isinstance(src.type, ir.PointerType) and isinstance(dst_type, ir.PointerType):
                return builder.bitcast(src, dst_type)
            case (src, dst_type) if isinstance(src.type, ir.PointerType) and isinstance(dst_type, ir.IntType):
                return builder.ptrtoint(src, dst_type)
            case (src, dst_type) if isinstance(src.type, ir.IntType) and isinstance(dst_type, ir.PointerType):
                return builder.inttoptr(src, dst_type)

            case (src, dst_type) if isinstance(src.type, ir.IntType) and isinstance(dst_type, ir.FloatType):
                return builder.uitofp(src, dst_type)
            case (src, dst_type) if isinstance(src.type, ir.FloatType) and isinstance(dst_type, ir.IntType):
                return builder.fptoui(src, dst_type)
            case (src, dst_type) if isinstance(src.type, ir.FloatType) and isinstance(dst_type, ir.FloatType):
                return src

            case (src, dst_type) if isinstance(src.type, ir.IntType) and isinstance(dst_type, ir.IntType) and src.type.width < dst_type.width:
                if signed:
                    return builder.sext(src, dst_type)
                else:
                    return builder.zext(src, dst_type)
            case (src, dst_type) if isinstance(src.type, ir.IntType) and isinstance(dst_type, ir.IntType) and src.type.width > dst_type.width:
                return builder.trunc(src, dst_type)
            case _:
                raise NotImplementedError(f"cannot convert {src} of type {src.type} into {dst_type}")
    return src