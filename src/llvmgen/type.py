import ida_typeinf

from llvmlite import ir
import llvmlite.binding as llvm

lifted_structs = {}

def lift_type(ida_tif):
    match ida_tif:
        case func if func.is_func():
            ida_rettype = func.get_rettype()
            ida_args = (func.get_nth_arg(i) for i in range(func.get_nargs()))
            is_vararg = func.is_vararg_cc()

            llvm_rettype = lift_type(ida_rettype)
            llvm_args = (lift_type(arg) for arg in ida_args)
            return ir.FunctionType(llvm_rettype, llvm_args, var_arg = is_vararg)

        case ptr if ptr.is_ptr():
            child_tif = ptr.get_ptrarr_object()

            # clang compiles C void * to LLVM IR i8*
            if child_tif.is_void():
                return ir.IntType(8).as_pointer()

            return lift_type(child_tif).as_pointer()

        case arr if arr.is_array():
            child_tif = arr.get_ptrarr_object()
            element = lift_type(child_tif)

            count = arr.get_array_nelems()
            if count == 0:
                arr.convert_array_to_ptr()
                return lift_type(arr)

            return ir.ArrayType(element, count)

        case void if void.is_void():
            return ir.VoidType()

        case udt if udt.is_udt():
            udt_data = ida_typeinf.udt_type_data_t()
            udt.get_udt_details(udt_data)
            name = udt.get_type_name()
            context = ir.context.global_context

            if name not in context.identified_types:
                struct_t = context.get_identified_type(name)
                elementTypes = []
                for idx in range(udt_data.size()):
                    udt_member = udt_data.at(idx)
                    element = lift_type(udt_member.type)
                    elementTypes.append(element)
                if udt.is_varstruct():
                    print("panick its a variable struct")
                struct_t.set_body(*elementTypes)
            return context.get_identified_type(name)

        case boolean if boolean.is_bool():
            return ir.IntType(1)

        case float_t if float_t.is_float():
            return ir.FloatType()

        case double if double.is_double():
            return ir.DoubleType()

        case _:
            byte_size = ida_tif.get_size()
            return ir.IntType(byte_size * 8)

def lift_from_llvm_type(ea, llvmtype, module=None, toplevel=False):
    import ida_bytes
    import ida_segment
    import struct

    match llvmtype:
        case llvmtype if isinstance(llvmtype, ir.IntType):
            # should probably check endianness
            r = ida_bytes.get_bytes(ea, llvmtype.width // 8)
            return llvmtype(int.from_bytes(r, "little"))

        case llvmtype if isinstance(llvmtype, ir.FloatType):
            # should probably check endianness
            # floats are not guaranteed to be 8 bytes long
            return llvmtype(struct.unpack('f', ida_bytes.get_bytes(ea, 8)))

        case llvmtype if isinstance(llvmtype, ir.DoubleType):
            # should probably check endianness
            # doubles are not guaranteed to be 8 bytes long
            return llvmtype(struct.unpack('d', ida_bytes.get_bytes(ea, 8)))

        case llvmtype if isinstance(llvmtype, ir.PointerType):
            dest_ea = ea
            if not toplevel:
                dest_ea = int.from_bytes(ida_bytes.get_bytes(ea, 8), 'little')

            # check if ea is valid
            if ida_segment.segtype(dest_ea) & ida_segment.SEG_BSS == ida_segment.SEG_BSS:
                val = ir.Constant(llvmtype, None)
            elif isinstance(llvmtype.pointee, ir.FunctionType):
                val = ir.Constant(llvmtype, None)
            else:
                assumedType = ir.ArrayType(llvmtype.pointee, 1000) # we assume the pointer points to maximally 1000 elements
                val = lift_from_llvm_type(dest_ea, assumedType, module)

            if not toplevel:
                ptr = ir.GlobalVariable(module, val.type, name=f"var{len(module.globals)}")
                ptr.initializer = val
                zero = ir.Constant(ir.IntType(64), 0)
                return ptr.gep((zero,))
            return val

        case llvmtype if isinstance(llvmtype, ir.ArrayType):
            td = llvm.create_target_data("e-m:e-i64:64-f80:128-n8:16:32:64-S128")
            subSize = llvmtype.element.get_abi_size(td)

            return ir.Constant.literal_array([
                lift_from_llvm_type(sub_ea, llvmtype.element, module)
                for sub_ea in range(ea, ea + subSize * llvmtype.count, subSize)
            ])

        case llvmtype if isinstance(llvmtype, ir.LiteralStructType) or isinstance(llvmtype, ir.IdentifiedStructType):
            td = llvm.create_target_data("e-m:e-i64:64-f80:128-n8:16:32:64-S128")
            sub_ea = ea
            structEles = []
            for el in llvmtype.elements:
                structEles.append(lift_from_llvm_type(sub_ea, el, module))
                subSize = el.get_abi_size(td)
                sub_ea += subSize

            return ir.Constant.literal_struct(structEles)

def retrieve_ptr(builder, arg, off):
    match arg:
        case ptr if ptr.isptr():
            match ptr.type.pointee:
                case arr if isinstance(arr, ir.ArrayType):
                    # assert size == arr.element.width
                    # count = off // size
                    count = off
                    return builder.gep(ptr, (ir.Constant(ir.IntType(8), 0), ir.Constant(ir.IntType(8), count),))
                
                case struct if isinstance(struct, ir.LiteralStructType):
                    return self.builder.bitcast(ptr, ir.IntType(8).as_pointer())

            return ptr
        case _:
            return arg

def load(builder, src):
    # i can't tell if this is neccessary
    # i will comment this out and come add it back later if needed
    # if isinstance(src.type.pointee, ir.LiteralStructType):
    #     src = builder.bitcast(src, ir.IntType(8).as_pointer())
    # if src.type.pointee.isptr() and isinstance(src.type.pointee.pointee, ir.LiteralStructType):
        # src = builder.bitcast(src, ir.IntType(8).as_pointer().as_pointer())
    return builder.load(src)

def store(builder, src, dst):
    if isinstance(dst.type.pointee, ir.ArrayType):
        arrtoptr = dst.type.pointee.element.as_pointer()
        dst = change_type(builder, dst, arrtoptr.as_pointer())
    src = change_type(builder, src, dst.type.pointee)
    return builder.store(src, dst)

def change_type(builder, src, dst_type):
    if src.type != dst_type:
        match (src, dst_type):
            case (src, dst_type) if src.isptr() and dst_type.isptr():
                return builder.bitcast(src, dst_type)
            case (src, dst_type) if src.isptr() and dst_type.isint():
                return builder.ptrtoint(src, dst_type)
            case (src, dst_type) if src.isint() and dst_type.isptr():
                return builder.inttoptr(src, dst_type)

            case (src, dst_type) if src.isint() and dst_type.isfloat():
                return builder.uitofp(src, dst_type)
            case (src, dst_type) if src.isfloat() and dst_type.isint():
                return builder.fptoui(src, dst_type)
            case (src, dst_type) if src.isfloat() and dst_type.isfloat():
                return src

            # neither src/dst_type are ptrs
            case (src, dst_type) if src.type.width < dst_type.width:
                return builder.sext(src, dst_type)
            case (src, dst_type) if src.type.width > dst_type.width:
                return builder.trunc(src, dst_type)
    return src