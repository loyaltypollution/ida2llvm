import ida_bytes
import ida_hexrays
import ida_segment
import ida_typeinf
import ida_nalt
import ida_name
import ida_funcs
import ida_idaapi
import logging
import struct
import llvmlite.binding as llvm

from llvmlite import ir
import ida2llvm

logger = logging.getLogger(__name__)

def lift_type_from_address(ea: int):
    if ida_segment.segtype(ea) & ida_segment.SEG_XTRN:
        # let's assume its a function that returns ONE register and takes in variadic arguments
        ida_func_details = ida_typeinf.func_type_data_t()
        void = ida_typeinf.tinfo_t()
        void.create_simple_type(ida_typeinf.BTF_VOID)
        ida_func_details.rettype = void
        ida_func_details.cc = ida_typeinf.CM_CC_ELLIPSIS | ida_typeinf.CC_CDECL_OK

        function_tinfo = ida_typeinf.tinfo_t()
        function_tinfo.create_func(ida_func_details)
        return function_tinfo

    if (func := ida_funcs.get_func(ea)) is not None:
        ida_hf = ida_hexrays.hexrays_failure_t()
        tif = ida_hexrays.decompile(func, ida_hf).type
        ida_nalt.set_tinfo(ea, tif)

    tif = ida_typeinf.tinfo_t()
    ida_nalt.get_tinfo(tif, ea)
    if tif.empty():
        raise NotImplementedError(f"not implemented: type inference for object at {hex(ea)}")
    return tif

def lift_from_address(module: ir.Module, ea: int, typ: ir.Type = None):
    if typ is None:
        tif = lift_type_from_address(ea)
        typ = ida2llvm.type.lift_tif(tif)
    return _lift_from_address(module, ea, typ)

def _lift_from_address(module: ir.Module, ea: int, typ: ir.Type):
    match typ:
        case typ if isinstance(typ, ir.FunctionType):
            ida_funcs.add_func(ea, ida_idaapi.BADADDR)
            func = ida_funcs.get_func(ea)
            func_name = ida_name.get_name(ea)
            res = module.get_global(func_name)
            res.lvars = dict()

            ida_hf = ida_hexrays.hexrays_failure_t()
            ida_mbr = ida_hexrays.mba_ranges_t()
            ida_mbr.ranges.push_back(func)

            lvars = ida_hexrays.decompile(func, ida_hf).lvars
            mba = ida_hexrays.gen_microcode(ida_mbr, ida_hf, None,
                                            ida_hexrays.DECOMP_ALL_BLKS,
                                            ida_hexrays.MMAT_LVARS)

            for index in range(mba.qty):
                res.append_basic_block(name = f"@{index}") 

            ida_func_details = ida_typeinf.func_type_data_t()
            tif = lift_type_from_address(ea)
            tif.get_func_details(ida_func_details)
            names = [ida_func_details.at(i).name for i in range(ida_func_details.size())]
            
            builder = ir.IRBuilder(res.entry_basic_block)

            with builder.goto_entry_block():
                # declare function arguments as stack variables
                for arg, arg_t, arg_n in zip(res.args, typ.args, names):
                    res.lvars[arg_n] = builder.alloca(arg_t, name = arg_n)
                
                # declare function results as stack variable
                if not isinstance(typ.return_type, ir.VoidType):
                    res.lvars["result"] = builder.alloca(typ.return_type, name = "result")

                # if function is variadic, declare va_start intrinsic
                if tif.is_vararg_cc() and typ.var_arg:
                    ptr = builder.alloca(ir.IntType(8).as_pointer(), name = "ArgList")
                    res.lvars["ArgList"] = ptr
                    va_start = module.declare_intrinsic('llvm.va_start', fnty=ir.FunctionType(ir.VoidType(), [ir.IntType(8).as_pointer()]))
                    ptr = builder.bitcast(ptr, ir.IntType(8).as_pointer())
                    builder.call(va_start, (ptr, ))

                # store stack variables
                for arg, arg_n in zip(res.args, names):
                    arg = ida2llvm.type.typecast(arg, res.lvars[arg_n].type.pointee, builder)
                    builder.store(arg, res.lvars[arg_n])

            with builder.goto_block(res.blocks[-1]):
                if isinstance(typ.return_type, ir.VoidType):
                    builder.ret_void()
                else:
                    builder.ret(builder.load(res.lvars["result"]))

            # lift each bblk in cfg
            for index, blk in enumerate(res.blocks):
                ida_blk = mba.get_mblock(index)

                ida_insn = ida_blk.head
                while ida_insn is not None:
                    lifted_insn = ida2llvm.insn.lift_insn(ida_insn, blk, builder)
                    logger.debug(f"=> {lifted_insn}")
                    ida_insn = ida_insn.next

                if not blk.is_terminated and index + 1 < len(res.blocks):
                    with builder.goto_block(blk):
                        builder.branch(res.blocks[index + 1])

            return res

            # # define function return type
            # define_rettype()
        case typ if isinstance(typ, ir.IntType):
            # should probably check endianness
            r = ida_bytes.get_bytes(ea, typ.width // 8)
            return typ(int.from_bytes(r, "little"))
        case typ if isinstance(typ, ir.FloatType):
            # should probably check endianness
            # floats are not guaranteed to be 8 bytes long
            return typ(struct.unpack('f', ida_bytes.get_bytes(ea, 8)))
        case typ if isinstance(typ, ir.DoubleType):
            # should probably check endianness
            # doubles are not guaranteed to be 8 bytes long
            return typ(struct.unpack('d', ida_bytes.get_bytes(ea, 8)))
        case typ if isinstance(typ, ir.PointerType):
            # check if ea is valid
            if (ida_segment.segtype(ea) & ida_segment.SEG_BSS == ida_segment.SEG_BSS
                or isinstance(typ.pointee, ir.FunctionType)):
                val = ir.Constant(typ, None)
            else:
                assumedType = ir.ArrayType(typ.pointee, 1000) # we assume the pointer points to maximally 1000 elements
                val = lift_from_address(module, ea, assumedType)
            return val
        case typ if isinstance(typ, ir.ArrayType):
            td = llvm.create_target_data("e")
            subSize = typ.element.get_abi_size(td)

            return ir.Constant.literal_array([ lift_from_address(module, sub_ea, typ.element)
                for sub_ea in range(ea, ea + subSize * typ.count, subSize)
            ])
        case typ if isinstance(typ, ir.LiteralStructType) or isinstance(typ, ir.IdentifiedStructType):
            td = llvm.create_target_data("e")
            sub_ea = ea
            structEles = []
            for el in typ.elements:
                if isinstance(el, ir.PointerType):
                    address_ea = ida_bytes.get_dword(sub_ea)
                    if ida_idaapi.get_inf_structure().is_64bit():
                        address_ea = ida_bytes.get_qword(sub_ea)
                    g_cmt = lift_from_address(module, address_ea, el)

                    val = ir.GlobalVariable(module, g_cmt.type, f"{typ}_{hex(ea)}")
                    val.initializer = g_cmt
                    structEle = val.gep((ir.IntType(64)(0),))
                else:
                    structEle = lift_from_address(module, sub_ea, el)
                structEles.append(structEle)
                subSize = el.get_abi_size(td)
                sub_ea += subSize

            return ir.Constant.literal_struct(structEles)
    raise NotImplementedError(f"object at {hex(ea)} is of unsupported type {typ}")