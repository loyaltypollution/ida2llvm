import ida_idaapi
import ida_funcs
import ida_hexrays
import ida_typeinf
import ida_segment
import ida_nalt
import ida_name
import itertools
import logging
import llvmlite.binding as llvm

from llvmlite import ir
from contextlib import suppress
import ida2llvm

logger = logging.getLogger(__name__)

def lift_mop(mop: ida_hexrays.mop_t, blk: ir.Block, builder: ir.IRBuilder) -> ir.Value:
    """Lifts an IDA mop_t object to LLVM Value.

    :param mop: mop_t object to lift
    :type mop: ida_hexrays.mop_t
    :param blk: LLVM Block to add instructions to
    :type blk: ir.Block
    :raises NotImplementedError: specific mop_t types are not implemented
    :param builder: builder to emit instructions into
    :type builder: ir.IRBuilder
    :return: lifted LLVM Value
    :rtype: ir.Value
    """
    builder.position_at_end(blk)
    match mop.t:
        case ida_hexrays.mop_r: # register value
            # logger.warning("register lifting not implemented, None is returned")
            return None
        case ida_hexrays.mop_n: # immediate value
            res = ir.Constant(ir.IntType(mop.size * 8), mop.nnn.value)
            res.parent = blk
            return res
        case ida_hexrays.mop_d: # another instruction
            d = lift_insn(mop.d, blk, builder)
            td = llvm.create_target_data("e")
            match mop:
                case voidType if isinstance(d.type, ir.VoidType):
                    pass
                case mcall if isinstance(mcall, ida_hexrays.mcallarg_t):
                    lltype = ida2llvm.type.lift_tif(mop.type)
                    d = ida2llvm.type.typecast(d, lltype, builder, signed=mop.type.is_signed())
                case sizeEnforced if d.type.get_abi_size(td) != mop.size and mop.size != -1:
                    d = ida2llvm.type.typecast(d, ir.IntType(mop.size * 8), builder)
            return d
        case ida_hexrays.mop_l: # local variables
            lvar_ref = mop.l
            lvar = lvar_ref.var()
            name = lvar.name
            off = lvar_ref.off

            if not lvar.has_user_type:
                ulvars = lvar_ref.mba.vars
                ulvar = ulvars.at(lvar_ref.idx)
                lvar.set_final_lvar_type(ulvar.tif)
                lvar.set_user_type()

            func = blk.parent
            if name not in func.lvars:
                with builder.goto_entry_block():                
                    func.lvars[name] = builder.alloca(ida2llvm.type.lift_tif(lvar.tif), name = name)

            llvm_arg = func.lvars[name]

            if lvar.width != mop.size and mop.size != -1:
                mop_type = ir.IntType(mop.size * 8).as_pointer()
                llvm_arg = ida2llvm.type.typecast(llvm_arg, mop_type, builder)

            llvm_arg = ida2llvm._utils.get_offset_to(builder, llvm_arg, off)
            return builder.load(llvm_arg)
        case ida_hexrays.mop_S: # stack variables
            pass
        case ida_hexrays.mop_b: # block number (used in jmp\call instruction)
            return blk.parent.blocks[mop.b]
        case ida_hexrays.mop_v: # global variable
            ea = mop.g
            name = ida_name.get_name(ea)
            if name == "":
                name = f"g_{hex(ea)}"
            tif = ida_typeinf.tinfo_t()
            ida_nalt.get_tinfo(tif, ea)
            if tif.empty():
                match mop.size:
                    case 1:
                        tif.create_simple_type(ida_typeinf.BT_UNK_BYTE)
                    case 2:
                        tif.create_simple_type(ida_typeinf.BT_UNK_WORD)
                    case 4:
                        tif.create_simple_type(ida_typeinf.BT_UNK_DWORD)
                    case 8:
                        tif.create_simple_type(ida_typeinf.BT_UNK_QWORD)
                    case 16:
                        tif.create_simple_type(ida_typeinf.BT_UNK_OWORD)
                    case _:
                        size = mop.size if mop.size > 0 else 1000
                        onebyte_tif = ida_typeinf.tinfo_t()
                        onebyte_tif.create_simple_type(ida_typeinf.BT_UNK_BYTE)
                        tif.create_array(onebyte_tif, size, 0, ida_typeinf.BT_ARRAY)
            match tif:
                case func if func.is_func() or func.is_funcptr():
                    with suppress(KeyError):
                        g = blk.parent.parent.get_global(name)
                        typ = ida2llvm.type.lift_tif(tif).as_pointer()
                        g = ida2llvm.type.typecast(g, typ, builder)
                        return g
                    if func.is_funcptr():
                        tif = tif.get_ptrarr_object()
                    # if function is a thunk function, define the actual function instead
                    if ida_funcs.get_func(ea).flags & ida_funcs.FUNC_THUNK: 
                        tfunc_ea, ptr = ida_funcs.calc_thunk_func_target(ida_funcs.get_func(ea))
                        if tfunc_ea != ida_idaapi.BADADDR:
                            ea = tfunc_ea
                            name = ida_name.get_name(ea)
                    
                    # if no function definition,
                    if ((ida_funcs.get_func(ea) is None)
                    # or if the function is a library function,
                    or (ida_funcs.get_func(ea).flags & ida_funcs.FUNC_LIB) 
                    # or if the function is declared in a XTRN segment,
                    or ida_segment.segtype(ea) & ida_segment.SEG_XTRN): 
                        # return function declaration
                        g = ida2llvm.function.lift_function(blk.parent.parent, name, True, tif)
                    else:
                        g = ida2llvm.function.lift_function(blk.parent.parent, name, False, tif)
                    return g
                case _:
                    with suppress(KeyError):
                        g = blk.parent.parent.get_global(name)
                        return builder.load(g)
                    typ = ida2llvm.type.lift_tif(tif)
                    g_cmt = ida2llvm.address.lift_from_address(blk.parent.parent, ea, typ)
                    g = ir.GlobalVariable(blk.parent.parent, g_cmt.type, name = name)
                    g.initializer = g_cmt
                    td = llvm.create_target_data("e")
                    if g.type.get_abi_size(td) != mop.size and mop.size != -1:
                        g = ida2llvm.type.typecast(g, ir.IntType(mop.size * 8).as_pointer(), builder)
                    return builder.load(g)
        case ida_hexrays.mop_f: # function call information
            mcallinfo = mop.f
            f_args = []

            for arg in mcallinfo.args:
                typ = ida2llvm.type.lift_tif(arg.type)
                f_arg = lift_mop(arg, blk, builder)
                f_arg = ida2llvm.type.typecast(f_arg, typ, builder)
                logger.debug(f"{f_arg} ({f_arg.type}) lifted from {arg} ({typ})")
                f_args.append(f_arg)
            return f_args
        case ida_hexrays.mop_a: # operating number address (mop_l\mop_v\mop_S\mop_r)
            mop_addr = mop.a
            val = ida2llvm._utils.dedereference(lift_mop(mop_addr, blk, builder))
            match mop:
                case mcall if isinstance(mcall, ida_hexrays.mcallarg_t):
                    lltype = ida2llvm.type.lift_tif(mop.type)
                    val = ida2llvm.type.typecast(val, lltype, builder)
                case mop_addr if isinstance(mop_addr, ida_hexrays.mop_addr_t):
                    lltype = ida2llvm.type.lift_tif(mop.type)
                    val = ida2llvm.type.typecast(val, lltype, builder)
                case _:
                    lltype = ir.IntType(8).as_pointer()
                    val = ida2llvm.type.typecast(val, lltype, builder)
            return val
        case ida_hexrays.mop_h: # auxiliary function number
            return ida2llvm.function.lift_intrinsic_function(blk.parent.parent, mop.helper)
        case ida_hexrays.mop_str: # string constant
            str_csnt = mop.cstr

            strType = ir.ArrayType(ir.IntType(8), len(str_csnt))
            g = ir.GlobalVariable(blk.parent.parent, strType, name=str_csnt)
            g.initializer = ir.Constant(strType, bytearray(str_csnt.encode("utf-8")))
            g.linkage = "private"
            g.global_constant = True
            return ida2llvm.type.typecast(g, ir.IntType(8).as_pointer(), builder)
        case ida_hexrays.mop_c: # switch case and target
            pass
        case ida_hexrays.mop_fn: # floating points constant
            pass
        case ida_hexrays.mop_p: # the number of operations is correct
            pass
        case ida_hexrays.mop_sc: # decentralized operation information
            pass
        case ida_hexrays.mop_z: # does not exist
            return None
    mop_descs = {ida_hexrays.mop_r: "register value",
                ida_hexrays.mop_n: "immediate value",
                ida_hexrays.mop_d: "another instruction",
                ida_hexrays.mop_l: "local variables",
                ida_hexrays.mop_S: "stack variables",
                ida_hexrays.mop_b: "block number (used in jmp\call instruction)",
                ida_hexrays.mop_v: "global variable",
                ida_hexrays.mop_f: "function call information",
                ida_hexrays.mop_a: "operating number address (mop_l\mop_v\mop_S\mop_r)",
                ida_hexrays.mop_h: "auxiliary function number",
                ida_hexrays.mop_str: "string constant",
                ida_hexrays.mop_c: "switch case and target",
                ida_hexrays.mop_fn: "floating points constant",
                ida_hexrays.mop_p: "the number of operations is correct",
                ida_hexrays.mop_sc: "decentralized operation information"
    }
    raise NotImplementedError(f"not implemented: {mop.dstr()} of type {mop_descs[mop.t]}")

def _store_as(l: ir.Value, d: ir.Value, blk: ir.Block, builder: ir.IRBuilder, d_typ: ir.Type = None, signed: bool = True):
    """
    Private helper function to store value to destination.
    """
    if d is None:  # destination does not exist
        return l

    d = ida2llvm._utils.dedereference(d)
    if d_typ:
        d = ida2llvm.type.typecast(d, d_typ, builder, signed)
    assert isinstance(d.type, ir.PointerType)

    if isinstance(d.type.pointee, ir.ArrayType):
        arrtoptr = d.type.pointee.element.as_pointer()
        d = ida2llvm.type.typecast(d, arrtoptr.as_pointer(), builder, signed)

    if isinstance(l.type, ir.VoidType):
        return

    l = ida2llvm.type.typecast(l, d.type.pointee, builder, signed)
    return builder.store(l, d)

def lift_insn(ida_insn: ida_hexrays.minsn_t, blk: ir.Block, builder: ir.IRBuilder) -> ir.Instruction:
    """Heavylifter function that lifts a given IDA Microcode instruction.

    A given ida instruction could comprise multiple Instructions.
    Note that only final instruction is returned.
    Intermediate instructions emitted discretely into `blk`.

    :param ida_insn: IDA Microcode instruction
    :type ida_insn: ida_hexrays.minsn_t
    :param blk: LLVM Block to emit instructions into
    :type blk: ir.Block
    :raises NotImplementedError: m_add only supports addition between integers/pointers
    :raises NotImplementedError: m_sub only supports subtraction between integers/pointers
    :raises NotImplementedError: certain minsn_t have not been lifted yet
    :param builder: builder to emit instructions into
    :type builder: ir.IRBuilder
    :return: final instruction (intermediate instructions emitted are not returned)
    :rtype:ir.Instruction
    """
    builder.position_at_end(blk)
    logger.debug(str(ida_insn.dstr()))
    l = lift_mop(ida_insn.l, blk, builder)
    r = lift_mop(ida_insn.r, blk, builder)
    d = lift_mop(ida_insn.d, blk, builder)
    logger.debug(f"{chr(10).join('-'+str(i) for i in (l,r,d) if i)}")
    blk_itr = iter(blk.parent.blocks)
    list(itertools.takewhile(lambda x: x.name != blk.name, blk_itr)) # consume iter
    next_blk = next(blk_itr, None)

    match ida_insn.opcode:
        case ida_hexrays.m_nop:  # 0x00,  nop    no operation
            return
        case ida_hexrays.m_stx:  # 0x01,  stx  l,    {r=sel, d=off}  store register to memory*F
            if d is None:  # destination does not exist
                return l
            if isinstance(l.type, ir.VoidType):
                return

            if isinstance(d.type, ir.ArrayType):
                arrtoptr = d.type.element.as_pointer()
                d = ida2llvm.type.typecast(d, arrtoptr, builder, True)
            elif isinstance(d.type, ir.IntType):
                d = builder.inttoptr(d, l.type.as_pointer())

            assert isinstance(d.type, ir.PointerType)
            l = ida2llvm.type.typecast(l, d.type.pointee, builder, True)
            return builder.store(l, d)
        case ida_hexrays.m_ldx:  # 0x02,  ldx  {l=sel,r=off}, d load    register from memory    *F
            if not isinstance(r.type, ir.PointerType):
                register_size = 8*ida_insn.r.size
                r = ida2llvm.type.typecast(r, ir.IntType(register_size).as_pointer(), builder)    
            r = builder.load(r)

            return _store_as(r, d, blk, builder)
        case ida_hexrays.m_ldc:  # 0x03,  ldc  l=const,d   load constant
            pass
        case ida_hexrays.m_mov:  # 0x04,  mov  l, d   move*F
            return _store_as(l, d, blk, builder)
        case ida_hexrays.m_neg:  # 0x05,  neg  l, d   negate
            l = builder.neg(l)
            l = builder.load(l)
            return _store_as(l, d, blk, builder)
        case ida_hexrays.m_lnot:  # 0x06,  lnot l, d   logical not
            assert isinstance(l.type, ir.IntType)
            cmp = builder.icmp_unsigned("==", l, ir.IntType(l.type.width)(0))
            return _store_as(cmp, d, blk, builder)
        case ida_hexrays.m_bnot:  # 0x07,  bnot l, d   bitwise not
            l = builder.xor(l.type(pow(l, l.type.width) - 1), l)
            return _store_as(l, d, blk, builder)
        case ida_hexrays.m_xds:  # 0x08,  xds  l, d   extend (signed)
            return _store_as(l, d, blk, builder)
        case ida_hexrays.m_xdu:  # 0x09,  xdu  l, d   extend (unsigned)
            return _store_as(l, d, blk, builder, signed=False)
        case ida_hexrays.m_low:  # 0x0A,  low  l, d   take low part
            return _store_as(l, d, blk, builder)
        case ida_hexrays.m_high:  # 0x0B,  high l, d   take high part
            return _store_as(l, d, blk, builder)
        case ida_hexrays.m_add:  # 0x0C,  add  l,   r, d   l + r -> dst
            match (l, r):
                case (ptr, const) if isinstance(ptr.type, ir.PointerType) and isinstance(const.type, ir.IntType):
                    castPtr = builder.bitcast(ptr, ir.IntType(8).as_pointer())
                    math = builder.gep(castPtr, (const, ))
                    math = builder.bitcast(math, ptr.type)
                case (const, ptr) if isinstance(ptr.type, ir.PointerType) and isinstance(const.type, ir.IntType):
                    castPtr = builder.bitcast(ptr, ir.IntType(8).as_pointer())
                    math = builder.gep(castPtr, (const, ))
                    math = builder.bitcast(math, ptr.type)
                case (const1, const2) if isinstance(const1.type, ir.IntType) and isinstance(const2.type, ir.IntType):
                    math = builder.add(const1, const2)
                case (ptr1, ptr2) if isinstance(ptr1.type, ir.PointerType) and isinstance(ptr2.type, ir.PointerType):
                    ptrType = ir.IntType(64) # get pointer type
                    const1 = builder.ptrtoint(ptr1, ptrType)
                    const2 = builder.ptrtoint(ptr2, ptrType)
                    math = builder.add(const1, const2)
                case _:
                    raise NotImplementedError("expected addition between pointer/integers")
            return _store_as(math, d, blk, builder) 
        case ida_hexrays.m_sub:  # 0x0D,  sub  l,   r, d   l - r -> dst
            match (l, r):
                case (ptr, const) if isinstance(ptr.type, ir.PointerType) and isinstance(const.type, ir.IntType):
                    const.constant *= -1
                    castPtr = builder.bitcast(ptr, ir.IntType(8).as_pointer())
                    math = builder.gep(castPtr, (const, ))
                    math = builder.bitcast(math, ptr.type)
                case (const, ptr) if isinstance(ptr.type, ir.PointerType) and isinstance(const.type, ir.IntType):
                    const.constant *= -1
                    castPtr = builder.bitcast(ptr, ir.IntType(8).as_pointer())
                    math = builder.gep(castPtr, (const, ))
                    math = builder.bitcast(math, ptr.type)
                case (const1, const2) if isinstance(const1.type, ir.IntType) and isinstance(const2.type, ir.IntType):
                    math = builder.sub(const1, const2)
                case (ptr1, ptr2) if isinstance(ptr1.type, ir.PointerType) and isinstance(ptr2.type, ir.PointerType):
                    ptrType = ir.IntType(64) # get pointer type
                    const1 = builder.ptrtoint(ptr1, ptrType)
                    const2 = builder.ptrtoint(ptr2, ptrType)
                    math = builder.sub(const1, const2)
                case _:
                    raise NotImplementedError("expected subtraction between pointer/integers")
            return _store_as(math, d, blk, builder) 
        case ida_hexrays.m_mul:  # 0x0E,  mul  l,   r, d   l * r -> dst
            math = builder.mul(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_udiv:  # 0x0F,  udiv l,   r, d   l / r -> dst
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.udiv(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_sdiv:  # 0x10,  sdiv l,   r, d   l / r -> dst
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.sdiv(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_umod:  # 0x11,  umod l,   r, d   l % r -> dst
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.urem(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_smod:  # 0x12,  smod l,   r, d   l % r -> dst
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.srem(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_or:  # 0x13,  or   l,   r, d   bitwise or
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.or_(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_and:  # 0x14,  and  l,   r, d   bitwise and
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.and_(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_xor:  # 0x15,  xor  l,   r, d   bitwise xor
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.xor(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_shl:  # 0x16,  shl  l,   r, d   shift logical left
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.shl(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_shr:  # 0x17,  shr  l,   r, d   shift logical right
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.shr(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_sar:  # 0x18,  sar  l,   r, d   shift arithmetic right
            r = ida2llvm.type.typecast(r, l.type, builder)
            math = builder.ashr(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_cfadd:  # 0x19,  cfadd l,  r,    d=carry    calculate carry    bit of (l+r)
            math = builder.sadd_with_overflow(l, r) # a { result, overflow bit } structure is returned
            math = math.gep((ir.IntType(64)(0), ir.IntType(64)(0)))
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_ofadd:  # 0x1A,  ofadd l,  r,    d=overf    calculate overflow bit of (l+r)
            math = builder.sadd_with_overflow(l, r) # a { result, overflow bit } structure is returned
            math = math.gep((ir.IntType(64)(0), ir.IntType(64)(1)))
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_cfshl:  # 0x1B,  cfshl l,  r,    d=carry    calculate carry    bit of (l<<r)
            pass
        case ida_hexrays.m_cfshr:  # 0x1C,  cfshr l,  r,    d=carry    calculate carry    bit of (l>>r)
            pass
        case ida_hexrays.m_sets:  # 0x1D,  sets  l,d=byte  SF=1Sign
            pass
        case ida_hexrays.m_seto:  # 0x1E,  seto  l,  r, d=byte  OF=1Overflow of (l-r)
            pass
        case ida_hexrays.m_setp:  # 0x1F,  setp  l,  r, d=byte  PF=1Unordered/Parity  *F
            pass
        case ida_hexrays.m_setnz:  # 0x20,  setnz l,  r, d=byte  ZF=0Not Equal    *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned("!=", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_setz:  # 0x21,  setz  l,  r, d=byte  ZF=1Equal   *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned("==", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_setae:  # 0x22,  setae l,  r, d=byte  CF=0Above or Equal    *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned(">=", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_setb:  # 0x23,  setb  l,  r, d=byte  CF=1Below   *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned("<", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_seta:  # 0x24,  seta  l,  r, d=byte  CF=0 & ZF=0   Above   *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned(">", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_setbe:  # 0x25,  setbe l,  r, d=byte  CF=1 | ZF=1   Below or Equal    *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned("<=", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_setg:  # 0x26,  setg  l,  r, d=byte  SF=OF & ZF=0  Greater
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_signed(">", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_setge:  # 0x27,  setge l,  r, d=byte  SF=OF    Greater or Equal
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_signed(">=", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_setl:  # 0x28,  setl  l,  r, d=byte  SF!=OF   Less
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_signed("<", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_setle:  # 0x29,  setle l,  r, d=byte  SF!=OF | ZF=1 Less or Equal
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_signed("<=", l, r)
            result = builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0))
            return _store_as(result, d, blk, builder)
        case ida_hexrays.m_jcnd:  # 0x2A,  jcnd   l,    d   d is mop_v or mop_b
            return builder.cbranch(l, d, next_blk)
        case ida_hexrays.m_jnz:  # 0x2B,  jnz    l, r, d   ZF=0Not Equal *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned("!=", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jz:  # 0x2C,  jzl, r, d   ZF=1Equal*F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned("==", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jae:  # 0x2D,  jae    l, r, d   CF=0Above or Equal *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned(">=", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jb:  # 0x2E,  jbl, r, d   CF=1Below*F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned("<", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_ja:  # 0x2F,  jal, r, d   CF=0 & ZF=0   Above*F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned(">", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jbe:  # 0x30,  jbe    l, r, d   CF=1 | ZF=1   Below or Equal *F
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_unsigned("<=", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jg:  # 0x31,  jgl, r, d   SF=OF & ZF=0  Greater
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_signed(">", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jge:  # 0x32,  jge    l, r, d   SF=OF    Greater or Equal
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_signed(">=", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jl:  # 0x33,  jll, r, d   SF!=OF   Less
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_signed("<", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jle:  # 0x34,  jle    l, r, d   SF!=OF | ZF=1 Less or Equal
            l = ida2llvm.type.typecast(l, ir.IntType(64), builder)
            r = ida2llvm.type.typecast(r, ir.IntType(64), builder)
            cond = builder.icmp_signed("<=", l, r)
            return builder.cbranch(cond, d, next_blk)
        case ida_hexrays.m_jtbl:  # 0x35,  jtbl   l, r=mcases    Table jump
            pass
        case ida_hexrays.m_ijmp:  # 0x36,  ijmp  {r=sel, d=off}  indirect unconditional jump
            pass
        case ida_hexrays.m_goto:  # 0x37,  goto   l    l is mop_v or mop_b
            return builder.branch(l)
        case ida_hexrays.m_call:  # 0x38,  call   ld   l is mop_v or mop_b or mop_h
            args = list(d)
            for (i, llvmtype) in enumerate(l.type.pointee.args):
                args[i] = ida2llvm.type.typecast(args[i], llvmtype, builder)
            
            if l.type.pointee.var_arg: # function is variadic
                function = blk.parent
                if "ArgList" in function.lvars:
                    logger.warning("nested variadic function detected, variadic arguments will not be passed properly")
                ltype = l.type.pointee
                newargs = list(ltype.args)
                for i in range(len(newargs), len(args)):
                    newargs.append(args[i].type)
                new_func_type = ir.FunctionType(ltype.return_type, newargs, var_arg=True).as_pointer()
                # l = ida2llvm.type.typecast(l, new_func_type, builder)
            logger.debug(f"lifting call: {l.type} {d}")
            return builder.call(l, args)
        case ida_hexrays.m_icall:  # 0x39,  icall  {l=sel, r=off} d    indirect call
            ftype = ir.FunctionType(ir.IntType(8).as_pointer(), (arg.type for arg in d))
            f = ida2llvm.type.typecast(r, ftype.as_pointer(), builder)
            return builder.call(f, d)
        case ida_hexrays.m_ret:  # 0x3A,  ret
            pass
        case ida_hexrays.m_push:  # 0x3B,  push   l
            pass
        case ida_hexrays.m_pop:  # 0x3C,  popd
            pass
        case ida_hexrays.m_und:  # 0x3D,  undd   undefine
            pass
        case ida_hexrays.m_ext:  # 0x3E,  ext  in1, in2,  out1  external insn, not microcode *F
            pass
        case ida_hexrays.m_f2i:  # 0x3F,  f2il,    d int(l) => d; convert fp -> integer   +F
            pass
        case ida_hexrays.m_f2u:  # 0x40,  f2ul,    d uint(l)=> d; convert fp -> uinteger  +F
            pass
        case ida_hexrays.m_i2f:  # 0x41,  i2fl,    d fp(l)  => d; convert integer -> fp e +F
            pass
        case ida_hexrays.m_u2f:  # 0x42,  i2fl,    d fp(l)  => d; convert uinteger -> fp  +F
            pass
        case ida_hexrays.m_f2f:  # 0x43,  f2fl,    d l => d; change fp precision+F
            pass
        case ida_hexrays.m_fneg:  # 0x44,  fneg    l,    d -l=> d; change sign   +F
            assert l.isfloat() and r.isfloat()
            math = builder.fadd(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_fadd:  # 0x45,  fadd    l, r, d l + r  => d; add +F
            assert l.isfloat() and r.isfloat()
            math = builder.fadd(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_fsub:  # 0x46,  fsub    l, r, d l - r  => d; subtract +F
            assert l.isfloat() and r.isfloat()
            math = builder.fsub(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_fmul:  # 0x47,  fmul    l, r, d l * r  => d; multiply +F
            assert l.isfloat() and r.isfloat()
            math = builder.fmul(l, r)
            return _store_as(math, d, blk, builder)
        case ida_hexrays.m_fdiv:  # 0x48,  fdiv    l, r, d l / r  => d; divide   +F
            assert l.isfloat() and r.isfloat()
            math = builder.fdiv(l, r)
            return _store_as(math, d, blk, builder)
    raise NotImplementedError(f"not implemented {ida_insn.dstr()}")