import ida_name
import ida_idaapi
import ida_hexrays
import ida_funcs
import ida_typeinf
import ida_nalt
import ida_bytes
import ida_segment

from llvmlite import ir

from llvmgen.singleton import MethodGlobal
import llvmgen.type

class Function(metaclass=MethodGlobal):
    def __init__(self, func_name, module, llvm_func_type=None):
        ir.Value.isptr = lambda x: isinstance(x.type, ir.PointerType)
        ir.Value.isint = lambda x: isinstance(x.type, ir.IntType)
        ir.Value.isfloat = lambda x: isinstance(x.type, (ir.FloatType, ir.DoubleType))
        ir.Type.isptr = lambda x: isinstance(x, ir.PointerType)
        ir.Type.isint = lambda x: isinstance(x, ir.IntType)
        ir.Type.isfloat = lambda x: isinstance(x, (ir.FloatType, ir.DoubleType))

        self.func_name = func_name
        self.libmodule = module
        self.module = self.libmodule.module

        print("declaring", func_name, llvm_func_type)
        if llvm_func_type is None:
            self.mba = self.get_microcode(self.func_name)
            self.tif = self.mba.idb_type
            llvm_func_type = llvmgen.type.lift_type(self.tif)
            print("retrieved", func_name, llvm_func_type, self.tif)
        self.llvm_f = ir.Function(self.module, 
                                  llvm_func_type, 
                                  self.func_name)

    def is_defined(self):
        # the function has been defined before
        return hasattr(self, 'builder')

    def define_function(self):
        if self.is_defined():
            return

        for index in range(self.mba.qty):
            blkname = f"@{self.func_name}{index}"
            self.llvm_f.append_basic_block(name=blkname) 

        self.builder = ir.IRBuilder(self.llvm_f.entry_basic_block)
        self.llvm_stack_args = {}

        # define function arguments
        self.define_args()

        # lift CFG information
        self.lift_cfg()

        # define function return type
        self.define_rettype()

    def define_args(self):
        with self.builder.goto_entry_block():
            llvm_functype = self.llvm_f.ftype
            names = Function.get_arg_names(self.tif)

            for arg, arg_t, name in zip(self.llvm_f.args,
                                        llvm_functype.args,
                                        names):
                ptr = self.builder.alloca(arg_t, name = name)
                self.builder.store(arg, ptr)
                self.llvm_stack_args[name] = ptr

            # declare function results as stack variable
            if not isinstance(llvm_functype.return_type, ir.VoidType):
                ptr = self.builder.alloca(llvm_functype.return_type, name = "result")
                self.llvm_stack_args["result"] = ptr

            # if function is variadic, declare va_start intrinsic
            if self.tif.is_vararg_cc() and llvm_functype.var_arg:
                ptr = self.builder.alloca(ir.IntType(8).as_pointer(), name = "ArgList")
                self.llvm_stack_args["ArgList"] = ptr
                va_start = self.module.declare_intrinsic('llvm.va_start', fnty=ir.FunctionType(ir.VoidType(), [ir.IntType(8).as_pointer()]))
                ptr = self.builder.bitcast(ptr, ir.IntType(8).as_pointer())
                self.builder.call(va_start, (ptr, ))

    def define_rettype(self):
        self.builder.position_at_end(self.llvm_f.blocks[-1])
        if isinstance(self.llvm_f.ftype.return_type, ir.VoidType):
            self.builder.ret_void()
        else:
            result = llvmgen.type.load(self.builder, self.llvm_stack_args["result"])
            self.builder.ret(result)

    def lift_cfg(self):
        from itertools import pairwise

        for index, (blk, next_blk) in enumerate(pairwise(self.llvm_f.blocks)):
            ida_blk = self.mba.get_mblock(index)

            self.builder.position_at_end(blk)

            ida_insn = ida_blk.head
            while ida_insn is not None:
                self.lift_insn(ida_insn, index)
                ida_insn = ida_insn.next

            if not blk.is_terminated:
                self.builder.branch(next_blk)

    @staticmethod
    def get_arg_names(ida_functif):
        ida_func_details = ida_typeinf.func_type_data_t()
        ida_functif.get_func_details(ida_func_details)
        ida_args = (ida_func_details.at(i) for i in range(ida_func_details.size()))
        return (arg.name for arg in ida_args)

    def get_microcode(self, func_name):
        self.func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, func_name)
        func = ida_funcs.get_func(self.func_ea)

        ida_hf = ida_hexrays.hexrays_failure_t()
        ida_mbr = ida_hexrays.mba_ranges_t()
        ida_mbr.ranges.push_back(func)

        self.lvars = ida_hexrays.decompile(func, ida_hf).lvars
        return ida_hexrays.gen_microcode(ida_mbr, ida_hf, None,
                                        ida_hexrays.DECOMP_NO_CACHE 
                                        | ida_hexrays.DECOMP_ALL_BLKS,
                                        ida_hexrays.MMAT_LVARS)

    def lift_mop(self, mop, blk, isptr = False, typeEnforce = None):
        match mop.t:
            case ida_hexrays.mop_r: # register value
                pass
            case ida_hexrays.mop_n: # immediate value
                bytesize = mop.size
                return ir.Constant(ir.IntType(bytesize * 8), mop.nnn.value)
            case ida_hexrays.mop_d: # another instruction
                d = self.lift_insn(mop.d, blk)
                import llvmlite.binding as llvm
                td = llvm.create_target_data("e-m:e-i64:64-f80:128-n8:16:32:64-S128")
                match mop:
                    case mcall if isinstance(mcall, ida_hexrays.mcallarg_t):
                        lltype = llvmgen.type.lift_type(mop.type)
                        d = llvmgen.type.change_type(self.builder, d, lltype)
                    case sizeEnforced if d.type.get_abi_size(td) != mop.size and mop.size != -1:
                        d = llvmgen.type.change_type(self.builder, d, ir.IntType(mop.size * 8))

                if typeEnforce:
                    d = llvmgen.type.change_type(self.builder, d, typeEnforce)
                return d

            case ida_hexrays.mop_l: # local variables
                lvar_ref = mop.l
                lvar = lvar_ref.var()
                name = lvar.name
                off = lvar_ref.off

                if not lvar.has_user_type:
                    for i in range(self.lvars.size()):
                        # search for ctree defined type information
                        if self.lvars.at(i).name == name:
                            lvar.set_final_lvar_type(self.lvars.at(i).tif)
                            lvar.set_user_type()

                # declare argument if not present
                if name not in self.llvm_stack_args:
                    with self.builder.goto_entry_block():
                        ptrtype = llvmgen.type.lift_type(lvar.tif)
                        ptr = self.builder.alloca(ptrtype, name = name)
                        self.llvm_stack_args[name] = ptr

                llvm_arg = self.llvm_stack_args[name]
                llvm_arg = llvmgen.type.retrieve_ptr(self.builder, llvm_arg, off)

                if lvar.width != mop.size and mop.size != -1:
                    llvm_arg = llvmgen.type.change_type(self.builder, llvm_arg, ir.IntType(mop.size * 8).as_pointer())
                if typeEnforce:
                    llvm_arg = llvmgen.type.change_type(self.builder, llvm_arg, typeEnforce.as_pointer())
                if isptr:
                    return llvm_arg
                return llvmgen.type.load(self.builder, llvm_arg)

            case ida_hexrays.mop_S: # stack variables
                pass
            case ida_hexrays.mop_b: # block number (used in jmp\call instruction)
                return self.llvm_f.blocks[mop.b]
            case ida_hexrays.mop_v: # global variable
                ea = mop.g
                tif = ida_typeinf.tinfo_t()
                ida_nalt.get_tinfo(tif, ea)
                name = ida_name.get_name(ea)
                
                import llvmlite.binding as llvm
                td = llvm.create_target_data("e-m:e-i64:64-f80:128-n8:16:32:64-S128")

                match tif:
                    case func if func.is_func() or func.is_funcptr():
                        try: # use try-except to check if global variable exists, as per documentation
                            return self.module.get_global(name)
                        except KeyError:
                            if func.is_funcptr():
                                tif = tif.get_ptrarr_object()
                            # if no function definition,
                            if ida_funcs.get_func(ea) is None:
                                return self.libmodule.declare_function(name, llvmgen.type.lift_type(tif)).llvm_f

                            # or if the function is a library function,
                            if ida_funcs.get_func(ea).flags & ida_funcs.FUNC_LIB:
                                return self.libmodule.declare_function(name, llvmgen.type.lift_type(tif)).llvm_f

                            # or if the function is declared in a XTRN segment,
                            if ida_segment.segtype(ea) & ida_segment.SEG_XTRN:
                                return self.libmodule.declare_function(name, llvmgen.type.lift_type(tif)).llvm_f
                            
                            return self.libmodule.define_function(name).llvm_f

                    case _:
                        try: # use try-except to check if global variable exists, as per documentation
                            g = self.module.get_global(name)
                        except KeyError:
                            gType = llvmgen.type.lift_type(tif)
                            # assert that if gType is a pointer, resolve once to find its pointee
                            g_cmt = llvmgen.type.lift_from_llvm_type(ea, gType, module=self.module, toplevel=True)
                            g = ir.GlobalVariable(self.module, g_cmt.type, name = name)
                            g.initializer = g_cmt
        
                        # g.align = 1
                        if typeEnforce:
                            g = llvmgen.type.change_type(self.builder, g, typeEnforce.as_pointer())
                        if isptr:
                            return g
                        if g.type.get_abi_size(td) != mop.size and mop.size != -1:
                            g = llvmgen.type.change_type(self.builder, g, ir.IntType(mop.size * 8).as_pointer())

                        return llvmgen.type.load(self.builder, g)

            case ida_hexrays.mop_f: # function call information
                mcallinfo = mop.f
                f_args = []
                for arg in mcallinfo.args:
                    llvmtype = llvmgen.type.lift_type(arg.type)
                    print("arg", len(f_args), llvmtype)
                    f_arg = self.lift_mop(arg, blk)
                    print("arg", len(f_args), f_arg)
                    f_arg = llvmgen.type.change_type(self.builder, f_arg, llvmtype)
                    f_args.append(f_arg)
                if mcallinfo.get_type().is_vararg_cc():
                    print("aw man this function is variadic we have a problem")
                return f_args

            case ida_hexrays.mop_a: # operating number address (mop_l\mop_v\mop_S\mop_r)
                mop_addr = mop.a
                val = self.lift_mop(mop_addr, blk, isptr=True)

                match mop:
                    case mcall if isinstance(mcall, ida_hexrays.mcallarg_t):
                        lltype = llvmgen.type.lift_type(mop.type)
                        val = llvmgen.type.change_type(self.builder, val, lltype)
                    case _:
                        lltype = ir.IntType(64)
                        val = llvmgen.type.change_type(self.builder, val, lltype)

                if typeEnforce:
                    return llvmgen.type.change_type(self.builder, val, typeEnforce)
                return val
            
            case ida_hexrays.mop_h: # auxiliary function number
                return self.libmodule.intrinsics(mop.helper)

            case ida_hexrays.mop_str: # string constant
                str_csnt = mop.cstr

                strType = ir.ArrayType(ir.IntType(8), len(str_csnt))
                g = ir.GlobalVariable(self.module, strType, name=str_csnt)
                g.initializer = ir.Constant(strType, bytearray(str_csnt.encode("utf-8")))
                g.linkage = "private"
                g.global_constant = True
                return llvmgen.type.change_type(self.builder, g, ir.IntType(8).as_pointer())

            case ida_hexrays.mop_c: # switch case and target
                pass
            case ida_hexrays.mop_fn: # floating points constant
                pass
            case ida_hexrays.mop_p: # the number of operations is correct
                pass
            case ida_hexrays.mop_sc: # decentralized operation information
                pass

    def lift_insn(self, ida_insn, blk):
        match ida_insn.opcode:
            case ida_hexrays.m_nop:  # 0x00,  nop    no operation
                pass
            case ida_hexrays.m_stx:  # 0x01,  stx  l,    {r=sel, d=off}  store register to memory*F
                print(hex(ida_insn.ea),"stx")
                d = self.lift_mop(ida_insn.l, blk)
                d = llvmgen.type.change_type(self.builder, d, ir.IntType(64))
 
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    print(hex(ida_insn.ea),"stx", d)
                    return d

                dst = self.lift_mop(ida_insn.d, blk)
                dst = llvmgen.type.change_type(self.builder, dst, ir.IntType(64).as_pointer())
                print(hex(ida_insn.ea),"stx", d, dst)
                return llvmgen.type.store(self.builder, d, dst)
            case ida_hexrays.m_ldx:  # 0x02,  ldx  {l=sel,r=off}, d load register from memory    *F
                print(hex(ida_insn.ea),"ldx")
                d = self.lift_mop(ida_insn.r, blk)
                match d:
                    case ptr if ptr.isptr():
                        d = self.builder.bitcast(ptr, ir.IntType(64).as_pointer())
                    case intcast if intcast.isint():
                        # more work needs to be done here
                        d = self.builder.inttoptr(d, ir.PointerType(ir.IntType(64))) # get pointer type
 
                result = llvmgen.type.load(self.builder, d)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    print(hex(ida_insn.ea),"ldx", result)
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                print(hex(ida_insn.ea),"ldx", result, dst)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_ldc:  # 0x03,  ldc  l=const,d   load constant
                pass
            case ida_hexrays.m_mov:  # 0x04,  mov  l, d   move*F
                print(hex(ida_insn.ea),"mov")
                l = self.lift_mop(ida_insn.l, blk)
                d = self.lift_mop(ida_insn.d, blk, True)
                print(hex(ida_insn.ea),"mov", l, d)
                result = llvmgen.type.store(self.builder, l, d)
                return result
            case ida_hexrays.m_neg:  # 0x05,  neg  l, d   negate
                print(hex(ida_insn.ea),"neg")
                d = self.lift_mop(ida_insn.l, blk)
                d = self.builder.neg(d)
                result = llvmgen.type.load(self.builder, d)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    print(hex(ida_insn.ea),"neg", result)
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                print(hex(ida_insn.ea),"neg", result, dst)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_lnot:  # 0x06,  lnot l, d   logical not
                print(hex(ida_insn.ea),"lnot")
                l = self.lift_mop(ida_insn.l, blk)
                assert l.isint()
                
                r = ir.IntType(l.type.width)(0)
                cmp = self.builder.icmp_unsigned("==", l, r)
                print(hex(ida_insn.ea),"lnot", cmp)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, cmp, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_bnot:  # 0x07,  bnot l, d   bitwise not
                print(hex(ida_insn.ea),"bnot")
                d = self.lift_mop(ida_insn.l, blk)

                if d.isptr():
                    d = self.builder.load(d)
                d = self.builder.xor(d.type(pow(2, d.type.width) - 1), d)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    print(hex(ida_insn.ea),"bnot", d)
                    return d
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                print(hex(ida_insn.ea),"bnot", d.type, dst.type)
                return llvmgen.type.store(self.builder, d, dst)
            case ida_hexrays.m_xds:  # 0x08,  xds  l, d   extend (signed)
                print(hex(ida_insn.ea),"xds")
                l = self.lift_mop(ida_insn.l, blk)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    print(hex(ida_insn.ea),"xds", l)
                    return l
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                print(hex(ida_insn.ea),"xds", l, d)
                return llvmgen.type.store(self.builder, l, d)
            case ida_hexrays.m_xdu:  # 0x09,  xdu  l, d   extend (unsigned)
                print(hex(ida_insn.ea),"xdu")
                l = self.lift_mop(ida_insn.l, blk)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    print(hex(ida_insn.ea),"xdu", l)
                    return l
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                print(hex(ida_insn.ea),"xdu", l, d)
                return llvmgen.type.store(self.builder, l, d)
            case ida_hexrays.m_low:  # 0x0A,  low  l, d   take low part
                print(hex(ida_insn.ea),"low")
                l = self.lift_mop(ida_insn.l, blk)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    print(hex(ida_insn.ea),"low", l.type)
                    return l
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                print(hex(ida_insn.ea),"low", l.type, d.type)
                return llvmgen.type.store(self.builder, l, d)
            case ida_hexrays.m_high:  # 0x0B,  high l, d   take high part
                print(hex(ida_insn.ea),"high")
                l = self.lift_mop(ida_insn.l, blk)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    print(hex(ida_insn.ea),"high", l)
                    return l
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                print(hex(ida_insn.ea),"high", l, d)
                return llvmgen.type.store(self.builder, l, d)
            case ida_hexrays.m_add:  # 0x0C,  add  l,   r, d   l + r -> dst
                print(hex(ida_insn.ea),"add")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                match (l, r):
                    case (ptr, const) if ptr.isptr() and const.isint():
                        castPtr = self.builder.bitcast(ptr, ir.IntType(8).as_pointer())
                        math = self.builder.gep(castPtr, (const, ))
                        math = self.builder.bitcast(math, ptr.type)
                    case (const, ptr) if ptr.isptr() and const.isint():
                        castPtr = self.builder.bitcast(ptr, ir.IntType(8).as_pointer())
                        math = self.builder.gep(castPtr, (const, ))
                        math = self.builder.bitcast(math, ptr.type)
                    case (const1, const2) if const1.isint() and const2.isint():
                        math = self.builder.add(const1, const2)
                    case (ptr1, ptr2) if ptr1.isptr() and ptr2.isptr():
                        ptrType = ir.IntType(64) # get pointer type
                        const1 = self.builder.ptrtoint(ptr1, ptrType)
                        const2 = self.builder.ptrtoint(ptr2, ptrType)
                        math = self.builder.add(const1, const2)
                    case _:
                        math = None
                print(hex(ida_insn.ea),"add", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_sub:  # 0x0D,  sub  l,   r, d   l - r -> dst
                print(hex(ida_insn.ea),"sub")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                match (l, r):
                    case (ptr, const) if ptr.isptr() and const.isint():
                        const.constant *= -1
                        castPtr = self.builder.bitcast(ptr, ir.IntType(8).as_pointer())
                        math = self.builder.gep(castPtr, (const, ))
                        math = self.builder.bitcast(math, ptr.type)
                    case (const, ptr) if ptr.isptr() and const.isint():
                        const.constant *= -1
                        castPtr = self.builder.bitcast(ptr, ir.IntType(8).as_pointer())
                        math = self.builder.gep(castPtr, (const, ))
                        math = self.builder.bitcast(math, ptr.type)
                    case (const1, const2) if const1.isint() and const2.isint():
                        math = self.builder.sub(const1, const2)
                    case (ptr1, ptr2) if ptr1.isptr() and ptr2.isptr():
                        ptrType = ir.IntType(64) # get pointer type
                        const1 = self.builder.ptrtoint(ptr1, ptrType)
                        const2 = self.builder.ptrtoint(ptr2, ptrType)
                        math = self.builder.sub(const1, const2)
                    case _:
                        math = None
                print(hex(ida_insn.ea),"sub", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)

            case ida_hexrays.m_mul:  # 0x0E,  mul  l,   r, d   l * r -> dst
                print(hex(ida_insn.ea),"mul")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                assert l.isint() and r.isint()
                math = self.builder.mul(l, r)
                
                print(hex(ida_insn.ea),"mul", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_udiv:  # 0x0F,  udiv l,   r, d   l / r -> dst
                print(hex(ida_insn.ea),"udiv")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.udiv(l, r)
                
                print(hex(ida_insn.ea),"udiv", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_sdiv:  # 0x10,  sdiv l,   r, d   l / r -> dst
                print(hex(ida_insn.ea),"sdiv")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.sdiv(l, r)
                
                print(hex(ida_insn.ea),"sdiv", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_umod:  # 0x11,  umod l,   r, d   l % r -> dst
                print(hex(ida_insn.ea),"umod")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.urem(l, r)
                
                print(hex(ida_insn.ea),"umod", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            
            case ida_hexrays.m_smod:  # 0x12,  smod l,   r, d   l % r -> dst
                print(hex(ida_insn.ea),"smod")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.srem(l, r)
                
                print(hex(ida_insn.ea),"smod", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_or:  # 0x13,  or   l,   r, d   bitwise or
                print(hex(ida_insn.ea),"or")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.or_(l, r)
                
                print(hex(ida_insn.ea),"or", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_and:  # 0x14,  and  l,   r, d   bitwise and
                print(hex(ida_insn.ea),"and")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()

                math = self.builder.and_(l, r)
                
                print(hex(ida_insn.ea),"and", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_xor:  # 0x15,  xor  l,   r, d   bitwise xor
                print(hex(ida_insn.ea),"xor")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.xor(l, r)
                
                print(hex(ida_insn.ea),"xor", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_shl:  # 0x16,  shl  l,   r, d   shift logical left
                print(hex(ida_insn.ea),"shl")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.shl(l, r)

                print(hex(ida_insn.ea),"shl", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_shr:  # 0x17,  shr  l,   r, d   shift logical right
                print(hex(ida_insn.ea),"shr")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.lshr(l, r)
                
                print(hex(ida_insn.ea),"shr", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_sar:  # 0x18,  sar  l,   r, d   shift arithmetic right
                print(hex(ida_insn.ea),"sar")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                r = llvmgen.type.change_type(self.builder, r, l.type)

                assert l.isint() and r.isint()
                math = self.builder.ashr(l, r)
                
                print(hex(ida_insn.ea),"sar", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_cfadd:  # 0x19,  cfadd l,  r,    d=carry    calculate carry    bit of (l+r)
                print(hex(ida_insn.ea),"cfadd")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                assert l.isint() and r.isint()
                math = self.builder.sadd_with_overflow(l, r) # a { result, overflow bit } structure is returned
                math = math.gep((ir.IntType(64)(0), ir.IntType(64)(0)))

                print(hex(ida_insn.ea),"cfadd", l, r, math)
                print("THIS IS VERY DUBIOUS CODE, PLEASE CHECK")
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_ofadd:  # 0x1A,  ofadd l,  r,    d=overf    calculate overflow bit of (l+r)
                print(hex(ida_insn.ea),"cfadd")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                assert l.isint() and r.isint()
                math = self.builder.sadd_with_overflow(l, r) # a { result, overflow bit } structure is returned
                math = math.gep((ir.IntType(64)(0), ir.IntType(64)(1)))

                print(hex(ida_insn.ea),"cfadd", l, r, math)
                print("THIS IS VERY DUBIOUS CODE, PLEASE CHECK")
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
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
                print(hex(ida_insn.ea),"setnz")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned("!=", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"setnz", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_setz:  # 0x21,  setz  l,  r, d=byte  ZF=1Equal   *F
                print(hex(ida_insn.ea),"setz")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned("==", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"setz", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_setae:  # 0x22,  setae l,  r, d=byte  CF=0Above or Equal    *F
                print(hex(ida_insn.ea),"setae")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned(">=", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"setae", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_setb:  # 0x23,  setb  l,  r, d=byte  CF=1Below   *F
                print(hex(ida_insn.ea),"m_setb")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned("<", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"m_setb", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_seta:  # 0x24,  seta  l,  r, d=byte  CF=0 & ZF=0   Above   *F
                print(hex(ida_insn.ea),"m_seta")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned(">", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"m_seta", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_setbe:  # 0x25,  setbe l,  r, d=byte  CF=1 | ZF=1   Below or Equal    *F
                print(hex(ida_insn.ea),"m_setbe")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned("<=", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"m_setbe", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_setg:  # 0x26,  setg  l,  r, d=byte  SF=OF & ZF=0  Greater
                print(hex(ida_insn.ea),"m_setg")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_signed(">", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"m_setg", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_setge:  # 0x27,  setge l,  r, d=byte  SF=OF    Greater or Equal
                print(hex(ida_insn.ea),"m_setge")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_signed(">=", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"m_setge", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_setl:  # 0x28,  setl  l,  r, d=byte  SF!=OF   Less
                print(hex(ida_insn.ea),"m_setl")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_signed("<", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"m_setl", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_setle:  # 0x29,  setle l,  r, d=byte  SF!=OF | ZF=1 Less or Equal
                print(hex(ida_insn.ea),"m_setle")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_signed("<=", l, r)
                result = self.builder.select(cond, ir.IntType(1)(1), ir.IntType(1)(0), name='')
                print(hex(ida_insn.ea),"m_setel", result)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return result
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, result, dst)
            case ida_hexrays.m_jcnd:  # 0x2A,  jcnd   l,    d   d is mop_v or mop_b
                l = self.lift_mop(ida_insn.l, blk)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(l, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jnz:  # 0x2B,  jnz    l, r, d   ZF=0Not Equal *F
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned("!=", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jz:  # 0x2C,  jzl, r, d   ZF=1Equal*F
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned("==", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jae:  # 0x2D,  jae    l, r, d   CF=0Above or Equal *F
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned(">=", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jb:  # 0x2E,  jbl, r, d   CF=1Below*F
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned("<", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_ja:  # 0x2F,  jal, r, d   CF=0 & ZF=0   Above*F
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned(">", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jbe:  # 0x30,  jbe    l, r, d   CF=1 | ZF=1   Below or Equal *F
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_unsigned("<=", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jg:  # 0x31,  jgl, r, d   SF=OF & ZF=0  Greater
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_signed(">", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jge:  # 0x32,  jge    l, r, d   SF=OF    Greater or Equal
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_signed(">=", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jl:  # 0x33,  jll, r, d   SF!=OF   Less
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_signed("<", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jle:  # 0x34,  jle    l, r, d   SF!=OF | ZF=1 Less or Equal
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)
                cond = self.builder.icmp_signed("<=", l, r)
                d = self.lift_mop(ida_insn.d, blk, isptr=True)
                return self.builder.cbranch(cond, d, self.llvm_f.blocks[blk+1])
            case ida_hexrays.m_jtbl:  # 0x35,  jtbl   l, r=mcases    Table jump
                pass
            case ida_hexrays.m_ijmp:  # 0x36,  ijmp  {r=sel, d=off}  indirect unconditional jump
                pass
            case ida_hexrays.m_goto:  # 0x37,  goto   l    l is mop_v or mop_b
                d = self.lift_mop(ida_insn.l, blk)
                return self.builder.branch(d)
            case ida_hexrays.m_call:  # 0x38,  call   ld   l is mop_v or mop_b or mop_h
                print(hex(ida_insn.ea), "call")
                f = self.lift_mop(ida_insn.l, blk, isptr=True)
                print(hex(ida_insn.ea), "call", f.name)
                args = self.lift_mop(ida_insn.d, blk)
                convertedArgs = []
                for (arg, llvmtype) in zip(args, f.type.pointee.args):
                    convertedArg = llvmgen.type.change_type(self.builder, arg, llvmtype)
                    convertedArgs.append(convertedArg)
                print(hex(ida_insn.ea), "call", f.name, f.type, [arg.type for arg in convertedArgs])
                return self.builder.call(f, convertedArgs)
            case ida_hexrays.m_icall:  # 0x39,  icall  {l=sel, r=off} d    indirect call
                print(hex(ida_insn.ea), "icall")
                f = self.lift_mop(ida_insn.r, blk)
                args = self.lift_mop(ida_insn.d, blk)
                ftype = ir.FunctionType(ir.IntType(8).as_pointer(), (arg.type for arg in args))
                f = llvmgen.type.change_type(self.builder, f, ftype.as_pointer())
                print(hex(ida_insn.ea), "icall", f)
                return self.builder.call(f, args)
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
                print(hex(ida_insn.ea),"fadd")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                assert l.isfloat() and r.isfloat()

                math = self.builder.fadd(l, r)
                
                print(hex(ida_insn.ea),"fadd", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_fadd:  # 0x45,  fadd    l, r, d l + r  => d; add +F
                print(hex(ida_insn.ea),"fadd")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                assert l.isfloat() and r.isfloat()

                math = self.builder.fadd(l, r)
                
                print(hex(ida_insn.ea),"fadd", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_fsub:  # 0x46,  fsub    l, r, d l - r  => d; subtract +F
                print(hex(ida_insn.ea),"fsub")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                assert l.isfloat() and r.isfloat()

                math = self.builder.fsub(l, r)
                
                print(hex(ida_insn.ea),"fsub", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_fmul:  # 0x47,  fmul    l, r, d l * r  => d; multiply +F
                print(hex(ida_insn.ea),"fmul")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                assert l.isfloat() and r.isfloat()

                math = self.builder.fmul(l, r)
                
                print(hex(ida_insn.ea),"fmul", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
            case ida_hexrays.m_fdiv:  # 0x48,  fdiv    l, r, d l / r  => d; divide   +F
                print(hex(ida_insn.ea),"fdiv")
                l = self.lift_mop(ida_insn.l, blk)
                r = self.lift_mop(ida_insn.r, blk)

                assert l.isfloat() and r.isfloat()

                math = self.builder.fdiv(l, r)
                
                print(hex(ida_insn.ea),"fdiv", l, r, math)
                if ida_insn.d.t == ida_hexrays.mop_z:  # destination does not exist
                    return math
                dst = self.lift_mop(ida_insn.d, blk, isptr=True)
                return llvmgen.type.store(self.builder, math, dst)
