import logging
import llvmlite.binding as llvm

from llvmlite import ir

logger = logging.getLogger(__name__)

def get_offset_to(arg: ir.Value, off: int = 0) -> ir.Value:
    """
    A Value can be indexed relative to some offset.

    :param arg: value to index from
    :type arg: ir.Value
    :param off: offset to index, defaults to 0
    :type off: int, optional
    :return: value after indexing by off
    :rtype: ir.Value
    """
    match arg:
        case ptr if isinstance(arg.type, ir.PointerType) and isinstance(ptr.type.pointee, ir.ArrayType):
            builder = ir.IRBuilder(arg.parent)
            with builder.goto_block(arg.parent):
                arr = ptr.type.pointee
                td = llvm.create_target_data("e")
                size = arr.element.get_abi_size(td)
                return builder.gep(ptr, (ir.Constant(ir.IntType(8), 0), ir.Constant(ir.IntType(8), off // size),))
        case ptr if isinstance(arg.type, ir.PointerType) and isinstance(ptr.type.pointee, ir.LiteralStructType):
            builder = ir.IRBuilder(arg.parent)
            with builder.goto_block(arg.parent):
                return builder.bitcast(ptr, ir.IntType(8).as_pointer())
        case _:
            return arg

def dedereference(arg: ir.Value) -> ir.Value:
    """
    A memory address is deferenced if the memory at the address is loaded.
    In LLVM, a LoadInstruction instructs the CPU to perform the dereferencing.

    In cases where we wish to retrieve the memory address, we "de-dereference".
    - this is needed as IDA microcode treats all LVARS as registers
    - whereas during lifting we treat all LVARS as stack variables (in accordance to LLVM SSA)

    :param arg: value to de-dereference
    :type arg: ir.Value
    :raises NotImplementedError: arg is not of type LoadInstr
    :return: original memory address
    :rtype: ir.Value
    """
    match arg:
        case arg if isinstance(arg, ir.LoadInstr):
            return arg.operands[0]
        case arg if isinstance(arg.type, ir.PointerType):
            return arg
        case _:
            raise NotImplementedError(f"not implemented: get reference for object {arg} of type {arg.type}")

