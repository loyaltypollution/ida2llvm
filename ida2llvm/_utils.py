import logging
import llvmlite.binding as llvm
import ida_name

from llvmlite import ir

logger = logging.getLogger(__name__)

def get_offset_to(builder: ir.IRBuilder, arg: ir.Value, off: int = 0) -> ir.Value:
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
            arr = ptr.type.pointee
            td = llvm.create_target_data("e")
            size = arr.element.get_abi_size(td)
            return builder.gep(ptr, (ir.Constant(ir.IntType(8), 0), ir.Constant(ir.IntType(8), off // size),))
        case ptr if isinstance(arg.type, ir.PointerType) and isinstance(ptr.type.pointee, ir.LiteralStructType):
            return builder.bitcast(ptr, ir.IntType(8).as_pointer())
        case ptr if isinstance(arg.type, ir.PointerType) and off > 0:
            td = llvm.create_target_data("e")
            size = ptr.type.pointee.get_abi_size(td)
            return builder.gep(ptr, (ir.Constant(ir.IntType(8), off // size),))
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
        case arg if isinstance(arg, ir.Constant) and isinstance(arg.type, ir.IntType):
            # An integer constant already represents a raw value, not a loaded pointer.
            # For address-like immediates (e.g., EA 0x1 lifted as i64 1) we simply
            # return the constant; caller may inttoptr later if pointer semantics needed.
            return arg
        case _:
            raise NotImplementedError(f"not implemented: get reference for object {arg} of type {arg.type}")

def demangle_name(mangled_name: str) -> tuple[str, str]:
    """
    Demangle a function name for display purposes.
    Returns both the demangled and original mangled names.
    
    :param mangled_name: The mangled function name from IDA
    :type mangled_name: str
    :return: Tuple of (demangled_name, original_mangled_name)
    :rtype: tuple[str, str]
    """
    # Try to demangle the name
    demangled = ida_name.demangle_name(mangled_name, 0)
    
    # If demangling fails or returns empty, use the original name
    if not demangled or demangled == "":
        demangled = mangled_name
    
    return demangled, mangled_name

def create_name_comment(demangled_name: str, mangled_name: str) -> str:
    """
    Create a comment showing the original mangled name.
    
    :param demangled_name: The demangled/display name
    :type demangled_name: str
    :param mangled_name: The original mangled name
    :type mangled_name: str
    :return: Comment string to add to LLVM IR
    :rtype: str
    """
    # Only add comment if the names differ
    if demangled_name.strip('"') != mangled_name:
        return f"; Mangled: {mangled_name}"
    return ""

