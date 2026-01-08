"""
Syscall interop module for IDA2LLVM
Provides syscall detection and annotation across multiple architectures and operating systems.
"""

import ida_idaapi
import ida_allins
import ida_ua
import logging
from llvmlite import ir

logger = logging.getLogger(__name__)

# Linux x86_64 syscall table (partial - common syscalls)
LINUX_X86_64_SYSCALLS = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
    6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
    12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask", 15: "rt_sigreturn",
    16: "ioctl", 17: "pread64", 18: "pwrite64", 19: "readv", 20: "writev",
    21: "access", 22: "pipe", 23: "select", 24: "sched_yield", 25: "mremap",
    26: "msync", 27: "mincore", 28: "madvise", 29: "shmget", 30: "shmat",
    31: "shmctl", 32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep",
    36: "getitimer", 37: "alarm", 38: "setitimer", 39: "getpid", 40: "sendfile",
    41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
    46: "sendmsg", 47: "recvmsg", 48: "shutdown", 49: "bind", 50: "listen",
    51: "getsockname", 52: "getpeername", 53: "socketpair", 54: "setsockopt",
    55: "getsockopt", 56: "clone", 57: "fork", 58: "vfork", 59: "execve",
    60: "exit", 61: "wait4", 62: "kill", 63: "uname", 64: "semget",
    65: "semop", 66: "semctl", 67: "shmdt", 68: "msgget", 69: "msgsnd",
    70: "msgrcv", 71: "msgctl", 72: "fcntl", 73: "flock", 74: "fsync",
    75: "fdatasync", 76: "truncate", 77: "ftruncate", 78: "getdents",
    79: "getcwd", 80: "chdir", 81: "fchdir", 82: "rename", 83: "mkdir",
    84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink",
    89: "readlink", 90: "chmod", 91: "fchmod", 92: "chown", 93: "fchown",
    94: "lchown", 95: "umask", 96: "gettimeofday", 97: "getrlimit",
    98: "getrusage", 99: "sysinfo", 100: "times", 101: "ptrace", 102: "getuid",
    103: "syslog", 104: "getgid", 105: "setuid", 106: "setgid", 107: "geteuid",
    108: "getegid", 109: "setpgid", 110: "getppid", 111: "getpgrp",
    112: "setsid", 113: "setreuid", 114: "setregid", 115: "getgroups",
    116: "setgroups", 117: "setresuid", 118: "getresuid", 119: "setresgid",
    120: "getresgid", 121: "getpgid", 122: "setfsuid", 123: "setfsgid",
    124: "getsid", 125: "capget", 126: "capset", 127: "rt_sigpending",
    128: "rt_sigtimedwait", 129: "rt_sigqueueinfo", 130: "rt_sigsuspend",
    131: "sigaltstack", 132: "utime", 133: "mknod", 134: "uselib",
    135: "personality", 136: "ustat", 137: "statfs", 138: "fstatfs",
    139: "sysfs", 140: "getpriority", 141: "setpriority", 142: "sched_setparam",
    143: "sched_getparam", 144: "sched_setscheduler", 145: "sched_getscheduler",
    146: "sched_get_priority_max", 147: "sched_get_priority_min",
    148: "sched_rr_get_interval", 149: "mlock", 150: "munlock",
}

# Linux x86 (32-bit) syscall table (partial)
LINUX_X86_SYSCALLS = {
    1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close",
    7: "waitpid", 8: "creat", 9: "link", 10: "unlink", 11: "execve",
    12: "chdir", 13: "time", 14: "mknod", 15: "chmod", 16: "lchown",
    19: "lseek", 20: "getpid", 21: "mount", 22: "umount", 23: "setuid",
    24: "getuid", 25: "stime", 26: "ptrace", 27: "alarm", 29: "pause",
    30: "utime", 33: "access", 34: "nice", 36: "sync", 37: "kill",
    38: "rename", 39: "mkdir", 40: "rmdir", 41: "dup", 42: "pipe",
    43: "times", 45: "brk", 46: "setgid", 47: "getgid", 48: "signal",
    49: "geteuid", 50: "getegid", 51: "acct", 52: "umount2", 54: "ioctl",
    55: "fcntl", 57: "setpgid", 60: "umask", 61: "chroot", 62: "ustat",
    63: "dup2", 64: "getppid", 65: "getpgrp", 66: "setsid", 67: "sigaction",
}

# ARM/AArch64 Linux syscall table (partial)
ARM_LINUX_SYSCALLS = {
    0: "io_setup", 1: "io_destroy", 2: "io_submit", 3: "io_cancel",
    4: "io_getevents", 5: "setxattr", 6: "lsetxattr", 7: "fsetxattr",
    8: "getxattr", 9: "lgetxattr", 10: "fgetxattr", 11: "listxattr",
    12: "llistxattr", 13: "flistxattr", 14: "removexattr", 15: "lremovexattr",
    16: "fremovexattr", 17: "getcwd", 18: "lookup_dcookie", 19: "eventfd2",
    20: "epoll_create1", 21: "epoll_ctl", 22: "epoll_pwait", 23: "dup",
    24: "dup3", 25: "fcntl", 26: "inotify_init1", 27: "inotify_add_watch",
    28: "inotify_rm_watch", 29: "ioctl", 30: "ioprio_set", 31: "ioprio_get",
    32: "flock", 33: "mknodat", 34: "mkdirat", 35: "unlinkat", 36: "symlinkat",
    37: "linkat", 38: "renameat", 39: "umount2", 40: "mount", 41: "pivot_root",
    42: "nfsservctl", 43: "statfs", 44: "fstatfs", 45: "truncate",
    46: "ftruncate", 47: "fallocate", 48: "faccessat", 49: "chdir",
    50: "fchdir", 51: "chroot", 52: "fchmod", 53: "fchmodat", 54: "fchownat",
    55: "fchown", 56: "openat", 57: "close", 58: "vhangup", 59: "pipe2",
    60: "quotactl", 61: "getdents64", 62: "lseek", 63: "read", 64: "write",
    65: "readv", 66: "writev", 67: "pread64", 68: "pwrite64", 69: "preadv",
    70: "pwritev", 71: "sendfile", 72: "pselect6", 73: "ppoll", 74: "signalfd4",
    75: "vmsplice", 76: "splice", 77: "tee", 78: "readlinkat", 79: "fstatat",
    80: "fstat", 81: "sync", 82: "fsync", 83: "fdatasync", 84: "sync_file_range",
}

# Windows NT syscalls (x64) - partial
WINDOWS_X64_SYSCALLS = {
    0x00: "NtAccessCheck", 0x01: "NtWorkerFactoryWorkerReady",
    0x02: "NtAcceptConnectPort", 0x03: "NtMapUserPhysicalPagesScatter",
    0x04: "NtWaitForSingleObject", 0x05: "NtCallbackReturn",
    0x06: "NtReadFile", 0x07: "NtDeviceIoControlFile",
    0x08: "NtWriteFile", 0x09: "NtRemoveIoCompletion",
    0x0A: "NtReleaseSemaphore", 0x0B: "NtReplyWaitReplyPort",
    0x0C: "NtReplyPort", 0x0D: "NtSetInformationThread",
    0x0E: "NtSetEvent", 0x0F: "NtClose", 0x10: "NtQueryObject",
    0x11: "NtQueryInformationToken", 0x12: "NtOpenThreadTokenEx",
    0x13: "NtOpenProcessTokenEx", 0x14: "NtOpenThread",
    0x15: "NtOpenProcess", 0x16: "NtResumeThread", 0x17: "NtSuspendThread",
    0x18: "NtTerminateProcess", 0x19: "NtTerminateThread",
    0x1A: "NtCreateFile", 0x1B: "NtAllocateVirtualMemory",
    0x1C: "NtFreeVirtualMemory", 0x1D: "NtDuplicateObject",
    0x1E: "NtQueryInformationProcess", 0x1F: "NtWaitForMultipleObjects",
}

# WASI (WebAssembly System Interface) syscalls
WASI_SYSCALLS = {
    0: "args_get", 1: "args_sizes_get", 2: "environ_get", 3: "environ_sizes_get",
    4: "clock_res_get", 5: "clock_time_get", 6: "fd_advise", 7: "fd_allocate",
    8: "fd_close", 9: "fd_datasync", 10: "fd_fdstat_get", 11: "fd_fdstat_set_flags",
    12: "fd_fdstat_set_rights", 13: "fd_filestat_get", 14: "fd_filestat_set_size",
    15: "fd_filestat_set_times", 16: "fd_pread", 17: "fd_prestat_get",
    18: "fd_prestat_dir_name", 19: "fd_pwrite", 20: "fd_read", 21: "fd_readdir",
    22: "fd_renumber", 23: "fd_seek", 24: "fd_sync", 25: "fd_tell",
    26: "fd_write", 27: "path_create_directory", 28: "path_filestat_get",
    29: "path_filestat_set_times", 30: "path_link", 31: "path_open",
    32: "path_readlink", 33: "path_remove_directory", 34: "path_rename",
    35: "path_symlink", 36: "path_unlink_file", 37: "poll_oneoff",
    38: "proc_exit", 39: "proc_raise", 40: "sched_yield", 41: "random_get",
    42: "sock_recv", 43: "sock_send", 44: "sock_shutdown",
}


def get_architecture():
    """
    Determine the current binary architecture.
    
    :return: Architecture string (x86, x64, arm, arm64, wasm)
    :rtype: str
    """
    procname = ida_idaapi.inf_get_procname()
    
    if procname.startswith("ARM") or procname.startswith("metapc"):
        if ida_idaapi.inf_is_64bit():
            if "ARM" in procname:
                return "arm64"
            return "x64"
        else:
            if "ARM" in procname:
                return "arm"
            return "x86"
    elif procname == "wasm":
        return "wasm"
    return "unknown"


def get_os_type():
    """
    Heuristically determine the OS type of the binary.
    
    :return: OS string (linux, windows, wasi, unknown)
    :rtype: str
    """
    import ida_nalt
    
    filetype = ida_idaapi.inf_get_filetype()
    
    # Check file type
    if filetype == ida_idaapi.f_ELF:
        return "linux"
    elif filetype == ida_idaapi.f_PE:
        return "windows"
    elif filetype == ida_idaapi.f_LOADER:
        # Could be WASM or other
        if get_architecture() == "wasm":
            return "wasi"
    
    return "unknown"


def get_syscall_name(syscall_number: int, arch: str = None, os_type: str = None) -> str:
    """
    Get the syscall name given its number, architecture, and OS.
    
    :param syscall_number: The syscall number
    :type syscall_number: int
    :param arch: Architecture (x86, x64, arm, arm64, wasm), defaults to auto-detect
    :type arch: str, optional
    :param os_type: OS type (linux, windows, wasi), defaults to auto-detect
    :type os_type: str, optional
    :return: Syscall name or "syscall_{number}" if unknown
    :rtype: str
    """
    if arch is None:
        arch = get_architecture()
    if os_type is None:
        os_type = get_os_type()
    
    syscall_table = None
    
    # Select appropriate syscall table
    if os_type == "linux":
        if arch == "x64":
            syscall_table = LINUX_X86_64_SYSCALLS
        elif arch == "x86":
            syscall_table = LINUX_X86_SYSCALLS
        elif arch in ["arm", "arm64"]:
            syscall_table = ARM_LINUX_SYSCALLS
    elif os_type == "windows":
        if arch == "x64":
            syscall_table = WINDOWS_X64_SYSCALLS
    elif os_type == "wasi":
        syscall_table = WASI_SYSCALLS
    
    if syscall_table and syscall_number in syscall_table:
        return syscall_table[syscall_number]
    
    return f"syscall_{syscall_number}"


def is_syscall_instruction(ea: int) -> bool:
    """
    Check if the instruction at the given address is a syscall instruction.
    
    :param ea: Effective address
    :type ea: int
    :return: True if it's a syscall instruction
    :rtype: bool
    """
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return False
    
    # Check for various syscall instructions
    arch = get_architecture()
    
    if arch in ["x86", "x64"]:
        # syscall, sysenter, int 0x80
        if insn.itype in [ida_allins.NN_syscall, ida_allins.NN_sysenter]:
            return True
        if insn.itype == ida_allins.NN_int and insn.Op1.value == 0x80:
            return True
    elif arch in ["arm", "arm64"]:
        # svc (supervisor call)
        if insn.itype == ida_allins.ARM_svc:
            return True
    
    return False


def inject_syscall_annotation(module: ir.Module, builder: ir.IRBuilder, 
                               syscall_name: str, syscall_number: int, 
                               args: list = None) -> ir.Value:
    """
    Inject a syscall annotation into the LLVM IR.
    This creates a call to a printf-style annotation function.
    
    :param module: LLVM module
    :type module: ir.Module
    :param builder: IR builder
    :type builder: ir.IRBuilder
    :param syscall_name: Name of the syscall
    :type syscall_name: str
    :param syscall_number: Syscall number
    :type syscall_number: int
    :param args: Optional syscall arguments to log
    :type args: list, optional
    :return: Annotation value
    :rtype: ir.Value
    """
    # Create or get the syscall_trace function
    i8ptr = ir.IntType(8).as_pointer()
    
    try:
        trace_func = module.get_global("syscall_trace")
    except KeyError:
        # Create syscall_trace function (external declaration)
        trace_func_type = ir.FunctionType(ir.VoidType(), [i8ptr, ir.IntType(64)], var_arg=True)
        trace_func = ir.Function(module, trace_func_type, "syscall_trace")
    
    # Create format string
    format_str = f"SYSCALL: {syscall_name} (#{syscall_number})\\n"
    str_type = ir.ArrayType(ir.IntType(8), len(format_str) + 1)
    str_constant = ir.Constant(str_type, bytearray(format_str.encode("utf-8") + b'\0'))
    
    str_global = ir.GlobalVariable(module, str_type, 
                                   name=f".syscall_str_{syscall_number}")
    str_global.initializer = str_constant
    str_global.linkage = "private"
    str_global.global_constant = True
    
    # Cast to i8*
    str_ptr = builder.bitcast(str_global, i8ptr)
    
    # Call trace function
    trace_args = [str_ptr, ir.Constant(ir.IntType(64), syscall_number)]
    if args:
        trace_args.extend(args[:6])  # Limit to first 6 arguments
    
    return builder.call(trace_func, trace_args)


def create_syscall_helper(module: ir.Module, syscall_name: str, 
                          syscall_number: int, arch: str = None) -> ir.Function:
    """
    Create a helper function that wraps a syscall.
    
    :param module: LLVM module
    :type module: ir.Module
    :param syscall_name: Name of the syscall
    :type syscall_name: str
    :param syscall_number: Syscall number
    :type syscall_number: int
    :param arch: Architecture (for calling convention)
    :type arch: str, optional
    :return: LLVM function wrapping the syscall
    :rtype: ir.Function
    """
    if arch is None:
        arch = get_architecture()
    
    # Create a generic syscall wrapper with variadic arguments
    func_type = ir.FunctionType(ir.IntType(64), [], var_arg=True)
    func = ir.Function(module, func_type, f"sys_{syscall_name}")
    
    # Add comment/metadata
    func.attributes.add("comment", f"Syscall {syscall_name} (#{syscall_number})")
    
    return func

