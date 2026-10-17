"""ctypes declarations for Win32 process, pipe, file and Job Object APIs (component-local).

Declarations only. Loading kernel32 happens lazily via ``load()`` so importing the
package on any OS performs no system call.
"""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes

CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
STARTF_USESTDHANDLES = 0x00000100
HANDLE_FLAG_INHERIT = 0x00000001
PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
JOB_BASIC_ACCOUNTING = 1
JOB_BASIC_PROCESS_ID_LIST = 3
JOB_ASSOCIATE_COMPLETION_PORT = 7
JOB_EXTENDED_LIMIT = 9
LIMIT_ACTIVE_PROCESS = 0x00000008
LIMIT_JOB_MEMORY = 0x00000200
LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400
LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
MSG_ACTIVE_PROCESS_ZERO = 4
MSG_NEW_PROCESS = 6
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102
INFINITE_WAIT_FORBIDDEN = 0xFFFFFFFF
ERROR_BROKEN_PIPE = 109
ERROR_NO_DATA = 232
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
SYNCHRONIZE = 0x00100000
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
STILL_ACTIVE = 259
TERMINATED_EXIT_CODE = 0xC000013A
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_WRITE = 0x40000000
DELETE = 0x00010000
FILE_READ_ATTRIBUTES = 0x0080
FILE_SHARE_WRITE = 0x00000002
FILE_SHARE_DELETE = 0x00000004
CREATE_NEW = 1
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
FILE_ATTRIBUTE_DIRECTORY = 0x10
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_RENAME_INFO_CLASS = 3
ERROR_FILE_NOT_FOUND = 2
ERROR_PATH_NOT_FOUND = 3
ERROR_PIPE_CONNECTED = 535
ERROR_OPERATION_ABORTED = 995
PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
THREAD_TERMINATE = 0x0001
TOKEN_QUERY = 0x0008
TOKEN_USER_CLASS = 1


class SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                ("inherit", wintypes.BOOL)]


class StartupInfo(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("reserved", wintypes.LPWSTR),
                ("desktop", wintypes.LPWSTR), ("title", wintypes.LPWSTR),
                ("x", wintypes.DWORD), ("y", wintypes.DWORD), ("x_size", wintypes.DWORD),
                ("y_size", wintypes.DWORD), ("x_chars", wintypes.DWORD),
                ("y_chars", wintypes.DWORD), ("fill", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("show", wintypes.WORD),
                ("reserved2_size", wintypes.WORD), ("reserved2", ctypes.POINTER(ctypes.c_ubyte)),
                ("stdin", wintypes.HANDLE), ("stdout", wintypes.HANDLE),
                ("stderr", wintypes.HANDLE)]


class StartupInfoEx(ctypes.Structure):
    _fields_ = [("startup", StartupInfo), ("attributes", ctypes.c_void_p)]


class ProcessInformation(ctypes.Structure):
    _fields_ = [("process", wintypes.HANDLE), ("thread", wintypes.HANDLE),
                ("pid", wintypes.DWORD), ("tid", wintypes.DWORD)]


class BasicLimit(ctypes.Structure):
    _fields_ = [("per_process_user_time", ctypes.c_longlong),
                ("per_job_user_time", ctypes.c_longlong), ("flags", wintypes.DWORD),
                ("min_working_set", ctypes.c_size_t), ("max_working_set", ctypes.c_size_t),
                ("active_process_limit", wintypes.DWORD), ("affinity", ctypes.c_size_t),
                ("priority_class", wintypes.DWORD), ("scheduling_class", wintypes.DWORD)]


class IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in
                ("reads", "writes", "others", "read_bytes", "write_bytes", "other_bytes")]


class ExtendedLimit(ctypes.Structure):
    _fields_ = [("basic", BasicLimit), ("io", IoCounters),
                ("process_memory_limit", ctypes.c_size_t), ("job_memory_limit", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t), ("peak_job_memory", ctypes.c_size_t)]


class BasicAccounting(ctypes.Structure):
    _fields_ = [("user_time", ctypes.c_longlong), ("kernel_time", ctypes.c_longlong),
                ("period_user_time", ctypes.c_longlong), ("period_kernel_time", ctypes.c_longlong),
                ("page_faults", wintypes.DWORD), ("total_processes", wintypes.DWORD),
                ("active_processes", wintypes.DWORD), ("terminated_processes", wintypes.DWORD)]


class FileInformation(ctypes.Structure):
    # BY_HANDLE_FILE_INFORMATION: FILETIME is two DWORDs (4-byte alignment), not a
    # c_ulonglong; the wrong type shifts every later field (sizeof 52, links at 40).
    _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME),
                ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME),
                ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]


class CompletionPortAssociation(ctypes.Structure):
    _fields_ = [("key", ctypes.c_void_p), ("port", wintypes.HANDLE)]


def process_id_list(capacity: int):
    class ProcessIdList(ctypes.Structure):
        _fields_ = [("assigned", wintypes.DWORD), ("listed", wintypes.DWORD),
                    ("ids", ctypes.c_size_t * capacity)]
    return ProcessIdList()


_KERNEL32 = None


def load():
    """Return a configured kernel32; refuses off Windows."""
    global _KERNEL32
    if os.name != "nt":
        raise OSError("windows_required")
    if _KERNEL32 is not None:
        return _KERNEL32
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    H, D, B, P = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, ctypes.c_void_p
    signatures = {
        "CreateJobObjectW": ([P, wintypes.LPCWSTR], H),
        "SetInformationJobObject": ([H, ctypes.c_int, P, D], B),
        "QueryInformationJobObject": ([H, ctypes.c_int, P, D, ctypes.POINTER(D)], B),
        "AssignProcessToJobObject": ([H, H], B),
        "TerminateJobObject": ([H, wintypes.UINT], B),
        "IsProcessInJob": ([H, H, ctypes.POINTER(B)], B),
        "CreateIoCompletionPort": ([H, H, ctypes.c_size_t, D], H),
        "GetQueuedCompletionStatus": ([H, ctypes.POINTER(D), ctypes.POINTER(ctypes.c_size_t),
                                       ctypes.POINTER(P), D], B),
        "CreatePipe": ([ctypes.POINTER(H), ctypes.POINTER(H), ctypes.POINTER(SecurityAttributes), D], B),
        "SetHandleInformation": ([H, D, D], B),
        "InitializeProcThreadAttributeList": ([P, D, D, ctypes.POINTER(ctypes.c_size_t)], B),
        "UpdateProcThreadAttribute": ([P, D, ctypes.c_size_t, P, ctypes.c_size_t, P, P], B),
        "DeleteProcThreadAttributeList": ([P], None),
        "CreateProcessW": ([wintypes.LPCWSTR, wintypes.LPWSTR, P, P, B, D, P, wintypes.LPCWSTR,
                            ctypes.POINTER(StartupInfoEx), ctypes.POINTER(ProcessInformation)], B),
        "ResumeThread": ([H], D),
        "TerminateProcess": ([H, wintypes.UINT], B),
        "WaitForSingleObject": ([H, D], D),
        "GetExitCodeProcess": ([H, ctypes.POINTER(D)], B),
        "ReadFile": ([H, P, D, ctypes.POINTER(D), P], B),
        "WriteFile": ([H, P, D, ctypes.POINTER(D), P], B),
        "CloseHandle": ([H], B),
        "OpenProcess": ([D, B, D], H),
        "CreateFileW": ([wintypes.LPCWSTR, D, D, P, D, D, H], H),
        "GetFinalPathNameByHandleW": ([H, wintypes.LPWSTR, D, D], D),
        "GetFileInformationByHandle": ([H, ctypes.POINTER(FileInformation)], B),
        "SetFileInformationByHandle": ([H, ctypes.c_int, P, D], B),
        "FlushFileBuffers": ([H], B),
        "SetFilePointerEx": ([H, ctypes.c_longlong, ctypes.POINTER(ctypes.c_longlong), D], B),
        "SetEndOfFile": ([H], B),
        "CreateNamedPipeW": ([wintypes.LPCWSTR, D, D, D, D, D, D, ctypes.POINTER(SecurityAttributes)], H),
        "ConnectNamedPipe": ([H, P], B),
        "DisconnectNamedPipe": ([H], B),
        "GetNamedPipeClientProcessId": ([H, ctypes.POINTER(wintypes.ULONG)], B),
        "QueryFullProcessImageNameW": ([H, D, wintypes.LPWSTR, ctypes.POINTER(D)], B),
        "OpenThread": ([D, B, D], H),
        "CancelSynchronousIo": ([H], B),
        "GetCurrentProcess": ([], H),
        "OpenProcessToken": ([H, D, ctypes.POINTER(H)], B),
        "GetProcessId": ([H], D),
        "LocalFree": ([P], P),
    }
    for name, (arguments, result) in signatures.items():
        function = getattr(k, name)
        function.argtypes, function.restype = arguments, result
    _KERNEL32 = k
    return k


_ADVAPI32 = None


def advapi():
    """Security-descriptor helpers (lazy, Windows only)."""
    global _ADVAPI32
    if os.name != "nt":
        raise OSError("windows_required")
    if _ADVAPI32 is None:
        a = ctypes.WinDLL("advapi32", use_last_error=True)
        a.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        a.GetTokenInformation.restype = wintypes.BOOL
        a.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        a.ConvertSidToStringSidW.restype = wintypes.BOOL
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.DWORD)]
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        _ADVAPI32 = a
    return _ADVAPI32
