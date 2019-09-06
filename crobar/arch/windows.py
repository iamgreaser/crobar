"""Windows-specific debugging/hacking interface."""
import ctypes
from ctypes import CDLL
from ctypes.wintypes import BOOL
from ctypes.wintypes import BYTE
from ctypes.wintypes import DWORD
from ctypes.wintypes import HANDLE
from ctypes.wintypes import HMODULE
from ctypes.wintypes import LPVOID
from ctypes.wintypes import LPWSTR
from ctypes import POINTER
from ctypes import c_size_t as SIZE_T
from ctypes import byref
from ctypes import create_string_buffer
from ctypes import sizeof
from ctypes import Structure
from typing import Optional
from typing import Tuple

from .base import BaseDebugInterface
from crobar.api import HackingOpException

# NOTE: Windows Vista and upwards supports PROCESS_QUERY_LIMITED_INFORMATION.
# This allows access to a subset of the information.
# Of course, one could argue that v244371 still works on XP...
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010

ERROR_SEM_TIMEOUT = 0x79

EXCEPTION_DEBUG_EVENT = 0x00000001
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
DBG_CONTINUE = 0x00010002

CONTEXT_ALL = 0x0001003F

ERROR_MESSAGE_FORMAT = 0x1300
ERROR_MESSAGE_LANG_ID = 0x0400

# doing it this way to keep mypy happy --GM
_windll = ctypes.windll  # type: ignore
_kernel32: CDLL = _windll.kernel32
_psapi: CDLL = _windll.psapi


class WindowsHackingException(HackingOpException):
    __slots__ = ()

    def __str__(self) -> str:
        message: str = super().__str__()

        code: int = _kernel32.GetLastError()
        if code == 0:
            return message

        error_buf = LPWSTR()
        length = _kernel32.FormatMessageW(
            ERROR_MESSAGE_FORMAT,
            None,
            code,
            ERROR_MESSAGE_LANG_ID,
            byref(error_buf),
            0,
            None
        )

        if error_buf.value is None or length == 0:
            return message
        error = error_buf.value[:length]

        return f"{message}\nError {code}: {error}"


class WindowsDebugInterface(BaseDebugInterface):
    __slots__ = (
        "_pid",
        "_process_handle",
        "_image_base_offset",
        "_is_debugger_attached",
        "_stopped_thread_id",
        "_stopped_thread_handle",
        "_current_context",
    )

    def __init__(self) -> None:
        self._is_debugger_attached: bool = False
        self._stopped_thread_id: int = 0
        self._stopped_thread_handle: int = 0
        self._current_context: Optional[_WOW64_CONTEXT] = None

        self._find_talos()
        self._attach_to_talos()

    def __del__(self) -> None:
        print(f"Deleting {self!r}")

        if self._stopped_thread_id != 0:
            print(f"Resuming thread {self._stopped_thread_id}")
            self.resume_from_breakpoint()

        if self._is_debugger_attached:
            _kernel32.DebugActiveProcessStop(DWORD(self._pid))

        result_close: int = _kernel32.CloseHandle(self._process_handle)
        print(f"Closed: {result_close}")

    def _find_talos(self) -> None:
        """Attempt to find Talos in the process list."""

        # I forgot how terrible this was on Windows.
        #
        # Here's how it works:
        # - Call EnumProcesses() to get a list of process IDs.
        # - For every process:
        #   - Call OpenProcess() to attach to the process.
        #   - Call EnumProcessModules() to get the first module in the process.
        #   - If the module could be found at all:
        #     - Call GetModuleBaseNameA() on that module.
        #   - Call CloseHandle().

        # Fetch all processes.
        # This should be large enough, hopefully
        process_list = (DWORD * 4096)()
        process_count_bytes = DWORD(0)
        did_enum: int = _psapi.EnumProcesses(
            byref(process_list),
            DWORD(sizeof(process_list)),
            byref(process_count_bytes)
        )

        if did_enum == 0:
            raise WindowsHackingException("EnumProcesses failed")

        process_count: int = process_count_bytes.value // sizeof(DWORD)

        if process_count > len(process_list):
            raise HackingOpException(f"EnumProcesses process count overflowed: {process_count:d} > {len(process_list):d}")

        for pid_idx in range(process_count):
            pid: int = process_list[pid_idx]

            # Open the process.
            prochandle: HANDLE = _kernel32.OpenProcess(
                DWORD(
                    PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_READ
                ),
                BOOL(False),
                DWORD(pid)
            )

            if prochandle == 0:  # type: ignore
                # OpenProcess failed - this happens plenty when we don't have permission
                continue

            try:
                # Grab the first module we can.
                first_module = HMODULE()
                module_buf_needed = DWORD()
                result_enum_modules: int = _psapi.EnumProcessModules(
                    prochandle,
                    byref(first_module),
                    DWORD(sizeof(first_module)),
                    byref(module_buf_needed)
                )

                if result_enum_modules == 0:
                    # This fails occasionally with an ERROR_PARTIAL_COPY, though it fails on Talos
                    continue

                if module_buf_needed.value == 0 or first_module.value is None:
                    print(f"EnumProcessModules yielded no modules for pid {pid:d}, skipping")
                    continue

                # Get the first module's name.
                procname_buf = create_string_buffer(1024)
                basename_length: int = _psapi.GetModuleBaseNameA(
                    prochandle,
                    first_module,
                    byref(procname_buf),
                    DWORD(sizeof(procname_buf))
                )

                if basename_length == 0:
                    print(f"GetModuleBaseNameA failed for pid {pid:d}, skipping")
                    continue

                procname: bytes = procname_buf.raw[:basename_length]
                if procname.lower().startswith(b"talos") and procname.lower().endswith(b".exe"):
                    print(f"{pid}: {prochandle:08X} {first_module.value:016X} {procname!r}")
                    self._pid: int = pid
                    self._image_base_offset: int = first_module.value - 0x00400000
                    return
            finally:
                result_close: int = _kernel32.CloseHandle(prochandle)
                if result_close == 0:
                    raise WindowsHackingException(f"CloseHandle failed for pid {pid:d}")
        else:
            raise HackingOpException("Could not find Talos in the process list")

    def _attach_to_talos(self) -> None:
        """Attempt to attach to Talos."""

        self._process_handle: int = _kernel32.OpenProcess(
            DWORD(
                PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
            ),
            BOOL(False),
            DWORD(self._pid)
        )

        if self._process_handle == 0:
            raise WindowsHackingException("OpenProcess failed")

    def read_memory(self, *, addr: int, length: int) -> bytes:
        """Read memory from the attached process."""

        result_buf = (BYTE * length)()
        number_of_bytes_read_buf = SIZE_T()
        result_read: int = _kernel32.ReadProcessMemory(
            HANDLE(self._process_handle),
            LPVOID(self.from_relative_addr(addr)),
            byref(result_buf),
            SIZE_T(sizeof(result_buf)),
            byref(number_of_bytes_read_buf)
        )

        if result_read == 0:
            raise WindowsHackingException("ReadProcessMemory failed")

        if number_of_bytes_read_buf.value == 0:
            raise HackingOpException(f"ReadProcessMemory couldn't read {length:d} bytes, it read {number_of_bytes_read_buf.value:d} bytes instead")

        return bytes(result_buf)

    def write_memory(self, *, addr: int, data: bytes) -> None:
        """Write memory to the attached process."""

        # This approach is kinda disgusting to be honest...
        result_buf = (BYTE * len(data))(*data)

        number_of_bytes_written_buf = SIZE_T()
        result_read: int = _kernel32.WriteProcessMemory(
            HANDLE(self._process_handle),
            LPVOID(self.from_relative_addr(addr)),
            byref(result_buf),
            SIZE_T(sizeof(result_buf)),
            byref(number_of_bytes_written_buf)
        )

        if result_read == 0:
            raise WindowsHackingException("WriteProcessMemory failed")

        if number_of_bytes_written_buf.value == 0:
            raise HackingOpException("WriteProcessMemory couldn't write {len(data):d} bytes, it wrote {number_of_bytes_written_buf.value:d} bytes instead")

    def from_relative_addr(self, addr: int) -> int:
        """Converts a relative-to-intended-memory-base address to an absolute address."""
        return addr + self._image_base_offset

    def wait_for_breakpoint(self) -> Tuple[int, bool]:
        """Waits for a breakpoint to be hit in the Talos process."""

        if not self._is_debugger_attached:
            _kernel32.DebugActiveProcess(self._pid)
            _kernel32.DebugSetProcessKillOnExit(BOOL(False))
            self._is_debugger_attached = True

        # We may get unrelated events before a breakpoint so we have to loop
        while True:
            # Big enough for all the bytes we want, even though more are returned
            # TODO: different order in 64 bit python?
            debug_event = (DWORD * 7)()

            wait_succeeded = _kernel32.WaitForDebugEvent(debug_event, 1000)
            if wait_succeeded == 0:
                error = _kernel32.GetLastError()
                if error == ERROR_SEM_TIMEOUT:
                    continue

                raise WindowsHackingException("WaitForDebugEvent failed")

            event_code = debug_event[0]
            pid = debug_event[1]
            thread_id = debug_event[2]
            self._stopped_thread_id = thread_id

            if event_code != EXCEPTION_DEBUG_EVENT or pid != self._pid:
                self.resume_from_breakpoint()
                continue

            exception_code = debug_event[3]
            if exception_code == EXCEPTION_BREAKPOINT or exception_code == EXCEPTION_SINGLE_STEP:
                addr = debug_event[6]
                return addr, exception_code == EXCEPTION_SINGLE_STEP

            self.resume_from_breakpoint()

    def resume_from_breakpoint(self) -> None:
        """Resumes the talos process after a breakpoint."""
        if self._stopped_thread_id == 0:
            raise HackingOpException("No thread is currently stopped")

        continued = _kernel32.ContinueDebugEvent(self._pid, self._stopped_thread_id, DBG_CONTINUE)
        if continued == 0:
            raise WindowsHackingException("ContinueDebugEvent failed")

        # Clear our "stopped-only" vars
        self._stopped_thread_id = 0
        self._stopped_thread_handle = 0
        self._current_context = None

    def _ensure_context_loaded(self) -> None:
        """Gets the 'CONTEXT' object that holds information about all registers."""
        if self._current_context is None:
            return

        if self._stopped_thread_handle == 0:
            self._stopped_thread_handle = _kernel32.OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                False,
                self._stopped_thread_id
            )
            if self._stopped_thread_handle == 0:
                raise WindowsHackingException("Unable to get thread handle")

        context = _WOW64_CONTEXT()
        context.ContextFlags = CONTEXT_ALL

        got_context = _kernel32.GetThreadContext(self._stopped_thread_handle, context)
        if got_context == 0:
            raise WindowsHackingException("GetThreadContext failed")

        self._current_context = context

    def get_register(self, register: str) -> int:
        """Returns the contents of the specified register."""
        if self._stopped_thread_id == 0:
            raise HackingOpException("No thread is currently stopped")

        if register not in _WOW64_CONTEXT.__dict__:
            raise HackingOpException(f"Unsupported register: {register}")

        self._ensure_context_loaded()

        return getattr(self._current_context, register)  # type: ignore

    def set_register(self, register: str, value: int) -> None:
        """Sets the value of the specified register."""
        if self._stopped_thread_id == 0:
            raise HackingOpException("No thread is currently stopped")

        if register not in _WOW64_CONTEXT.__dict__:
            raise HackingOpException(f"Unsupported register: {register}")

        self._ensure_context_loaded()
        setattr(self._current_context, register, value)

        set_context = _kernel32.SetThreadContext(self._stopped_thread_handle, self._current_context)
        if set_context == 0:
            raise WindowsHackingException("SetThreadContext failed")


# TODO: Probably changes with 64 bit
class _WOW64_CONTEXT(Structure):
    _fields_ = [
        ('ContextFlags', DWORD),
        ('dr0', DWORD),
        ('dr1', DWORD),
        ('dr2', DWORD),
        ('dr3', DWORD),
        ('dr4', DWORD),
        ('dr5', DWORD),
        ('dr6', DWORD),
        ('dr7', DWORD),
        ('ControlWord', DWORD),
        ('StatusWord', DWORD),
        ('TagWord', DWORD),
        ('ErrorOffset', DWORD),
        ('ErrorSelector', DWORD),
        ('DataOffset', DWORD),
        ('DataSelector', DWORD),
        ('RegisterArea', POINTER(BYTE)),
        ('Cr0NpxState', DWORD),
        ('SegGs', DWORD),
        ('SegFs', DWORD),
        ('SegEs', DWORD),
        ('SegDs', DWORD),
        ('edi', DWORD),
        ('esi', DWORD),
        ('ebx', DWORD),
        ('edx', DWORD),
        ('ecx', DWORD),
        ('eax', DWORD),
        ('ebp', DWORD),
        ('eip', DWORD),
        ('SegCs', DWORD),
        ('EFlags', DWORD),
        ('Esp', DWORD),
        ('SegSs', DWORD),
        ('ExtendedRegisters', POINTER(BYTE)),
    ]
