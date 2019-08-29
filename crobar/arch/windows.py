"""Windows-specific debugging/hacking interface."""
import ctypes
from ctypes import CDLL
from ctypes import c_byte
from ctypes import c_uint32
from ctypes import c_size_t
from ctypes import create_string_buffer
# Why do these two work differently :|
from ctypes import pointer
from ctypes import POINTER
from ctypes import sizeof
from ctypes import Structure
from typing import Optional

from crobar.arch.base import BaseDebugInterface
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

# doing it this way to keep mypy happy --GM
_windll = ctypes.windll  # type: ignore
_kernel32: CDLL = _windll.kernel32
_psapi: CDLL = _windll.psapi


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
        self._find_talos()
        self._attach_to_talos()

        self._is_debugger_attached: bool = False
        self._stopped_thread_id: int = 0
        self._stopped_thread_handle: int = 0
        self._current_context: Optional[_CONTEXT] = None

    def __del__(self) -> None:
        print(f"Deleting {self!r}")

        if self._stopped_thread_id != 0:
            print(f"Resuming thread {self._stopped_thread_id}")
            self.resume_from_breakpoint()

        if self._is_debugger_attached:
            _kernel32.DebugActiveProcessStop(c_uint32(self._pid))

        result_close: int = _kernel32.CloseHandle(self._process_handle)
        print(f"Closed: {result_close}")

    def _find_talos(self) -> None:
        """Attempt to find Talos in the process list."""

        # I forgot how terrible this was on Windows.
        #
        # Here's how it works according to what I could scrape on MSDN.
        # - Call EnumProcesses() to get a list of process IDs.
        # - For every process:
        #   - Call OpenProcess() to attach to the process.
        #   - Call EnumProcessModules() to get the first module in the process.
        #   - If the module could be found at all:
        #     - Call GetModuleBaseNameA() on that module.
        #   - Call CloseHandle().
        #
        # Windows XP added some fun where you had to get your process security right,
        # and I think Wine straight up doesn't emulate this.
        # Then again, ovl075 was a thing, so I've definitely had it working on official Windows.
        # I don't quite recall how to get that garbage working.

        # Fetch all processes.
        # This should be large enough, hopefully
        process_list = (c_uint32 * 4096)()
        process_count_bytes = c_uint32(0)
        did_enum: int = _psapi.EnumProcesses(
            pointer(process_list),
            c_uint32(sizeof(process_list)),
            pointer(process_count_bytes))

        if did_enum == 0:
            raise HackingOpException(f"EnumProcesses failed")

        process_count: int = process_count_bytes.value // sizeof(c_uint32)

        if process_count > len(process_list):
            raise HackingOpException(f"EnumProcesses process count overflowed: {process_count:d} > {len(process_list):d}")

        for pid_idx in range(process_count):
            pid: int = process_list[pid_idx]

            # Open the process.
            prochandle: int = _kernel32.OpenProcess(
                c_uint32(0
                         | PROCESS_QUERY_INFORMATION
                         | PROCESS_VM_READ
                         ),
                c_uint32(int(False)),
                c_uint32(pid))

            if prochandle == 0:
                # print(f"OpenProcess failed for pid {pid:d}, skipping")
                continue

            try:
                # Grab the first module we can.
                module_buf = c_size_t(0)
                module_buf_needed = c_uint32(0)
                result_enum_modules: int = _psapi.EnumProcessModules(
                    prochandle,
                    pointer(module_buf),
                    sizeof(module_buf),
                    pointer(module_buf_needed))

                if result_enum_modules == 0:
                    # print(f"EnumProcessModules failed for pid {pid:d}, skipping")
                    continue

                if module_buf_needed.value == 0:
                    print(f"EnumProcessModules yielded no modules for pid {pid:d}, skipping")
                    continue

                procmodule: int = module_buf.value

                # Get the first module's name.
                procname_buf = create_string_buffer(1024)
                result_basename: int = _psapi.GetModuleBaseNameA(
                    c_uint32(prochandle),
                    c_size_t(procmodule),
                    pointer(procname_buf),
                    sizeof(procname_buf))

                if result_basename == 0:
                    print(f"GetModuleBaseNameA failed for pid {pid:d}, skipping")
                    continue

                procname: bytes = procname_buf.raw.partition(b"\x00")[0]
                if procname.lower().startswith(b"talos") and procname.lower().endswith(b".exe"):
                    print(f"{pid}: {prochandle:08X} {procmodule:016X} {procname!r}")
                    self._pid: int = pid
                    self._image_base_offset: int = procmodule - 0x00400000
                    return
            finally:
                result_close: int = _kernel32.CloseHandle(prochandle)
                if result_close == 0:
                    raise HackingOpException(f"CloseHandle failed for pid {pid:d}")
        else:
            raise HackingOpException(f"Could not find Talos in the process list")

    def _attach_to_talos(self) -> None:
        """Attempt to attach to Talos."""

        self._process_handle: int = _kernel32.OpenProcess(
            c_uint32(0
                     | PROCESS_VM_OPERATION
                     | PROCESS_VM_READ
                     | PROCESS_VM_WRITE
                     ),
            c_uint32(int(False)),
            c_uint32(self._pid))

        if self._process_handle == 0:
            raise HackingOpException(f"OpenProcess failed")

    def read_memory(self, *, addr: int, length: int) -> bytes:
        """Read memory from the attached process."""

        # On the other hand, the Windows interface for actually hacking stuff is nice.
        #
        # Dammit Linux, why don't you just allow mmap() against f"/proc/{pid:d}/mem"?
        # That would be *logical*... but noooo, we have to do this clunky ptrace() shit,
        # where we have to poke a whole "word", where the man page doesn't even define
        # what a fucking word is.
        #
        # It turns out that a "word" is probably the width of a pointer.
        #
        # THANKS SUN YOUR INTERFACE TOTALLY DOESN'T FUCKING SUCK BALLS

        result_buf = (c_byte * length)()
        number_of_bytes_read_buf = c_size_t(0)
        result_read: int = _kernel32.ReadProcessMemory(
            c_uint32(self._process_handle),
            c_size_t(self.from_relative_addr(addr)),
            pointer(result_buf),
            c_size_t(sizeof(result_buf)),
            pointer(number_of_bytes_read_buf))

        if result_read == 0:
            raise HackingOpException(f"ReadProcessMemory failed, error code {_kernel32.GetLastError()}")

        if number_of_bytes_read_buf.value == 0:
            raise HackingOpException(f"ReadProcessMemory couldn't read {length:d} bytes, it read {number_of_bytes_read_buf.value:d} bytes instead")

        return bytes(result_buf)

    def write_memory(self, *, addr: int, data: bytes) -> None:
        """Write memory to the attached process."""

        # This approach is kinda disgusting to be honest...
        result_buf = (c_byte * len(data))(*data)

        number_of_bytes_written_buf = c_size_t(0)
        result_read: int = _kernel32.WriteProcessMemory(
            c_size_t(self._process_handle),
            c_size_t(self.from_relative_addr(addr)),
            pointer(result_buf),
            c_size_t(sizeof(result_buf)),
            pointer(number_of_bytes_written_buf))

        if result_read == 0:
            raise HackingOpException(f"WriteProcessMemory failed")

        if number_of_bytes_written_buf.value == 0:
            raise HackingOpException(f"WriteProcessMemory couldn't write {len(data):d} bytes, it wrote {number_of_bytes_written_buf.value:d} bytes instead")

    def from_relative_addr(self, addr: int) -> int:
        """Converts a relative-to-intended-memory-base address to an absolute address."""
        return addr + self._image_base_offset

    def wait_for_breakpoint(self) -> int:
        """Waits for a breakpoint to be hit in the Talos process."""

        if not self._is_debugger_attached:
            _kernel32.DebugActiveProcess(self._pid)
            _kernel32.DebugSetProcessKillOnExit(c_uint32(0))
            self._is_debugger_attached = True

        # We may get unrelated events before a breakpoint so we have to loop
        while True:
            # Big enough for all the bytes we want, even though more are returned
            # TODO: different order in 64 bit python?
            debug_event = (c_uint32 * 7)()

            wait_succeeded = _kernel32.WaitForDebugEvent(debug_event, 1000)
            if wait_succeeded == 0:
                error = _kernel32.GetLastError()
                if error == ERROR_SEM_TIMEOUT:
                    continue

                raise HackingOpException(f"WaitForDebugEvent failed {_kernel32.GetLastError()}")

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
                return addr

            self.resume_from_breakpoint()

    def resume_from_breakpoint(self) -> None:
        """Resumes the talos process after a breakpoint."""
        if self._stopped_thread_id == 0:
            raise HackingOpException("No thread is currently stopped")

        continued = _kernel32.ContinueDebugEvent(self._pid, self._stopped_thread_id, DBG_CONTINUE)
        if continued == 0:
            raise HackingOpException("ContinueDebugEvent failed")

        # Clear our "stopped-only" vars
        self._stopped_thread_id = 0
        self._stopped_thread_handle = 0
        self._current_context = None

    def _ensure_context_loaded(self) -> None:
        """Gets the 'CONTEXT' object that holds information about all registers."""
        if self._current_context != None:
            return

        if self._stopped_thread_handle == 0:
            self._stopped_thread_handle = _kernel32.OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                False,
                self._stopped_thread_id
            )
            if self._stopped_thread_handle == 0:
                raise HackingOpException("Unable to get thread handle")

        context = _CONTEXT()

        got_context = _kernel32.GetThreadContext(self._stopped_thread_handle, context)
        if got_context == 0:
            raise HackingOpException("GetThreadContext failed")

        self._current_context = context

    def get_register(self, register: str) -> int:
        """Returns the contents of the specified register."""
        if self._stopped_thread_id == 0:
            raise HackingOpException("No thread is currently stopped")

        if register not in _CONTEXT.__dict__:
            raise HackingOpException(f"Unsupported register: {register}")

        self._ensure_context_loaded()

        return getattr(self._current_context, register) # type: ignore

    def set_register(self, register: str, value: int) -> None:
        """Sets the value of the specified register."""
        if self._stopped_thread_id == 0:
            raise HackingOpException("No thread is currently stopped")

        if register not in _CONTEXT.__dict__:
            raise HackingOpException(f"Unsupported register: {register}")

        self._ensure_context_loaded()
        setattr(self._current_context, register, value)

        set_context = _kernel32.SetThreadContext(self._stopped_thread_handle, self._current_context)
        if set_context == 0:
            raise HackingOpException("SetThreadContext failed")


# TODO: Probably changes with 64 bit
class _CONTEXT(Structure):
    _fields_ = [
        ('ContextFlags', c_uint32),
        ('dr0', c_uint32),
        ('dr1', c_uint32),
        ('dr2', c_uint32),
        ('dr3', c_uint32),
        ('dr4', c_uint32),
        ('dr5', c_uint32),
        ('dr6', c_uint32),
        ('dr7', c_uint32),
        ('ControlWord', c_uint32),
        ('StatusWord', c_uint32),
        ('TagWord', c_uint32),
        ('ErrorOffset', c_uint32),
        ('ErrorSelector', c_uint32),
        ('DataOffset', c_uint32),
        ('DataSelector', c_uint32),
        ('RegisterArea', POINTER(c_byte)),
        ('Cr0NpxState', c_uint32),
        ('SegGs', c_uint32),
        ('SegFs', c_uint32),
        ('SegEs', c_uint32),
        ('SegDs', c_uint32),
        ('edi', c_uint32),
        ('esi', c_uint32),
        ('ebx', c_uint32),
        ('edx', c_uint32),
        ('ecx', c_uint32),
        ('eax', c_uint32),
        ('ebp', c_uint32),
        ('eip', c_uint32),
        ('SegCs', c_uint32),
        ('EFlags', c_uint32),
        ('Esp', c_uint32),
        ('SegSs', c_uint32),
        ('ExtendedRegisters', POINTER(c_byte)),
    ]
