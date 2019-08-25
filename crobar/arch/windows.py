"""Windows-specific debugging/hacking interface.

FIXME: THIS IS COMPLETELY UNTESTED AT THIS STAGE.
"""
import ctypes
from ctypes import CDLL
from ctypes import c_byte
from ctypes import c_uint32
from ctypes import c_uint64
from ctypes import c_size_t
from ctypes import create_string_buffer
from ctypes import pointer
from ctypes import sizeof
import struct
from typing import Any
from typing import Optional
from typing import cast

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

# doing it this way to keep mypy happy --GM
_windll = ctypes.windll # type: ignore
_kernel32: CDLL = _windll.kernel32


class WindowsDebugInterface(BaseDebugInterface):
    __slots__ = (
        "_pid",
        "_process_handle",
        "_image_base_offset",
    )

    def __init__(self) -> None:
        self._find_talos()
        self._attach_to_talos()

    def __del__(self) -> None:
        print(f"Deleting {self!r}")
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
        did_enum: int = _kernel32.EnumProcesses(
            pointer(process_list),
            c_uint32(sizeof(process_list)),
            pointer(process_count))

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
                c_uint32(self._pid))

            if prochandle == 0:
                print(f"OpenProcess failed for pid {pid:d}, skipping")
                continue

            try:
                # Grab the first module we can.
                module_buf = c_size_t(0)
                module_buf_needed = c_uint32(0)
                result_enum_modules: int = _kernel32.EnumProcessModules(
                    prochandle,
                    pointer(module_buf),
                    sizeof(module_buf),
                    pointer(module_buf_needed))

                if result_enum_modules == 0:
                    print(f"EnumProcessModules failed for pid {pid:d}, skipping")
                    continue

                if module_buf_needed.value == 0:
                    print(f"EnumProcessModules yielded no modules for pid {pid:d}, skipping")
                    continue

                procmodule: int = module_buf.value

                # Get the first module's name.
                procname_buf = create_string_buffer(1024)
                procname: bytes = procname_buf.raw.partition(b"\x00")[0]
                result_basename: int = _kernel32.GetModuleBaseNameA(
                    c_uint32(prochandle),
                    c_size_t(procmodule),
                    pointer(procname_buf),
                    sizeof(procname_buf))

                if result_basename == 0:
                    print(f"GetModuleBaseNameA failed for pid {pid:d}, skipping")
                    continue

                if b"talos" in procname.lower() and b".exe" in procname.lower():
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
            c_size_t(self._process_handle),
            c_size_t(self.from_relative_addr(addr)),
            pointer(result_buf),
            c_size_t(sizeof(result_buf)),
            pointer(number_of_bytes_read_buf))

        if result_read == 0:
            raise HackingOpException(f"ReadProcessMemory failed")

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


