"""Linux-specific debugging/hacking interface."""
from ctypes import CDLL
from ctypes import c_uint32
from ctypes import c_uint64
from glob import glob
import struct
from typing import Any
from typing import Optional
from typing import cast

from .base import BaseDebugInterface
from crobar.api import HackingOpException

PTRACE_PEEKTEXT = 1
PTRACE_PEEKDATA = 2
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5
PTRACE_CONT = 7
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
PTRACE_INTERRUPT = 0x4207

_libc = CDLL("libc.so.6")


class PtraceException(HackingOpException):
    """Generic exception fires whenever ptrace() fails."""
    __slots__ = ()


class LinuxDebugInterface(BaseDebugInterface):
    __slots__ = (
        "_pid",
    )

    def __init__(self) -> None:
        self._find_talos()
        self._attach_to_talos()

    def __del__(self) -> None:
        print(f"Deleting {self!r}")
        result_cont: int = self._ptrace(cmd=PTRACE_CONT)
        print(f"Continued: {result_cont}")
        result_detach: int = self._ptrace(cmd=PTRACE_DETACH)
        print(f"Detached: {result_cont}")

    def _find_talos(self) -> None:
        """Attempt to find Talos in the process list."""
        for cmdline_name in glob("/proc/*/comm"):
            pid_str: str = cmdline_name.partition("/proc/")[-1].partition("/")[0]
            if pid_str.isdigit():
                procname: str = open(cmdline_name, "r").read().rstrip()
                pid: int = int(pid_str)
                if procname.startswith("Talos"):
                    print(f"{pid}: {procname!r}")
                    self._pid: int = pid
                    return
        else:
            raise Exception(f"Could not find Talos in the process list")
                    
    def _attach_to_talos(self) -> None:
        """Attempt to attach to Talos."""
        result: int = self._ptrace(cmd=PTRACE_ATTACH)
        if result == -1:
            raise PtraceException(f"PTRACE_ATTACH failed")

        pid_result: int = _libc.waitpid(self._pid, None, 0)
        if pid_result == -1:
            raise PtraceException(f"waitpid for PTRACE_ATTACH failed")

    def _ptrace(self, *, cmd: int, addr: Optional[Any]=None, data: Optional[Any]=None) -> int:
        """Interface to ptrace."""
        return cast(int, _libc.ptrace(cmd, self._pid, addr, data))

    def _read_word(self, *, addr: int) -> int:
        """Read a word from the attached process."""
        result: int = self._ptrace(cmd=PTRACE_PEEKDATA, addr=c_uint64(addr))
        # FIXME: it's hard to tell if an error has happened here
        #if result == -1: raise PtraceException(f"PTRACE_PEEKDATA failed for {hex(addr)}")
        return result

    def _write_word(self, *, addr: int, data: int) -> None:
        """Read a word from the attached process."""
        result: int = self._ptrace(cmd=PTRACE_POKEDATA, addr=c_uint64(addr), data=c_uint64(data))
        if result == -1:
            raise PtraceException(f"PTRACE_POKEDATA failed")

    def read_memory(self, *, addr: int, length: int) -> bytes:
        """Read memory from the attached process."""
        result: bytes = b""

        for offs in range(0, length, 4):
            v: int = self._read_word(addr=addr+offs)
            #print(v)
            result += struct.pack("<I", v&0xFFFFFFFF)

        return result[:length]

    def write_memory(self, *, addr: int, data: bytes) -> None:
        """Write memory to the attached process."""

        # Pad memory with extra bytes from the process
        # if the length isn't a whole number of 32-bit words
        padded_length: int = (len(data)+0x3)&~0x3
        if padded_length > 0:
            data += self.read_memory(
                addr=addr+len(data),
                length=padded_length-len(data))

        assert len(data) % 4 == 0

        for offs in range(0, len(data), 4):
            v: int = struct.unpack("<I", data[offs:offs+4])[0]
            self._write_word(
                addr=addr+offs,
                data=v)

