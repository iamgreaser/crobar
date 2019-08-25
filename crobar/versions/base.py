from abc import ABCMeta
from abc import abstractmethod
import struct
from typing import Tuple

from crobar.api import DebugInterface
from crobar.api import TalosVersion
from crobar.api import HackingOpException


class BaseTalosVersion(TalosVersion, metaclass=ABCMeta):
    __slots__ = (
        "_debug_interface",
    )

    def __init__(self, *, debug_interface: DebugInterface) -> None:
        self._debug_interface = debug_interface

    def from_relative_addr(self, addr: int) -> int:
        """Converts a relative-to-intended-memory-base address to an absolute address."""
        return self._debug_interface.from_relative_addr(addr)

    def pack_relative_addr(self, addr: int) -> bytes:
        """Packs a relative-to-intended-memory-base address as an absolute address."""
        return struct.pack("<I", self.from_relative_addr(addr))

    def patch_memory(self, *, addr: int, old: bytes, new: bytes) -> bool:
        """Attempts to apply a patch at the given address.

        Returns True if the patch applied.
        Returns False if the patch was applied earlier
        Throws a HackingOpException if the data there is neither old nor new.
        """

        assert len(old) == len(new)

        ref: bytes = self._debug_interface.read_memory(
            addr=addr,
            length=len(old))

        print(repr(ref))
        if ref == new:
            # Already been patched.
            return False
        elif ref == old:
            # Needs to be patched.
            self._debug_interface.write_memory(
                addr=addr,
                data=new)
            return True
        else:
            # Unexpected data!
            raise HackingOpException(f"unexpected data to be patched: {ref!r}")

