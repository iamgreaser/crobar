from abc import ABCMeta
from abc import abstractmethod
from io import IOBase
import struct
from typing import IO
from typing import Optional
from typing import Tuple

from crobar.api import DebugInterface
from crobar.api import TalosVersion
from crobar.api import HackingOpException


# TODO!
class MemoryReadIO(IOBase):
    __slots__ = (
        "_addr",
        "_debug_interface",
    )

    def __init__(self, *, addr: int, debug_interface: DebugInterface) -> None:
        self._addr = addr
        self._debug_interface = debug_interface

    def read(self, length: Optional[int]=None) -> bytes:
        if length is not None:
            result: bytes = self._debug_interface.read_memory(addr=self._addr, length=length)
            self._addr += length
            return result
        else:
            raise ValueError(f"Please provide a length for {self.__class__.__name__}.read()!")


class BaseTalosVersion(TalosVersion, metaclass=ABCMeta):
    __slots__ = (
        "_debug_interface",
    )

    def __init__(self, *, debug_interface: DebugInterface) -> None:
        self._debug_interface = debug_interface
        self.load_all_types()

    def from_relative_addr(self, addr: int) -> int:
        """Converts a relative-to-intended-memory-base address to an absolute address."""
        return self._debug_interface.from_relative_addr(addr)

    def read_memory(self, *, addr: int, length: int) -> bytes:
        """Read memory from the attached process."""
        return self._debug_interface.read_memory(addr=addr, length=length)

    def write_memory(self, *, addr: int, data: bytes) -> None:
        """Write memory to the attached process."""
        self._debug_interface.write_memory(addr=addr, data=data)

    def pack_relative_addr(self, addr: int) -> bytes:
        """Packs a relative-to-intended-memory-base address as an absolute address."""
        return struct.pack("<I", self.from_relative_addr(addr))

    def read_asciiz(self, *, addr: int) -> bytes:
        """Read a NUL-terminated string and return a bytes value."""

        assert addr >= 0x100, "we've hit a null pointer somewhere, TODO handle this more elegantly"

        b: bytes = b""
        while True:
            block: bytes = self.read_memory(addr=addr, length=8)
            b += block
            addr += 8
            if b"\x00" in b:
                b = b.partition(b"\x00")[0]
                return b

    def patch_memory(self, *, addr: int, old: bytes, new: bytes) -> bool:
        """Attempts to apply a patch at the given address.

        Returns True if the patch applied.
        Returns False if the patch was applied earlier
        Throws a HackingOpException if the data there is neither old nor new.
        """

        assert len(old) == len(new)

        ref: bytes = self.read_memory(
            addr=addr,
            length=len(old))

        print(repr(ref))
        if ref == new:
            # Already been patched.
            return False
        elif ref == old:
            # Needs to be patched.
            self.write_memory(
                addr=addr,
                data=new)
            return True
        else:
            # Unexpected data!
            raise HackingOpException(f"unexpected data to be patched: {ref!r}")

    def load_all_types(self) -> None:
        """Load all types that can be extracted from the executable."""
        pass

    def load_types_block(self, *, addr: int) -> None:
        """Load types from a given block in the executable."""

        fp = MemoryReadIO(
            addr=addr,
            debug_interface=self._debug_interface)

        # TODO actually store this crap
        # TODO use an I/O wrapper
        while True:
            typ0: int
            typ0, = struct.unpack("<i", fp.read(4))

            if typ0 == -1:
                break
            elif typ0 == 1:
                typ1: int
                typ2: int
                typname_ptr: int
                unk4: int
                length_in_bytes: int
                unk6: int
                unk7: int
                unk8: int
                typ1, typ2, typname_ptr, unk4, length_in_bytes, unk6, unk7, unk8, = (
                    struct.unpack("<IIIIIIII", fp.read(32)))

                typname: bytes = self.read_asciiz(addr=typname_ptr)
                print(f"Type: {typ0} {typ1} {typ2} {typname!r} {unk4} {length_in_bytes} {unk6} {unk7} {unk8}")

                if typ1 == 1:
                    # Enum
                    enum_length: int
                    enum_length, = struct.unpack("<I", fp.read(4))
                    print(f"- Enum length: {enum_length}")

                    for field_idx in range(enum_length):
                        field_value: int
                        field_name_ptr: int
                        field_desc_ptr: int
                        field_value, field_name_ptr, field_desc_ptr, = struct.unpack("<III",
                            fp.read(12))

                        field_name: bytes = self.read_asciiz(addr=field_name_ptr)
                        field_desc: bytes = self.read_asciiz(addr=field_desc_ptr)
                        print(f"  - {field_name!r} = {field_value!r} // {field_desc!r}")

                    enum_unk_footer1_ptr: int
                    enum_unk_footer1_ptr, = struct.unpack("<I",
                        fp.read(4))

                    print(f"- Enum unk footer1 ptr: {enum_unk_footer1_ptr}")

                elif typ1 == 2:
                    # T*
                    if unk8 != 1:
                        raise NotImplementedError(f"TODO: typ1={typ1} unk8!=1 ({unk8})")

                    clsname_ptr: int
                    clsname_ptr, = struct.unpack("<I", fp.read(4))
                    clsname: bytes = self.read_asciiz(addr=clsname_ptr)
                    print(f"- Pointer to class {clsname!r}")

                elif typ1 == 3:
                    # T&
                    if unk8 != 1:
                        raise NotImplementedError(f"TODO: typ1={typ1} unk8!=1 ({unk8})")

                    clsname_ptr, = struct.unpack("<I", fp.read(4))
                    clsname = self.read_asciiz(addr=clsname_ptr)
                    print(f"- Reference to class {clsname!r}")

                elif typ1 == 4:
                    # T[count]
                    if unk8 != 1:
                        raise NotImplementedError(f"TODO: typ1={typ1} unk8!=1 ({unk8})")

                    clsname_ptr, = struct.unpack("<I", fp.read(4))
                    clsname = self.read_asciiz(addr=clsname_ptr)
                    print(f"- Array of class {clsname!r}")

                    array_dims, = struct.unpack("<I", fp.read(4))
                    print(f"- Dimensions: {array_dims}")
                    for i in range(array_dims):
                        array_dim_length, = struct.unpack("<I", fp.read(4))
                        print(f"  - Dimension {i+1:d} length: {array_dim_length}")

                elif typ1 == 7:
                    # CStaticStackArray<T>
                    if unk8 != 1:
                        unk9_ref, = struct.unpack("<I", fp.read(4))
                        #unk9_ptr, = struct.unpack("<I", self.read_memory(addr=0x0a1f26a4+4*unk9_ref, length=4))
                        #print(f"- Stack array w/ unknown reference {unk9_ref!r} {unk9_ptr:08X}")
                        print(f"- Stack array w/ unknown reference {unk9_ref!r}")
                    else:
                        clsname_ptr, = struct.unpack("<I", fp.read(4))
                        clsname = self.read_asciiz(addr=clsname_ptr)
                        print(f"- Stack array of class {clsname!r}")

                elif typ1 == 8:
                    # CDynamicContainer<T>
                    if unk8 != 1:
                        raise NotImplementedError(f"TODO: typ1={typ1} unk8!=1 ({unk8})")

                    clsname_ptr, = struct.unpack("<I", fp.read(4))
                    clsname = self.read_asciiz(addr=clsname_ptr)
                    print(f"- Contains class {clsname!r}")

                elif typ1 == 9:
                    # Method?
                    if unk8 != 1:
                        raise NotImplementedError(f"TODO: typ1={typ1} unk8!=1 ({unk8})")

                    method_unk1_ptr, = struct.unpack("<I", fp.read(4))
                    method_unk1 = self.read_asciiz(addr=method_unk1_ptr)
                    print(f"- Method unk1 {method_unk1!r}")

                    method_unk2_prefix, = struct.unpack("<I", fp.read(4))
                    method_unk2_ptr, = struct.unpack("<I", fp.read(4))
                    if method_unk2_prefix != 1:
                        print(f"- Method unk2 unknown {method_unk2_prefix} {method_unk2_ptr}")
                    else:
                        method_unk2 = self.read_asciiz(addr=method_unk2_ptr)
                        print(f"- Method unk2 {method_unk2!r}")

                    method_arg_count, = struct.unpack("<I", fp.read(4))
                    for method_arg_idx in range(method_arg_count):
                        method_arg_typ_prefix, = struct.unpack("<I", fp.read(4))
                        method_arg_typ_ptr, = struct.unpack("<I", fp.read(4))
                        method_arg_name_ptr, = struct.unpack("<I", fp.read(4))
                        method_arg_name = self.read_asciiz(addr=method_arg_name_ptr)
                        method_arg_unk4, = struct.unpack("<I", fp.read(4))

                        if method_arg_typ_prefix != 1:
                            print(f"  - Method arg {method_arg_idx:d}: unhandled type {method_arg_typ_prefix}/{method_arg_typ_ptr}, {method_arg_name!r}, {method_arg_unk4}")
                        else:
                            method_arg_typ = self.read_asciiz(addr=method_arg_typ_ptr)
                            print(f"  - Method arg {method_arg_idx:d}: {method_arg_typ!r} {method_arg_name!r}, {method_arg_unk4}")

                    method_footer_unk1, = struct.unpack("<I", fp.read(4))
                    print(f"- Method footer unk1 {method_footer_unk1!r}")

                elif typ1 == 11:
                    # Ptr<T>
                    if unk8 != 1:
                        raise NotImplementedError(f"TODO: typ1={typ1} unk8!=1 ({unk8})")

                    clsname_ptr, = struct.unpack("<I", fp.read(4))
                    clsname = self.read_asciiz(addr=clsname_ptr)
                    print(f"- Pointer for class {clsname!r}")

                elif typ1 == 12:
                    # Handle<T>
                    if unk8 != 1:
                        raise NotImplementedError(f"TODO: typ1={typ1} unk8!=1 ({unk8})")

                    clsname_ptr, = struct.unpack("<I", fp.read(4))
                    clsname = self.read_asciiz(addr=clsname_ptr)
                    print(f"- Handle for class {clsname!r}")

                elif typ1 == 14:
                    # U<T>
                    baseclsname = self.read_asciiz(addr=unk8)
                    unk9, = struct.unpack("<I", fp.read(4))
                    if unk9 != 1:
                        unk10_ref, = struct.unpack("<I", fp.read(4))
                        print(f"- Generic {baseclsname!r} w/ unknown reference {unk10_ref!r}")
                    else:
                        clsname_ptr, = struct.unpack("<I", fp.read(4))
                        clsname = self.read_asciiz(addr=clsname_ptr)
                        print(f"- Generic {baseclsname!r} for class {clsname!r}")

                    entry_count, = struct.unpack("<I", fp.read(4))
                    for entry_idx in range(entry_count):
                        entry_mask, entry_ptr, = struct.unpack("<II", fp.read(8))
                        print(f"  - Entry mask {entry_mask:08X} function 0x{entry_ptr:x}")

                    unk_footer1_ptr: int
                    unk_footer1_ptr, = struct.unpack("<I",
                        fp.read(4))

                    print(f"- Unk footer1 ptr: {unk_footer1_ptr}")

                else:
                    raise NotImplementedError(f"unhandled typ1 {typ1!r}")
            else:
                raise NotImplementedError(f"unhandled typ0 {typ0:08X}")

