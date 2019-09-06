from crobar.api import DebugInterface
from crobar.api import HackingOpException

from typing import Callable
from typing import Set
from typing import Optional
from typing import Union
from .Breakpoint import Breakpoint

INT3_OPCODE = b"\xCC"
TRAP_FLAG = 0x0100


class BreakpointHandler:
    __slots__ = (
        "_debug_interface",
        "_current_breakpoints",
    )

    def __init__(self, debug_interface: DebugInterface) -> None:
        self._debug_interface: DebugInterface = debug_interface
        self._current_breakpoints: Set[Breakpoint] = set()

        debug_interface.attach_debugger()

    def __del__(self) -> None:
        print(f"Deleting {self!r}")
        # Don't want to leave extra breakpoints lying around when we close
        for bp in self._current_breakpoints:
            self.remove_breakpoint(bp)

    def add_breakpoint(self, addr: int, callback: Callable[[], None], name: Optional[str] = None) -> None:
        """Creates a breakpoint that runs a callback function when triggered.

        You can create multiple breakpoints on the same address, and they will all run seperatly
        """
        # First check if we have another breakpoint already at this address
        for existing_bp in self._current_breakpoints:
            if existing_bp.addr != addr:
                continue

            # If we do then copy the old byte and add the new breakpoint directly to the set
            new_bp = Breakpoint(addr, callback, existing_bp.old_byte, name)
            new_bp.state = Breakpoint.State.ACTIVE
            self._current_breakpoints.add(new_bp)
            return

        # If this is the first one then we need make a copy of the byte currently at the address
        old_byte = self._debug_interface.read_memory(addr=addr, length=1)
        bp = Breakpoint(addr, callback, old_byte, name)
        self._current_breakpoints.add(bp)

        # Overwrite the start of the instruction with an INT3, which will break to our debugger
        self._debug_interface.write_memory(addr=addr, data=INT3_OPCODE)
        bp.state = Breakpoint.State.ACTIVE

    def remove_breakpoint(self, val: Union[int, str, Breakpoint]) -> None:
        """Removes a breakpoint.

        You may specify either the breakpoint address, name, or give a reference to it directly,

        If you give an address/name then all breakpoints with the same name/address will be removed
        If you give a reference then only that breakpoint will be removed
        """

        if isinstance(val, Breakpoint):
            self._debug_interface.write_memory(
                addr=val.addr,
                data=val.old_byte
            )
            self._current_breakpoints.remove(val)
            return

        is_name = isinstance(val, str)
        found_one = False
        for bp in self._current_breakpoints:
            if is_name and bp.name == val:
                self.remove_breakpoint(bp)
                found_one = True
            elif bp.addr == val:
                self.remove_breakpoint(bp)
                found_one = True

        if not found_one:
            HackingOpException(f"Tried to remove a breakpoint that does not exist")

    # TODO: Thread this
    def _wait(self) -> None:
        while True:
            addr, is_breakpoint = self._debug_interface.wait_for_breakpoint()

            if is_breakpoint:
                for bp in self._current_breakpoints:
                    if addr != bp.addr:
                        continue

                    print(f"Hit Breakpoint at: {bp.name if bp.name else f'{addr:016X}'}")

                    if bp.state == Breakpoint.State.INACTIVE:
                        self._debug_interface.resume_from_breakpoint()
                        raise HackingOpException("Inactive breakpoint was triggered")

                    # Add the trap flag so that we break again on the next instruction
                    registers = self._debug_interface.get_registers()
                    registers.eflags |= TRAP_FLAG
                    self._debug_interface.set_registers(registers)

                    bp.state = Breakpoint.State.WAITING_STEP

                    # Add the old byte back so this instruction executes properly
                    # If we have multiple breakpoints then they should all have the same old byte
                    self._debug_interface.write_memory(addr=bp.addr, data=bp.old_byte)

                    # See https://github.com/python/mypy/issues/708
                    bp.callback()  # type: ignore

            # After a breakpoint we let a single step pass
            # Instructions are at most 15 bytes long, so we reset any waiting breakpoints within
            #  that range of where we stopped
            # In practice this will only be the ones we originally stopped for last time
            else:
                # Even if we don't find any breakpoints, we have to remove the trap flag so that
                #  the game keeps running properly
                registers = self._debug_interface.get_registers()
                registers.eflags &= (TRAP_FLAG ^ 0xFFFFFFFF)
                self._debug_interface.set_registers(registers)
                print(f"rip: {registers.rip:08X}")

                for bp in self._current_breakpoints:
                    if bp.state != Breakpoint.State.WAITING_STEP or bp.addr > addr > bp.addr + 0x10:
                        continue

                    print(f"Resetting Breakpoint at: {bp.name if bp.name else f'{addr:016X}'}")
                    bp.state = Breakpoint.State.ACTIVE
                    self._debug_interface.write_memory(addr=bp.addr, data=INT3_OPCODE)

            # No matter the result, we have to resume the program
            self._debug_interface.resume_from_breakpoint()
