from crobar.api import DebugInterface
from crobar.api import HackingOpException

from typing import Callable
from typing import Dict
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
        self._current_breakpoints: Dict[int, Breakpoint] = {}

    def __del__(self) -> None:
        print(f"Deleting {self!r}")
        # Don't want to leave extra breakpoints lying around when we close
        for bp in self._current_breakpoints:
            self.remove_breakpoint(bp)

    def add_breakpoint(self, addr: int, callback: Callable[[], None]) -> bool:
        """Creates a breakpoint that runs a callback function when triggered"""
        old_byte = self._debug_interface.read_memory(addr=addr, length=1)

        bp = Breakpoint(addr, callback, old_byte)
        self._current_breakpoints[addr] = bp

        self._debug_interface.write_memory(addr=addr, data=INT3_OPCODE)
        bp.state = Breakpoint.STATE_ACTIVE

        return False

    def remove_breakpoint(self, addr: int) -> bool:
        """Removes a breakpoint"""
        if addr not in self._current_breakpoints:
            HackingOpException(f"Tried to remove a breakpoint that does not exist")

        self._debug_interface.write_memory(
            addr=addr,
            data=self._current_breakpoints[addr].old_byte
        )
        del self._current_breakpoints[addr]

        return False

    # TODO: Thread this
    def _wait(self) -> None:
        while True:
            addr, is_single_step = self._debug_interface.wait_for_breakpoint()
            if addr in self._current_breakpoints:
                bp = self._current_breakpoints[addr]
                print(f"Breakpoint: {addr:08X}")

                if bp.state == Breakpoint.STATE_INACTIVE:
                    raise HackingOpException("Inactive breakpoint was triggered")

                elif bp.state == Breakpoint.STATE_ACTIVE and not is_single_step:
                    # Add the trap flag so that we break again on the next instruction
                    eflags = self._debug_interface.get_register("EFlags")
                    eflags |= TRAP_FLAG
                    self._debug_interface.set_register("EFlags", eflags)
                    bp.state = Breakpoint.STATE_WAITING_STEP

                    # Add the old byte back so this instruction executes properly
                    self._debug_interface.write_memory(addr=bp.addr, data=bp.old_byte)

                    bp.callback()

                elif bp.state == Breakpoint.STATE_WAITING_STEP and is_single_step:
                    # Remove the trap flag and replace the instruction with an int3 again
                    eflags = self._debug_interface.get_register("EFlags")
                    eflags &= (TRAP_FLAG ^ 0xFFFFFFFF)
                    self._debug_interface.set_register("EFlags", eflags)
                    bp.state = Breakpoint.STATE_ACTIVE
                    self._debug_interface.write_memory(addr=bp.addr, data=INT3_OPCODE)

                else:
                    raise HackingOpException("Breakpoint state desynced")

            self._debug_interface.resume_from_breakpoint()
