from typing import Callable


class Breakpoint:
    __slots__ = (
        "addr",
        "callback",
        "old_byte",
        "state",
    )

    STATE_INACTIVE = 0
    STATE_ACTIVE = 1
    STATE_WAITING_STEP = 2

    def __init__(self, addr: int, callback: Callable[[], None], old_byte: bytes):
        self.addr = addr
        self.old_byte = old_byte
        self.callback = callback
        self.state = Breakpoint.STATE_INACTIVE
