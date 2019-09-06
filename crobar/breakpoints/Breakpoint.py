from typing import Callable
from typing import Optional
from dataclasses import dataclass
from dataclasses import field


@dataclass(unsafe_hash=True)
class Breakpoint:
    class State:
        INACTIVE = 0
        ACTIVE = 1
        WAITING_STEP = 2

    addr: int
    callback: Callable[[], None]
    old_byte: bytes
    name: Optional[str] = None
    state: int = field(default=State.INACTIVE, compare=False)
