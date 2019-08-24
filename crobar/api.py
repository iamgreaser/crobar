from abc import ABCMeta
from abc import abstractmethod
from typing import Tuple


class HackingOpException(Exception):
    """Generic exception fires whenever we can't quite hack something."""
    __slots__ = ()


class DebugInterface(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def read_memory(self, *, addr: int, length: int) -> bytes:
        """Read memory from the attached process."""
        raise NotImplementedError()

    @abstractmethod
    def write_memory(self, *, addr: int, data: bytes) -> None:
        """Write memory to the attached process."""
        raise NotImplementedError()


class TalosVersion(metaclass=ABCMeta):
    __slots__ = ()

    @abstractmethod
    def __init__(self, *, debug_interface: "DebugInterface") -> None:
        pass

    @classmethod
    @abstractmethod
    def get_version_identifier(cls) -> Tuple[int, bytes]:
        """Returns an (address, bytes) tuple uniquely identifying this build."""
        raise NotImplementedError()

    @abstractmethod
    def patch_memory(self, *, addr: int, old: bytes, new: bytes) -> bool:
        """Attempts to apply a patch at the given address."""
        raise NotImplementedError()

    #
    # Patches to implement
    #

    @abstractmethod
    def patch_enable_esga(self) -> bool:
        """PATCH: Stops prjStartNewTalosGame() from scrubbing out the gam_esgaStartAs variable.

        Patch-hunting advice:
        Search for gam_esgaStartAs, set a write watchpoint on it, then start a game.
        That instruction needs to be nopped.
        """
        raise NotImplementedError()

    @abstractmethod
    def patch_bypass_game_mode_checks_for_map_vote(self) -> bool:
        """PATCH: Allows voting for any map regardless of game mode.

        Patch-hunting advice: Search for this string:
        "Cannot start vote to change map because requested level %1 is not valid forgame mode %2!"

        This shows up in two similar functions.
        Choose the shorter one which apparently has 3 arguments.
        The other one is longer, has 1 argument, and does 3 calls to virtual methods on that argument.

        There should be two checks and if either of them fail, you end up failing the map vote.
        Patch out the first check, and leave the second check as-is.
        """
        raise NotImplementedError()

