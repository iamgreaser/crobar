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

    @abstractmethod
    def from_relative_addr(self, addr: int) -> int:
        """Converts a relative-to-intended-memory-base address to an absolute address."""
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

        Alternatively, search for "Content/Talos/Levels/Demo.wld",
        then find all things that refer to it.

        The one you're interested in sets 3 things near the end to 0, 0, 3.
        The first 0 is gam_esgaStartAs.
        The second 0 is probably custom difficulty?
        The 3 is gam_gdDifficulty.
        """
        raise NotImplementedError()

    @abstractmethod
    def patch_bypass_game_mode_checks_for_map_vote(self) -> bool:
        """PATCH: Allows voting for any map regardless of game mode.

        Patch-hunting advice: Search for this string:
        "Cannot start vote to change map because requested level %1 is not valid forgame mode %2!"

        This shows up in two similar functions.
        One is shorter and apparently has 3 arguments.
        The other one is longer, has 1 argument, and does 3 calls to virtual methods on that argument.

        There should be two checks and if either of them fail, you end up failing the map vote.
        Patch out the first check, and leave the second check as-is.

        Do it for both functions.
        """
        raise NotImplementedError()

    # Not required at the moment - experimental. --GM
    #@abstractmethod
    def patch_crash_on_nexus_0001(self) -> bool:
        """PATCH: WIP

        Patch-hunting advice: Join a game and go into the Nexus.
        Then NOP out the final crashing call.
        """
        #raise NotImplementedError()
        print("Unimplmented, not required")
        return False

    @abstractmethod
    def patch_upgrade_singleplayer(self) -> bool:
        """PATCH: Upgrade the SinglePlayer mode to a multiplayer mode.

        Patch-hunting advice:
        There's a pointer to an array of game rules, and a length.
        Also, do a search for the string "CGameRules",
        then look for stuff that points to that string.

        You should find a table.

        The order there should match the order of the elements in a game rules set.

        Hunting down the actual pointer itself is a bit tricky
        as the game rules are somewhat further into the game rules set.
        """
        raise NotImplementedError()

    @abstractmethod
    def patch_ignore_pure_mode(self) -> bool:
        """PATCH: Force Pure mode to accept our replacement resources.

        Patch-hunting advice:
        Search for "Pure mode doesn't support replacement resources".
        Then make sure all calls which use it never happen.
        """
        raise NotImplementedError()
