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
        """PATCH: Stops prjStartNewTalosGame() from scrubbing out the gam_esgaStartAs variable."""
        raise NotImplementedError()

