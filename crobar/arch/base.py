"""Base classes for platform-independent debugging and hacking."""
from abc import ABCMeta
from abc import abstractmethod

from crobar.api import DebugInterface


class BaseDebugInterface(DebugInterface, metaclass=ABCMeta):
    __slots__ = ()
