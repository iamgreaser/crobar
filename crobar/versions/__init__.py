from typing import Sequence
from typing import Type

from crobar.api import TalosVersion


# Add versions here...
# v(220480|244371|326589|440323|...)_(linux|macos|windows)_(x86)_(32|64)
from .v244371_linux_x86_32 import TalosVersion_v244371_linux_x86_32

# ...and also remember to add them here too so they show up
# Yes, for all OSes, it IS possible to debug Windows stuff on Linux and FreeBSD via Wine
ALL_VERSIONS: Sequence[Type[TalosVersion]] = (
    TalosVersion_v244371_linux_x86_32,
)

