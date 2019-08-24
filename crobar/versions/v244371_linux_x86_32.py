
from typing import Tuple

from crobar.api import TalosVersion
from .base import BaseTalosVersion


class TalosVersion_v244371_linux_x86_32(BaseTalosVersion):
    @classmethod
    def get_version_identifier(cls) -> Tuple[int, bytes]:
        """Returns an (address, bytes) tuple uniquely identifying this build."""
        return (
            0x09a7d174,
            b"$Version: Talos_PC_distro; Talos_Executables-Linux-Final; 244371 2015-07-23 19:11:33 @builderl02; Linux-Static-Final-Default$",)

    def patch_enable_esga(self) -> bool:
        """PATCH: Stops prjStartNewTalosGame() from scrubbing out the gam_esgaStartAs variable."""
        # MOV dword ptr [EStartGameAs_09e9084c],0x0
        return self.patch_memory(
            addr=0x08b9c4a8,
            old=bytes([0xc7, 0x05, 0x4c, 0x08, 0xe9, 0x09, 0x00, 0x00, 0x00, 0x00]),
            new=bytes([0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        )

    def patch_bypass_game_mode_checks_for_map_vote(self) -> bool:
        """PATCH: Allows voting for any map regardless of game mode."""
        return self.patch_memory(
            addr=0x08939b2c,
            old=bytes([0xe8, 0x5f, 0xb9, 0xc1, 0xff, 0x85, 0xc0, 0x75, 0x63]),
            new=bytes([0xe8, 0x5f, 0xb9, 0xc1, 0xff, 0x85, 0xc0, 0xeb, 0x63]),
        )

