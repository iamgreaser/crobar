import struct
from typing import List
from typing import Tuple

from crobar.api import HackingOpException
from crobar.api import TalosVersion
from .base import BaseTalosVersion


class TalosVersion_v244371_windows_x86_32(BaseTalosVersion):
    @classmethod
    def get_version_identifier(cls) -> Tuple[int, bytes]:
        """Returns an (address, bytes) tuple uniquely identifying this build."""
        return (
            0x01515f38,
            b"$Version: Talos_PC_distro; Talos-Windows-Final; 244371 2015-07-23 19:11:28 @builder14; Win32-Static-Final-Default$",)

    def patch_enable_esga(self) -> bool:
        """PATCH: Stops prjStartNewTalosGame() from scrubbing out the gam_esgaStartAs variable."""
        return self.patch_memory(
            addr=0x00773a1f,
            old=bytes([0x89, 0x35, 0x98, 0x6d, 0x5d, 0x01]),
            new=bytes([0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        )

    def patch_bypass_game_mode_checks_for_map_vote(self) -> bool:
        """PATCH: Allows voting for any map regardless of game mode."""
        patches_applied: List[bool] = []

        patches_applied.append(self.patch_memory(
            addr=0x00915282,
            old=bytes([0x74, 0x58]),
            new=bytes([0x90, 0x90]),
        ))

        patches_applied.append(self.patch_memory(
            addr=0x00565c7e,
            old=bytes([0xe8, 0x5d, 0xe3, 0x9c, 0x00]),
            new=bytes([0xb8, 0x01, 0x00, 0x00, 0x00]),
        ))

        patches_applied.append(self.patch_memory(
            addr=0x00565cb0,
            old=bytes([0x0f, 0x85, 0xc7, 0x00, 0x00, 0x00]),
            new=bytes([0x90, 0x90, 0x90, 0x90, 0x90, 0x90]),
        ))

        return any(patches_applied)

    def patch_upgrade_singleplayer(self) -> bool:
        """PATCH: Upgrade the SinglePlayer mode to a multiplayer mode."""
        patches_applied: List[bool] = []

        game_mode_base: int
        game_mode_count: int
        game_mode_base, game_mode_count, = struct.unpack(
            "<II",
            self._debug_interface.read_memory(
                addr=0x0156e150,
                length=0x8))

        # Find the SinglePlayer game mode
        print(f"Game modes: {game_mode_count} @ 0x{game_mode_base:x}")
        for idx in range(game_mode_count):
            game_mode_addr: int = game_mode_base + idx*0x1B4
            game_mode_data: bytes = self._debug_interface.read_memory(
                addr=game_mode_addr,
                length=0x1B4)

            game_mode_name_ptr: int
            game_mode_name_ptr, = struct.unpack("<I", game_mode_data[4:4+4])

            # 16 bytes should be enough to get the point across
            game_mode_name: bytes = self._debug_interface.read_memory(
                addr=game_mode_name_ptr,
                length=16)
            game_mode_name = game_mode_name.partition(b"\x00")[0]
            print(f"  - {idx:2d}: {game_mode_name!r}")
            if game_mode_name == b"SinglePlayer":
                print(f"    - Found it!")
                break
        else:
            raise HackingOpException("Could not find the \"SinglePlayer\" game mode")

        # Set gar_bAllowsMP = true and gar_ctMaxPlayersTop = 16
        patches_applied.append(
            self.patch_memory(
                addr=game_mode_addr + 4*15,
                old=bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]),
                new=bytes([0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00])))

        return any(patches_applied)

    def patch_ignore_pure_mode(self) -> bool:
        patches_applied: List[bool] = []

        patches_applied.append(self.patch_memory(
            addr=0x00F505F4,
            old=bytes([0x74]),
            new=bytes([0xeb]),
        ))

        patches_applied.append(self.patch_memory(
            addr=0x00F5088D,
            old=bytes([0x74]),
            new=bytes([0xeb]),
        ))

        return any(patches_applied)
