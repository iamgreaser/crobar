import sys

from .arch import ConcreteDebugInterface
from .versions import ALL_VERSIONS
from crobar.api import DebugInterface
from crobar.api import TalosVersion


# TODO move all this stuff out into proper classes and packages and stuff
print("Attaching to Talos")
debug_interface: DebugInterface = ConcreteDebugInterface()

print("Finding Talos version")
for talos_version_type in ALL_VERSIONS:
    ver_addr, ver_string, = talos_version_type.get_version_identifier()
    exe_string: bytes = debug_interface.read_memory(
        addr=ver_addr,
        length=len(ver_string))
    if ver_string == exe_string:
        print(f"Found Talos version: {talos_version_type!r}")
        talos_version: TalosVersion = talos_version_type(
            debug_interface=debug_interface)
        break
else:
    raise Exception(f"Could not identify the version of the running Talos executable")

raise Exception("TODO: finish loading types")
print("Applying patches")

sys.stdout.write("- patch_enable_esga: ")
sys.stdout.write("OK" if talos_version.patch_enable_esga() else "Already patched")
sys.stdout.write("\n")

sys.stdout.write("- patch_bypass_game_mode_checks_for_map_vote: ")
sys.stdout.write("OK" if talos_version.patch_bypass_game_mode_checks_for_map_vote() else "Already patched")
sys.stdout.write("\n")

sys.stdout.write("- patch_crash_on_nexus_0001: ")
sys.stdout.write("OK" if talos_version.patch_crash_on_nexus_0001() else "Already patched")
sys.stdout.write("\n")

sys.stdout.write("- patch_upgrade_singleplayer: ")
sys.stdout.write("OK" if talos_version.patch_upgrade_singleplayer() else "Already patched")
sys.stdout.write("\n")

sys.stdout.write("- patch_ignore_pure_mode: ")
sys.stdout.write("OK" if talos_version.patch_ignore_pure_mode() else "Already patched")
sys.stdout.write("\n")
