import sys

if sys.platform.startswith("linux"):
    from .linux import LinuxDebugInterface as ConcreteDebugInterface
elif sys.platform.startswith("win32"):
    from .windows import WindowsDebugInterface as ConcreteDebugInterface
else:
    raise NotImplementedError(f"Operating system platform {sys.platform!r} not supported yet")
