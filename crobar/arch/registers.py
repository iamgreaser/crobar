from dataclasses import dataclass

"""A simple dataclass to store register values.

DebugInterfaces should be able to get/set all values in this class.
"""
@dataclass(init=False)
class Registers:
    rax: int
    rbp: int
    rbx: int
    rcx: int
    rdi: int
    rdx: int
    rip: int
    rsi: int
    rsp: int
    eflags: int
