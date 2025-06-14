
from dataclasses import dataclass
from typing import Any

Insn = tuple[Any, int]
InsnBitSizes = tuple[int, ...]

@dataclass
class LDRLiteral:
    magic: int
    rt: int
    imm8: int


@dataclass
class CMP:
    magic1: int
    magic2: int
    rn: int
    imm8: int


@dataclass
class MOVS:
    magic1: int
    magic2: int
    rd: int
    imm8: int


@dataclass
class MOV_W:
    magic1: int
    i: int
    magic2: int
    magic3: int
    s: int
    magic4: int
    magic5: int
    imm3: int
    rd: int
    imm8: int


@dataclass
class MOVW:
    magic1: int
    i: int
    magic2: int
    magic3: int
    magic4: int
    magic5: int
    magic6: int
    imm4: int
    magic7: int
    imm3: int
    rd: int
    imm8: int


@dataclass
class BL:
    magic1: int
    s: int
    imm10: int
    magic2: int
    j1: int
    magic3: int
    j2: int
    imm11: int


@dataclass
class LDR_W:
    magic1: int
    magic2: int
    magic3: int
    magic4: int
    magic5: int
    magic6: int
    rn: int
    rt: int
    imm12: int    


@dataclass
class PUSH:
    magic1: int
    magic2: int
    magic3: int
    m: int
    register_list: int


@dataclass
class MOVT:
    magic1: int
    i: int
    magic2: int
    magic3: int
    magic4: int
    magic5: int
    magic6: int
    imm4: int
    magic7: int
    imm3: int
    rd: int
    imm8: int


@dataclass
class BLXRegister:
    magic1: int
    magic2: int
    magic3: int
    rm: int
    magic4: int


@dataclass
class POP:
    magic1: int
    magic2: int
    magic3: int
    p: int
    register_list: int


@dataclass
class MOVRegister:
    magic1: int
    magic2: int
    d: int
    rm: int
    rd: int


@dataclass
class BNE_W:
    magic1: int
    s: int
    cond: int
    imm6: int
    magic2: int
    j1: int
    magic3: int
    j2: int
    imm11: int


@dataclass
class LDRB:
    magic1: int
    magic2: int
    magic3: int
    imm5: int
    rn: int
    rt: int


@dataclass
class NEGS:
    magic1: int
    rn: int
    rd: int


@dataclass
class IT:
    magic1: int
    firstcond: int
    mask: int
