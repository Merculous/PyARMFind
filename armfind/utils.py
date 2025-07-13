
from struct import unpack_from
from typing import Any, Callable

from .types import InsnBitSizes


def instructionToObject(insn: bytes, obj: Any, attrSizes: InsnBitSizes, validator: Callable, flip: bool = True) -> Any | None:
    insnSize = len(insn)

    if insnSize not in (2, 4):
        return

    insnBits = 8 * insnSize
    insnInt = int.from_bytes(insn, 'little' if flip else 'big')

    if sum(attrSizes) != insnBits:
        return

    if insnSize == 4:
        # Make things easier for ourselves
        insnInt = ((insnInt & 0xFFFF) << 16) | (insnInt >> 16)

    attrs = []
    shift = insnBits

    for size in attrSizes:
        shift -= size
        attrs.append((insnInt >> shift) & ((1 << size) - 1))

    obj = obj(*attrs)

    if not validator(obj):
        return

    return obj


def objectToInstruction(obj: Any, attrSizes: InsnBitSizes, flip: bool = True) -> bytes:
    insnSize = sum(attrSizes) // 8

    if insnSize not in (2, 4):
        raise Exception('Invalid instruction size!')

    attrs = vars(obj)
    insn = 0
    shift = 8 * insnSize

    for attr, size in zip(attrs.values(), attrSizes):
        shift -= size
        insn |= (attr & ((1 << size) - 1)) << shift

    if insnSize == 4:
        insn = ((insn & 0xFFFF) << 16) | (insn >> 16)

    return insn.to_bytes(insnSize, 'little' if flip else 'big')


# Taken from iBoot32Patcher and converted via ChatGPT
def resolve_bl32(bl: bytes) -> int:
    # Ensure we have at least 4 bytes
    if len(bl) != 4:
        raise ValueError("Input must be at least 4 bytes long")

    # Unpack two 16-bit little-endian values
    bits_val, exts_val = unpack_from('<HH', bl)

    # Decode first 16 bits
    bits_immediate = bits_val & 0x03FF       # 10 bits
    bits_s = (bits_val >> 10) & 0x01         # 1 bit

    # Decode second 16 bits
    exts_immediate = exts_val & 0x07FF       # 11 bits
    exts_j2 = (exts_val >> 11) & 0x01        # 1 bit
    exts_x = (exts_val >> 12) & 0x01         # 1 bit
    exts_j1 = (exts_val >> 13) & 0x01        # 1 bit

    # Reconstruct signed 25-bit immediate offset (shifted left by 1)
    jump = 0
    jump |= bits_s << 24
    jump |= (~(bits_s ^ exts_j1) & 0x1) << 23
    jump |= (~(bits_s ^ exts_j2) & 0x1) << 22
    jump |= bits_immediate << 12
    jump |= exts_immediate << 1
    jump |= exts_x

    # Sign-extend from 25 bits to 32 bits
    if jump & (1 << 24):
        jump |= ~((1 << 25) - 1)  # Fill upper bits with 1's

    # Resulting address is PC-relative: PC + 4 + jump
    return 4 + jump
