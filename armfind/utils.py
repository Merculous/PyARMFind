
from typing import Any

from binpatch.types import Buffer

from .types import InsnBitSizes


def instructionToObject(insn: Buffer, obj: Any, attrSizes: InsnBitSizes, flip: bool = True) -> Any | None:
    insnSize = len(insn)

    if insnSize not in (2, 4):
        return None

    insnBits = 8 * insnSize
    insn = int.from_bytes(insn, 'little' if flip else 'big')

    if sum(attrSizes) != insnBits:
        return

    if insnSize == 4:
        # Make things easier for ourselves
        insn = ((insn & 0xFFFF) << 16) | (insn >> 16)

    attrs = []
    shift = insnBits

    for size in attrSizes:
        shift -= size
        attrs.append((insn >> shift) & ((1 << size) - 1))

    return obj(*attrs)


def objectToInstruction(obj: Any, attrSizes: InsnBitSizes, flip: bool = True) -> Buffer:
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
