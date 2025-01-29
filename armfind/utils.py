
from typing import Any

from binpatch.types import Buffer
from binpatch.utils import getBufferAtIndex

from .types import InsnBitSizes


def instructionToObject(insn: Buffer, obj: Any, attrSizes: InsnBitSizes, flip: bool = True) -> Any | None:
    insnSize = len(insn)

    if insnSize not in (2, 4):
        return None

    insnBits = 8 * insnSize
    insn = int.from_bytes(insn, 'little' if flip else 'big')
    binStr = bin(insn)[2:].zfill(insnBits)

    if sum(attrSizes) != insnBits:
        return

    if insnSize == 4:
        # Make things easier for ourselves
        binStr1 = getBufferAtIndex(binStr, 0, 16)
        binStr2 = getBufferAtIndex(binStr, 16, 16)
        binStr = ''.join((binStr2, binStr1))

    i = 0
    attrs = []

    for bitSize in attrSizes:
        buffer = getBufferAtIndex(binStr, i, bitSize)
        attrs.append(buffer)
        i += bitSize

    attrs = [int(a, 2) for a in attrs]
    return obj(*attrs)


def objectToInstruction(obj: Any, attrSizes: InsnBitSizes, flip: bool = True) -> Buffer:
    insnSize = sum(attrSizes) // 8

    if insnSize not in (2, 4):
        raise Exception('Invalid instruction size!')

    attrs = vars(obj)
    insn = ''

    for attr, attrSize in zip(attrs, attrSizes):
        value = attrs[attr]
        bStr = bin(value)[2:].zfill(attrSize)

        insn += bStr

    if insnSize == 4:
        binStr1 = getBufferAtIndex(insn, 0, 16)
        binStr2 = getBufferAtIndex(insn, 16, 16)
        insn = ''.join((binStr2, binStr1))

    insn = int(insn, 2).to_bytes(insnSize, 'little' if flip else 'big')
    return insn
