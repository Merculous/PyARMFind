
from typing import Any

from binpatch.types import Buffer
from binpatch.utils import getBufferAtIndex

from .types import InsnBitSizes

def instructionToObject(insn: Buffer, obj: Any, attrSizes: InsnBitSizes, flip: bool = True) -> Any | None:
    insnSize = len(insn)

    if insnSize not in (2, 4):
        return None

    insnBits = 8 * insnSize
    insn = int.from_bytes(insn, 'little') if flip else int.from_bytes(insn, 'big')
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
