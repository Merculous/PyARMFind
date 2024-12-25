
from typing import Any

from binpatch.utils import getBufferAtIndex
from binpatch.types import Buffer, Index, Size

from .sizes import (
    LDRLiteralBitSizes,
    CMPBitSizes,
    MOVSBitSizes,
    MOV_WBitSizes,
    MOVWBitSizes,
    BLBitSizes
)
from .types import (
    Insn,
    InsnBitSizes,
    LDRLiteral,
    CMP,
    MOV_W,
    MOVS,
    MOVW,
    BL
)
from .utils import instructionToObject
from .validators import (
    isLDRLiteral,
    isCMP,
    isMOV_W,
    isMOVS,
    isMOVW,
    isBL
)


def searchForInsn(data: Buffer, offset: Index, insn: Any, insnBitSizes: InsnBitSizes, insnValidator: Any, flip: bool = True) -> Insn | None:
    insnSize = sum(insnBitSizes) // 8
    searchSize = len(data) - insnSize + 1
    match = None
    table = set()

    for i in range(searchSize - offset):
        buffer = getBufferAtIndex(data, offset + i, insnSize)
        bufferHash = hash(buffer)

        if bufferHash in table:
            continue

        table.add(bufferHash)
        insnObj = instructionToObject(buffer, insn, insnBitSizes, flip)

        if not insnValidator(insnObj):
            continue

        match = (insnObj, offset + i)
        break

    return match


def find_next_LDR_Literal(data: Buffer, offset: Index, skip: Size, value: Buffer) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(dataSize):
        ldr = searchForInsn(data, i, LDRLiteral, LDRLiteralBitSizes, isLDRLiteral)

        if ldr is None:
            break

        ldr, ldrOffset = ldr
        i = ldrOffset
        ldrRefOffset = (ldrOffset + (ldr.imm8 << 2) + 4) & ~3

        if ldrOffset >= dataSize + 1:
            i += 2
            continue

        window = getBufferAtIndex(data, ldrRefOffset, 4)

        if window != value:
            i += 2
            continue

        if skip <= 0:
            match = (ldr, i)
            break

        skip -= 1
        i += 2

    return match


def find_next_CMP_with_value(data, offset, skip, value) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(dataSize):
        cmp = searchForInsn(data, i, CMP, CMPBitSizes, isCMP)

        if cmp is None:
            break

        cmp, cmpOffset = cmp
        i = cmpOffset

        if cmp.imm8 != value:
            i += 2
            continue

        if skip <= 0:
            match = (cmp, i)
            break

        skip -= 1
        i += 2

    return match


def find_next_MOV_W_with_value(data: Buffer, offset: Index, skip: Size, value: Size) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(dataSize):
        mov_w = searchForInsn(data, i, MOV_W, MOV_WBitSizes, isMOV_W)

        if mov_w is None:
            break

        mov_w, mov_wOffset = mov_w
        i = mov_wOffset
        imm32 = (mov_w.i << 11) | (mov_w.s << 12) | (mov_w.imm3 << 8) | mov_w.imm8

        if imm32 != value:
            i += 4
            continue

        if skip <= 0:
            match = (mov_w, i)
            break

        skip -= 1
        i += 4

    return match


def find_next_MOVS_with_value(data: Buffer, offset: Index, skip: Size, value: Size) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(dataSize):
        movs = searchForInsn(data, i, MOVS, MOVSBitSizes, isMOVS)

        if movs is None:
            break

        movs, movsOffset = movs
        i = movsOffset

        if movs.imm8 != value:
            i += 2
            continue

        if skip <= 0:
            match = (movs, i)
            break

        skip -= 1
        i += 2

    return match


def find_next_MOVW_with_value(data: Buffer, offset: Index, skip: Size, value: Size) -> Insn | None:
    match = None
    i = offset

    while i in range(len(data)):
        movw = searchForInsn(data, i, MOVW, MOVWBitSizes, isMOVW)

        if movw is None:
            break

        movw, movwOffset = movw
        i = movwOffset
        imm32 = (movw.i << 11) | (movw.imm4 << 12) | (movw.imm3 << 8) | movw.imm8

        if imm32 != value:
            i += 4
            continue

        if skip <= 0:
            match = (movw, i)
            break

        skip -= 1
        i += 4

    return match



def find_next_BL(data: Buffer, offset: Index, skip: Size) -> Insn | None:
    match = None
    i = offset

    while i in range(len(data)):
        bl = searchForInsn(data, i, BL, BLBitSizes, isBL)

        if bl is None:
            break

        bl, blOffset = bl
        i = blOffset

        if skip <= 0:
            match = (bl, i)
            break

        skip -= 1
        i += 4

    return match
