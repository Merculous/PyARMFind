
from typing import Any

from binpatch.types import Buffer, Index, Size
from binpatch.utils import getBufferAtIndex

from .sizes import (BLBitSizes, BLXRegisterBitSizes, CMPBitSizes,
                    LDR_WBitSizes, LDRLiteralBitSizes, MOV_WBitSizes,
                    MOVSBitSizes, MOVTBitSizes, MOVWBitSizes, POPBitSizes,
                    PUSHBitSizes)
from .types import (BL, CMP, LDR_W, MOV_W, MOVS, MOVT, MOVW, POP, PUSH,
                    BLXRegister, Insn, InsnBitSizes, LDRLiteral)
from .utils import instructionToObject
from .validators import (isBL, isBLXRegister, isCMP, isLDR_W, isLDRLiteral,
                         isMOV_W, isMOVS, isMOVT, isMOVW, isPOP, isPUSH)


def searchForInsn(data: Buffer, offset: Index, insn: Any, insnBitSizes: InsnBitSizes, insnValidator: Any, flip: bool = True) -> Insn | None:
    insnSize = sum(insnBitSizes) // 8

    if insnSize not in (2, 4):
        raise Exception(f'Instruction size is not 2 or 4!')

    searchStart = offset & ~(insnSize - 1)
    searchEnd = len(data)
    match = None
    table = {}

    for i in range(searchStart, searchEnd, 2):
        buffer = getBufferAtIndex(data, i, insnSize)

        if buffer in table:
            continue

        insnObj = instructionToObject(buffer, insn, insnBitSizes, flip)
        table[buffer] = insnObj

        if not insnValidator(insnObj):
            continue

        match = (insnObj, i)
        break

    return match


def find_next_LDR_Literal(data: Buffer, offset: Index, skip: Size, value: Buffer) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(offset, dataSize):
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

    while i in range(offset, dataSize):
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

    while i in range(offset, dataSize):
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

    while i in range(offset, dataSize):
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
    dataSize = len(data)
    match = None
    i = offset

    while i in range(offset, dataSize):
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
    dataSize = len(data)
    match = None
    i = offset

    while i in range(offset, dataSize):
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


def find_next_LDR_W_with_value(data: Buffer, offset: Index, skip: Size, value: Buffer) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(offset, dataSize):
        ldr_w = searchForInsn(data, i, LDR_W, LDR_WBitSizes, isLDR_W)

        if ldr_w is None:
            break

        ldr_w, ldr_wOffset = ldr_w
        i = ldr_wOffset
        ldrRefOffset = (ldr_wOffset + ldr_w.imm12 + 4) & ~3

        window = getBufferAtIndex(data, ldrRefOffset, 4)

        if window != value:
            i += 4
            continue

        if skip <= 0:
            match = (ldr_w, i)
            break

        skip -= 1
        i += 4

    return match


def find_next_push(data: Buffer, offset: Index, skip: Size) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(offset, dataSize):
        push = searchForInsn(data, i, PUSH, PUSHBitSizes, isPUSH)

        if push is None:
            break

        push, pushOffset = push
        i = pushOffset

        if skip <= 0:
            match = (push, i)
            break

        skip -= 1
        i += 2

    return match


def find_next_MOVT_with_value(data: Buffer, offset: Index, skip: Size, value: Size) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(offset, dataSize):
        movt = searchForInsn(data, i, MOVT, MOVTBitSizes, isMOVT)

        if movt is None:
            break

        movt, movtOffset = movt
        i = movtOffset

        imm32 = (movt.i << 11) | (movt.imm4 << 12) | (movt.imm3 << 8) | movt.imm8

        if imm32 != value:
            i += 4
            continue

        if skip <= 0:
            match = (movt, i)
            break

        skip -= 1
        i += 4
    
    return match


def find_next_blx_register(data: Buffer, offset: Index, skip: Size) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(offset, dataSize):
        blx = searchForInsn(data, i, BLXRegister, BLXRegisterBitSizes, isBLXRegister)

        if blx is None:
            break

        blx, blxOffset = blx
        i = blxOffset

        if skip <= 0:
            match = (blx, i)
            break

        skip -= 1
        i += 2

    return match


def find_next_pop(data: Buffer, offset: Index, skip: Size) -> Insn | None:
    dataSize = len(data)
    match = None
    i = offset

    while i in range(offset, dataSize):
        pop = searchForInsn(data, i, POP, POPBitSizes, isPOP)

        if pop is None:
            break

        pop, popOffset = pop
        i = popOffset

        if skip <= 0:
            match = (pop, i)
            break

        skip -= 1
        i += 2

    return match
