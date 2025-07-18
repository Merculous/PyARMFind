
from .types import (BL, BNE_W, CMP, IT, LDR_W, LDRB, MOV_W, MOVS, MOVT, MOVW,
                    NEGS, POP, PUSH, BLXRegister, LDRLiteral, MOVRegister)


def isLDRLiteral(insnObj: LDRLiteral | None) -> bool:
    if insnObj is None:
        return False

    if not isinstance(insnObj, LDRLiteral):
        raise TypeError

    if insnObj.magic == 9:
        return True

    return False


def isCMP(insnObj: CMP | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, CMP):
        raise TypeError

    if insnObj.magic1 == 1 and insnObj.magic2 == 1:
        return True
    
    return False


def isMOVS(insnObj: MOVS | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, MOVS):
        raise TypeError

    if insnObj.magic1 == 0b001 and insnObj.magic2 == 0b00:
        return True
    
    return False


def isMOV_W(insnObj: MOV_W | None) -> bool:
    if insnObj is None:
        return False

    if not isinstance(insnObj, MOV_W):
        raise TypeError

    if (
        insnObj.magic1 == 0b11110 and
        insnObj.magic2 == 0b0 and
        insnObj.magic3 == 0b0010 and
        insnObj.magic4 == 0b1111
    ):
        return True

    return False


def isMOVW(insnObj: MOVW | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, MOVW):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b11110 and
        insnObj.magic2 == 0b10 and
        insnObj.magic3 == 0b0 and
        insnObj.magic4 == 0b1 and
        insnObj.magic5 == 0b0 and
        insnObj.magic6 == 0b0
    ):
        return True
    
    return False


def isBL(insnObj: BL | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, BL):
        raise TypeError

    if (
        insnObj.magic1 == 0b11110 and
        insnObj.magic2 == 0b11 and
        insnObj.magic3 == 0b1 and
        insnObj.j1 == 0b1 and
        insnObj.j2 == 0b1
    ):
        return True

    return False


def isLDR_W(insnObj: LDR_W | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, LDR_W):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b11111 and
        insnObj.magic2 == 0b00 and
        insnObj.magic3 == 0b0 and
        insnObj.magic4 == 0b1 and
        insnObj.magic5 == 0b10 and
        insnObj.magic6 == 0b1
    ):
        return True

    return False


def isPUSH(insnObj: PUSH | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, PUSH):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b1011 and
        insnObj.magic2 == 0b0 and
        insnObj.magic3 == 0b10
    ):
        return True
    
    return False


def isMOVT(insnObj: MOVT | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, MOVT):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b11110 and
        insnObj.magic2 == 0b10 and
        insnObj.magic3 == 0b1 and
        insnObj.magic4 == 0b1 and
        insnObj.magic5 == 0b0 and
        insnObj.magic6 == 0b0 and
        insnObj.magic7 == 0b0
    ):
        return True
    
    return False


def isBLXRegister(insnObj: BLXRegister | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, BLXRegister):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b010001 and
        insnObj.magic2 == 0b11 and 
        insnObj.magic3 == 0b1 and
        insnObj.magic4 == 0b000
    ):
        return True
    
    return False


def isPOP(insnObj: POP | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, POP):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b1011 and
        insnObj.magic2 == 0b1 and
        insnObj.magic3 == 0b10
    ):
        return True
    
    return False


def isMOVRegister(insnObj: MOVRegister | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, MOVRegister):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b010001 and
        insnObj.magic2 == 0b10
    ):
        return True
    
    return False


def isBNE_W(insnObj: BNE_W | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, BNE_W):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b11110 and
        insnObj.magic2 == 0b10 and
        insnObj.magic3 == 0b0
    ):
        return True
    
    return False


def isLDRB(insnObj: LDRB | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, LDRB):
        raise TypeError
    
    if (
        insnObj.magic1 == 0b011 and
        insnObj.magic2 == 0b1 and
        insnObj.magic3 == 0b1
    ):
        return True
    
    return False


def isNEGS(insnObj: NEGS | None) -> bool:
    if insnObj is None:
        return False
    
    if not isinstance(insnObj, NEGS):
        raise TypeError
    
    if insnObj.magic1 == 0b0100001001:
        return True
    
    return False


def isIT(insnObj: IT | None) -> bool:
    if insnObj is None:
        return False
    
    if insnObj.magic1 == 0b10111111:
        return True
    
    return False
