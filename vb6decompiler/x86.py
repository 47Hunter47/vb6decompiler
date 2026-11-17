"""Optional x86 decode: the only place capstone may live inside the library.

Milestone D's first layer is the raw dump — instructions with their addresses,
not VB6 semantics. The core package never imports capstone at module level:
it arrives only through the existing ``asm`` extra
(``pip install "vb6decompiler[asm]"``), and a missing engine is a named
refusal carrying that hint, never an ImportError traceback.

The pip bindings (5.0.x) differ from the upstream docs in two ways measured
on this machine, so the attributes are pinned here once and the later IR work
does not rediscover them: operands are ``op_str`` (not ``op_text``), and
instruction bytes plus register access need ``detail = True``. Operand strings
are kept verbatim as the engine renders them (immediates inside them read
``0x...``) — they are quoted text, while this module's own ``va``/``bytes``
fields follow the repo rule of bare uppercase hex.
"""
from __future__ import annotations

ASM_HINT = 'pip install "vb6decompiler[asm]"'


class EngineUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__(f"capstone is not installed ({ASM_HINT})")


def engine():
    """A fresh 32-bit x86 engine, or a named refusal naming the extra."""
    try:
        import capstone
    except ImportError:
        raise EngineUnavailable() from None
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    return md


def decode(data: bytes, va: int, limit: int = 200) -> dict:
    """Decode instructions from ``data`` starting at (virtual) address ``va``.

    Stops at the first ``ret``, at ``limit`` instructions, or where the bytes
    stop decoding. The returned ``ended`` names which happened — "the buffer
    stopped making sense" is a reported result, not silence. No VB6 meaning
    is claimed yet: this is the layer the semantics get built on.
    """
    rows: list[dict] = []
    consumed = 0
    ended = "no-bytes"
    for ins in engine().disasm(data, va):
        rows.append({"va": f"{ins.address:X}", "bytes": ins.bytes.hex(),
                     "mnemonic": ins.mnemonic, "operands": ins.op_str})
        consumed += len(ins.bytes)
        if ins.mnemonic == "ret":
            ended = "ret"
            break
        if len(rows) >= limit:
            ended = "limit"
            break
    else:
        if rows:
            # disasm ran off the buffer or hit bytes it cannot express here
            ended = "undecodable"
    return {"va": f"{va:X}", "requested_limit": limit,
            "instructions": len(rows), "consumed_bytes": consumed,
            "ended": ended, "rows": rows}
