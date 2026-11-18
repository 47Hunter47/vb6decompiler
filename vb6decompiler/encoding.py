"""Which code page a VB6 build's text is in, and where that answer came from.

Why this exists
---------------
Every parser in this package used to decode text as CP1254 by name. That is right
for the builds it was calibrated on and silently wrong for every other code page:
a German build decodes ``ä`` into a box, a Russian build turns half its menu into
``?``. The bytes never belonged to one language; the *build machine's* ANSI code
page chose them, and the
``VB5!`` header records the developer's LCID (``procs._vb_header``) — a hint, not
the answer.

Two facts drive this module:

* **The header LCID is a hint.** It records the language the IDE ran in. The string
  bytes follow the ANSI code page of the machine that compiled the project, which
  is usually — not always — the same. A developer on an English Windows compiling
  text localized for another language writes CP1252 bytes and a 0x0409 header. So an explicit code page
  (`--encoding`) always wins over the header, and the header wins over the default.
* **The parsers index bytes and characters alike.** ``frm.py`` maps a decoded
  character offset straight back onto the raw bytes; that identity holds for a
  single-byte code page and breaks for a multi-byte one (cp932/936/949/950, UTF-8,
  the ISO-2022 family). :func:`validate_single_byte` therefore refuses them instead
  of returning offsets that are quietly wrong.

The LCID table below is *measured*, not remembered. It was produced on Windows with
the `GetLocaleInfoEx(LOCALE_IDEFAULTANSICODEPAGE)` probe, which returns the ANSI
code page Windows itself associates with each locale — the same association the VB6
IDE used when it wrote the file. LCIDs whose probe returned no code page (for
example Armenian and Kazakh, which have no ANSI default) are left out on purpose: an
unmapped LCID falls back to :data:`DEFAULT_CODEPAGE` and the caller says so on
stderr, rather than being given a guessed answer.

Probe (re-run to extend the table; every value must come from its output):

    python -c "import ctypes;k=ctypes.windll.kernel32;b=ctypes.create_unicode_buffer(85);\\
    k.LCIDToLocaleName(0x041F,b,85,0);p=ctypes.create_unicode_buffer(85);\\
    k.GetLocaleInfoEx(b,0x1004,p,85);print(p.value)"

Multi-byte LCIDs are listed even though they cannot be parsed, so that a Japanese
build is *refused with its own name* (exit 2) instead of falling back to CP1254 and
printing plausible garbage.
"""

from __future__ import annotations

import codecs
import os

#: Code page used when nothing else is known. CP1254 keeps every pre-existing
#: behaviour and output byte for byte, which is what the historical callers assume.
DEFAULT_CODEPAGE = "cp1254"

#: Environment variable that sets the code page for a whole shell. Second in the
#: order (flag > env > header LCID > default), see :func:`choice`.
ENV_VAR = "VB6D_ENCODING"

#: ANSI code pages a VB6 build can legitimately use. Anything outside this set is
#: refused: the parsers rely on one byte being one character, and an arbitrary
#: codec name (UTF-8, UTF-16, an ISO-2022 page) would break that silently.
SINGLE_BYTE_CODEPAGES = frozenset(
    ["cp874"] + [f"cp{n}" for n in range(1250, 1259)]
)

#: Double-byte code pages. Refused by name so the message can say what the build is.
MULTIBYTE_CODEPAGES = frozenset({"cp932", "cp936", "cp949", "cp950"})

#: Python's canonical name for each multi-byte page — ``codecs.lookup("cp936").name``
#: is ``gbk``, so a membership test has to run on the canonical form, not the alias.
_MULTIBYTE_BY_CANONICAL = {codecs.lookup(c).name: c for c in MULTIBYTE_CODEPAGES}

#: LCID -> ANSI code page, measured with GetLocaleInfoEx (see the module docstring).
#: Keys are the low 16 bits of the LCID as stored in the VB5 header.
LCID_TO_CODEPAGE: dict[int, str] = {
    0x0401: "cp1256",  # ar-SA
    0x0402: "cp1251",  # bg-BG
    0x0403: "cp1252",  # ca-ES
    0x0404: "cp950",   # zh-TW
    0x0405: "cp1250",  # cs-CZ
    0x0406: "cp1252",  # da-DK
    0x0407: "cp1252",  # de-DE
    0x0408: "cp1253",  # el-GR
    0x0409: "cp1252",  # en-US
    0x040A: "cp1252",  # es-ES
    0x040B: "cp1252",  # fi-FI
    0x040C: "cp1252",  # fr-FR
    0x040D: "cp1255",  # he-IL
    0x040E: "cp1250",  # hu-HU
    0x040F: "cp1252",  # is-IS
    0x0410: "cp1252",  # it-IT
    0x0411: "cp932",   # ja-JP
    0x0412: "cp949",   # ko-KR
    0x0413: "cp1252",  # nl-NL
    0x0414: "cp1252",  # nb-NO
    0x0415: "cp1250",  # pl-PL
    0x0416: "cp1252",  # pt-BR
    0x0417: "cp1252",  # rm-CH
    0x0418: "cp1250",  # ro-RO
    0x0419: "cp1251",  # ru-RU
    0x041A: "cp1250",  # hr-HR
    0x041B: "cp1250",  # sk-SK
    0x041C: "cp1250",  # sq-AL
    0x041D: "cp1252",  # sv-SE
    0x041E: "cp874",   # th-TH
    0x041F: "cp1254",  # tr-TR
    0x0420: "cp1256",  # ur-PK
    0x0421: "cp1252",  # id-ID
    0x0422: "cp1251",  # uk-UA
    0x0423: "cp1251",  # be-BY
    0x0424: "cp1250",  # sl-SI
    0x0425: "cp1257",  # et-EE
    0x0426: "cp1257",  # lv-LV
    0x0427: "cp1257",  # lt-LT
    0x0428: "cp1251",  # tg-Cyrl
    0x0429: "cp1256",  # fa-IR
    0x042A: "cp1258",  # vi-VN
    0x042C: "cp1254",  # az-Latn
    0x042D: "cp1252",  # eu-ES
    0x042F: "cp1251",  # mk-MK
    0x0436: "cp1252",  # af-ZA
    0x043E: "cp1252",  # ms-MY
    0x0440: "cp1251",  # ky-KG
    0x0441: "cp1252",  # sw-KE
    0x0444: "cp1251",  # tt-RU
    0x0452: "cp1252",  # cy-GB
    0x0456: "cp1252",  # gl-ES
    0x0464: "cp1252",  # fil-PH
    0x0804: "cp936",   # zh-CN
    0x0809: "cp1252",  # en-GB
    0x080A: "cp1252",  # es-MX
    0x0816: "cp1252",  # pt-PT
    0x081A: "cp1250",  # sr-Latn
    0x0C01: "cp1256",  # ar-EG
    0x0C04: "cp950",   # zh-HK
    0x0C09: "cp1252",  # en-AU
    0x0C0A: "cp1252",  # es-ES
    0x0C0C: "cp1252",  # fr-CA
    0x0C1A: "cp1251",  # sr-Cyrl
    0x1009: "cp1252",  # en-CA
}


def codepage_for_lcid(lcid: int) -> str | None:
    """The measured ANSI code page for an LCID, or ``None`` when unmapped."""
    return LCID_TO_CODEPAGE.get(lcid)


def canonical_codec(name: str) -> str:
    """Python's canonical name for a codec; ``ValueError`` if the name is unknown.

    Accepts the aliases users actually type (``windows-1251``, ``latin1``) and
    returns what the rest of this module compares against (``cp1251``, ``iso8859-1``).
    """
    try:
        return codecs.lookup(name).name
    except LookupError:
        raise ValueError(
            f"unknown code page {name!r} (use a Python codec name, e.g. 'cp1251', 'cp1254')"
        ) from None


def validate_single_byte(codec: str) -> None:
    """Refuse anything where a byte is not a character; a no-op for ANSI pages.

    Raised as ``ValueError`` with one line, because the CLI turns it into exit 2
    without a traceback.
    """
    name = canonical_codec(codec)
    if name in _MULTIBYTE_BY_CANONICAL:
        documented = _MULTIBYTE_BY_CANONICAL[name]
        label = documented if documented == name else f"{documented}/{name}"
        raise ValueError(
            f"{label} is a multi-byte code page; this toolkit maps character offsets "
            "back onto bytes and needs a single-byte ANSI page"
        )
    if name not in SINGLE_BYTE_CODEPAGES:
        raise ValueError(
            f"{name} is not a single-byte ANSI code page; supported: "
            + ", ".join(sorted(SINGLE_BYTE_CODEPAGES))
        )


def resolve_encoding(explicit: str | None, lcid: int | None) -> tuple[str, str]:
    """Pick the codec for one run: ``(codec, source)`` with source explicit/lcid/default.

    Order is the whole point: a flag the user typed beats a header field that only
    describes the developer's IDE. Both inputs are optional because directory inputs
    (``.frm`` text, listings) have no header at all.
    """
    if explicit:
        codec = canonical_codec(explicit)
        validate_single_byte(codec)
        return codec, "explicit"
    if lcid is not None:
        codec = codepage_for_lcid(lcid)
        if codec is not None:
            validate_single_byte(codec)
            return codec, "lcid"
    return DEFAULT_CODEPAGE, "default"


def env_codepage() -> str | None:
    """The code page named by ``VB6D_ENCODING``, or ``None`` when unset/empty.

    The variable is the second source in the order (flag > env > header LCID >
    default): a shell-wide default for a batch of builds, overridable per run.
    """
    raw = os.environ.get(ENV_VAR, "").strip()
    return raw or None


def choice(explicit: str | None, lcid: int | None) -> tuple[str, str]:
    """Resolve with ``VB6D_ENCODING`` in second place (flag > env > LCID > default).

    Same table as :func:`resolve_encoding`, one extra source label: ``env`` tells the
    reader the value came from the shell, not from the command line.
    """
    if explicit:
        return resolve_encoding(explicit, None)
    from_env = env_codepage()
    if from_env:
        codec, _ = resolve_encoding(from_env, None)
        return codec, "env"
    return resolve_encoding(None, lcid)


def summary_line(codec: str, source: str) -> str:
    """The one ``#`` line a stage prints so the user sees which code page it used."""
    return f"# encoding: {codec} ({source})"
