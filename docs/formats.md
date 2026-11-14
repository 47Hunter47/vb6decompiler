# VB6 binary structures, as measured

Everything below was read out of real files with the parsers in this package, and
every offset was cross-checked by resolving a field twice (two independent pointers
into the same structure) or by comparing against `.frm` design text. Where a field
is documented elsewhere but did not hold in a native build, that is stated
explicitly — those are the places where a confident-looking reader produces a
plausible wrong answer.

Byte order is little-endian throughout. Addresses inside these structures are
normally **VA** (`≥ ImageBase`); some builds store an RVA and a few store a raw
file offset, so every reader here tries VA, then RVA, then offset.

---

## 1. The PE image, in VB6 terms

A native VB6 program is an ordinary 32-bit PE with a fixed `ImageBase` of
`0x400000`. Three properties matter more than the header itself:

| Property | Typical value | Why it matters |
|---|---|---|
| `.text` size | 106 MB of 111 MB total | the code *and* the string literals live here |
| `.data` size | 4 KB | there is almost nothing to find in `.data` |
| imports | one entry: `MSVBVM60.DLL`, 276 functions | everything else is COM created at run time |

The import table therefore describes the *runtime*, not the program. Data access
goes through `MSRDO20.DLL` (RDO → ODBC) or an OLE DB provider created from a
connection string stored as a literal, and 131,460 call sites have no static target
because they dispatch through `IDispatch` vtable slots.

A self-registering VB6 component (a `.dll` or `.ocx` built with VB6) exports the
same four symbols every COM in-proc server does: `DllRegisterServer`,
`DllUnregisterServer`, `DllGetClassObject`, `DllCanUnloadNow`.

## 2. Strings: `BSTR`, not C strings

```
+--------+------------------------------+-----+
| len:u32| text (len bytes, UTF-16LE)   | 00 00|
+--------+------------------------------+-----+
          ^ this is the address the code loads
```

* `len` is the **byte** count (2 × characters).
* The text is `UTF-16LE`. Turkish characters (`ş`, `ğ`, `İ`) are code units above
  `0x7F`, so a "high byte must be zero" scan silently splits them.
* There is no NUL between strings; two literals can be adjacent, and one odd-length
  neighbour shifts the alignment of everything after it. Decode both byte
  alignments.
* ASCII strings exist too (connection strings, file paths) and are NUL-terminated.
  They are a minority: 122,280 ASCII runs against 45,284 UTF-16 runs in one build,
  but the UTF-16 set is where the SQL is.

`vb6decompiler/literals.py` validates a candidate by checking that the 4 bytes before
it equal `2 × len(text)`. That check is the difference between a literal and a
coincidence.

## 3. `VBHeader` — found by searching for `VB5!`

VB5 and VB6 share the same magic (`VB5!`); the runtime version is in the header, not
in the magic. The header sits in the image wherever the linker put it, so it is
located by search, not by offset. 104 bytes:

| Offset | Type | Field | Notes |
|---|---|---|---|
| 0x00 | char[4] | `magic` | `"VB5!"` |
| 0x04 | u16 | `runtime_build` | |
| 0x06 | char[14] | `lang_dll` | e.g. `VBA6.DLL` |
| 0x14 | char[14] | `seclang_dll` | |
| 0x22 | u16 | `runtime_rev` | |
| 0x24 | u32 | `lcid` | |
| 0x28 | u32 | `seclcid` | |
| 0x2C | u32 | `lpSubMain` | |
| **0x30** | u32 | **`lpProjectData`** | → `ProjectInfo` |
| 0x34 | u32 | `fMdlIntCtls` | |
| 0x38 | u32 | `fMdlIntCtls2` | |
| 0x3C | u32 | `thread_flags` | |
| 0x40 | u32 | `thread_count` | |
| 0x44 | u16 | `form_count` | 826 in the reference build, vs 802 declared form objects |
| 0x46 | u16 | `external_count` | |
| 0x48 | u32 | `thunk_count` | |
| 0x4C | u32 | `lpGuiTable` | see §7 — not used here, see the warning |
| 0x50 | u32 | `lpExternalTable` | |
| 0x54 | u32 | `lpComRegisterData` | |
| 0x58 | u32 | `desc_selfrel` | **relative to the header itself** |
| 0x5C | u32 | `exe_selfrel` | relative |
| 0x60 | u32 | `help_selfrel` | relative |
| 0x64 | u32 | `name_selfrel` | relative → project name |

The four `bSZ*` fields are offsets **from the start of the `VBHeader`**, not VAs.
Treating them as VAs yields garbage strings that look like text.

## 4. `ProjectInfo` → `ObjectTable` → objects

```
VBHeader.lpProjectData
  └── ProjectInfo      +0x00 dwVersion (0x1F4 = 500)
                       +0x04 lpObjectTable
        └── ObjectTable
              +0x2A u16 total_objects     (834 in the reference build)
              +0x2C u16 compiled_objects  (834)
              +0x30 u32 lpObjectArray     → 0x30-byte records
              +0x40 u32 project name VA
              +0x50 u32 identifier        (small integer, 0x2 in the reference build)
```

Object record, 0x30 bytes:

| Offset | Field |
|---|---|
| 0x00 | `lpObjectInfo` → `ObjectInfo` |
| 0x04 | reserved (`0xFFFFFFFF`) |
| 0x08 | `lpPublicObjectDescriptor` |
| 0x0C | `lpObjectStatic` |
| 0x10 | `lpModulePublic` |
| 0x14 | `lpModuleStatic` |
| **0x18** | **name VA** (CP1254, NUL-terminated) |
| **0x1C** | **method count** (u32) |
| 0x20 | `lpMethodNames` → array of u32 name VAs (forms and classes only) |
| 0x24 | `o_stat` (u16 + padding) |
| **0x28** | **`fObjectType`** |

`fObjectType` is **not** a small enum. Measured values in one build:

| Value | Meaning | Count |
|---|---|---|
| `0x18001` | module (`.bas`) | 7 |
| `0x18083` | form (`.frm`) | 802 |
| `0x118003` | class (`.cls`) | 1 |
| `0x1018083` | embedded DataReport | 24 |

A reader that maps "unknown" to the nearest known type mislabels all four. Print
unknown values as hex.

### The honest gap: method entry addresses

`ObjectInfo` (0x38 bytes) has `wMethodCount` at `+0x20`, `lpMethods` at `+0x24` and
a constants count at `+0x28`. In the reference **native** build the `lpMethods` slot
does not hold a table of code addresses: every candidate pointer in the block
pointed at code bytes rather than at an array of entry points, and none of the 9
known entries of a test form appeared anywhere in the block. The small integers it
did contain (`0x4`, `0x7`) are not addresses at all.

So this package reports **counts** from the object table (which are reliable and
free: 834 objects, 34,415 methods in 0.4 s) and takes **addresses** from a
decompiler listing's `'VA` comments, marking their source. Do not "fix" the
address reader to accept those integers; accept them and you get 208 "procedures"
of which zero start with a VB6 prologue (`55 8B EC`).

An entry point is only believed when the three bytes there are `55 8B EC`. Sampling
200 procedures that a generic engine missed: 199 had it.

### What a generic engine's output cannot resolve either

Measured on the reference build, over pseudo-C from a generic engine:

* An indirect call through an object global (`(*DAT_06df6168)[0x6]()`) has no static
  target. Reading the four bytes stored at such a global yields 0 — the object is
  created at run time — or, when non-zero, a small token rather than an address. In
  **every** readable case it was a vtable built at run time, so `slot -> procedure`
  is a trace question, not a disassembly question. Three lines of code prove it for
  any build: read `u32(global)`; if it is 0 or below the image base, there is no
  vtable to walk.
* A method receiver never appears as `this`. VB6 delivers it as `param_1`, so
  `Me.Field` offsets cannot be read off the pseudo-C either; bind them through the
  form's field layout (`vb6d frm`, or the control blob when no `.frm` survives).
* Unnamed globals (`DAT_x`) have no name table to recover, because a VB6 symbol
  record holds no name. Census them by procedure frequency
  (`scripts/pseudoc_inventory.py` -> `*_globals.csv`): the ranking is the shortlist
  for a run-time trace, and it is a *shortlist*, not knowledge.

## 5. Form data blobs — geometry without `.frm`

The executable stores each form's *design state* as a serialised property tree. This
is what makes 433 forms recoverable when only 369 `.frm` files exist.

```
<size:int32> <idx:u8> <namelen:u16> <name> 0x00 <class:u8> <property pairs…>
```

* If `size` has bit 31 set, the record is a **control array element**:
  `<size|0x80000000> <idx:u8> <index:u16> <namelen:u16> <name> 0x00 …`. Miss this
  and the record length is nonsense and the rest of the blob desynchronises.
* `class == 0xFF` means the class name is the next property:
  `<len:u16> "MSComctlLib.SSTab" 0x00`. Otherwise `class` is a small numeric id.
* `class == 0x0D` opens a **form object**; one blob can hold several, so a reader
  must segment on it. Splitting only on the first segment keeps one form and drops
  the rest.
* Properties are `<pid:u8> <value>`; the value's type depends on the class's
  property table, so this is not a fixed struct.

### Geometry

One property carries `Left, Top, Width, Height` as **4 × int16**, and the pid is
class-specific:

| pid | Classes |
|---|---|
| `0x02` | `VScrollBar`, `HScrollBar` |
| `0x03` | `Image`, and every OCX (`GEOM_PID_OCX`) |
| `0x04` | `TextBox`, `CommandButton`, `ListBox`, `FileListBox`, `Shape` |
| `0x05` | `Label`, `PictureBox`, `Frame`, `CheckBox`, `OptionButton`, `ComboBox` |

When any coordinate exceeds `32767` the property is written as
`pid + 0x8000` followed by **4 × int32**.

The geometry property is not always the first property of the record: records that
embed a bitmap put it near the end. `GEOM_TAIL_WINDOW = 192` bytes is the search
window; it was swept 64→640 against ground truth and 160→640 are all flat at
24,967/24,967, so 192 sits inside a plateau rather than on a peak.

### Client rect (pid `0x35`)

`0x35` is followed by four **int32**: `ClientLeft, ClientTop, ClientWidth,
ClientHeight`. Reading it as "a block length plus three values" still matches most
forms (360 of 368) and silently rejects every form whose client origin is large.
With the correct reading: 368/368.

### `Visible`

A hidden control is written as `<VISIBLE_PID> 0x00` immediately after its geometry.
The pid is class-specific (`0x0A` frame/label/combo/check, `0x09` text/list, `0x07`
mask-edit/progress). Controls of classes with no calibrated marker stay
**unknown** — 254 of 432 hidden controls are claimed, with **zero** false
positives. Guessing the rest would be worse than not knowing.

### Validation

Ground truth is the `.frm` text that shipped with the same program:
**24,967/24,967 controls** matched on type + Left/Top/Width/Height (100 %),
**367/369** forms fully matched (99.46 %), client size **368/368**. The two forms
that fail are named in the output: one rebuilt after the `.frm` in hand (`formRec01`,
28 extra array elements in the compiled form) and one with no blob at all (`modMain`
is a module, not a form).

### `.frx` files — a slice, not a second source

A decompiler that writes `.frm` text usually writes `.frx` next to it. On the
reference corpus 358 `.frx` files were compared byte-for-byte against the matching
form-blob region inside the executable:

| Relation to that region | Files |
|---|---|
| contained in full | 53 |
| identical prefix of ≥ 4 096 bytes, then diverges | 279 |
| shorter identical prefix | 15 |
| form has a blob, `.frx` head not found in it | 10 |
| form has no blob at all | 1 |

The shared part begins 43–70 bytes into the blob region — at the first control
record — which is why 279 of the 358 share the same 4 162-byte opening with the
blob the reader already cut.

So a `.frx` is not independent evidence: when the executable is at hand it holds
nothing the blob does not already hold, and it is useful as a cross-check of the
blob cutter (53 files are byte-exact copies of a region).

Reading `.frx` **without** an executable is calibrated for one record type
only: the **icon record**. These files start inside a property/value region,
so the shape used to find control records — `namelen:u16`, ASCII name,
`0x00`, class byte — matches **0** records in them. What sits there instead is
a UTF-16 property entry (`0C 00` then `L\0a\0b\0e\0l\01\0`), measured at the
same offset in a `.frx` and in the executable's own region. Relaxing the ASCII
rule to accept those names yields records with no geometry, so control records
are still not parsed.

The leading icon sits outside that grammar and *is* parsed, without an
executable. For forms that carry an icon the file opens with a short
property-blob header (length varies; measured: the ICONDIR signature sits at
even offsets up to 32 bytes in) followed by a complete ICON resource —
`<header> <ICONDIR> <ICONDIRENTRY ×N> <image data>`. `scripts/frx_icon.py`
extracts it: entry type 1 or 2, count 1..20, and every `imageOffset` is
relative to the ICONDIR start — the same layout a standalone `.ico` carries —
so the slice ending at `max(offset + size)` is a valid `.ico` on its own and
offsets are not rewritten. Measured on the reference corpus: **347 of 358**
`.frx` files yield an icon, **10 distinct images** among them; of the **347 of
802** `.frm` files that declare `Icon = "<name>.frx":<offset>`, **346** match
extraction (one module `.frx` is declared but carries no ICON bytes; one form
carries icon bytes with no declaration — VB6 does not serialise a property
equal to its default). The script prints both sets by name. A `.frm` with no
`Icon` line is absence, not proof of no icon.

**`SSTab` captions are a blob result, not a `.frm` result.** Every `.frm` in the
corpus that contains an `SSTab` has no `TabCaption` line in its text (14 of 14 —
the decompiler drops them). The blob route recovers titles for all 14 (47 titles),
and 68 titles over the 20 forms that carry an `SSTab`. Page *membership* is a
separate measure and counts only the controls the `SSTab` record itself names.

## 6. `DataReport` blobs — reports

Report definitions are `DataReport` class objects inside `rpt*.dll` (and, in the
reference install, 24 more inside the executable itself).

* Strings are **`len32` + UTF-16LE**, unlike form blobs (`len16` + CP1254). The two
  families look alike and are not alike.
* Scan **byte by byte**: a single even-length string can carry a `00 00` alignment
  pad, and a 4-byte stride then loses alignment for the rest of the stream and reads
  strings as integers.
* A record is a name followed by an int32 property array. The first four ints are
  `Left, Top, Width, Height`.
* **VB6 does not serialise a property equal to its default.** So a record can be
  `(L, W, H, X)` with `Top` absent, or `(L, H≈225, X, Y)` with both `Top` and
  `Width` absent. Measured over all 437 designs (19,325 controls): full L/T/W/H
  **75.2 %**, `Top` unknown **17.1 %**, `Width` unknown **7.7 %**. Inferred values
  are flagged (`top_inferred=True`), never presented as read ones.
* Section ownership is **positional**: a control belongs to the last section record
  before it. Controls per section (437 designs): `Section1` 4,293 = Detail,
  `Section2` 11,890 = PageHeader (the `%p`/`%P` page fields and the page caption land here),
  `Section3` **27** = PageFooter — VB6's creation order, weakly evidenced, `Section4`
  136 = rptHeader, `Section5` 2,979 = rptFooter (219 captioned totals). Gate: every data
  box (`txt*`/`Text*`) lands in Detail.
* Name vs caption is a prefix rule (`lbl`, `txt`, `Text`, `Label`, `Line`, `Shape`,
  `fun`, `Function`, `SectionN` are names; everything else is a caption).
* Join key must be `(file name, design name)`: **13** design names appear in more
  than one file (six of them among the eight DLLs, the rest shared with the copy
  embedded in the executable), and a name-keyed dict silently overwrites one.
* `DataField` is **not** in the blob. It is assigned by class code at run time, so
  layout alone is not a report specification.

## 7. What is *not* documented here, and why

* **GUI table (`lpGuiTable`).** The `VBHeader` points at a table that should map
  form objects to their blobs. Reading it with the documented 0x50-byte stride
  produced two entries and garbage on the reference build (a wrong stride and a
  wrong field layout look identical from the outside). Blob discovery here scans for
  class-`0x0D` records directly, which found 801 blobs whose names match the `.frm`
  set — so the table is unnecessary, and an undocumented guess is not shipped.
* **Method entry addresses** — see §4.
* **Control records in a `.frx` read without an executable** — see §5: the
  property/control grammar those files start in is still uncalibrated. The
  leading icon record is the one exception and ships as `scripts/frx_icon.py`.
* **Expression-level code.** Not a binary structure: reconstructing VB semantics
  (`Variant`, late binding, `On Error`) from native code is research, not a parse.
* **`.dsr` layout.** `.dsr` files carry no SQL and no caption text; the layout lives
  in the DLL's blob (§6). Any tool that offers to "export the .dsr" is exporting a
  name.
