#!/usr/bin/env python3
"""Drive a Windows GUI program from a console session: enumerate windows and
child controls, read text/checkbox/list contents, click, type.

Why this exists: headless runs of vendor RE tools (decompilers, scanners)
usually need one or two real clicks, and three cross-boundary traps make
naive driving fail:

  * A 64-bit driver against a 32-bit target marshals simple messages
    (WM_GETTEXT, BM_GETCHECK, LVM_GETITEMCOUNT) fine, but menu-struct APIs
    (GetMenuItemInfoW) fail — menus are a UI Automation job, not a raw-API job.
  * VB6 ActiveX (Ocx) buttons/checkboxes IGNORE `BM_CLICK`.  What works is a
    centre-point `WM_LBUTTONDOWN` + `WM_LBUTTONUP` pair (SendMessage).
  * An exception raised inside an `EnumWindows`/`EnumChildWindows` callback
    aborts the enumeration after the first window, usually silently.  Every
    callback here swallows its own exceptions.

`GetWindowThreadProcessId` is looked up with a guarded fallback: some ctypes
setups raise for it on `kernel32` and answer on a different module.

Stdlib only (ctypes).  Tested logic is the pure parts (rect math, index
selection, vk map); the message plumbing needs a live desktop and is exercised
by the smoke test on Windows.

Usage:
  win32_gui_probe.py list [--title SUB] [--class SUB] [--pid N]
  win32_gui_probe.py dump <hwnd>
  win32_gui_probe.py read <hwnd> (<caption> | -i N)
  win32_gui_probe.py click <hwnd> (<caption> | -i N) [--bmclick]
  win32_gui_probe.py tick <hwnd> (<caption> | -i N)      # checkbox, then verify
  win32_gui_probe.py settext <hwnd> (<caption> | -i N) --text VALUE
  win32_gui_probe.py key <hwnd> --vk Enter|Escape|Tab|... [--child caption]
  win32_gui_probe.py items <hwnd> LISTVIEW [--max N]     # row texts (native
                                                    ListView, both bitnesses)
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import sys

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
WM_SETTEXT = 0x000C
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
BM_CLICK = 0x00F5
BM_GETCHECK = 0x00F3
LVM_GETITEMCOUNT = 0x1004
LVM_GETITEMTEXTW = 0x1073
VK = {"ENTER": 0x0D, "RETURN": 0x0D, "ESCAPE": 0x1B, "TAB": 0x09, "SPACE": 0x20}

WEP = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def _gwt():
    """Guarded GetWindowThreadProcessId (lookup differs across ctypes setups)."""
    for mod in (kernel32, user32):
        try:
            return getattr(mod, "GetWindowThreadProcessId")
        except AttributeError:
            continue
    return None


_GWT = _gwt()


def window_pid(hwnd):
    if _GWT is None:
        return -1
    pd = wt.DWORD(0)
    try:
        _GWT(ctypes.c_void_p(hwnd), ctypes.byref(pd))
        return pd.value
    except Exception:
        return -1


def win_text(hwnd, n=256):
    buf = ctypes.create_unicode_buffer(n)
    user32.GetWindowTextW(hwnd, buf, n)
    return buf.value or ""


def win_class(hwnd, n=128):
    buf = ctypes.create_unicode_buffer(n)
    user32.GetClassNameW(hwnd, buf, n)
    return buf.value or ""


def _collect(enumerator):
    """enumerator(cb) where cb gets one hwnd; returns list, callbacks safe."""
    out = []

    def cb(hwnd, _lparam):
        try:
            out.append(hwnd)
        except Exception:
            pass
        return True

    enumerator(WEP(cb))
    return out


def top_windows():
    return _collect(lambda cb: user32.EnumWindows(cb, 0))


def child_windows(parent):
    return _collect(lambda cb: user32.EnumChildWindows(ctypes.c_void_p(parent), cb))


def lparam_center(hwnd):
    """Centre-point LPARAM x|(y<<16) for mouse messages (pure, tested)."""
    r = wt.RECT()
    user32.GetWindowRect(ctypes.c_void_p(hwnd), ctypes.byref(r))
    x = (r.right - r.left) // 2
    y = (r.bottom - r.top) // 2
    return (y << 16) | (x & 0xFFFF)


def is_target_64(hwnd_target):
    pid = window_pid(hwnd_target)
    if pid <= 0:
        return None
    wow = wt.BOOL(False)
    process = kernel32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED is enough here
    if not process:
        return None
    try:
        kernel32.IsWow64Process(ctypes.c_void_p(process), ctypes.byref(wow))
        return not wow.value  # Wow64 => target is 32-bit
    finally:
        kernel32.CloseHandle(ctypes.c_void_p(process))


def pick(hwnd_parent, caption, index):
    kids = child_windows(hwnd_parent)
    if index is not None:
        kids = kids[index : index + 1]
    else:
        kids = [h for h in kids if win_text(h).strip() == caption.strip()]
    if not kids:
        raise SystemExit("no child window matched (caption=%r index=%r)" % (caption, index))
    return kids[0]


def read_edit(hwnd):
    n = user32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
    n = max(int(n), 0)
    buf = ctypes.create_unicode_buffer(n + 2)
    user32.SendMessageW(hwnd, WM_GETTEXT, n + 1, buf)
    return buf.value


def read_items(hwnd, max_rows=500):
    """Row texts of a native ListView.  LVITEM lives in the TARGET's address
    space, with the TARGET's pointer size — allocate there, write a packed
    item, SendMessage, read the buffer back."""
    count = int(user32.SendMessageW(hwnd, LVM_GETITEMCOUNT, 0, 0))
    count = max(min(count, max_rows), 0)
    pid = window_pid(hwnd)
    if pid <= 0 or count == 0:
        return count, []
    target64 = is_target_64(hwnd)
    buf_size = 1024
    item_size = 44 + (16 if target64 else 8)  # LVITEMW with the target's pointer size
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.VirtualAllocEx.restype = ctypes.c_void_p
    # VirtualAllocEx takes a HANDLE, not a pid; the mask needs VM_OPERATION
    ph = kernel32.OpenProcess(0x1000 | 0x0010 | 0x0020 | 0x0008, False, pid)
    if not ph:
        return count, []
    ph = ctypes.c_void_p(ph)
    mem = kernel32.VirtualAllocEx(ph, 0, item_size + buf_size * 2,
                                  0x1000 | 0x2000, 0x04)  # COMMIT|PRIVATE, READWRITE
    if not mem:
        kernel32.CloseHandle(ph)
        return count, []
    base = ctypes.cast(mem, ctypes.c_void_p).value
    rows = []
    try:
        for i in range(count):
            text_addr = base + item_size
            item = ctypes.create_string_buffer(item_size)
            off = 0

            def put(v, size=4):
                nonlocal off
                item[off : off + size] = ctypes.string_at(ctypes.byref(
                    (ctypes.c_uint64 if size == 8 else ctypes.c_uint32)(v)), size)
                off += size

            put(0x0001)                     # LVIF_TEXT
            put(0)                          # iItem
            put(0)                          # iSubItem
            put(0); put(0)                  # state, stateMask
            if target64:
                put(0)                      # align pszText to 8
            put(text_addr, 8 if target64 else 4)   # pszText
            put(buf_size)                   # cchTextMax
            kernel32.WriteProcessMemory(ph, ctypes.c_void_p(base), item, item_size, 0)
            user32.SendMessageW(hwnd, LVM_GETITEMTEXTW, i, ctypes.c_void_p(base))
            remote = ctypes.create_unicode_buffer(buf_size)
            rd = ctypes.c_size_t(0)
            kernel32.ReadProcessMemory(ph, ctypes.c_void_p(text_addr),
                                       remote, buf_size * 2, ctypes.byref(rd))
            rows.append(remote.value)
    finally:
        kernel32.VirtualFreeEx(ph, ctypes.c_void_p(base), 0, 0x8000)
        kernel32.CloseHandle(ph)
    return count, rows


def cmd_list(args):
    for h in top_windows():
        t, c = win_text(h), win_class(h)
        pid = window_pid(h)
        if args.title and args.title.lower() not in t.lower():
            continue
        if args.cls and args.cls.lower() not in c.lower():
            continue
        if args.pid and pid != args.pid:
            continue
        if not t:
            continue
        vis = bool(user32.IsWindowVisible(ctypes.c_void_p(h)))
        print("hwnd=%d pid=%s vis=%s class=%s title=%r" % (h, pid, vis, c, t))


def cmd_dump(args):
    for h in child_windows(args.hwnd):
        c, t = win_class(h), win_text(h)
        extra = ""
        low = c.lower()
        if "checkbox" in low:
            extra = " check=%d" % user32.SendMessageW(h, BM_GETCHECK, 0, 0)
        elif low == "combobox":
            extra = " items=%d" % user32.SendMessageW(h, 0x0147, 0, 0)
        elif "textbox" in low or low == "edit":
            extra = " text=%r" % read_edit(h)[:80]
        print("hwnd=%d class=%s caption=%r%s" % (h, c, t, extra))


def cmd_read(args):
    print(read_edit(pick(args.hwnd, args.caption, args.index)))


def cmd_click(args):
    h = pick(args.hwnd, args.caption, args.index)
    lp = lparam_center(h)
    user32.SendMessageW(h, WM_LBUTTONDOWN, 0, lp)
    user32.SendMessageW(h, WM_LBUTTONUP, 0, lp)
    if args.bmclick:
        user32.PostMessageW(h, BM_CLICK)


def cmd_tick(args):
    h = pick(args.hwnd, args.caption, args.index)
    lp = lparam_center(h)
    user32.SendMessageW(h, WM_LBUTTONDOWN, 0, lp)
    user32.SendMessageW(h, WM_LBUTTONUP, 0, lp)
    print("%s check=%d" % (args.caption, user32.SendMessageW(h, BM_GETCHECK, 0, 0)))


def cmd_settext(args):
    user32.SendMessageW(pick(args.hwnd, args.caption, args.index),
                        WM_SETTEXT, 0, args.text)


def cmd_key(args):
    vk = VK.get(args.vk.upper())
    if vk is None:
        raise SystemExit("unknown vk %r (known: %s)" % (args.vk, ",".join(sorted(VK))))
    target = args.hwnd
    if args.child:
        target = pick(args.hwnd, args.child, None)
    user32.PostMessageW(target, WM_KEYDOWN, vk, 0)
    user32.PostMessageW(target, WM_KEYUP, vk, 0)


def cmd_items(args):
    total, rows = read_items(args.hwnd, args.max)
    print("items=%d (showing %d)" % (total, len(rows)))
    for i, r in enumerate(rows):
        print("%03d %s" % (i, r))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list")
    p.add_argument("--title"); p.add_argument("--class", dest="cls"); p.add_argument("--pid", type=int)
    p.set_defaults(fn=cmd_list)
    def add_pick(name):
        q = sub.add_parser(name)
        q.add_argument("hwnd", type=int)
        q.add_argument("caption", nargs="?", default="")
        q.add_argument("-i", "--index", type=int)
        return q
    p = add_pick("dump"); p.set_defaults(fn=cmd_dump)
    q = add_pick("read"); q.set_defaults(fn=cmd_read)
    q = add_pick("click"); q.add_argument("--bmclick", action="store_true"); q.set_defaults(fn=cmd_click)
    q = add_pick("tick"); q.set_defaults(fn=cmd_tick)
    q = add_pick("settext"); q.add_argument("--text", required=True); q.set_defaults(fn=cmd_settext)
    q = sub.add_parser("key"); q.add_argument("hwnd", type=int); q.add_argument("--vk", required=True)
    q.add_argument("--child"); q.set_defaults(fn=cmd_key)
    q = sub.add_parser("items"); q.add_argument("hwnd", type=int)
    q.add_argument("--max", type=int, default=500); q.set_defaults(fn=cmd_items)
    args = ap.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
