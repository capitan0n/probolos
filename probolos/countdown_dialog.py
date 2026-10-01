"""
The countdown window for a CRITICAL device: "Allow anyway" stays disabled
until the countdown ends.

Run by dialogs.TkinterBackend in an interpreter of its own -- tkinter must own
a main thread, and a broken tk must not take the agent down:

    python3 -I countdown_dialog.py TITLE TEXT YES_LABEL NO_LABEL SECONDS

Exit 10 means allow and 11 keep blocked. Anything else -- a crash, no display
-- is "no decision" to the caller. Never 1 for an answer: that is what Python
exits with on any uncaught exception.

Standalone on purpose (standard library only, no probolos imports), so -I can
isolate it from the environment and the current directory.

It takes the desktop's colours and font from ~/.config/kdeglobals when that
exists, so on KDE it looks like the kdialog windows beside it rather than a
grey Tk default; elsewhere it falls back to a neutral light theme.
"""

import configparser
import os
import sys

ALLOW, KEEP = 10, 11


def _kdeglobals() -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    try:
        parser.read(os.path.join(base, "kdeglobals"), encoding="utf-8")
    except (OSError, configparser.Error, UnicodeError):
        pass
    return parser


def kde_colors(parser=None) -> dict:
    """The desktop's colours as #rrggbb, only for keys that are present and
    well formed."""
    parser = parser if parser is not None else _kdeglobals()

    def rgb(section, key):
        try:
            parts = [int(x) for x in parser.get(section, key).split(",")[:3]]
        except (configparser.Error, ValueError):
            return None
        if len(parts) != 3 or not all(0 <= p <= 255 for p in parts):
            return None
        return "#%02x%02x%02x" % tuple(parts)

    colors = {
        "bg": rgb("Colors:Window", "BackgroundNormal"),
        "fg": rgb("Colors:Window", "ForegroundNormal"),
        "muted": rgb("Colors:Window", "ForegroundInactive"),
        "button": rgb("Colors:Button", "BackgroundNormal"),
        "button_fg": rgb("Colors:Button", "ForegroundNormal"),
        "accent": rgb("Colors:Selection", "BackgroundNormal"),
        "danger": rgb("Colors:Window", "ForegroundNegative"),
    }
    return {k: v for k, v in colors.items() if v}


def kde_font(parser=None):
    """(family, points) from kdeglobals [General] font, or None."""
    parser = parser if parser is not None else _kdeglobals()
    try:
        family, size = parser.get("General", "font").split(",")[:2]
        points = int(float(size))
    except (configparser.Error, ValueError):
        return None
    if not family.strip() or not 4 <= points <= 72:
        return None
    return family.strip(), points


def main(argv) -> int:
    title, text, yes, no = argv[1:5]
    delay = max(0, int(float(argv[5])))

    import tkinter as tk
    from tkinter import ttk

    parser = _kdeglobals()
    c = kde_colors(parser)
    bg = c.get("bg", "#eff0f1")
    fg = c.get("fg", "#232629")
    muted = c.get("muted", "#707d8a")
    button = c.get("button", "#fcfcfc")
    button_fg = c.get("button_fg", fg)
    accent = c.get("accent", "#3daee9")
    danger = c.get("danger", "#da4453")
    font = kde_font(parser) or ("TkDefaultFont", 10)

    root = tk.Tk()
    root.title(title)
    root.configure(background=bg)
    root.attributes("-topmost", True)
    root.resizable(False, False)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=bg, foreground=fg, font=font)
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground=fg)
    style.configure("Icon.TLabel", foreground=danger,
                    font=(font[0], font[1] * 3))
    style.configure("TButton", background=button, foreground=button_fg,
                    bordercolor=muted, lightcolor=button, darkcolor=button,
                    focuscolor=accent, padding=(14, 5))
    style.map("TButton",
              background=[("disabled", bg), ("pressed", accent),
                          ("active", accent)],
              foreground=[("disabled", muted)],
              bordercolor=[("focus", accent)])

    result = [KEEP]

    def done(code):
        result[0] = code
        root.destroy()

    body = ttk.Frame(root, padding=(18, 16, 18, 8))
    body.pack(fill="both", expand=True)
    ttk.Label(body, text="⛔", style="Icon.TLabel").pack(
        side="left", anchor="n", padx=(0, 16))
    ttk.Label(body, text=text, justify="left", wraplength=540).pack(
        side="left", fill="x")

    bar = ttk.Frame(root, padding=(18, 6, 18, 16))
    bar.pack(fill="x")
    keep = ttk.Button(bar, text=no, command=lambda: done(KEEP))
    keep.pack(side="right")
    allow = ttk.Button(bar, command=lambda: done(ALLOW), state="disabled")
    allow.pack(side="right", padx=(0, 8))

    # Focus starts on "keep blocked"; Escape and closing the window refuse.
    # ttk buttons answer Space, not Return, so no key held down across the
    # countdown can approve the moment it ends.
    keep.focus_set()
    root.bind("<Escape>", lambda _event: done(KEEP))
    root.protocol("WM_DELETE_WINDOW", lambda: done(KEEP))

    def tick(left):
        if left <= 0:
            allow.configure(text=yes, state="normal")
        else:
            allow.configure(text=f"{yes} ({left})")
            root.after(1000, tick, left - 1)

    tick(delay)
    root.mainloop()
    return result[0]


if __name__ == "__main__":
    sys.exit(main(sys.argv))
