#!/usr/bin/env python3
"""
VaultKey — Offline Desktop Password Manager
Requires: pip install cryptography pyperclip
"""

import tkinter as tk
from tkinter import messagebox
import json, os, base64, secrets, string

# ── Version ────────────────────────────────────────────────────────────────
VERSION = "1.4.0"
CHANGELOG = [
    ("1.4.0", "Added password generator with strength meter"),
    ("1.3.0", "Added ability to change master password"),
    ("1.2.0", "Fixed card layout and resize behaviour"),
    ("1.1.0", "Fixed compatibility with Python 3.14 on Windows"),
    ("1.0.0", "Initial release"),
]

try:
    import pyperclip
    CLIPBOARD_OK = True
except ImportError:
    CLIPBOARD_OK = False

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

# ── Paths ──────────────────────────────────────────────────────────────────
APP_DIR    = os.path.join(os.path.expanduser("~"), ".vaultkey")
VAULT_FILE = os.path.join(APP_DIR, "vault.enc")
META_FILE  = os.path.join(APP_DIR, "meta.json")
os.makedirs(APP_DIR, exist_ok=True)

# ── Crypto ─────────────────────────────────────────────────────────────────
def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return kdf.derive(password.encode())

def encrypt_data(key, plaintext):
    iv = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), None)
    return iv + ct

def decrypt_data(key, ciphertext):
    iv, ct = ciphertext[:12], ciphertext[12:]
    return AESGCM(key).decrypt(iv, ct, None).decode()

def load_meta():
    if os.path.exists(META_FILE):
        with open(META_FILE) as f:
            return json.load(f)
    return None

def save_meta(salt_b64, verify_b64):
    with open(META_FILE, "w") as f:
        json.dump({"salt": salt_b64, "verify": verify_b64}, f)

def vault_exists():
    return os.path.exists(META_FILE) and os.path.exists(VAULT_FILE)

# ── Theme ──────────────────────────────────────────────────────────────────
BG       = "#0e0e16"
SURFACE  = "#16161f"
SURFACE2 = "#1e1e2a"
BORDER   = "#2d2d42"
ACCENT   = "#7c5cfc"
GREEN    = "#4ecca3"
RED      = "#fc5c7d"
TEXT     = "#e4e4f0"
MUTED    = "#6b6b90"

FNT_TITLE  = ("Courier New", 22, "bold")
FNT_HEAD   = ("Segoe UI", 12, "bold")
FNT_BODY   = ("Segoe UI", 11)
FNT_MONO   = ("Courier New", 11)
FNT_SM     = ("Segoe UI", 9)
FNT_BTN    = ("Segoe UI", 11, "bold")

CAT_COLORS = {
    "Work":    ("#9f7eff", "#1a1035"),
    "Email":   ("#ff7a9a", "#300f20"),
    "Social":  ("#4ecca3", "#0e2e27"),
    "Finance": ("#ffb347", "#2e1e0a"),
    "Dev":     ("#61dafb", "#0a2030"),
    "Other":   ("#8888aa", "#18182a"),
}
CAT_EMOJI  = {"Work":"💼","Email":"📧","Social":"🌐","Finance":"💳","Dev":"💻","Other":"📁"}
CATEGORIES = list(CAT_COLORS.keys())

# ── Styled Button helper ───────────────────────────────────────────────────
def mk_btn(parent, text, cmd, bg=ACCENT, fg="white", w=16):
    b = tk.Button(parent, text=text, command=cmd, bg=bg, fg=fg,
                  font=FNT_BTN, relief="flat", cursor="hand2",
                  activebackground=ACCENT, activeforeground="white",
                  padx=14, pady=8, width=w, bd=0)
    b.bind("<Enter>", lambda e: b.config(bg=_lighten(bg)))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b

def _lighten(hex_color):
    r,g,b = int(hex_color[1:3],16),int(hex_color[3:5],16),int(hex_color[5:7],16)
    r,g,b = min(255,r+30),min(255,g+30),min(255,b+30)
    return f"#{r:02x}{g:02x}{b:02x}"

def mk_entry(parent, var, show=None, mono=False, w=30):
    return tk.Entry(parent, textvariable=var,
                    font=FNT_MONO if mono else FNT_BODY,
                    bg=SURFACE2, fg=TEXT, insertbackground=TEXT,
                    relief="flat", show=show or "", width=w)

# ══════════════════════════════════════════════════════════════════════════════
# Lock Screen
# ══════════════════════════════════════════════════════════════════════════════
class LockScreen(tk.Frame):
    def __init__(self, master, on_unlock):
        super().__init__(master, bg=BG)
        self.on_unlock = on_unlock
        self.pack(fill="both", expand=True)
        self._build()

    def _build(self):
        center = tk.Frame(self, bg=BG)
        center.place(relx=0.5, rely=0.5, anchor="center")

        tk.Label(center, text="🔐", font=("Segoe UI", 54), bg=BG).pack()
        tk.Label(center, text="VAULTKEY", font=("Courier New", 28, "bold"),
                 fg=ACCENT, bg=BG).pack()
        tk.Label(center, text="your offline password vault",
                 font=FNT_SM, fg=MUTED, bg=BG).pack(pady=(2, 24))

        card = tk.Frame(center, bg=SURFACE, padx=40, pady=32,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack()

        if not vault_exists():
            self._build_setup(card)
        else:
            self._build_login(card)

    def _build_login(self, card):
        tk.Label(card, text="MASTER PASSWORD", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")
        self.pw_var = tk.StringVar()
        e = mk_entry(card, self.pw_var, show="●", mono=True, w=32)
        e.pack(fill="x", ipady=10, pady=(4,0))
        e.bind("<Return>", lambda _: self._do_login())
        e.focus_set()

        self.err_lbl = tk.Label(card, text="", font=FNT_SM, fg=RED, bg=SURFACE)
        self.err_lbl.pack(pady=(8,0))

        tk.Frame(card, bg=SURFACE, height=12).pack()
        mk_btn(card, "Unlock Vault", self._do_login, w=24).pack(fill="x")

    def _do_login(self):
        pw   = self.pw_var.get()
        meta = load_meta()
        if not meta:
            self.err_lbl.config(text="No vault found."); return
        salt = base64.b64decode(meta["salt"])
        try:
            key    = derive_key(pw, salt)
            verify = base64.b64decode(meta["verify"])
            if decrypt_data(key, verify) != "VAULTKEY_OK":
                raise ValueError
            self.on_unlock(key)
        except Exception:
            self.err_lbl.config(text="Incorrect password. Try again.")
            self.pw_var.set("")

    def _build_setup(self, card):
        tk.Label(card, text="Welcome! Create your master password.",
                 font=FNT_BODY, fg=TEXT, bg=SURFACE).pack(pady=(0,18))

        tk.Label(card, text="MASTER PASSWORD", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")
        self.pw_var = tk.StringVar()
        mk_entry(card, self.pw_var, show="●", mono=True, w=32).pack(
            fill="x", ipady=10, pady=(4,14))

        tk.Label(card, text="CONFIRM PASSWORD", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")
        self.conf_var = tk.StringVar()
        e2 = mk_entry(card, self.conf_var, show="●", mono=True, w=32)
        e2.pack(fill="x", ipady=10, pady=(4,0))
        e2.bind("<Return>", lambda _: self._do_setup())

        self.err_lbl = tk.Label(card, text="", font=FNT_SM, fg=RED, bg=SURFACE)
        self.err_lbl.pack(pady=(8,0))

        tk.Frame(card, bg=SURFACE, height=12).pack()
        mk_btn(card, "Create Vault", self._do_setup, w=24).pack(fill="x")
        tk.Label(card,
                 text="This password encrypts all data.\nThere is no recovery if forgotten.",
                 font=FNT_SM, fg=MUTED, bg=SURFACE, justify="center").pack(pady=(12,0))

    def _do_setup(self):
        pw = self.pw_var.get()
        cf = self.conf_var.get()
        if not pw:
            self.err_lbl.config(text="Password cannot be empty."); return
        if pw != cf:
            self.err_lbl.config(text="Passwords do not match."); return
        salt      = secrets.token_bytes(16)
        key       = derive_key(pw, salt)
        verify_ct = encrypt_data(key, "VAULTKEY_OK")
        save_meta(base64.b64encode(salt).decode(),
                  base64.b64encode(verify_ct).decode())
        raw = encrypt_data(key, json.dumps([]))
        with open(VAULT_FILE, "wb") as f:
            f.write(raw)
        self.on_unlock(key)


# ── Password Generator Helper ─────────────────────────────────────────────
def generate_password(length=16, upper=True, lower=True,
                      digits=True, symbols=True):
    pool = ""
    required = []
    if upper:
        pool += string.ascii_uppercase
        required.append(secrets.choice(string.ascii_uppercase))
    if lower:
        pool += string.ascii_lowercase
        required.append(secrets.choice(string.ascii_lowercase))
    if digits:
        pool += string.digits
        required.append(secrets.choice(string.digits))
    if symbols:
        sym = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pool += sym
        required.append(secrets.choice(sym))
    if not pool:
        pool = string.ascii_letters + string.digits
    remaining = [secrets.choice(pool) for _ in range(length - len(required))]
    pw_list = required + remaining
    secrets.SystemRandom().shuffle(pw_list)
    return "".join(pw_list)

def password_strength(pw):
    score = 0
    if len(pw) >= 8:  score += 1
    if len(pw) >= 12: score += 1
    if len(pw) >= 16: score += 1
    if any(c.isupper() for c in pw):   score += 1
    if any(c.islower() for c in pw):   score += 1
    if any(c.isdigit() for c in pw):   score += 1
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pw): score += 1
    if score <= 2:   return "Weak",   "#fc5c7d", score / 7
    if score <= 4:   return "Fair",   "#ffb347", score / 7
    if score <= 5:   return "Good",   "#61dafb", score / 7
    return             "Strong", "#4ecca3", score / 7


class GeneratorDialog(tk.Toplevel):
    """Standalone password generator — callable from header or entry dialog."""
    def __init__(self, master, on_use=None):
        super().__init__(master)
        self.on_use = on_use   # callback(password) when Use button clicked
        self.title("Password Generator")
        self.configure(bg=SURFACE)
        self.resizable(False, False)
        self.grab_set()
        w, h = 440, 480
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self._build()
        self._generate()

    def _build(self):
        pad = tk.Frame(self, bg=SURFACE, padx=30, pady=24)
        pad.pack(fill="both", expand=True)

        tk.Label(pad, text="⚙️  Password Generator", font=FNT_HEAD,
                 fg=TEXT, bg=SURFACE).pack(anchor="w", pady=(0, 20))

        # Generated password display
        pw_frame = tk.Frame(pad, bg=SURFACE2,
                            highlightbackground=BORDER, highlightthickness=1)
        pw_frame.pack(fill="x", pady=(0, 6))
        self.v_pw = tk.StringVar()
        self.pw_lbl = tk.Entry(pw_frame, textvariable=self.v_pw,
                               font=("Courier New", 13, "bold"),
                               bg=SURFACE2, fg=GREEN,
                               insertbackground=GREEN, relief="flat",
                               justify="center", state="readonly")
        self.pw_lbl.pack(fill="x", ipady=14, padx=10)

        # Strength bar
        self.str_lbl = tk.Label(pad, text="", font=FNT_SM,
                                fg=MUTED, bg=SURFACE)
        self.str_lbl.pack(anchor="w")
        bar_bg = tk.Frame(pad, bg=SURFACE2, height=6)
        bar_bg.pack(fill="x", pady=(2, 16))
        bar_bg.pack_propagate(False)
        self.str_bar = tk.Frame(bar_bg, bg=ACCENT, height=6)
        self.str_bar.place(x=0, y=0, relheight=1, relwidth=0)

        tk.Frame(pad, bg=BORDER, height=1).pack(fill="x", pady=(0, 14))

        # Length slider
        tk.Label(pad, text="LENGTH", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")
        len_row = tk.Frame(pad, bg=SURFACE)
        len_row.pack(fill="x", pady=(4, 14))
        self.v_len = tk.IntVar(value=16)
        self.len_lbl = tk.Label(len_row, text="16",
                                font=("Courier New", 12, "bold"),
                                fg=ACCENT, bg=SURFACE, width=3)
        self.len_lbl.pack(side="right")
        slider = tk.Scale(len_row, from_=8, to=48,
                          orient="horizontal", variable=self.v_len,
                          bg=SURFACE, fg=TEXT, troughcolor=SURFACE2,
                          activebackground=ACCENT, highlightthickness=0,
                          showvalue=False, relief="flat",
                          command=self._on_len)
        slider.pack(side="left", fill="x", expand=True)

        tk.Frame(pad, bg=BORDER, height=1).pack(fill="x", pady=(0, 14))

        # Character options
        tk.Label(pad, text="INCLUDE", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w", pady=(0, 8))

        self.v_upper   = tk.BooleanVar(value=True)
        self.v_lower   = tk.BooleanVar(value=True)
        self.v_digits  = tk.BooleanVar(value=True)
        self.v_symbols = tk.BooleanVar(value=True)

        opts = [
            ("A-Z  Uppercase",  self.v_upper),
            ("a-z  Lowercase",  self.v_lower),
            ("0-9  Numbers",    self.v_digits),
            ("!@#  Symbols",    self.v_symbols),
        ]
        opt_grid = tk.Frame(pad, bg=SURFACE)
        opt_grid.pack(fill="x", pady=(0, 16))
        for i, (label, var) in enumerate(opts):
            r, c = divmod(i, 2)
            cb = tk.Checkbutton(opt_grid, text=label, variable=var,
                                font=FNT_SM, bg=SURFACE, fg=TEXT,
                                selectcolor=SURFACE2, activebackground=SURFACE,
                                activeforeground=TEXT, relief="flat",
                                cursor="hand2",
                                command=self._generate)
            cb.grid(row=r, column=c, sticky="w", padx=(0, 20), pady=3)

        tk.Frame(pad, bg=BORDER, height=1).pack(fill="x", pady=(0, 14))

        # Buttons
        btn_row = tk.Frame(pad, bg=SURFACE)
        btn_row.pack(fill="x")
        mk_btn(btn_row, "🔄 Regenerate", self._generate,
               bg=SURFACE2, fg=TEXT, w=16).pack(side="left")
        mk_btn(btn_row, "📋 Copy", self._copy,
               bg=SURFACE2, fg=TEXT, w=10).pack(side="left", padx=(8, 0))
        if self.on_use:
            mk_btn(btn_row, "Use Password", self._use,
                   w=14).pack(side="right")
        else:
            mk_btn(btn_row, "Close", self.destroy,
                   bg=SURFACE2, fg=MUTED, w=10).pack(side="right")

    def _on_len(self, val):
        self.len_lbl.config(text=str(val))
        self._generate()

    def _generate(self):
        pw = generate_password(
            length=self.v_len.get(),
            upper=self.v_upper.get(),
            lower=self.v_lower.get(),
            digits=self.v_digits.get(),
            symbols=self.v_symbols.get()
        )
        self.v_pw.set(pw)
        self._update_strength(pw)

    def _update_strength(self, pw):
        label, color, ratio = password_strength(pw)
        self.str_lbl.config(text=f"Strength: {label}", fg=color)
        self.str_bar.place(relwidth=ratio)
        self.str_bar.config(bg=color)

    def _copy(self):
        pw = self.v_pw.get()
        if CLIPBOARD_OK:
            pyperclip.copy(pw)
        else:
            self.clipboard_clear()
            self.clipboard_append(pw)
        self.str_lbl.config(text="✅  Copied to clipboard!", fg=GREEN)
        self.after(1500, lambda: self._update_strength(self.v_pw.get()))

    def _use(self):
        if self.on_use:
            self.on_use(self.v_pw.get())
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# Add / Edit Dialog
# ══════════════════════════════════════════════════════════════════════════════
class EntryDialog(tk.Toplevel):
    def __init__(self, master, on_save, entry=None):
        super().__init__(master)
        self.on_save = on_save
        self.entry   = entry
        self.configure(bg=SURFACE)
        self.title("Edit Entry" if entry else "New Entry")
        self.resizable(False, False)
        self.grab_set()
        w, h = 460, 540
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self._build()

    def _lbl(self, parent, text):
        tk.Label(parent, text=text, font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")

    def _build(self):
        pad = tk.Frame(self, bg=SURFACE, padx=30, pady=24)
        pad.pack(fill="both", expand=True)

        tk.Label(pad, text="✏️  Edit Entry" if self.entry else "🗝️  New Entry",
                 font=FNT_HEAD, fg=TEXT, bg=SURFACE).pack(anchor="w", pady=(0,18))

        g = self.entry or {}
        self.v_name  = tk.StringVar(value=g.get("name",""))
        self.v_user  = tk.StringVar(value=g.get("user",""))
        self.v_pass  = tk.StringVar(value=g.get("password",""))
        self.v_url   = tk.StringVar(value=g.get("url",""))
        self.v_notes = tk.StringVar(value=g.get("notes",""))
        self.v_cat   = tk.StringVar(value=g.get("category","Work"))

        self._lbl(pad, "SERVICE / APP NAME")
        mk_entry(pad, self.v_name, w=38).pack(fill="x", ipady=9, pady=(4,14))

        self._lbl(pad, "USERNAME / EMAIL")
        mk_entry(pad, self.v_user, w=38).pack(fill="x", ipady=9, pady=(4,14))

        self._lbl(pad, "PASSWORD")
        pw_row = tk.Frame(pad, bg=SURFACE)
        pw_row.pack(fill="x", pady=(4, 4))
        self.pw_entry = mk_entry(pw_row, self.v_pass, show="●", mono=True, w=26)
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=9)
        self.pw_entry.bind("<KeyRelease>", lambda e: self._update_pw_strength())
        self.show_pw = False
        tk.Button(pw_row, text="👁", font=FNT_SM, bg=SURFACE2, fg=MUTED,
                  relief="flat", cursor="hand2", bd=0,
                  command=self._toggle_pw).pack(side="left", padx=(6,0), ipady=9, ipadx=6)
        tk.Button(pw_row, text="⚙️ Generate", font=FNT_SM, bg=ACCENT, fg="white",
                  relief="flat", cursor="hand2", bd=0, padx=8,
                  command=self._open_generator).pack(side="left", padx=(6,0), ipady=9)

        # Strength bar under password
        str_row = tk.Frame(pad, bg=SURFACE)
        str_row.pack(fill="x", pady=(2, 10))
        self.str_lbl = tk.Label(str_row, text="", font=FNT_SM,
                                fg=MUTED, bg=SURFACE)
        self.str_lbl.pack(side="left")
        bar_bg = tk.Frame(str_row, bg=SURFACE2, height=5, width=160)
        bar_bg.pack(side="right")
        bar_bg.pack_propagate(False)
        self.str_bar = tk.Frame(bar_bg, bg=ACCENT, height=5)
        self.str_bar.place(x=0, y=0, relheight=1, relwidth=0)
        self._update_pw_strength()

        self._lbl(pad, "URL (optional)")
        mk_entry(pad, self.v_url, w=38).pack(fill="x", ipady=9, pady=(4,14))

        self._lbl(pad, "CATEGORY")
        cat_f = tk.Frame(pad, bg=SURFACE)
        cat_f.pack(anchor="w", pady=(4,16))
        for cat in CATEGORIES:
            c, _ = CAT_COLORS[cat]
            tk.Radiobutton(cat_f, text=f"{CAT_EMOJI[cat]} {cat}",
                           variable=self.v_cat, value=cat,
                           bg=SURFACE, fg=c, selectcolor=SURFACE2,
                           activebackground=SURFACE, activeforeground=c,
                           font=FNT_SM, relief="flat",
                           cursor="hand2").pack(side="left", padx=(0,10))

        btn_row = tk.Frame(pad, bg=SURFACE)
        btn_row.pack(fill="x", pady=(6,0))
        mk_btn(btn_row, "Cancel", self.destroy,
               bg=SURFACE2, fg=MUTED, w=12).pack(side="left")
        mk_btn(btn_row, "Save Entry", self._save, w=16).pack(side="right")

    def _toggle_pw(self):
        self.show_pw = not self.show_pw
        self.pw_entry.config(show="" if self.show_pw else "●")

    def _open_generator(self):
        def use_password(pw):
            self.v_pass.set(pw)
            self._update_pw_strength()
        GeneratorDialog(self, on_use=use_password)

    def _update_pw_strength(self):
        pw = self.v_pass.get()
        if not pw:
            self.str_lbl.config(text="")
            self.str_bar.place(relwidth=0)
            return
        label, color, ratio = password_strength(pw)
        self.str_lbl.config(text=f"Strength: {label}", fg=color)
        self.str_bar.place(relwidth=ratio)
        self.str_bar.config(bg=color)

    def _save(self):
        n = self.v_name.get().strip()
        u = self.v_user.get().strip()
        p = self.v_pass.get()
        if not n or not u or not p:
            messagebox.showwarning("Missing Fields",
                                   "Name, Username, and Password are required.",
                                   parent=self)
            return
        self.on_save({"name": n, "user": u, "password": p,
                      "url": self.v_url.get().strip(),
                      "notes": self.v_notes.get().strip(),
                      "category": self.v_cat.get()})
        self.destroy()


# ══════════════════════════════════════════════════════════════════════════════
# Main Vault UI
# ══════════════════════════════════════════════════════════════════════════════
class VaultApp(tk.Frame):
    def __init__(self, master, key, on_lock):
        super().__init__(master, bg=BG)
        self.key     = key
        self.on_lock = on_lock
        self.vault   = []
        self.pw_visible = {}
        self._load_vault()
        self.pack(fill="both", expand=True)
        self._build_ui()
        self._render()

    def _load_vault(self):
        if not os.path.exists(VAULT_FILE):
            return
        with open(VAULT_FILE, "rb") as f:
            raw = f.read()
        self.vault = json.loads(decrypt_data(self.key, raw))

    def _save_vault(self):
        raw = encrypt_data(self.key, json.dumps(self.vault))
        with open(VAULT_FILE, "wb") as f:
            f.write(raw)

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=SURFACE, pady=12,
                       highlightbackground=BORDER, highlightthickness=1)
        hdr.pack(fill="x")
        left = tk.Frame(hdr, bg=SURFACE)
        left.pack(side="left", padx=20)
        tk.Label(left, text="🔐  VAULTKEY", font=("Courier New",15,"bold"),
                 fg=ACCENT, bg=SURFACE).pack(side="left")
        tk.Label(left, text=f"v{VERSION}", font=("Courier New",9),
                 fg=MUTED, bg=SURFACE).pack(side="left", padx=(8,0), pady=(4,0))
        right = tk.Frame(hdr, bg=SURFACE)
        right.pack(side="right", padx=20)
        self.count_lbl = tk.Label(right, text="", font=FNT_SM, fg=MUTED, bg=SURFACE)
        self.count_lbl.pack(side="left", padx=(0,10))
        mk_btn(right, "+ Add", self._add_entry, w=7).pack(side="left", padx=(0,6))
        mk_btn(right, "⚙️ Gen", self._open_generator, bg=SURFACE2, fg=MUTED, w=7).pack(side="left", padx=(0,6))
        mk_btn(right, "🔑 Passwd", self._change_password, bg=SURFACE2, fg=MUTED, w=9).pack(side="left", padx=(0,6))
        mk_btn(right, "ℹ About", self._show_about, bg=SURFACE2, fg=MUTED, w=8).pack(side="left", padx=(0,6))
        mk_btn(right, "🔒 Lock", self.on_lock, bg=SURFACE2, fg=MUTED, w=8).pack(side="left")

        # Search
        sf = tk.Frame(self, bg=BG, padx=20, pady=12)
        sf.pack(fill="x")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._render())
        wrap = tk.Frame(sf, bg=SURFACE2, highlightbackground=BORDER, highlightthickness=1)
        wrap.pack(fill="x")
        tk.Label(wrap, text="🔍", font=FNT_BODY, bg=SURFACE2, fg=MUTED).pack(
            side="left", padx=(10,4))
        tk.Entry(wrap, textvariable=self.search_var, font=FNT_BODY,
                 bg=SURFACE2, fg=TEXT, insertbackground=TEXT,
                 relief="flat").pack(side="left", fill="x", expand=True, ipady=9)

        # Scrollable area
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(outer, bg=BG, highlightthickness=0)
        sb = tk.Scrollbar(outer, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.cards_frame = tk.Frame(self.canvas, bg=BG)
        self._cw = self.canvas.create_window((0,0), window=self.cards_frame, anchor="nw")
        self._resize_job = None
        self._last_canvas_width = 0
        self.cards_frame.bind("<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self.canvas.bind_all("<MouseWheel>",
            lambda e: self.canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

    def _on_canvas_resize(self, event):
        self.canvas.itemconfig(self._cw, width=event.width)
        if event.width != self._last_canvas_width:
            self._last_canvas_width = event.width
            if self._resize_job:
                self.after_cancel(self._resize_job)
            self._resize_job = self.after(120, self._render)

    def _render(self):
        for w in self.cards_frame.winfo_children():
            w.destroy()
        self.pw_visible.clear()

        q = self.search_var.get().lower()
        filtered = [e for e in self.vault
                    if q in e.get("name","").lower()
                    or q in e.get("user","").lower()
                    or q in e.get("category","").lower()
                    or q in e.get("url","").lower()]

        n = len(self.vault)
        self.count_lbl.config(text=f"{n} entr{'y' if n==1 else 'ies'}")

        if not filtered:
            msg = ("No results found." if q
                   else "Your vault is empty.\nClick '+ Add Entry' to store your first password.")
            tk.Label(self.cards_frame, text=msg, font=FNT_BODY,
                     fg=MUTED, bg=BG, justify="center").pack(pady=80)
            return

        # Configure columns once
        self.cards_frame.grid_columnconfigure(0, weight=1, uniform="col")
        self.cards_frame.grid_columnconfigure(1, weight=1, uniform="col")

        num_rows = (len(filtered) + 1) // 2
        for r in range(num_rows):
            self.cards_frame.grid_rowconfigure(r, weight=1)

        for i, entry in enumerate(filtered):
            real_idx = self.vault.index(entry)
            row, col = divmod(i, 2)
            cell = tk.Frame(self.cards_frame, bg=BG)
            cell.grid(row=row, column=col, sticky="nsew", padx=12, pady=8)
            cell.grid_rowconfigure(0, weight=1)
            cell.grid_columnconfigure(0, weight=1)
            self._make_card(cell, entry, real_idx)

    def _make_card(self, parent, entry, idx):
        cat = entry.get("category", "Other")
        fg_c, bg_c = CAT_COLORS.get(cat, (MUTED, SURFACE2))
        card = tk.Frame(parent, bg=SURFACE,
                        highlightbackground=ACCENT, highlightthickness=1)
        card.grid(row=0, column=0, sticky="nsew")
        tk.Frame(card, bg=ACCENT, height=3).pack(fill="x")
        inner = tk.Frame(card, bg=SURFACE, padx=16, pady=14)
        inner.pack(fill="both", expand=True)

        hdr = tk.Frame(inner, bg=SURFACE)
        hdr.pack(fill="x")
        tk.Label(hdr, text=CAT_EMOJI.get(cat,"📁"), font=("Segoe UI",20),
                 bg=bg_c, fg=fg_c, padx=8, pady=4).pack(side="left")
        info = tk.Frame(hdr, bg=SURFACE)
        info.pack(side="left", padx=(10,0), fill="x", expand=True)
        tk.Label(info, text=entry.get("name",""), font=FNT_HEAD,
                 fg=TEXT, bg=SURFACE, anchor="w").pack(anchor="w")
        tk.Label(info, text=cat, font=FNT_SM, fg=fg_c, bg=SURFACE).pack(anchor="w")

        acts = tk.Frame(hdr, bg=SURFACE)
        acts.pack(side="right")
        tk.Button(acts, text="✏️", font=FNT_SM, bg=SURFACE2, fg=TEXT,
                  relief="flat", cursor="hand2", bd=0, padx=6,
                  command=lambda i=idx: self._edit(i)).pack(side="left", padx=2)
        tk.Button(acts, text="🗑", font=FNT_SM, bg=SURFACE2, fg=RED,
                  relief="flat", cursor="hand2", bd=0, padx=6,
                  command=lambda i=idx: self._delete(i)).pack(side="left", padx=2)

        tk.Frame(inner, bg=BORDER, height=1).pack(fill="x", pady=10)
        self._field(inner, "User", entry.get("user",""),     idx, masked=False)
        self._field(inner, "Pass", entry.get("password",""), idx, masked=True)
        if entry.get("url"):
            self._field(inner, "URL", entry["url"], idx, masked=False)
        if entry.get("notes"):
            tk.Label(inner, text=f"📝  {entry['notes']}",
                     font=FNT_SM, fg=MUTED, bg=SURFACE, anchor="w").pack(anchor="w", pady=(4,0))

    def _field(self, parent, label, value, idx, masked):
        row = tk.Frame(parent, bg=SURFACE2)
        row.pack(fill="x", pady=2)
        tk.Label(row, text=label, font=FNT_SM, fg=MUTED,
                 bg=SURFACE2, width=5, anchor="w").pack(side="left", padx=(10,6))
        key = f"{label}_{idx}"
        display = "● ● ● ● ● ●" if masked else value
        lbl = tk.Label(row, text=display, font=FNT_MONO,
                       fg=TEXT, bg=SURFACE2, anchor="w")
        lbl.pack(side="left", fill="x", expand=True, ipady=6)

        if masked:
            self.pw_visible[key] = False
            def toggle(l=lbl, v=value, k=key):
                self.pw_visible[k] = not self.pw_visible[k]
                l.config(text=v if self.pw_visible[k] else "● ● ● ● ● ●")
            tk.Button(row, text="👁", font=FNT_SM, bg=SURFACE2, fg=MUTED,
                      relief="flat", cursor="hand2", bd=0, padx=4,
                      command=toggle).pack(side="right", padx=2)

        tk.Button(row, text="📋", font=FNT_SM, bg=SURFACE2, fg=MUTED,
                  relief="flat", cursor="hand2", bd=0, padx=4,
                  command=lambda v=value, r=row: self._copy(v, r)
                  ).pack(side="right", padx=2)

    def _copy(self, value, row):
        if CLIPBOARD_OK:
            pyperclip.copy(value)
        else:
            self.winfo_toplevel().clipboard_clear()
            self.winfo_toplevel().clipboard_append(value)
        orig = SURFACE2
        widgets = [row] + list(row.winfo_children())
        for w in widgets:
            try: w.config(bg="#0e3028")
            except: pass
        self.after(500, lambda: [w.config(bg=orig)
                                 for w in widgets if w.winfo_exists()])

    def _open_generator(self):
        GeneratorDialog(self.winfo_toplevel())

    def _change_password(self):
        win = tk.Toplevel(self.winfo_toplevel())
        win.title("Change Master Password")
        win.configure(bg=SURFACE)
        win.resizable(False, False)
        win.grab_set()
        w, h = 420, 460
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        pad = tk.Frame(win, bg=SURFACE, padx=30, pady=28)
        pad.pack(fill="both", expand=True)

        tk.Label(pad, text="🔑  Change Master Password", font=FNT_HEAD,
                 fg=TEXT, bg=SURFACE).pack(anchor="w", pady=(0, 20))

        # Current password
        tk.Label(pad, text="CURRENT PASSWORD", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")
        v_current = tk.StringVar()
        mk_entry(pad, v_current, show="●", mono=True, w=36).pack(
            fill="x", ipady=10, pady=(4, 14))

        # New password
        tk.Label(pad, text="NEW PASSWORD", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")
        v_new = tk.StringVar()
        mk_entry(pad, v_new, show="●", mono=True, w=36).pack(
            fill="x", ipady=10, pady=(4, 14))

        # Confirm new password
        tk.Label(pad, text="CONFIRM NEW PASSWORD", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")
        v_confirm = tk.StringVar()
        mk_entry(pad, v_confirm, show="●", mono=True, w=36).pack(
            fill="x", ipady=10, pady=(4, 0))

        # Error label
        err_lbl = tk.Label(pad, text="", font=FNT_SM, fg=RED, bg=SURFACE)
        err_lbl.pack(pady=(8, 0))

        # Success label
        ok_lbl = tk.Label(pad, text="", font=FNT_SM, fg=GREEN, bg=SURFACE)
        ok_lbl.pack()

        def do_change():
            current  = v_current.get()
            new_pw   = v_new.get()
            confirm  = v_confirm.get()
            err_lbl.config(text="")
            ok_lbl.config(text="")

            # Verify current password
            meta = load_meta()
            salt = base64.b64decode(meta["salt"])
            try:
                test_key = derive_key(current, salt)
                verify   = base64.b64decode(meta["verify"])
                if decrypt_data(test_key, verify) != "VAULTKEY_OK":
                    raise ValueError
            except Exception:
                err_lbl.config(text="Current password is incorrect.")
                return

            if not new_pw:
                err_lbl.config(text="New password cannot be empty.")
                return
            if len(new_pw) < 6:
                err_lbl.config(text="New password must be at least 6 characters.")
                return
            if new_pw != confirm:
                err_lbl.config(text="New passwords do not match.")
                return
            if new_pw == current:
                err_lbl.config(text="New password must be different from current.")
                return

            # Re-encrypt vault with new key
            new_salt = secrets.token_bytes(16)
            new_key  = derive_key(new_pw, new_salt)

            # Save new meta
            new_verify = encrypt_data(new_key, "VAULTKEY_OK")
            save_meta(base64.b64encode(new_salt).decode(),
                      base64.b64encode(new_verify).decode())

            # Re-encrypt vault data
            raw = encrypt_data(new_key, json.dumps(self.vault))
            with open(VAULT_FILE, "wb") as f:
                f.write(raw)

            # Update the live key in memory
            self.key = new_key

            ok_lbl.config(text="✅  Master password changed successfully!")
            err_lbl.config(text="")

            # Clear fields
            v_current.set("")
            v_new.set("")
            v_confirm.set("")

            # Auto close after 2 seconds
            win.after(2000, win.destroy)

        tk.Frame(pad, bg=SURFACE, height=4).pack()
        btn_row = tk.Frame(pad, bg=SURFACE)
        btn_row.pack(fill="x", pady=(8, 0))
        mk_btn(btn_row, "Cancel", win.destroy, bg=SURFACE2, fg=MUTED, w=12).pack(side="left")
        mk_btn(btn_row, "Change Password", do_change, w=18).pack(side="right")

    def _show_about(self):
        win = tk.Toplevel(self.winfo_toplevel())
        win.title("About VaultKey")
        win.configure(bg=SURFACE)
        win.resizable(False, False)
        win.grab_set()
        w, h = 400, 340
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        pad = tk.Frame(win, bg=SURFACE, padx=30, pady=24)
        pad.pack(fill="both", expand=True)

        tk.Label(pad, text="🔐", font=("Segoe UI",36), bg=SURFACE).pack()
        tk.Label(pad, text="VAULTKEY", font=("Courier New",18,"bold"),
                 fg=ACCENT, bg=SURFACE).pack()
        tk.Label(pad, text=f"Version {VERSION}", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(pady=(2,20))

        tk.Frame(pad, bg=BORDER, height=1).pack(fill="x", pady=(0,14))

        tk.Label(pad, text="What's New", font=("Segoe UI",10,"bold"),
                 fg=TEXT, bg=SURFACE).pack(anchor="w")

        for ver, note in CHANGELOG:
            row = tk.Frame(pad, bg=SURFACE)
            row.pack(fill="x", pady=2)
            tag_bg = ACCENT if ver == VERSION else SURFACE2
            tag_fg = "white" if ver == VERSION else MUTED
            tk.Label(row, text=f" v{ver} ", font=("Courier New",9,"bold"),
                     bg=tag_bg, fg=tag_fg).pack(side="left")
            tk.Label(row, text=note, font=FNT_SM,
                     fg=TEXT if ver == VERSION else MUTED,
                     bg=SURFACE).pack(side="left", padx=(10,0))

        tk.Frame(pad, bg=BORDER, height=1).pack(fill="x", pady=14)
        tk.Label(pad, text="Your data is stored in  ~/.vaultkey/  on your machine.",
                 font=FNT_SM, fg=MUTED, bg=SURFACE).pack()
        mk_btn(pad, "Close", win.destroy, bg=SURFACE2, fg=MUTED, w=10).pack(pady=(16,0))

    def _add_entry(self):
        def on_save(r):
            self.vault.insert(0, r)
            self._save_vault(); self._render()
        EntryDialog(self.winfo_toplevel(), on_save)

    def _edit(self, idx):
        def on_save(r):
            self.vault[idx] = r
            self._save_vault(); self._render()
        EntryDialog(self.winfo_toplevel(), on_save, entry=self.vault[idx])

    def _delete(self, idx):
        if messagebox.askyesno("Delete",
                               f"Delete '{self.vault[idx]['name']}'? Cannot be undone.",
                               parent=self.winfo_toplevel()):
            del self.vault[idx]
            self._save_vault(); self._render()


# ══════════════════════════════════════════════════════════════════════════════
# Root Window
# ══════════════════════════════════════════════════════════════════════════════
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VaultKey")
        self.configure(bg=BG)
        w, h = 920, 660
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self.minsize(820, 520)
        self._show_lock()

    def _clear(self):
        for w in self.winfo_children():
            w.destroy()

    def _show_lock(self):
        self._clear()
        LockScreen(self, on_unlock=self._show_vault)

    def _show_vault(self, key):
        self._clear()
        VaultApp(self, key=key, on_lock=self._show_lock)


if __name__ == "__main__":
    if not CRYPTO_OK:
        import sys
        print("ERROR: run:  pip install cryptography pyperclip")
        sys.exit(1)
    App().mainloop()
