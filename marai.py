#!/usr/bin/env python3
"""
Marai — Offline Desktop Password Manager
Requires: pip install cryptography pyperclip
"""

import tkinter as tk
from tkinter import messagebox
import json, os, base64, secrets, string, threading, urllib.request, webbrowser, subprocess, ctypes, sys

# ── Version ────────────────────────────────────────────────────────────────
VERSION = "2.1.0"
CHANGELOG = [
    ("2.1.0", "Upgraded to Argon2id key derivation — silent migration on login"),
    ("2.0.0", "Rebranded from VaultKey to Marai"),
    ("1.7.0", "Passwords never enter Windows clipboard history (Win+V)"),
    ("1.6.0", "Added automatic update checker"),
    ("1.5.0", "Security hardening: lockout, auto-lock, clipboard clear"),
    ("1.4.0", "Added password generator with strength meter"),
    ("1.3.0", "Added ability to change master password"),
    ("1.2.0", "Fixed card layout and resize behaviour"),
    ("1.1.0", "Fixed compatibility with Python 3.14 on Windows"),
    ("1.0.0", "Initial release"),
]

# ── Update Checker ────────────────────────────────────────────────────────
GITHUB_USER    = "ManPlate"
GITHUB_REPO    = "Marai"
VERSION_URL    = f"https://raw.githubusercontent.com/{GITHUB_USER}/{GITHUB_REPO}/main/version.json"
RELEASES_URL   = f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}/releases"

def check_for_update(callback):
    """Runs in a background thread. Calls callback(new_version) if update found."""
    def _check():
        try:
            req = urllib.request.Request(
                VERSION_URL,
                headers={"User-Agent": f"Marai/{VERSION}"}
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                data    = json.loads(r.read().decode())
                latest  = data.get("version", "")
                if latest and latest != VERSION:
                    # Compare version tuples e.g. 1.6.0 vs 1.5.0
                    def parse(v): return tuple(int(x) for x in v.split("."))
                    if parse(latest) > parse(VERSION):
                        callback(latest)
        except Exception:
            pass   # Silently fail — app works fully offline
    threading.Thread(target=_check, daemon=True).start()

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

try:
    from argon2.low_level import hash_secret_raw, Type
    ARGON2_OK = True
except ImportError:
    ARGON2_OK = False

# ── Paths ──────────────────────────────────────────────────────────────────
APP_DIR    = os.path.join(os.path.expanduser("~"), ".marai")
VAULT_FILE = os.path.join(APP_DIR, "vault.enc")
META_FILE  = os.path.join(APP_DIR, "meta.json")
os.makedirs(APP_DIR, exist_ok=True)

# ── Migrate from VaultKey if needed ───────────────────────────────────────
def migrate_from_vaultkey():
    old_dir = os.path.join(os.path.expanduser("~"), ".vaultkey")
    if not os.path.exists(old_dir):
        return
    if os.path.exists(os.path.join(APP_DIR, "meta.json")):
        return
    import shutil
    try:
        for fname in ["vault.enc", "meta.json"]:
            src = os.path.join(old_dir, fname)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(APP_DIR, fname))
        # Leave a flag so we patch the verify token on next unlock
        open(os.path.join(APP_DIR, ".needs_token_patch"), "w").close()
    except Exception:
        pass

migrate_from_vaultkey()


def patch_verify_token_if_needed(key):
    """Called after successful unlock to update VAULTKEY_OK -> MARAI_OK."""
    flag = os.path.join(APP_DIR, ".needs_token_patch")
    if not os.path.exists(flag):
        return
    try:
        new_verify = encrypt_data(key, "MARAI_OK")
        with open(META_FILE, encoding="utf-8") as f:
            meta = json.load(f)
        meta["verify"] = base64.b64encode(new_verify).decode()
        with open(META_FILE, "w", encoding="utf-8") as f:
            json.dump(meta, f)
        os.remove(flag)
    except Exception:
        pass

# ── Crypto ─────────────────────────────────────────────────────────────────
# Argon2id parameters (OWASP recommended minimums)
ARGON2_TIME_COST   = 3       # iterations
ARGON2_MEMORY_COST = 65536   # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN    = 32
KDF_VERSION        = "argon2id"

def derive_key_argon2id(password, salt):
    """Argon2id — memory-hard, GPU-resistant. Current default."""
    return hash_secret_raw(
        secret      = password.encode(),
        salt        = salt,
        time_cost   = ARGON2_TIME_COST,
        memory_cost = ARGON2_MEMORY_COST,
        parallelism = ARGON2_PARALLELISM,
        hash_len    = ARGON2_HASH_LEN,
        type        = Type.ID
    )

def derive_key_pbkdf2(password, salt):
    """PBKDF2 — legacy, used for migrating old vaults only."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    return kdf.derive(password.encode())

def derive_key(password, salt, kdf=None):
    """Derive key using the appropriate KDF. Defaults to Argon2id."""
    if kdf == "pbkdf2" or (not ARGON2_OK):
        return derive_key_pbkdf2(password, salt)
    return derive_key_argon2id(password, salt)

def encrypt_data(key, plaintext):
    iv = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(iv, plaintext.encode(), None)
    return iv + ct

def decrypt_data(key, ciphertext):
    iv, ct = ciphertext[:12], ciphertext[12:]
    return AESGCM(key).decrypt(iv, ct, None).decode()

def load_meta():
    if os.path.exists(META_FILE):
        with open(META_FILE, encoding="utf-8") as f:
            return json.load(f)
    return None

def save_meta(salt_b64, verify_b64, kdf=KDF_VERSION):
    with open(META_FILE, "w", encoding="utf-8") as f:
        json.dump({"salt": salt_b64, "verify": verify_b64, "kdf": kdf}, f)

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

        # ── Concentric logo icon (matches marai_logo.svg) ────────────────
        icon_size = 120
        c = tk.Canvas(center, width=icon_size, height=icon_size,
                      bg=BG, highlightthickness=0)
        c.pack(pady=(0, 10))
        cx, cy = icon_size / 2, icon_size / 2

        import math

        def ring_points(cx, cy, rx, ry, n_sides, rotation_deg):
            """Generate polygon points for an irregular ring."""
            pts = []
            for i in range(n_sides):
                angle = math.radians(rotation_deg + i * 360 / n_sides)
                x = cx + rx * math.cos(angle)
                y = cy + ry * math.sin(angle)
                pts.extend([x, y])
            return pts

        # Layer 6 — outermost, faintest
        pts = ring_points(cx, cy, 52, 48, 7, 12)
        c.create_polygon(pts, fill="", outline="#2a1f5e", width=1, smooth=False)

        # Layer 5
        pts = ring_points(cx, cy, 46, 42, 7, 22)
        c.create_polygon(pts, fill="", outline="#3d2d8a", width=1, smooth=False)

        # Layer 4
        pts = ring_points(cx, cy, 39, 36, 7, 5)
        c.create_polygon(pts, fill="", outline="#5438b0", width=2, smooth=False)

        # Layer 3
        pts = ring_points(cx, cy, 31, 29, 7, 18)
        c.create_polygon(pts, fill="", outline=ACCENT, width=2, smooth=False)

        # Layer 2 — brighter
        pts = ring_points(cx, cy, 22, 21, 7, 8)
        c.create_polygon(pts, fill="", outline="#9d7fff", width=2, smooth=False)

        # Layer 1 — innermost ring with fill
        pts = ring_points(cx, cy, 13, 13, 7, 20)
        c.create_polygon(pts, fill="#1e1040", outline="#c4b0ff", width=1.5, smooth=False)

        # Core glow
        c.create_oval(cx-9, cy-9, cx+9, cy+9,
                      fill="#c4b0ff", outline="", width=0)
        c.create_oval(cx-5, cy-5, cx+5, cy+5,
                      fill="#ffffff", outline="", width=0)

        # ── Name with letter spacing ──────────────────────────────────────
        tk.Label(center, text="M  A  R  A  I",
                 font=("Segoe UI", 26, "bold"),
                 fg=ACCENT, bg=BG).pack()
        tk.Label(center, text="your offline password vault — hidden by design",
                 font=FNT_SM, fg=MUTED, bg=BG).pack(pady=(4, 24))

        card = tk.Frame(center, bg=SURFACE, padx=40, pady=32,
                        highlightbackground=BORDER, highlightthickness=1)
        card.pack()

        if not vault_exists():
            self._build_setup(card)
        else:
            self._build_login(card)

    def _build_login(self, card):
        self._attempts   = 0
        self._locked_out = False

        tk.Label(card, text="MASTER PASSWORD", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(anchor="w")
        self.pw_var = tk.StringVar()
        self._pw_entry = mk_entry(card, self.pw_var, show="●", mono=True, w=32)
        self._pw_entry.pack(fill="x", ipady=10, pady=(4,0))
        self._pw_entry.bind("<Return>", lambda _: self._do_login())
        self._pw_entry.focus_set()

        self.err_lbl = tk.Label(card, text="", font=FNT_SM, fg=RED, bg=SURFACE)
        self.err_lbl.pack(pady=(8,0))

        tk.Frame(card, bg=SURFACE, height=12).pack()
        self._unlock_btn = mk_btn(card, "Unlock Vault", self._do_login, w=24)
        self._unlock_btn.pack(fill="x")

    def _do_login(self):
        if self._locked_out:
            return
        pw = self.pw_var.get()
        meta = load_meta()
        if not meta:
            self.err_lbl.config(text="No vault found."); return
        salt     = base64.b64decode(meta["salt"])
        kdf_used = meta.get("kdf", "pbkdf2")   # old vaults have no kdf field
        try:
            key    = derive_key(pw, salt, kdf=kdf_used)
            verify = base64.b64decode(meta["verify"])
            # Accept both old VaultKey token and new Marai token
            decrypted = decrypt_data(key, verify)
            if decrypted not in ("MARAI_OK", "VAULTKEY_OK"):
                raise ValueError
            self._attempts = 0
            patch_verify_token_if_needed(key)
            # Silent upgrade: if vault still uses PBKDF2, re-derive with
            # Argon2id and re-encrypt everything in the background
            if kdf_used == "pbkdf2" and ARGON2_OK:
                self.after(200, lambda: self._upgrade_kdf(pw, key))
            self.on_unlock(key)
        except Exception:
            self._attempts += 1
            remaining = 5 - self._attempts
            if self._attempts >= 5:
                self._locked_out = True
                self._unlock_btn.config(state="disabled")
                self._pw_entry.config(state="disabled")
                self._countdown(30)
            else:
                self.err_lbl.config(
                    text=f"Incorrect password. {remaining} attempt{'s' if remaining != 1 else ''} remaining.",
                    fg=RED)
            self.pw_var.set("")

    def _upgrade_kdf(self, password, old_key):
        """
        Silently re-encrypts the vault using Argon2id.
        Runs once after first login on any PBKDF2 vault.
        The user never sees this happen.
        """
        try:
            # Load existing vault data with old key
            with open(VAULT_FILE, "rb") as f:
                raw = f.read()
            vault_json = decrypt_data(old_key, raw)

            # Generate new salt and derive Argon2id key
            new_salt = secrets.token_bytes(16)
            new_key  = derive_key(password, new_salt, kdf="argon2id")

            # Re-encrypt vault and verification token
            new_vault_ct  = encrypt_data(new_key, vault_json)
            new_verify_ct = encrypt_data(new_key, "MARAI_OK")

            with open(VAULT_FILE, "wb") as f:
                f.write(new_vault_ct)
            save_meta(
                base64.b64encode(new_salt).decode(),
                base64.b64encode(new_verify_ct).decode(),
                kdf="argon2id"
            )
            # Update the in-memory key so auto-save uses new key
            vault_frame = self.master.nametowidget(self.master.winfo_children()[-1].winfo_name())
            if hasattr(vault_frame, "key"):
                vault_frame.key = new_key
        except Exception:
            pass   # If anything fails, vault remains on PBKDF2 — no data loss

    def _countdown(self, secs):
        if secs > 0:
            self.err_lbl.config(
                text=f"Too many attempts. Wait {secs}s before trying again.",
                fg="#ffb347")
            self.after(1000, lambda: self._countdown(secs - 1))
        else:
            self._locked_out = False
            self._attempts   = 0
            self._unlock_btn.config(state="normal")
            self._pw_entry.config(state="normal")
            self.err_lbl.config(text="You may try again.", fg=GREEN)
            self._pw_entry.focus_set()

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
        key       = derive_key(pw, salt, kdf="argon2id" if ARGON2_OK else "pbkdf2")
        verify_ct = encrypt_data(key, "MARAI_OK")
        save_meta(base64.b64encode(salt).decode(),
                  base64.b64encode(verify_ct).decode(),
                  kdf="argon2id" if ARGON2_OK else "pbkdf2")
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
        w, h = 500, 480
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
               bg=SURFACE2, fg=TEXT, w=14).pack(side="left")
        mk_btn(btn_row, "📋 Copy", self._copy,
               bg=SURFACE2, fg=TEXT, w=10).pack(side="left", padx=(8, 0))
        if self.on_use:
            mk_btn(btn_row, "Use Password", self._use,
                   w=16).pack(side="right")
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
        self._auto_lock_job   = None
        self._AUTO_LOCK_SECS  = 300   # 5 minutes
        self._reset_auto_lock()
        # Bind mouse/keyboard activity to reset the auto-lock timer
        self.winfo_toplevel().bind_all("<Motion>",   lambda e: self._reset_auto_lock())
        self.winfo_toplevel().bind_all("<KeyPress>",  lambda e: self._reset_auto_lock())
        # Check for updates in background
        check_for_update(self._on_update_found)

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
        tk.Label(left, text="🔐  MARAI", font=("Segoe UI",15,"bold"),
                 fg=ACCENT, bg=SURFACE).pack(side="left")
        tk.Label(left, text=f"v{VERSION}", font=("Courier New",9),
                 fg=MUTED, bg=SURFACE).pack(side="left", padx=(8,0), pady=(4,0))
        right = tk.Frame(hdr, bg=SURFACE)
        right.pack(side="right", padx=20)
        self.count_lbl = tk.Label(right, text="", font=FNT_SM, fg=MUTED, bg=SURFACE)
        self.count_lbl.pack(side="left", padx=(0,10))
        self.lock_timer_lbl = tk.Label(right, text="", font=FNT_SM, fg=MUTED, bg=SURFACE)
        self.lock_timer_lbl.pack(side="left", padx=(0,10))
        self._update_lock_timer_display()
        mk_btn(right, "+ Add", self._add_entry, w=7).pack(side="left", padx=(0,6))
        mk_btn(right, "⚙️ Gen", self._open_generator, bg=SURFACE2, fg=MUTED, w=7).pack(side="left", padx=(0,6))
        mk_btn(right, "🔑 Passwd", self._change_password, bg=SURFACE2, fg=MUTED, w=9).pack(side="left", padx=(0,6))
        mk_btn(right, "ℹ About", self._show_about, bg=SURFACE2, fg=MUTED, w=8).pack(side="left", padx=(0,6))
        mk_btn(right, "🔒 Lock", self.on_lock, bg=SURFACE2, fg=MUTED, w=8).pack(side="left")

        # Update banner (hidden until update found)
        self._update_banner = tk.Frame(self, bg="#1a2a10",
                                       highlightbackground="#4ecca3",
                                       highlightthickness=1)
        self._update_lbl = tk.Label(self._update_banner,
                                    text="", font=FNT_SM,
                                    fg="#4ecca3", bg="#1a2a10")
        self._update_lbl.pack(side="left", padx=16, pady=8)
        self._update_btn = tk.Button(self._update_banner,
                                     text="Download",
                                     font=("Segoe UI", 9, "bold"),
                                     bg="#4ecca3", fg="#0a0a0a",
                                     relief="flat", cursor="hand2",
                                     padx=10, pady=4,
                                     command=lambda: webbrowser.open(RELEASES_URL))
        self._update_btn.pack(side="right", padx=16, pady=6)
        tk.Button(self._update_banner, text="✕",
                  font=FNT_SM, bg="#1a2a10", fg="#4ecca3",
                  relief="flat", cursor="hand2", bd=0,
                  command=self._dismiss_update_banner).pack(side="right", padx=(0,4))

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
        self._copy_secure(value)
        orig = SURFACE2
        widgets = [row] + list(row.winfo_children())
        for w in widgets:
            try: w.config(bg="#0e3028")
            except: pass
        self.after(500, lambda: [w.config(bg=orig)
                                 for w in widgets if w.winfo_exists()])

    def _copy_secure(self, value):
        """
        Copy to clipboard bypassing Windows clipboard history (Win+V).
        Uses ExcludeClipboardContentFromMonitorProcessing flag via ctypes.
        Falls back to normal copy on non-Windows or if API call fails.
        """
        copied = False
        if sys.platform == "win32":
            try:
                u32      = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32

                # Register the special format that tells Windows to skip history
                CF_EXCLUDE     = u32.RegisterClipboardFormatW(
                    "ExcludeClipboardContentFromMonitorProcessing")
                CF_UNICODETEXT = 13
                GMEM_MOVEABLE  = 0x0002

                # Encode text as null-terminated UTF-16-LE
                encoded  = (value + "\0").encode("utf-16-le")
                h_mem    = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(encoded))
                if h_mem:
                    p_mem = kernel32.GlobalLock(h_mem)
                    if p_mem:
                        ctypes.memmove(p_mem, encoded, len(encoded))
                        kernel32.GlobalUnlock(h_mem)
                        if u32.OpenClipboard(0):
                            u32.EmptyClipboard()
                            u32.SetClipboardData(CF_UNICODETEXT, h_mem)
                            u32.SetClipboardData(CF_EXCLUDE, None)
                            u32.CloseClipboard()
                            copied = True
            except Exception:
                pass

        if not copied:
            # Fallback for non-Windows or if ctypes call failed
            if CLIPBOARD_OK:
                pyperclip.copy(value)
            else:
                self.winfo_toplevel().clipboard_clear()
                self.winfo_toplevel().clipboard_append(value)

    def _on_update_found(self, new_version):
        """Called from background thread — use after() to safely update UI."""
        self.after(0, lambda: self._show_update_banner(new_version))

    def _show_update_banner(self, new_version):
        self._update_lbl.config(
            text=f"🎉  Marai v{new_version} is available!  You are on v{VERSION}.")
        self._update_banner.pack(fill="x", after=self.winfo_children()[0])

    def _dismiss_update_banner(self):
        self._update_banner.pack_forget()

    def _reset_auto_lock(self):
        if self._auto_lock_job:
            self.after_cancel(self._auto_lock_job)
        self._auto_lock_job = self.after(
            self._AUTO_LOCK_SECS * 1000,
            self._auto_lock_trigger)
        self._lock_start = self.winfo_toplevel().tk.call("clock", "seconds")
        self._update_lock_timer_display()

    def _update_lock_timer_display(self):
        try:
            now     = int(self.winfo_toplevel().tk.call("clock", "seconds"))
            elapsed = now - int(self._lock_start) if hasattr(self, "_lock_start") else 0
            remain  = max(0, self._AUTO_LOCK_SECS - elapsed)
            mins, secs = divmod(remain, 60)
            self.lock_timer_lbl.config(text=f"🔒 {mins}:{secs:02d}")
            self.after(1000, self._update_lock_timer_display)
        except Exception:
            pass

    def _auto_lock_trigger(self):
        # Clear decrypted vault from memory before locking
        self.vault = []
        self.key   = None
        self.on_lock()


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
                kdf_used = meta.get("kdf", "pbkdf2")
                test_key = derive_key(current, salt, kdf=kdf_used)
                verify   = base64.b64decode(meta["verify"])
                if decrypt_data(test_key, verify) not in ("MARAI_OK", "VAULTKEY_OK"):
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

            # Re-encrypt vault with new Argon2id key
            new_salt = secrets.token_bytes(16)
            new_key  = derive_key(new_pw, new_salt, kdf="argon2id" if ARGON2_OK else "pbkdf2")

            # Save new meta with kdf field
            new_verify = encrypt_data(new_key, "MARAI_OK")
            save_meta(base64.b64encode(new_salt).decode(),
                      base64.b64encode(new_verify).decode(),
                      kdf="argon2id" if ARGON2_OK else "pbkdf2")

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
        win.title("About Marai")
        win.configure(bg=SURFACE)
        win.resizable(False, False)
        win.grab_set()
        w, h = 520, 480
        sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
        win.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")

        # ── Header (fixed, always visible) ───────────────────────────────
        hdr = tk.Frame(win, bg=SURFACE, padx=30, pady=20)
        hdr.pack(fill="x")
        # Small concentric icon for About dialog
        import math
        ac = tk.Canvas(hdr, width=64, height=64, bg=SURFACE, highlightthickness=0)
        ac.pack()
        ax, ay = 32.0, 32.0
        def aring(cx, cy, rx, ry, n, rot):
            pts = []
            for i in range(n):
                a = math.radians(rot + i * 360 / n)
                pts.extend([cx + rx*math.cos(a), cy + ry*math.sin(a)])
            return pts
        ac.create_polygon(aring(ax,ay,28,26,7,12), fill="", outline="#2a1f5e", width=1)
        ac.create_polygon(aring(ax,ay,23,21,7,22), fill="", outline="#3d2d8a", width=1)
        ac.create_polygon(aring(ax,ay,18,17,7,5),  fill="", outline=ACCENT,    width=1.5)
        ac.create_polygon(aring(ax,ay,12,12,7,18), fill="", outline="#9d7fff",  width=1.5)
        ac.create_polygon(aring(ax,ay,7,7,7,20),   fill="#1e1040", outline="#c4b0ff", width=1)
        ac.create_oval(ax-5,ay-5,ax+5,ay+5, fill="#c4b0ff", outline="")
        ac.create_oval(ax-2.5,ay-2.5,ax+2.5,ay+2.5, fill="#ffffff", outline="")
        tk.Label(hdr, text="M  A  R  A  I", font=("Segoe UI",18,"bold"),
                 fg=ACCENT, bg=SURFACE).pack()
        tk.Label(hdr, text=f"Version {VERSION}", font=FNT_SM,
                 fg=MUTED, bg=SURFACE).pack(pady=(2,0))

        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(12,0))

        # ── Scrollable changelog ──────────────────────────────────────────
        tk.Label(win, text="What's New", font=("Segoe UI",10,"bold"),
                 fg=TEXT, bg=SURFACE).pack(anchor="w", padx=30, pady=(10,4))

        scroll_frame = tk.Frame(win, bg=SURFACE, height=160)
        scroll_frame.pack(fill="x", padx=30)
        scroll_frame.pack_propagate(False)

        canvas = tk.Canvas(scroll_frame, bg=SURFACE, highlightthickness=0)
        scrollbar = tk.Scrollbar(scroll_frame, orient="vertical",
                                 command=canvas.yview)
        inner = tk.Frame(canvas, bg=SURFACE)

        inner.bind("<Configure>",
                   lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for ver, note in CHANGELOG:
            row = tk.Frame(inner, bg=SURFACE)
            row.pack(fill="x", pady=3)
            tag_bg = ACCENT if ver == VERSION else SURFACE2
            tag_fg = "white" if ver == VERSION else MUTED
            tk.Label(row, text=f" v{ver} ", font=("Courier New",9,"bold"),
                     bg=tag_bg, fg=tag_fg, width=8).pack(side="left")
            tk.Label(row, text=note, font=FNT_SM,
                     fg=TEXT if ver == VERSION else MUTED,
                     bg=SURFACE, anchor="w", wraplength=340,
                     justify="left").pack(side="left", padx=(10,0), fill="x")

        # ── Footer (fixed, always visible) ───────────────────────────────
        tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=30, pady=(12,0))

        ftr = tk.Frame(win, bg=SURFACE, padx=30, pady=14)
        ftr.pack(fill="x")

        tk.Label(ftr, text="Your data is stored in  ~/.marai/  on your machine.",
                 font=FNT_SM, fg=MUTED, bg=SURFACE).pack()

        # Clickable GitHub link
        gh_url = f"https://github.com/{GITHUB_USER}/{GITHUB_REPO}"
        gh_lbl = tk.Label(ftr, text=gh_url, font=FNT_SM,
                          fg=ACCENT, bg=SURFACE, cursor="hand2")
        gh_lbl.pack(pady=(6,0))
        gh_lbl.bind("<Button-1>", lambda e: webbrowser.open(gh_url))
        gh_lbl.bind("<Enter>", lambda e: gh_lbl.config(fg=GREEN))
        gh_lbl.bind("<Leave>", lambda e: gh_lbl.config(fg=ACCENT))

        mk_btn(ftr, "Close", win.destroy, bg=SURFACE2, fg=MUTED, w=10).pack(pady=(14,0))

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
        self.title("Marai")
        self.configure(bg=BG)
        w, h = 920, 660
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self.minsize(820, 520)
        self._set_icon()
        self._show_lock()

    def _set_icon(self):
        """Set the window icon for title bar and taskbar."""
        # When bundled with PyInstaller, resources are in sys._MEIPASS
        # When running from source, look in the same folder as the script
        import sys
        base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
        ico = os.path.join(base, "marai.ico")
        if os.path.exists(ico):
            try:
                self.iconbitmap(ico)
            except Exception:
                pass

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
