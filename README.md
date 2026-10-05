# Passary — Secure Desktop Password Manager

Passary is a modern, realistic, production-style Desktop Password Manager built in Python using **CustomTkinter** for a dark/light interface, **SQLite** for encrypted local persistence, and the **cryptography** library for AES authenticated encryption.

---

## Key Features

### 1. Master Password & Authentication
- **First-Launch Setup:** Create a Master Password with instant password strength feedback.
- **OWASP-Compliant Key Derivation:** Uses **PBKDF2-HMAC-SHA256** with **600,000 iterations** and a unique 16-byte random salt.
- **Zero Plain-Text Storage:** Master password is never saved to disk.
- **Memory Key Protection:** Derived encryption keys reside strictly in RAM and are wiped upon session lock or exit.
- **Rate-Limited Login:** Protects against brute-force attacks with lockout timers.
- **Configurable Auto-Lock:** Automatically locks the vault after a configurable period of inactivity (1 min, 5 min, 15 min, 30 min, or Never).

### 2. Encrypted Credential Vault
- **AES Authenticated Encryption:** Passwords and sensitive notes are encrypted using **Fernet** (AES-128-CBC + HMAC-SHA256).
- **CRUD Operations:** Easily Add, Edit, Delete, and Inspect account credentials.
- **Fields Stored:** Website Name, Website URL, Username/Email, Encrypted Password, Notes, Category, Favorite Flag, Created Date, and Updated Date.
- **Passary UI:** Left list pane with domain badge icons, category tags, quick copy buttons; Right detail inspector pane.

### 3. Real-Time Search & Filtering
- Instant search by website name, username, URL, or notes.
- Category filtering (`Personal`, `Work`, `Finance`, `Social`, `SSH`).
- One-click Favorites view.

### 4. CSPRNG Password Generator
- Uses Python's `secrets` module (Cryptographically Secure Pseudo-Random Number Generator).
- Custom length slider (6 to 64 characters).
- Optional character sets (Uppercase, Lowercase, Digits, Symbols).
- Real-time **entropy bit calculation** and strength rating.

### 5. Security Audit Center
- Analyzes all stored vault credentials.
- Displays **Vault Security Health Score (0–100%)**.
- Highlights weak passwords, short passwords, and **reused passwords** across accounts.
- Direct "Fix Password" quick-action button.

---

## Technology Stack

- **GUI:** Python 3 + `CustomTkinter`
- **Database:** SQLite 3 (`data/vault.db`)
- **Encryption:** `cryptography.fernet` (Fernet AES-128-CBC + HMAC-SHA256)
- **Key Derivation:** `cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC`
- **Randomness:** `secrets` module
- **Clipboard:** `pyperclip`

---

## Project Architecture

```
PasswordManager/
│
├── main.py                    # Application entry point
├── requirements.txt           # Package dependencies
├── README.md                  # Project documentation & security guide
│
├── database/                  # SQLite persistence layer
│   ├── database.py            # SQLite connection pool, schema, & CRUD queries
│   └── models.py              # User, Credential, Settings data models
│
├── security/                  # Cryptography & Security layer
│   ├── encryption.py          # PBKDF2 key derivation & Fernet encryption
│   ├── authentication.py      # Master password hashing & RAM SessionManager
│   └── password_generator.py  # CSPRNG generator & entropy math
│
├── ui/                        # CustomTkinter GUI presentation views
│   ├── app.py                 # Main window container & sidebar navigation
│   ├── login.py               # Master password setup & login screen
│   ├── dashboard.py           # Stats summary overview dashboard
│   ├── vault.py               # Credential table list & detail inspector
│   ├── add_password.py        # Add / Edit modal dialog
│   ├── generator.py           # Standalone password generator
│   ├── security_center.py     # Vault audit & health center
│   └── settings.py            # Preferences, auto-lock, & re-encryption settings
│
└── utils/                     # Utility helpers
    └── helpers.py             # Clipboard, date formatting, browser integration
```

---

## Installation & Running

### 1. Install Dependencies
Run the following command in your terminal:

```bash
pip install -r requirements.txt
```

### 2. Launch Application
Run:

```bash
python main.py
```

---

## Security Explanation

1. **How is the Master Password stored?**
   - The master password itself is **NEVER** stored.
   - When you set up your master password, Passary generates a 16-byte random salt and derives an **Authentication Hash** using PBKDF2-HMAC-SHA256 with 600,000 iterations. Only the salt and authentication hash are written to `vault.db`.

2. **How are saved passwords encrypted?**
   - When you log in, Passary derives a separate **32-byte encryption key** from your master password in RAM.
   - Credentials are encrypted before saving to disk using **Fernet** (authenticated AES encryption).
   - If someone steals your `vault.db` file, they cannot read any passwords without your Master Password.

3. **What happens during Auto-Lock or Lock Vault?**
   - The session encryption key is completely cleared from RAM memory, and the UI transitions back to the Login screen.

---

## Common Issues & Troubleshooting

- **`ModuleNotFoundError: No module named 'customtkinter'`**
  - Fix: Run `pip install customtkinter cryptography pyperclip pillow` in your Python environment.
- **Clipboard copying not working on Linux?**
  - Fix: Install `xclip` or `xsel` on your Linux system (`sudo apt install xclip`).
