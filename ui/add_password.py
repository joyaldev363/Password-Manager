import customtkinter as ctk
from tkinter import messagebox
from typing import Optional, Callable
from database.database import DatabaseManager
from database.models import Credential
from security.authentication import SessionManager
from security.encryption import encrypt_password, decrypt_password
from security.password_generator import generate_password, assess_password_strength


class AddEditPasswordModal(ctk.CTkToplevel):
    """
    Modal dialog to Add or Edit a credential in the vault.
    """

    def __init__(self, parent, db_manager: DatabaseManager, credential: Optional[Credential] = None, on_save_callback: Optional[Callable] = None):
        super().__init__(parent)
        self.db_manager = db_manager
        self.credential = credential
        self.on_save_callback = on_save_callback

        self.title("Edit Credential" if credential else "Add New Credential")
        self.geometry("520x680")
        self.resizable(False, False)

        # Make modal window stay on top and capture grab
        self.transient(parent)
        self.grab_set()

        self.show_password = False
        self._build_ui()
        self._populate_fields()

    def _build_ui(self):
        # Header title
        header_text = "Edit Account Credential" if self.credential else "Add New Credential"
        header_lbl = ctk.CTkLabel(self, text=header_text, font=ctk.CTkFont(size=20, weight="bold"))
        header_lbl.pack(pady=(20, 15))

        # Main Scrollable Frame
        self.scroll_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_frame.pack(fill="both", expand=True, padx=25, pady=(0, 10))

        # 1. Website / App Name
        ctk.CTkLabel(self.scroll_frame, text="Website or App Name *", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(5, 2))
        self.website_entry = ctk.CTkEntry(self.scroll_frame, placeholder_text="e.g. GitHub, Netflix, Google...", height=38)
        self.website_entry.pack(fill="x", pady=(0, 10))

        # 2. Website URL
        ctk.CTkLabel(self.scroll_frame, text="Website URL", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(5, 2))
        self.url_entry = ctk.CTkEntry(self.scroll_frame, placeholder_text="e.g. https://github.com", height=38)
        self.url_entry.pack(fill="x", pady=(0, 10))

        # 3. Username / Email
        ctk.CTkLabel(self.scroll_frame, text="Username or Email *", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(5, 2))
        self.username_entry = ctk.CTkEntry(self.scroll_frame, placeholder_text="e.g. user@example.com", height=38)
        self.username_entry.pack(fill="x", pady=(0, 10))

        # 4. Password & Actions
        ctk.CTkLabel(self.scroll_frame, text="Password *", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(5, 2))

        pwd_row = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
        pwd_row.pack(fill="x", pady=(0, 5))

        self.password_entry = ctk.CTkEntry(pwd_row, show="•", placeholder_text="Enter or generate password...", height=38)
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.password_entry.bind("<KeyRelease>", self._on_password_change)

        gen_btn = ctk.CTkButton(
            pwd_row,
            text="Generate",
            width=100,
            height=38,
            fg_color="#89b4fa",
            hover_color="#74c7ec",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            command=self._generate_password
        )
        gen_btn.pack(side="right")

        # Password Strength Bar
        self.strength_bar = ctk.CTkProgressBar(self.scroll_frame, height=5)
        self.strength_bar.set(0)
        self.strength_bar.pack(fill="x", pady=(5, 2))

        self.strength_lbl = ctk.CTkLabel(self.scroll_frame, text="Strength: None", font=ctk.CTkFont(size=11), text_color="gray60", anchor="w")
        self.strength_lbl.pack(fill="x", pady=(0, 5))

        # Show password checkbox
        self.show_pwd_chk = ctk.CTkCheckBox(self.scroll_frame, text="Show Password", command=self._toggle_show_password, font=ctk.CTkFont(size=12))
        self.show_pwd_chk.pack(anchor="w", pady=(0, 12))

        # 5. Category Dropdown
        ctk.CTkLabel(self.scroll_frame, text="Category", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(5, 2))
        categories = self.db_manager.get_categories()
        self.category_dropdown = ctk.CTkOptionMenu(self.scroll_frame, values=categories, height=38)
        self.category_dropdown.pack(fill="x", pady=(0, 12))

        # 6. Favorite Checkbox
        self.favorite_chk = ctk.CTkCheckBox(self.scroll_frame, text="Mark as Favorite", font=ctk.CTkFont(size=12))
        self.favorite_chk.pack(anchor="w", pady=(0, 12))

        # 7. Notes
        ctk.CTkLabel(self.scroll_frame, text="Notes (Optional)", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(5, 2))
        self.notes_entry = ctk.CTkTextbox(self.scroll_frame, height=75)
        self.notes_entry.pack(fill="x", pady=(0, 15))

        # Action Buttons
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=25, pady=15, side="bottom")

        cancel_btn = ctk.CTkButton(btn_frame, text="Cancel", fg_color="gray40", hover_color="gray50", width=120, height=40, command=self.destroy)
        cancel_btn.pack(side="left")

        save_btn = ctk.CTkButton(
            btn_frame,
            text="Save Credential",
            width=160,
            height=40,
            fg_color="#a6e3a1",
            hover_color="#94e2d5",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            command=self._save_credential
        )
        save_btn.pack(side="right")

    def _populate_fields(self):
        if not self.credential:
            return

        self.website_entry.insert(0, self.credential.website)
        self.url_entry.insert(0, self.credential.url)
        self.username_entry.insert(0, self.credential.username)
        self.category_dropdown.set(self.credential.category)

        if self.credential.favorite:
            self.favorite_chk.select()

        if self.credential.notes:
            self.notes_entry.insert("1.0", self.credential.notes)

        # Decrypt password
        try:
            session_key = SessionManager.get_instance().get_key()
            decrypted = decrypt_password(self.credential.encrypted_password, session_key)
            self.password_entry.insert(0, decrypted)
            self._on_password_change(None)
        except Exception:
            messagebox.showerror("Decryption Error", "Failed to decrypt saved password.")

    def _toggle_show_password(self):
        self.show_password = self.show_pwd_chk.get() == 1
        self.password_entry.configure(show="" if self.show_password else "•")

    def _generate_password(self):
        pwd = generate_password(length=18, uppercase=True, lowercase=True, numbers=True, symbols=True)
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, pwd)
        self._on_password_change(None)

    def _on_password_change(self, event):
        pwd = self.password_entry.get()
        if not pwd:
            self.strength_bar.set(0)
            self.strength_lbl.configure(text="Strength: None", text_color="gray60")
            return

        res = assess_password_strength(pwd)
        self.strength_bar.set(res["score"] / 100.0)
        self.strength_bar.configure(progress_color=res["color"])
        self.strength_lbl.configure(text=f"Strength: {res['label']} ({res['entropy']} bits entropy)", text_color=res["color"])

    def _save_credential(self):
        website = self.website_entry.get().strip()
        url = self.url_entry.get().strip()
        username = self.username_entry.get().strip()
        pwd = self.password_entry.get()
        category = self.category_dropdown.get()
        favorite = self.favorite_chk.get() == 1
        notes = self.notes_entry.get("1.0", "end-1c").strip()

        if not website:
            messagebox.showwarning("Validation Error", "Website or App Name is required.")
            return
        if not username:
            messagebox.showwarning("Validation Error", "Username or Email is required.")
            return
        if not pwd:
            messagebox.showwarning("Validation Error", "Password cannot be empty.")
            return

        try:
            session_key = SessionManager.get_instance().get_key()
            encrypted_pwd = encrypt_password(pwd, session_key)

            if self.credential:
                # Update existing
                self.db_manager.update_credential(
                    cred_id=self.credential.id,
                    website=website,
                    url=url,
                    username=username,
                    encrypted_password=encrypted_pwd,
                    notes=notes,
                    category=category,
                    favorite=favorite
                )
            else:
                # Add new
                self.db_manager.add_credential(
                    website=website,
                    url=url,
                    username=username,
                    encrypted_password=encrypted_pwd,
                    notes=notes,
                    category=category,
                    favorite=favorite
                )

            if self.on_save_callback:
                self.on_save_callback()

            self.destroy()

        except Exception as e:
            messagebox.showerror("Storage Error", f"Failed to encrypt and store credential: {str(e)}")
