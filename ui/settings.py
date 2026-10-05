import customtkinter as ctk
from tkinter import messagebox
from database.database import DatabaseManager
from security.authentication import SessionManager, verify_master_password, hash_master_password
from security.encryption import generate_salt, decrypt_password, encrypt_password, derive_key


class SettingsFrame(ctk.CTkFrame):
    """
    Settings view.
    Manages Auto-Lock timeout, UI Appearance Theme, and Master Password re-encryption.
    """

    def __init__(self, parent, db_manager: DatabaseManager, on_theme_change_callback):
        super().__init__(parent, fg_color="transparent")
        self.db_manager = db_manager
        self.on_theme_change_callback = on_theme_change_callback

        self.settings = self.db_manager.get_settings()
        self._build_ui()

    def _build_ui(self):
        # Header title
        hdr = ctk.CTkLabel(self, text="Preferences & Security Settings", font=ctk.CTkFont(size=24, weight="bold"))
        hdr.pack(anchor="w", padx=25, pady=(20, 15))

        # Main scrollable card
        card = ctk.CTkFrame(self, corner_radius=16, fg_color=("white", "#1e1e2e"))
        card.pack(fill="both", expand=True, padx=25, pady=(0, 20))

        scroll = ctk.CTkScrollableFrame(card, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=25, pady=25)

        # 1. Appearance Theme Section
        ctk.CTkLabel(scroll, text="APPEARANCE & THEME", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(0, 5))

        theme_row = ctk.CTkFrame(scroll, fg_color="transparent")
        theme_row.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(theme_row, text="Color Mode:", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")

        self.theme_dropdown = ctk.CTkOptionMenu(
            theme_row,
            values=["dark", "light", "system"],
            width=150,
            command=self._on_theme_changed
        )
        self.theme_dropdown.set(self.settings.theme)
        self.theme_dropdown.pack(side="right")

        # 2. Auto-Lock Duration Section
        ctk.CTkLabel(scroll, text="VAULT SECURITY & AUTO-LOCK", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(0, 5))

        lock_row = ctk.CTkFrame(scroll, fg_color="transparent")
        lock_row.pack(fill="x", pady=(0, 25))

        ctk.CTkLabel(lock_row, text="Auto-lock vault when idle:", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")

        self.lock_dropdown = ctk.CTkOptionMenu(
            lock_row,
            values=["1 Minute", "5 Minutes", "15 Minutes", "30 Minutes", "Never"],
            width=150,
            command=self._on_autolock_changed
        )
        # Set dropdown initial value
        val_map = {1: "1 Minute", 5: "5 Minutes", 15: "15 Minutes", 30: "30 Minutes", 0: "Never"}
        self.lock_dropdown.set(val_map.get(self.settings.auto_lock_minutes, "5 Minutes"))
        self.lock_dropdown.pack(side="right")

        # 3. Change Master Password Section
        ctk.CTkLabel(scroll, text="CHANGE MASTER PASSWORD", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(0, 10))

        pwd_card = ctk.CTkFrame(scroll, corner_radius=12, fg_color=("gray95", "#181825"))
        pwd_card.pack(fill="x", padx=15, pady=(0, 20))

        ctk.CTkLabel(pwd_card, text="Current Master Password", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(0, 2))
        self.curr_pwd_entry = ctk.CTkEntry(pwd_card, show="•", height=38, placeholder_text="Enter current master password...")
        self.curr_pwd_entry.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(pwd_card, text="New Master Password", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(0, 2))
        self.new_pwd_entry = ctk.CTkEntry(pwd_card, show="•", height=38, placeholder_text="Enter new master password...")
        self.new_pwd_entry.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(pwd_card, text="Confirm New Master Password", font=ctk.CTkFont(size=12, weight="bold"), anchor="w").pack(fill="x", pady=(0, 2))
        self.confirm_new_pwd_entry = ctk.CTkEntry(pwd_card, show="•", height=38, placeholder_text="Confirm new master password...")
        self.confirm_new_pwd_entry.pack(fill="x", pady=(0, 15))

        change_btn = ctk.CTkButton(
            pwd_card,
            text="Update Master Password",
            height=40,
            fg_color="#89b4fa",
            hover_color="#74c7ec",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            command=self._change_master_password
        )
        change_btn.pack(fill="x")

    def _on_theme_changed(self, choice: str):
        ctk.set_appearance_mode(choice)
        self.settings.theme = choice
        self.db_manager.update_settings(self.settings.auto_lock_minutes, choice, self.settings.show_password_default)
        if self.on_theme_change_callback:
            self.on_theme_change_callback(choice)

    def _on_autolock_changed(self, choice: str):
        val_map = {"1 Minute": 1, "5 Minutes": 5, "15 Minutes": 15, "30 Minutes": 30, "Never": 0}
        minutes = val_map.get(choice, 5)
        self.settings.auto_lock_minutes = minutes
        self.db_manager.update_settings(minutes, self.settings.theme, self.settings.show_password_default)

    def _change_master_password(self):
        curr_pwd = self.curr_pwd_entry.get()
        new_pwd = self.new_pwd_entry.get()
        confirm_pwd = self.confirm_new_pwd_entry.get()

        if not curr_pwd or not new_pwd:
            messagebox.showwarning("Input Error", "All password fields are required.")
            return

        if new_pwd != confirm_pwd:
            messagebox.showerror("Mismatch Error", "New master passwords do not match.")
            return

        if len(new_pwd) < 8:
            messagebox.showwarning("Weak Password", "New master password should be at least 8 characters.")
            return

        user = self.db_manager.get_user()
        if not user or not verify_master_password(curr_pwd, user.password_hash, user.salt):
            messagebox.showerror("Authentication Error", "Incorrect current master password.")
            return

        try:
            # 1. Derive old key and decrypt all credentials
            old_key = SessionManager.get_instance().get_key()
            all_creds = self.db_manager.get_all_credentials()

            decrypted_creds = []
            for c in all_creds:
                dec_pwd = decrypt_password(c.encrypted_password, old_key)
                decrypted_creds.append((c, dec_pwd))

            # 2. Derive new key and salt
            new_salt = generate_salt()
            new_hash = hash_master_password(new_pwd, new_salt)
            new_key = derive_key(new_pwd, new_salt)

            # 3. Re-encrypt all credentials with new key
            for c, dec_pwd in decrypted_creds:
                new_enc_pwd = encrypt_password(dec_pwd, new_key)
                self.db_manager.update_credential(
                    cred_id=c.id,
                    website=c.website,
                    url=c.url,
                    username=c.username,
                    encrypted_password=new_enc_pwd,
                    notes=c.notes,
                    category=c.category,
                    favorite=c.favorite
                )

            # 4. Update master password in database and update active session
            self.db_manager.update_master_password(new_hash, new_salt)
            SessionManager.get_instance().login(new_pwd, new_salt)

            messagebox.showinfo("Success", "Master password updated successfully! All vault credentials re-encrypted.")
            self.curr_pwd_entry.delete(0, "end")
            self.new_pwd_entry.delete(0, "end")
            self.confirm_new_pwd_entry.delete(0, "end")

        except Exception as e:
            messagebox.showerror("Re-encryption Failed", f"An error occurred while updating master password: {str(e)}")
