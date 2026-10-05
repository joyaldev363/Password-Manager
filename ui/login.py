import time
import customtkinter as ctk
from tkinter import messagebox
from database.database import DatabaseManager
from security.authentication import SessionManager, hash_master_password, verify_master_password
from security.encryption import generate_salt
from security.password_generator import assess_password_strength
from utils.helpers import generate_shield_icon


class LoginFrame(ctk.CTkFrame):
    """
    Login and Master Password Setup screen matching exact Passary reference design.
    """

    def __init__(self, parent, db_manager: DatabaseManager, on_login_success):
        super().__init__(parent, fg_color="transparent")
        self.parent = parent
        self.db_manager = db_manager
        self.on_login_success = on_login_success

        self.failed_attempts = 0
        self.lockout_time = 0
        self.show_password = False

        self.is_first_launch = not self.db_manager.has_user()

        self._build_ui()

    def _build_ui(self):
        # Center container card with deep navy background matching reference screenshot
        self.card = ctk.CTkFrame(
            self,
            corner_radius=22,
            fg_color=("white", "#101426"),
            border_width=1,
            border_color=("gray85", "#1e2642"),
            width=460,
            height=580
        )
        self.card.place(relx=0.5, rely=0.5, anchor="center")
        self.card.grid_propagate(False)

        # 1. Gradient Shield Lock Icon (Programmatically drawn matching reference)
        try:
            pil_shield = generate_shield_icon(target_size=88)
            self.shield_ctk_image = ctk.CTkImage(light_image=pil_shield, dark_image=pil_shield, size=(88, 88))
            self.shield_label = ctk.CTkLabel(self.card, image=self.shield_ctk_image, text="")
            self.shield_label.pack(pady=(35, 12))
        except Exception:
            pass

        # 2. Dual-Color Brand Title Header ("Pass" in White, "ary" in Blue)
        brand_frame = ctk.CTkFrame(self.card, fg_color="transparent")
        brand_frame.pack(pady=(0, 2))

        pass_lbl = ctk.CTkLabel(
            brand_frame,
            text="Pass",
            font=ctk.CTkFont(family="Helvetica", size=36, weight="bold"),
            text_color=("gray10", "#FFFFFF")
        )
        pass_lbl.pack(side="left")

        ary_lbl = ctk.CTkLabel(
            brand_frame,
            text="ary",
            font=ctk.CTkFont(family="Helvetica", size=36, weight="bold"),
            text_color="#5B7FFF"
        )
        ary_lbl.pack(side="left")

        # Subtitle Text
        subtitle_text = "Set up your Vault Master Password" if self.is_first_launch else "Unlock your Secure Password Vault"
        sub_label = ctk.CTkLabel(
            self.card,
            text=subtitle_text,
            font=ctk.CTkFont(family="Helvetica", size=13),
            text_color=("gray50", "#94A3B8")
        )
        sub_label.pack(pady=(0, 25))

        # 3. Input fields container
        self.form_frame = ctk.CTkFrame(self.card, fg_color="transparent")
        self.form_frame.pack(fill="x", padx=40)

        # Master Password Label
        pwd_lbl = ctk.CTkLabel(
            self.form_frame,
            text="Master Password",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("gray20", "#E2E8F0"),
            anchor="w"
        )
        pwd_lbl.pack(fill="x", pady=(0, 6))

        # Master Password Input Box
        self.pwd_entry = ctk.CTkEntry(
            self.form_frame,
            show="•",
            height=48,
            placeholder_text="Enter your master password...",
            font=ctk.CTkFont(size=13),
            border_width=1,
            border_color=("gray75", "#1E293B"),
            fg_color=("gray98", "#0F172A")
        )
        self.pwd_entry.pack(fill="x", pady=(0, 10))
        self.pwd_entry.bind("<Return>", lambda event: self._on_submit())

        # Strength Bar (only on setup)
        if self.is_first_launch:
            self.pwd_entry.bind("<KeyRelease>", self._on_pwd_key_release)

            self.confirm_lbl = ctk.CTkLabel(self.form_frame, text="Confirm Master Password", font=ctk.CTkFont(size=12, weight="bold"), text_color=("gray20", "#E2E8F0"), anchor="w")
            self.confirm_lbl.pack(fill="x", pady=(10, 4))

            self.confirm_entry = ctk.CTkEntry(
                self.form_frame,
                show="•",
                height=48,
                placeholder_text="Re-enter master password...",
                font=ctk.CTkFont(size=13),
                border_width=1,
                border_color=("gray75", "#1E293B"),
                fg_color=("gray98", "#0F172A")
            )
            self.confirm_entry.pack(fill="x", pady=(0, 10))
            self.confirm_entry.bind("<Return>", lambda event: self._on_submit())

            self.strength_bar = ctk.CTkProgressBar(self.form_frame, height=6)
            self.strength_bar.set(0)
            self.strength_bar.pack(fill="x", pady=(5, 2))

            self.strength_lbl = ctk.CTkLabel(self.form_frame, text="Password Strength: None", font=ctk.CTkFont(size=11), text_color="gray60", anchor="w")
            self.strength_lbl.pack(fill="x", pady=(0, 12))

        # Show/Hide Password Checkbox
        self.show_pwd_chk = ctk.CTkCheckBox(
            self.form_frame,
            text="Show Password",
            command=self._toggle_password_visibility,
            font=ctk.CTkFont(size=12),
            text_color=("gray30", "#CBD5E1")
        )
        self.show_pwd_chk.pack(anchor="w", pady=(5, 20))

        # 4. Action Pill Button (Vibrant Electric Blue)
        btn_text = "Create Vault" if self.is_first_launch else "Unlock Vault"
        self.action_btn = ctk.CTkButton(
            self.card,
            text=btn_text,
            height=48,
            corner_radius=12,
            font=ctk.CTkFont(family="Helvetica", size=15, weight="bold"),
            fg_color="#5B7FFF",
            hover_color="#4F46E5",
            text_color="#FFFFFF",
            command=self._on_submit
        )
        self.action_btn.pack(fill="x", padx=40, pady=(0, 20))

        # 5. Footer Line ("── End-to-end encrypted locally ──")
        footer_frame = ctk.CTkFrame(self.card, fg_color="transparent")
        footer_frame.pack(side="bottom", fill="x", padx=40, pady=25)

        line_left = ctk.CTkFrame(footer_frame, height=1, fg_color=("gray80", "#26334d"))
        line_left.pack(side="left", fill="x", expand=True)

        footer_msg = "End-to-end encrypted locally"
        footer_lbl = ctk.CTkLabel(
            footer_frame,
            text=f"  {footer_msg}  ",
            font=ctk.CTkFont(size=10),
            text_color=("gray50", "#64748B")
        )
        footer_lbl.pack(side="left")

        line_right = ctk.CTkFrame(footer_frame, height=1, fg_color=("gray80", "#26334d"))
        line_right.pack(side="right", fill="x", expand=True)

    def _toggle_password_visibility(self):
        self.show_password = self.show_pwd_chk.get() == 1
        show_char = "" if self.show_password else "•"
        self.pwd_entry.configure(show=show_char)
        if self.is_first_launch:
            self.confirm_entry.configure(show=show_char)

    def _on_pwd_key_release(self, event):
        if not self.is_first_launch:
            return
        pwd = self.pwd_entry.get()
        if not pwd:
            self.strength_bar.set(0)
            self.strength_lbl.configure(text="Password Strength: None", text_color="gray60")
            return

        res = assess_password_strength(pwd)
        self.strength_bar.set(res["score"] / 100.0)
        self.strength_bar.configure(progress_color=res["color"])
        self.strength_lbl.configure(text=f"Password Strength: {res['label']} ({res['entropy']} bits)", text_color=res["color"])

    def _on_submit(self):
        # Check lockout
        if self.lockout_time > time.time():
            remaining = int(self.lockout_time - time.time())
            messagebox.showerror("Vault Locked", f"Too many failed attempts. Try again in {remaining} seconds.")
            return

        pwd = self.pwd_entry.get()

        if self.is_first_launch:
            confirm = self.confirm_entry.get()
            if not pwd:
                messagebox.showwarning("Input Error", "Master password cannot be empty.")
                return
            if len(pwd) < 8:
                messagebox.showwarning("Weak Password", "Master password should be at least 8 characters long.")
                return
            if pwd != confirm:
                messagebox.showerror("Mismatch Error", "Master passwords do not match.")
                return

            # Generate salt and create user
            salt = generate_salt()
            pwd_hash = hash_master_password(pwd, salt)
            self.db_manager.create_user(pwd_hash, salt)

            # Log into session
            SessionManager.get_instance().login(pwd, salt)
            self.on_login_success()

        else:
            if not pwd:
                messagebox.showwarning("Input Error", "Please enter your master password.")
                return

            user = self.db_manager.get_user()
            if not user:
                messagebox.showerror("Error", "No user found in database.")
                return

            if verify_master_password(pwd, user.password_hash, user.salt):
                self.failed_attempts = 0
                SessionManager.get_instance().login(pwd, user.salt)
                self.on_login_success()
            else:
                self.failed_attempts += 1
                if self.failed_attempts >= 5:
                    self.lockout_time = time.time() + 30
                    messagebox.showerror("Account Locked", "5 failed attempts! Application locked for 30 seconds.")
                else:
                    attempts_left = 5 - self.failed_attempts
                    messagebox.showerror("Authentication Failed", f"Invalid Master Password. {attempts_left} attempts remaining.")
                self.pwd_entry.delete(0, "end")
