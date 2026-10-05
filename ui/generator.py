import customtkinter as ctk
from security.password_generator import generate_password, assess_password_strength
from utils.helpers import copy_to_clipboard


class PasswordGeneratorFrame(ctk.CTkFrame):
    """
    Standalone Password Generator interface.
    Allows custom length, character set configuration, real-time entropy calculation, and copy button.
    """

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        self.length = 16
        self.use_uppercase = True
        self.use_lowercase = True
        self.use_numbers = True
        self.use_symbols = True

        self._build_ui()
        self._generate_new_password()

    def _build_ui(self):
        # Header title
        hdr = ctk.CTkLabel(self, text="Password Generator", font=ctk.CTkFont(size=24, weight="bold"))
        hdr.pack(anchor="w", padx=25, pady=(20, 15))

        # Main Card Container
        card = ctk.CTkFrame(self, corner_radius=16, fg_color=("white", "#1e1e2e"))
        card.pack(fill="both", expand=True, padx=25, pady=(0, 20))

        scroll = ctk.CTkScrollableFrame(card, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=25, pady=25)

        # 1. Generated Password Display Box
        ctk.CTkLabel(scroll, text="GENERATED PASSWORD", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(0, 5))

        pwd_display_box = ctk.CTkFrame(scroll, fg_color=("gray90", "#313244"), height=54, corner_radius=10)
        pwd_display_box.pack(fill="x", pady=(0, 10))

        self.pwd_label = ctk.CTkLabel(pwd_display_box, text="", font=ctk.CTkFont(family="Consolas", size=20, weight="bold"), text_color="#89b4fa", anchor="w")
        self.pwd_label.pack(side="left", fill="x", expand=True, padx=15)

        regen_btn = ctk.CTkButton(
            pwd_display_box,
            text="Refresh",
            width=90,
            height=38,
            fg_color="gray30",
            hover_color="gray40",
            font=ctk.CTkFont(weight="bold"),
            command=self._generate_new_password
        )
        regen_btn.pack(side="right", padx=(0, 8))

        copy_btn = ctk.CTkButton(
            pwd_display_box,
            text="Copy",
            width=90,
            height=38,
            fg_color="#89b4fa",
            hover_color="#74c7ec",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            command=self._copy_password
        )
        copy_btn.pack(side="right", padx=(0, 8))

        # Strength Bar & Readout
        self.strength_bar = ctk.CTkProgressBar(scroll, height=6)
        self.strength_bar.set(0)
        self.strength_bar.pack(fill="x", pady=(0, 4))

        self.strength_lbl = ctk.CTkLabel(scroll, text="", font=ctk.CTkFont(size=12), text_color="gray60", anchor="w")
        self.strength_lbl.pack(fill="x", pady=(0, 25))

        # 2. Controls Section
        ctk.CTkLabel(scroll, text="CUSTOMIZE PARAMETERS", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(0, 10))

        # Length Slider Row
        len_row = ctk.CTkFrame(scroll, fg_color="transparent")
        len_row.pack(fill="x", pady=(0, 15))

        ctk.CTkLabel(len_row, text="Password Length:", font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        self.len_val_lbl = ctk.CTkLabel(len_row, text=str(self.length), font=ctk.CTkFont(size=15, weight="bold"), text_color="#89b4fa")
        self.len_val_lbl.pack(side="right")

        self.slider = ctk.CTkSlider(scroll, from_=6, to=64, number_of_steps=58, command=self._on_slider_change)
        self.slider.set(self.length)
        self.slider.pack(fill="x", pady=(0, 25))

        # Character Sets Checkboxes
        ctk.CTkLabel(scroll, text="CHARACTER TYPES", font=ctk.CTkFont(size=11, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(0, 10))

        self.chk_upper = ctk.CTkCheckBox(scroll, text="Uppercase Letters (A-Z)", font=ctk.CTkFont(size=13), command=self._on_options_change)
        self.chk_upper.select()
        self.chk_upper.pack(anchor="w", pady=(0, 12))

        self.chk_lower = ctk.CTkCheckBox(scroll, text="Lowercase Letters (a-z)", font=ctk.CTkFont(size=13), command=self._on_options_change)
        self.chk_lower.select()
        self.chk_lower.pack(anchor="w", pady=(0, 12))

        self.chk_numbers = ctk.CTkCheckBox(scroll, text="Numeric Digits (0-9)", font=ctk.CTkFont(size=13), command=self._on_options_change)
        self.chk_numbers.select()
        self.chk_numbers.pack(anchor="w", pady=(0, 12))

        self.chk_symbols = ctk.CTkCheckBox(scroll, text="Special Symbols (!@#$%^&*)", font=ctk.CTkFont(size=13), command=self._on_options_change)
        self.chk_symbols.select()
        self.chk_symbols.pack(anchor="w", pady=(0, 20))

    def _on_slider_change(self, val):
        self.length = int(val)
        self.len_val_lbl.configure(text=str(self.length))
        self._generate_new_password()

    def _on_options_change(self):
        self.use_uppercase = self.chk_upper.get() == 1
        self.use_lowercase = self.chk_lower.get() == 1
        self.use_numbers = self.chk_numbers.get() == 1
        self.use_symbols = self.chk_symbols.get() == 1
        self._generate_new_password()

    def _generate_new_password(self):
        pwd = generate_password(
            length=self.length,
            uppercase=self.use_uppercase,
            lowercase=self.use_lowercase,
            numbers=self.use_numbers,
            symbols=self.use_symbols
        )
        self.pwd_label.configure(text=pwd)

        res = assess_password_strength(pwd)
        self.strength_bar.set(res["score"] / 100.0)
        self.strength_bar.configure(progress_color=res["color"])
        self.strength_lbl.configure(text=f"Security Level: {res['label']} • Entropy: {res['entropy']} bits • Score: {res['score']}/100", text_color=res["color"])

    def _copy_password(self):
        pwd = self.pwd_label.cget("text")
        if copy_to_clipboard(pwd):
            pass
