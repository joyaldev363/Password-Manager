import sys
import time
import customtkinter as ctk
from database.database import DatabaseManager
from security.authentication import SessionManager
from ui.login import LoginFrame
from ui.dashboard import DashboardFrame
from ui.vault import VaultFrame
from ui.generator import PasswordGeneratorFrame
from ui.security_center import SecurityCenterFrame
from ui.settings import SettingsFrame
from ui.add_password import AddEditPasswordModal


class AppWindow(ctk.CTk):
    """
    Main Desktop Window Container for Passary Password Manager.
    Manages navigation switching, idle timer auto-lock, and theme styling.
    """

    def __init__(self):
        super().__init__()

        self.title("Passary — Secure Password Manager")
        self.geometry("1150x740")
        self.minsize(980, 640)
        # Launch maximized in full desktop size
        try:
            self.after(10, lambda: self.state("zoomed"))
        except Exception:
            pass

        # Database Instance
        self.db_manager = DatabaseManager()

        # Load saved settings theme
        settings = self.db_manager.get_settings()
        ctk.set_appearance_mode(settings.theme)
        ctk.set_default_color_theme("blue")

        # Auto lock state tracking
        self.last_activity_time = time.time()
        self.auto_lock_timer_job = None

        # Bind window close event and activity timers
        self.protocol("WM_DELETE_WINDOW", self._on_closing)
        self.bind_all("<Any-KeyPress>", self._reset_activity_timer)
        self.bind_all("<Any-ButtonPress>", self._reset_activity_timer)

        self.current_frame = None
        self.nav_buttons = {}

        self._show_login_screen()
        self._start_autolock_checker()

    def _on_closing(self):
        try:
            if self.auto_lock_timer_job:
                self.after_cancel(self.auto_lock_timer_job)
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass
        sys.exit(0)

    def _reset_activity_timer(self, event=None):
        self.last_activity_time = time.time()

    def _start_autolock_checker(self):
        self._check_autolock()

    def _check_autolock(self):
        if SessionManager.get_instance().is_unlocked():
            settings = self.db_manager.get_settings()
            if settings.auto_lock_minutes > 0:
                idle_seconds = time.time() - self.last_activity_time
                if idle_seconds >= (settings.auto_lock_minutes * 60):
                    self.lock_vault()

        # Check every 5 seconds
        self.auto_lock_timer_job = self.after(5000, self._check_autolock)

    def _show_login_screen(self):
        SessionManager.get_instance().lock()

        # Clear existing window frames
        for child in self.winfo_children():
            child.destroy()

        self.login_frame = LoginFrame(self, self.db_manager, on_login_success=self._on_login_success)
        self.login_frame.pack(fill="both", expand=True)

    def _on_login_success(self):
        self.login_frame.destroy()
        self._build_main_app_layout()
        self.navigate_to("dashboard")

    def _build_main_app_layout(self):
        self.sidebar_expanded = True

        # 1. Left Navigation Sidebar
        self.sidebar = ctk.CTkFrame(self, width=230, corner_radius=0, fg_color=("gray95", "#11111b"), border_width=1, border_color=("gray85", "#1e1e2e"))
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # Brand Header Frame (Title + Toggle Button)
        self.brand_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.brand_frame.pack(fill="x", padx=10, pady=(15, 15))

        self.toggle_btn = ctk.CTkButton(
            self.brand_frame,
            text="≡",
            width=36,
            height=36,
            corner_radius=8,
            fg_color="transparent",
            hover_color=("gray85", "#313244"),
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#89b4fa",
            command=self._toggle_sidebar
        )
        self.toggle_btn.pack(side="left")

        self.brand_lbl = ctk.CTkLabel(
            self.brand_frame,
            text="Passary",
            font=ctk.CTkFont(family="Helvetica", size=20, weight="bold"),
            text_color="#89b4fa"
        )
        self.brand_lbl.pack(side="left", padx=(10, 0))

        # Nav Buttons Container
        self.nav_container = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.nav_container.pack(fill="x", padx=10)

        # Nav Items Mapping: (route, full_label, short_label)
        self.nav_items = [
            ("dashboard", "Dashboard", "D"),
            ("vault", "Vault Entries", "V"),
            ("favorites", "Favorites", "F"),
            ("generator", "Password Generator", "G"),
            ("security_center", "Security Center", "S"),
            ("settings", "Settings", "Set")
        ]

        for route, full_label, short_label in self.nav_items:
            btn = ctk.CTkButton(
                self.nav_container,
                text=full_label,
                anchor="w",
                height=40,
                corner_radius=8,
                fg_color="transparent",
                text_color=("gray20", "gray80"),
                hover_color=("gray85", "#313244"),
                font=ctk.CTkFont(size=13, weight="bold"),
                command=lambda r=route: self.navigate_to(r)
            )
            btn.pack(fill="x", pady=2)
            self.nav_buttons[route] = btn

        # Bottom Lock Button
        self.lock_btn = ctk.CTkButton(
            self.sidebar,
            text="Lock Vault",
            anchor="w",
            height=40,
            corner_radius=8,
            fg_color="#f38ba8",
            hover_color="#e64553",
            text_color="#11111b",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=self.lock_vault
        )
        self.lock_btn.pack(side="bottom", fill="x", padx=15, pady=20)

        # 2. Main Content View Container
        self.content_area = ctk.CTkFrame(self, fg_color=("gray98", "#1e1e2e"), corner_radius=0)
        self.content_area.pack(side="right", fill="both", expand=True)

    def _toggle_sidebar(self):
        """Toggle sidebar between expanded (230px) and collapsed (70px) states smoothly."""
        self.sidebar_expanded = not self.sidebar_expanded

        if self.sidebar_expanded:
            self.sidebar.configure(width=230)
            self.brand_lbl.configure(text="Passary")
            for route, full_label, short_label in self.nav_items:
                if route in self.nav_buttons:
                    self.nav_buttons[route].configure(text=full_label, anchor="w")
            self.lock_btn.configure(text="Lock Vault", anchor="w")
        else:
            self.sidebar.configure(width=70)
            self.brand_lbl.configure(text="")
            for route, full_label, short_label in self.nav_items:
                if route in self.nav_buttons:
                    self.nav_buttons[route].configure(text=short_label, anchor="center")
            self.lock_btn.configure(text="L", anchor="center")

        self.update_idletasks()

    def navigate_to(self, route: str):
        """Switch active view frame and highlight active navigation tab."""
        if not SessionManager.get_instance().is_unlocked():
            self._show_login_screen()
            return

        # Update button highlights
        for key, btn in self.nav_buttons.items():
            if key == route or (key == "vault" and route == "add_password"):
                btn.configure(fg_color=("#89b4fa", "#313244"), text_color=("#11111b", "#89b4fa"))
            else:
                btn.configure(fg_color="transparent", text_color=("gray20", "gray80"))

        # Clear current content view
        if self.current_frame:
            self.current_frame.destroy()

        if route == "dashboard":
            self.current_frame = DashboardFrame(self.content_area, self.db_manager, nav_callback=self.navigate_to)
        elif route == "vault":
            self.current_frame = VaultFrame(self.content_area, self.db_manager, favorite_only_mode=False)
        elif route == "favorites":
            self.current_frame = VaultFrame(self.content_area, self.db_manager, favorite_only_mode=True)
        elif route == "generator":
            self.current_frame = PasswordGeneratorFrame(self.content_area)
        elif route == "security_center":
            self.current_frame = SecurityCenterFrame(self.content_area, self.db_manager)
        elif route == "settings":
            self.current_frame = SettingsFrame(self.content_area, self.db_manager, on_theme_change_callback=None)
        elif route == "add_password":
            self.current_frame = VaultFrame(self.content_area, self.db_manager, favorite_only_mode=False)
            AddEditPasswordModal(self, self.db_manager, credential=None, on_save_callback=self.current_frame.refresh_vault)

        if self.current_frame:
            self.current_frame.pack(fill="both", expand=True)

    def lock_vault(self):
        """Wipe session key and show login screen."""
        self._show_login_screen()
