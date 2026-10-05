import customtkinter as ctk
from database.database import DatabaseManager
from security.authentication import SessionManager
from security.encryption import decrypt_password
from security.password_generator import assess_password_strength
from utils.helpers import copy_to_clipboard, get_initial_badge, format_iso_date


class DashboardFrame(ctk.CTkFrame):
    """
    Main overview dashboard view.
    Displays summary statistics cards, security audit summary, and recent account items.
    """

    def __init__(self, parent, db_manager: DatabaseManager, nav_callback):
        super().__init__(parent, fg_color="transparent")
        self.db_manager = db_manager
        self.nav_callback = nav_callback

        self._build_ui()
        self.refresh_dashboard()

    def _build_ui(self):
        # Header banner
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.pack(fill="x", padx=25, pady=(20, 10))

        title_lbl = ctk.CTkLabel(header_frame, text="Vault Overview", font=ctk.CTkFont(size=24, weight="bold"))
        title_lbl.pack(side="left")

        quick_add_btn = ctk.CTkButton(
            header_frame,
            text="+ Quick Add",
            fg_color="#89b4fa",
            hover_color="#74c7ec",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            height=36,
            command=lambda: self.nav_callback("add_password")
        )
        quick_add_btn.pack(side="right")

        # Scrollable container
        self.container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=25, pady=(0, 20))

        # Stat Cards Grid (4 Cards)
        self.cards_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        self.cards_frame.pack(fill="x", pady=(0, 20))

        # Card 1: Total Accounts
        self.total_card = self._create_stat_card(self.cards_frame, "Total Accounts", "0", "#89b4fa")
        self.total_card.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Card 2: Favorites
        self.fav_card = self._create_stat_card(self.cards_frame, "Favorites", "0", "#f9e2af")
        self.fav_card.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Card 3: Weak Passwords Warning
        self.weak_card = self._create_stat_card(self.cards_frame, "Security Alert", "0 Weak", "#f38ba8")
        self.weak_card.pack(side="left", fill="both", expand=True, padx=(0, 10))

        # Card 4: Password Health Score
        self.health_card = self._create_stat_card(self.cards_frame, "Vault Health", "100%", "#a6e3a1")
        self.health_card.pack(side="left", fill="both", expand=True)

        # Recent Items Title
        recent_hdr = ctk.CTkLabel(self.container, text="Recently Added / Updated Accounts", font=ctk.CTkFont(size=16, weight="bold"))
        recent_hdr.pack(anchor="w", pady=(5, 10))

        self.recent_frame = ctk.CTkFrame(self.container, corner_radius=12, fg_color=("white", "#1e1e2e"))
        self.recent_frame.pack(fill="x", pady=(0, 20))

    def _create_stat_card(self, parent, title: str, val_text: str, accent_color: str) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, corner_radius=12, fg_color=("white", "#1e1e2e"))
        
        # Color bar indicator on top
        color_bar = ctk.CTkFrame(card, height=4, fg_color=accent_color, corner_radius=2)
        color_bar.pack(fill="x", side="top")

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=15)

        t_lbl = ctk.CTkLabel(content, text=title, font=ctk.CTkFont(size=12), text_color="gray60", anchor="w")
        t_lbl.pack(fill="x")

        v_lbl = ctk.CTkLabel(content, text=val_text, font=ctk.CTkFont(size=22, weight="bold"), anchor="w")
        v_lbl.pack(fill="x", pady=(5, 0))
        card.val_label = v_lbl

        return card

    def refresh_dashboard(self):
        """Reload statistics and recent accounts list."""
        all_creds = self.db_manager.get_all_credentials()
        total_count = len(all_creds)
        fav_count = sum(1 for c in all_creds if c.favorite)

        weak_count = 0
        total_score = 0

        session_key = None
        try:
            session_key = SessionManager.get_instance().get_key()
        except Exception:
            pass

        if session_key:
            for c in all_creds:
                try:
                    decrypted = decrypt_password(c.encrypted_password, session_key)
                    res = assess_password_strength(decrypted)
                    total_score += res["score"]
                    if res["score"] < 50:
                        weak_count += 1
                except Exception:
                    pass

        avg_health = round(total_score / total_count) if total_count > 0 else 100

        # Update Card values
        self.total_card.val_label.configure(text=str(total_count))
        self.fav_card.val_label.configure(text=str(fav_count))
        self.weak_card.val_label.configure(text=f"{weak_count} Weak")
        self.health_card.val_label.configure(text=f"{avg_health}%")

        # Clear recent frame widgets
        for widget in self.recent_frame.winfo_children():
            widget.destroy()

        if not all_creds:
            empty_lbl = ctk.CTkLabel(self.recent_frame, text="No credentials saved yet. Click 'Quick Add' to create your first item!", font=ctk.CTkFont(size=13), text_color="gray60")
            empty_lbl.pack(pady=30)
            return

        # Display up to 5 recent items
        recent_creds = sorted(all_creds, key=lambda c: c.updated_at, reverse=True)[:5]

        for cred in recent_creds:
            row = ctk.CTkFrame(self.recent_frame, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=10)

            # Badge Icon
            badge_text = get_initial_badge(cred.website)
            badge = ctk.CTkButton(
                row,
                text=badge_text,
                width=36,
                height=36,
                corner_radius=8,
                fg_color="#89b4fa",
                text_color="#11111b",
                font=ctk.CTkFont(weight="bold"),
                state="disabled"
            )
            badge.pack(side="left", padx=(0, 12))

            # Info text
            info_frame = ctk.CTkFrame(row, fg_color="transparent")
            info_frame.pack(side="left", fill="x", expand=True)

            w_lbl = ctk.CTkLabel(info_frame, text=cred.website, font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
            w_lbl.pack(fill="x")

            u_lbl = ctk.CTkLabel(info_frame, text=cred.username, font=ctk.CTkFont(size=11), text_color="gray60", anchor="w")
            u_lbl.pack(fill="x")

            # Date
            date_lbl = ctk.CTkLabel(row, text=format_iso_date(cred.updated_at), font=ctk.CTkFont(size=11), text_color="gray50")
            date_lbl.pack(side="right", padx=15)

            # Copy Username & Copy Password Buttons
            copy_user_btn = ctk.CTkButton(
                row,
                text="Copy User",
                width=90,
                height=30,
                fg_color="gray30",
                hover_color="gray40",
                font=ctk.CTkFont(size=11),
                command=lambda u=cred.username: copy_to_clipboard(u)
            )
            copy_user_btn.pack(side="right", padx=(0, 8))
