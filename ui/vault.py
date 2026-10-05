import customtkinter as ctk
from tkinter import messagebox
from typing import Optional, List
from database.database import DatabaseManager
from database.models import Credential
from security.authentication import SessionManager
from security.encryption import decrypt_password
from security.password_generator import assess_password_strength
from ui.add_password import AddEditPasswordModal
from utils.helpers import copy_to_clipboard, open_url_in_browser, format_iso_date, get_initial_badge, mask_password


class VaultFrame(ctk.CTkFrame):
    """
    Main Password Vault view.
    Features real-time search, category filters, credential list, and interactive detail inspector pane.
    """

    def __init__(self, parent, db_manager: DatabaseManager, favorite_only_mode: bool = False):
        super().__init__(parent, fg_color="transparent")
        self.db_manager = db_manager
        self.favorite_only_mode = favorite_only_mode
        self.selected_credential: Optional[Credential] = None

        self.show_detail_password = False

        self._build_ui()
        self.refresh_vault()

    def _build_ui(self):
        # 1. Top Bar Navigation & Search Controls
        top_bar = ctk.CTkFrame(self, fg_color="transparent")
        top_bar.pack(fill="x", padx=20, pady=(15, 10))

        # Title
        title_text = "Favorite Accounts" if self.favorite_only_mode else "Password Vault"
        title_lbl = ctk.CTkLabel(top_bar, text=title_text, font=ctk.CTkFont(size=22, weight="bold"))
        title_lbl.pack(side="left", padx=(0, 15))

        # Add Entry Button
        add_btn = ctk.CTkButton(
            top_bar,
            text="+ New Entry",
            fg_color="#89b4fa",
            hover_color="#74c7ec",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            height=36,
            command=self._open_add_modal
        )
        add_btn.pack(side="left", padx=(0, 15))

        # Search Entry Box
        self.search_entry = ctk.CTkEntry(
            top_bar,
            placeholder_text="Search accounts, websites, tags, or usernames...",
            width=280,
            height=36
        )
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 15))
        self.search_entry.bind("<KeyRelease>", lambda e: self.refresh_vault())

        # Category Dropdown Filter
        categories = ["All"] + self.db_manager.get_categories()
        self.category_dropdown = ctk.CTkOptionMenu(
            top_bar,
            values=categories,
            width=130,
            height=36,
            command=lambda v: self.refresh_vault()
        )
        self.category_dropdown.pack(side="right")

        # 2. Split Main View (Left Credentials List + Right Detail Inspector)
        self.main_split = ctk.CTkFrame(self, fg_color="transparent")
        self.main_split.pack(fill="both", expand=True, padx=20, pady=(0, 15))

        # Left List Container
        self.left_pane = ctk.CTkScrollableFrame(self.main_split, fg_color="transparent")
        self.left_pane.pack(side="left", fill="both", expand=True)

        # Right Detail Pane (Initially hidden)
        self.right_pane = ctk.CTkFrame(self.main_split, width=360, corner_radius=12, fg_color=("white", "#1e1e2e"))
        self.right_pane.pack_propagate(False)

    def _close_detail_pane(self):
        self.selected_credential = None
        self.right_pane.pack_forget()
        self.refresh_vault()

    def refresh_vault(self):
        """Re-query database and rebuild credential item rows."""
        query = self.search_entry.get()
        category = self.category_dropdown.get()

        credentials = self.db_manager.search_credentials(
            query=query,
            category=category,
            favorite_only=self.favorite_only_mode
        )

        for widget in self.left_pane.winfo_children():
            widget.destroy()

        if not credentials:
            no_data = ctk.CTkLabel(
                self.left_pane,
                text="No credentials matching your criteria.",
                font=ctk.CTkFont(size=14),
                text_color="gray50"
            )
            no_data.pack(pady=50)
            self.right_pane.pack_forget()
            return

        for cred in credentials:
            row_card = self._create_credential_row(cred)
            row_card.pack(fill="x", pady=4)

        # Re-select active credential if still present
        if self.selected_credential:
            matching = [c for c in credentials if c.id == self.selected_credential.id]
            if matching:
                self.selected_credential = matching[0]
                self.right_pane.pack(side="right", fill="both", expand=False, padx=(15, 0))
                self._build_detail_pane(matching[0])
            else:
                self.selected_credential = None
                self.right_pane.pack_forget()
        else:
            self.right_pane.pack_forget()

    def _create_credential_row(self, cred: Credential) -> ctk.CTkFrame:
        is_selected = self.selected_credential and self.selected_credential.id == cred.id
        bg_color = ("#e6e9ef", "#313244") if is_selected else ("white", "#181825")

        card = ctk.CTkFrame(self.left_pane, corner_radius=10, fg_color=bg_color, cursor="hand2")

        # Click event to select row
        card.bind("<Button-1>", lambda e, c=cred: self._select_credential(c))

        # Badge Icon
        badge = ctk.CTkButton(
            card,
            text=get_initial_badge(cred.website),
            width=40,
            height=40,
            corner_radius=8,
            fg_color="#89b4fa",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold", size=14),
            command=lambda c=cred: self._select_credential(c)
        )
        badge.pack(side="left", padx=(12, 10), pady=10)

        # Website & Username Text
        info = ctk.CTkFrame(card, fg_color="transparent")
        info.pack(side="left", fill="x", expand=True, padx=(0, 10))
        info.bind("<Button-1>", lambda e, c=cred: self._select_credential(c))

        name_lbl = ctk.CTkLabel(info, text=cred.website, font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
        name_lbl.pack(fill="x")
        name_lbl.bind("<Button-1>", lambda e, c=cred: self._select_credential(c))

        user_lbl = ctk.CTkLabel(info, text=cred.username, font=ctk.CTkFont(size=11), text_color="gray60", anchor="w")
        user_lbl.pack(fill="x")
        user_lbl.bind("<Button-1>", lambda e, c=cred: self._select_credential(c))

        # Category Tag Badge Color Map
        cat_colors = {
            "Personal": (("#dbeafe", "#1e3a8a"), ("#1e293b", "#93c5fd")),
            "Work": (("#f3e8ff", "#581c87"), ("#2e1065", "#d8b4fe")),
            "Finance": (("#dcfce7", "#14532d"), ("#052e16", "#86efac")),
            "Social": (("#fef9c3", "#713f12"), ("#422006", "#fde047")),
            "SSH": (("#fee2e2", "#7f1d1d"), ("#450a0a", "#fca5a5"))
        }
        bg_c, text_c = cat_colors.get(cred.category, (("gray85", "gray20"), ("gray25", "gray80")))

        cat_badge = ctk.CTkLabel(
            card,
            text=f" {cred.category} ",
            font=ctk.CTkFont(size=10, weight="bold"),
            fg_color=bg_c,
            text_color=text_c,
            corner_radius=6
        )
        cat_badge.pack(side="left", padx=(0, 15))

        # Star Favorite Toggle Button
        star_icon = "Fav" if cred.favorite else "☆"
        star_btn = ctk.CTkButton(
            card,
            text=star_icon,
            width=32,
            height=32,
            fg_color="transparent",
            hover_color=("gray80", "gray30"),
            font=ctk.CTkFont(size=16),
            command=lambda c=cred: self._toggle_favorite(c)
        )
        star_btn.pack(side="right", padx=(0, 8))

        # Quick Copy Username Button
        copy_u_btn = ctk.CTkButton(
            card,
            text="Copy User",
            width=65,
            height=30,
            fg_color="gray30",
            hover_color="gray40",
            font=ctk.CTkFont(size=11),
            command=lambda u=cred.username: copy_to_clipboard(u)
        )
        copy_u_btn.pack(side="right", padx=(0, 5))

        # Quick Copy Password Button
        copy_p_btn = ctk.CTkButton(
            card,
            text="Copy Pass",
            width=65,
            height=30,
            fg_color="#89b4fa",
            hover_color="#74c7ec",
            text_color="#11111b",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=lambda c=cred: self._copy_credential_password(c)
        )
        copy_p_btn.pack(side="right", padx=(0, 5))

        return card

    def _select_credential(self, cred: Credential):
        self.selected_credential = cred
        self.show_detail_password = False
        self.right_pane.pack(side="right", fill="both", expand=False, padx=(15, 0))
        self._build_detail_pane(cred)
        self.refresh_vault()

    def _build_detail_pane(self, cred: Credential):
        for widget in self.right_pane.winfo_children():
            widget.destroy()

        container = ctk.CTkFrame(self.right_pane, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=15, pady=15)

        # Header Badge & Name + Close 'X' Button
        hdr = ctk.CTkFrame(container, fg_color="transparent")
        hdr.pack(fill="x", pady=(0, 15))

        close_btn = ctk.CTkButton(
            hdr,
            text="✕",
            width=28,
            height=28,
            corner_radius=6,
            fg_color="transparent",
            hover_color=("gray85", "#313244"),
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self._close_detail_pane
        )
        close_btn.pack(side="right")

        badge = ctk.CTkButton(
            hdr,
            text=get_initial_badge(cred.website),
            width=50,
            height=50,
            corner_radius=12,
            fg_color="#89b4fa",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold", size=18),
            state="disabled"
        )
        badge.pack(side="left", padx=(0, 12))

        title_box = ctk.CTkFrame(hdr, fg_color="transparent")
        title_box.pack(side="left", fill="x", expand=True)

        w_title = ctk.CTkLabel(title_box, text=cred.website, font=ctk.CTkFont(size=16, weight="bold"), anchor="w")
        w_title.pack(fill="x")

        cat_lbl = ctk.CTkLabel(title_box, text=cred.category, font=ctk.CTkFont(size=12), text_color="gray60", anchor="w")
        cat_lbl.pack(fill="x")

        # Action bar (Edit & Delete)
        act_box = ctk.CTkFrame(container, fg_color="transparent")
        act_box.pack(fill="x", pady=(0, 15))

        edit_btn = ctk.CTkButton(
            act_box,
            text="Edit",
            width=100,
            height=32,
            fg_color="#89b4fa",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            command=lambda: self._open_edit_modal(cred)
        )
        edit_btn.pack(side="left", padx=(0, 8))

        del_btn = ctk.CTkButton(
            act_box,
            text="Delete",
            width=100,
            height=32,
            fg_color="#f38ba8",
            hover_color="#e64553",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            command=lambda: self._delete_credential(cred)
        )
        del_btn.pack(side="left")

        # 1. Username
        ctk.CTkLabel(container, text="USERNAME / EMAIL", font=ctk.CTkFont(size=10, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(10, 2))
        u_box = ctk.CTkFrame(container, fg_color=("gray90", "#313244"), corner_radius=8)
        u_box.pack(fill="x", pady=(0, 12))

        u_val = ctk.CTkLabel(u_box, text=cred.username, font=ctk.CTkFont(size=13), anchor="w")
        u_val.pack(side="left", fill="x", expand=True, padx=10, pady=8)

        u_copy = ctk.CTkButton(
            u_box,
            text="Copy",
            width=50,
            height=26,
            fg_color="gray30",
            hover_color="gray40",
            font=ctk.CTkFont(size=10),
            command=lambda: copy_to_clipboard(cred.username)
        )
        u_copy.pack(side="right", padx=6)

        # 2. Password Section
        ctk.CTkLabel(container, text="PASSWORD", font=ctk.CTkFont(size=10, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(5, 2))
        p_box = ctk.CTkFrame(container, fg_color=("gray90", "#313244"), corner_radius=8)
        p_box.pack(fill="x", pady=(0, 5))

        # Decrypt password for detail view
        decrypted_pwd = ""
        try:
            session_key = SessionManager.get_instance().get_key()
            decrypted_pwd = decrypt_password(cred.encrypted_password, session_key)
        except Exception:
            decrypted_pwd = "[Decryption Error]"

        pwd_display_text = decrypted_pwd if self.show_detail_password else mask_password(len(decrypted_pwd))
        p_val = ctk.CTkLabel(p_box, text=pwd_display_text, font=ctk.CTkFont(size=13), anchor="w")
        p_val.pack(side="left", fill="x", expand=True, padx=10, pady=8)

        show_icon = "Hide" if self.show_detail_password else "Show"
        p_show = ctk.CTkButton(
            p_box,
            text=show_icon,
            width=32,
            height=26,
            fg_color="transparent",
            hover_color="gray40",
            command=lambda: self._toggle_detail_password(cred)
        )
        p_show.pack(side="right", padx=(0, 4))

        p_copy = ctk.CTkButton(
            p_box,
            text="Copy",
            width=50,
            height=26,
            fg_color="#89b4fa",
            hover_color="#74c7ec",
            text_color="#11111b",
            font=ctk.CTkFont(size=10, weight="bold"),
            command=lambda: copy_to_clipboard(decrypted_pwd)
        )
        p_copy.pack(side="right", padx=6)

        # Strength Bar Gauge
        res = assess_password_strength(decrypted_pwd)
        st_bar = ctk.CTkProgressBar(container, height=5)
        st_bar.set(res["score"] / 100.0)
        st_bar.configure(progress_color=res["color"])
        st_bar.pack(fill="x", pady=(2, 2))

        st_lbl = ctk.CTkLabel(container, text=f"Strength: {res['label']} ({res['score']}/100)", font=ctk.CTkFont(size=10), text_color=res["color"], anchor="w")
        st_lbl.pack(fill="x", pady=(0, 12))

        # 3. URL
        if cred.url:
            ctk.CTkLabel(container, text="WEBSITE URL", font=ctk.CTkFont(size=10, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(5, 2))
            url_box = ctk.CTkFrame(container, fg_color=("gray90", "#313244"), corner_radius=8)
            url_box.pack(fill="x", pady=(0, 12))

            url_val = ctk.CTkLabel(url_box, text=cred.url, font=ctk.CTkFont(size=12), text_color="#89b4fa", anchor="w", cursor="hand2")
            url_val.pack(side="left", fill="x", expand=True, padx=10, pady=8)
            url_val.bind("<Button-1>", lambda e: open_url_in_browser(cred.url))

            url_open = ctk.CTkButton(
                url_box,
                text="Open",
                width=55,
                height=26,
                fg_color="gray30",
                hover_color="gray40",
                font=ctk.CTkFont(size=10),
                command=lambda: open_url_in_browser(cred.url)
            )
            url_open.pack(side="right", padx=6)

        # 4. Notes
        if cred.notes:
            ctk.CTkLabel(container, text="NOTES", font=ctk.CTkFont(size=10, weight="bold"), text_color="gray60", anchor="w").pack(fill="x", pady=(5, 2))
            notes_box = ctk.CTkTextbox(container, height=80, font=ctk.CTkFont(size=12), fg_color=("gray90", "#313244"))
            notes_box.insert("1.0", cred.notes)
            notes_box.configure(state="disabled")
            notes_box.pack(fill="x", pady=(0, 12))

        # 5. Metadata timestamps
        ctk.CTkLabel(container, text=f"Created: {format_iso_date(cred.created_at)}", font=ctk.CTkFont(size=10), text_color="gray50", anchor="w").pack(fill="x", pady=(10, 1))
        ctk.CTkLabel(container, text=f"Updated: {format_iso_date(cred.updated_at)}", font=ctk.CTkFont(size=10), text_color="gray50", anchor="w").pack(fill="x")

    def _toggle_detail_password(self, cred: Credential):
        self.show_detail_password = not self.show_detail_password
        self._build_detail_pane(cred)

    def _copy_credential_password(self, cred: Credential):
        try:
            session_key = SessionManager.get_instance().get_key()
            decrypted = decrypt_password(cred.encrypted_password, session_key)
            if copy_to_clipboard(decrypted):
                pass
        except Exception:
            messagebox.showerror("Error", "Could not decrypt password.")

    def _toggle_favorite(self, cred: Credential):
        self.db_manager.toggle_favorite(cred.id)
        self.refresh_vault()

    def _open_add_modal(self):
        AddEditPasswordModal(self, self.db_manager, credential=None, on_save_callback=self.refresh_vault)

    def _open_edit_modal(self, cred: Credential):
        AddEditPasswordModal(self, self.db_manager, credential=cred, on_save_callback=self.refresh_vault)

    def _delete_credential(self, cred: Credential):
        confirm = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to permanently delete the credentials for '{cred.website}'?\nThis action cannot be undone."
        )
        if confirm:
            self.db_manager.delete_credential(cred.id)
            self.selected_credential = None
            self.refresh_vault()
