from collections import Counter
import customtkinter as ctk
from database.database import DatabaseManager
from security.authentication import SessionManager
from security.encryption import decrypt_password
from security.password_generator import assess_password_strength
from ui.add_password import AddEditPasswordModal


class SecurityCenterFrame(ctk.CTkFrame):
    """
    Security Center & Password Audit view.
    Audits stored passwords for strength, reuse, and vulnerability risks.
    """

    def __init__(self, parent, db_manager: DatabaseManager):
        super().__init__(parent, fg_color="transparent")
        self.db_manager = db_manager

        self._build_ui()
        self.run_audit()

    def _build_ui(self):
        # Header
        hdr_frame = ctk.CTkFrame(self, fg_color="transparent")
        hdr_frame.pack(fill="x", padx=25, pady=(20, 10))

        title_lbl = ctk.CTkLabel(hdr_frame, text="Security Center & Vault Audit", font=ctk.CTkFont(size=24, weight="bold"))
        title_lbl.pack(side="left")

        reaudit_btn = ctk.CTkButton(
            hdr_frame,
            text="Re-run Audit",
            fg_color="#89b4fa",
            hover_color="#74c7ec",
            text_color="#11111b",
            font=ctk.CTkFont(weight="bold"),
            height=36,
            command=self.run_audit
        )
        reaudit_btn.pack(side="right")

        # Container
        self.container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=25, pady=(0, 20))

        # Overview score card
        self.score_card = ctk.CTkFrame(self.container, corner_radius=16, fg_color=("white", "#1e1e2e"))
        self.score_card.pack(fill="x", padx=15, pady=(0, 20))

        self.score_lbl = ctk.CTkLabel(self.score_card, text="Vault Health Score: 100%", font=ctk.CTkFont(size=22, weight="bold"), text_color="#a6e3a1")
        self.score_lbl.pack(anchor="w")

        self.desc_lbl = ctk.CTkLabel(self.score_card, text="Your password vault security audit summary.", font=ctk.CTkFont(size=13), text_color="gray60")
        self.desc_lbl.pack(anchor="w", pady=(2, 0))

        # Vulnerable Items Table Title
        ctk.CTkLabel(self.container, text="Security Vulnerabilities & Recommendations", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", pady=(10, 10))

        self.vuln_frame = ctk.CTkFrame(self.container, corner_radius=12, fg_color=("white", "#1e1e2e"))
        self.vuln_frame.pack(fill="both", expand=True, pady=(0, 20))

    def run_audit(self):
        """Audit all passwords and update health score and vulnerability list."""
        all_creds = self.db_manager.get_all_credentials()

        for widget in self.vuln_frame.winfo_children():
            widget.destroy()

        if not all_creds:
            lbl = ctk.CTkLabel(self.vuln_frame, text="No accounts in vault to audit.", font=ctk.CTkFont(size=14), text_color="gray60")
            lbl.pack(pady=40)
            self.score_lbl.configure(text="Vault Health Score: 100%", text_color="#a6e3a1")
            return

        session_key = None
        try:
            session_key = SessionManager.get_instance().get_key()
        except Exception:
            pass

        decrypted_map = {}
        plain_passwords = []

        if session_key:
            for c in all_creds:
                try:
                    dec = decrypt_password(c.encrypted_password, session_key)
                    decrypted_map[c.id] = dec
                    plain_passwords.append(dec)
                except Exception:
                    decrypted_map[c.id] = ""

        # Find reused passwords
        counts = Counter(plain_passwords)
        reused_set = {p for p, count in counts.items() if count > 1 and p != ""}

        vulnerable_items = []
        total_score = 0

        for c in all_creds:
            pwd = decrypted_map.get(c.id, "")
            res = assess_password_strength(pwd)
            total_score += res["score"]

            issues = []
            if res["score"] < 50:
                issues.append("Weak Password Strength")
            if pwd in reused_set:
                issues.append("Reused across multiple accounts!")
            if len(pwd) < 10:
                issues.append("Password too short (< 10 chars)")

            if issues:
                vulnerable_items.append((c, issues, res))

        overall_score = round(total_score / len(all_creds)) if all_creds else 100

        # Update Health Score header
        if overall_score >= 80:
            score_color = "#a6e3a1"  # Green
        elif overall_score >= 60:
            score_color = "#e9c46a"  # Yellow
        else:
            score_color = "#f38ba8"  # Red

        self.score_lbl.configure(text=f"Vault Health Score: {overall_score}%", text_color=score_color)
        self.desc_lbl.configure(text=f"Audited {len(all_creds)} accounts. Found {len(vulnerable_items)} items requiring attention.")

        if not vulnerable_items:
            success_lbl = ctk.CTkLabel(
                self.vuln_frame,
                text="Excellent! All saved passwords are unique and strong.",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#a6e3a1"
            )
            success_lbl.pack(pady=40)
            return

        # Render list of vulnerable accounts
        for cred, issues, res in vulnerable_items:
            row = ctk.CTkFrame(self.vuln_frame, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=12)

            info = ctk.CTkFrame(row, fg_color="transparent")
            info.pack(side="left", fill="x", expand=True)

            w_lbl = ctk.CTkLabel(info, text=cred.website, font=ctk.CTkFont(size=14, weight="bold"), anchor="w")
            w_lbl.pack(fill="x")

            issue_text = " • ".join(issues)
            i_lbl = ctk.CTkLabel(info, text=issue_text, font=ctk.CTkFont(size=12), text_color="#f38ba8", anchor="w")
            i_lbl.pack(fill="x")

            fix_btn = ctk.CTkButton(
                row,
                text="Fix Password",
                width=110,
                height=32,
                fg_color="#89b4fa",
                hover_color="#74c7ec",
                text_color="#11111b",
                font=ctk.CTkFont(weight="bold"),
                command=lambda c=cred: self._open_fix_modal(c)
            )
            fix_btn.pack(side="right", padx=(10, 0))

    def _open_fix_modal(self, cred):
        AddEditPasswordModal(self, self.db_manager, credential=cred, on_save_callback=self.run_audit)
