import os
import sqlite3
from datetime import datetime
from typing import List, Optional, Tuple
from database.models import User, Credential, Settings

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_PATH = os.path.join(DB_DIR, "vault.db")


class DatabaseManager:
    """SQLite Database Manager for Passary Password Manager."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._ensure_db_directory()
        self.init_database()

    def _ensure_db_directory(self) -> None:
        """Ensure the target directory for the SQLite database exists."""
        db_dir = os.path.dirname(self.db_path)
        if not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

    def get_connection(self) -> sqlite3.Connection:
        """Create and return a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_database(self) -> None:
        """Create database tables if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Create Users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

            # Create Credentials table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    website TEXT NOT NULL,
                    url TEXT,
                    username TEXT NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT,
                    category TEXT DEFAULT 'Personal',
                    favorite INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)

            # Create Settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    auto_lock_minutes INTEGER DEFAULT 5,
                    theme TEXT DEFAULT 'dark',
                    show_password_default INTEGER DEFAULT 0
                )
            """)

            # Insert default settings if empty
            cursor.execute("SELECT COUNT(*) FROM settings")
            if cursor.fetchone()[0] == 0:
                cursor.execute("""
                    INSERT INTO settings (id, auto_lock_minutes, theme, show_password_default)
                    VALUES (1, 5, 'dark', 0)
                """)

            conn.commit()

    # --- USER AUTHENTICATION QUERIES ---

    def has_user(self) -> bool:
        """Check if a Master Password user exists in the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            return cursor.fetchone()[0] > 0

    def get_user(self) -> Optional[User]:
        """Fetch the master user record."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash, salt, created_at FROM users LIMIT 1")
            row = cursor.fetchone()
            if row:
                return User(
                    id=row["id"],
                    password_hash=row["password_hash"],
                    salt=row["salt"],
                    created_at=row["created_at"]
                )
            return None

    def create_user(self, password_hash: str, salt: bytes) -> bool:
        """Initialize master password user."""
        now = datetime.now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (password_hash, salt, created_at) VALUES (?, ?, ?)",
                (password_hash, salt, now)
            )
            conn.commit()
            return True

    def update_master_password(self, new_hash: str, new_salt: bytes) -> bool:
        """Update master password hash and salt."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE id = (SELECT id FROM users LIMIT 1)",
                (new_hash, new_salt)
            )
            conn.commit()
            return True

    # --- CREDENTIALS VAULT CRUD QUERIES ---

    def add_credential(
        self,
        website: str,
        url: str,
        username: str,
        encrypted_password: str,
        notes: str = "",
        category: str = "Personal",
        favorite: bool = False
    ) -> int:
        """Add a new encrypted credential to the database."""
        now = datetime.now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO credentials 
                (website, url, username, encrypted_password, notes, category, favorite, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (website, url, username, encrypted_password, notes, category, 1 if favorite else 0, now, now))
            conn.commit()
            return cursor.lastrowid

    def get_all_credentials(self) -> List[Credential]:
        """Fetch all credentials stored in the vault."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM credentials ORDER BY website COLLATE NOCASE ASC")
            rows = cursor.fetchall()
            return [self._row_to_credential(row) for row in rows]

    def search_credentials(self, query: str = "", category: str = "All", favorite_only: bool = False) -> List[Credential]:
        """Search and filter credentials by website, username, category, or favorite status."""
        sql = "SELECT * FROM credentials WHERE 1=1"
        params = []

        if query.strip():
            sql += " AND (website LIKE ? OR username LIKE ? OR url LIKE ? OR notes LIKE ?)"
            pattern = f"%{query.strip()}%"
            params.extend([pattern, pattern, pattern, pattern])

        if category and category != "All":
            sql += " AND category = ?"
            params.append(category)

        if favorite_only:
            sql += " AND favorite = 1"

        sql += " ORDER BY website COLLATE NOCASE ASC"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()
            return [self._row_to_credential(row) for row in rows]

    def get_credential_by_id(self, cred_id: int) -> Optional[Credential]:
        """Get a single credential by ID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM credentials WHERE id = ?", (cred_id,))
            row = cursor.fetchone()
            return self._row_to_credential(row) if row else None

    def update_credential(
        self,
        cred_id: int,
        website: str,
        url: str,
        username: str,
        encrypted_password: str,
        notes: str,
        category: str,
        favorite: bool
    ) -> bool:
        """Update an existing credential record."""
        now = datetime.now().isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE credentials
                SET website = ?, url = ?, username = ?, encrypted_password = ?, notes = ?, category = ?, favorite = ?, updated_at = ?
                WHERE id = ?
            """, (website, url, username, encrypted_password, notes, category, 1 if favorite else 0, now, cred_id))
            conn.commit()
            return cursor.rowcount > 0

    def delete_credential(self, cred_id: int) -> bool:
        """Delete a credential from the vault."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
            conn.commit()
            return cursor.rowcount > 0

    def toggle_favorite(self, cred_id: int) -> bool:
        """Toggle favorite status of a credential."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE credentials SET favorite = 1 - favorite WHERE id = ?", (cred_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_categories(self) -> List[str]:
        """Fetch distinct categories in the vault."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT category FROM credentials WHERE category IS NOT NULL AND category != ''")
            categories = [row[0] for row in cursor.fetchall()]
            defaults = ["Personal", "Work", "Finance", "Social", "SSH"]
            for d in defaults:
                if d not in categories:
                    categories.append(d)
            return sorted(categories)

    # --- SETTINGS QUERIES ---

    def get_settings(self) -> Settings:
        """Retrieve user application settings."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, auto_lock_minutes, theme, show_password_default FROM settings WHERE id = 1")
            row = cursor.fetchone()
            if row:
                return Settings(
                    id=row["id"],
                    auto_lock_minutes=row["auto_lock_minutes"],
                    theme=row["theme"],
                    show_password_default=bool(row["show_password_default"])
                )
            return Settings(id=1, auto_lock_minutes=5, theme="dark", show_password_default=False)

    def update_settings(self, auto_lock_minutes: int, theme: str, show_password_default: bool) -> bool:
        """Update app settings."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE settings
                SET auto_lock_minutes = ?, theme = ?, show_password_default = ?
                WHERE id = 1
            """, (auto_lock_minutes, theme, 1 if show_password_default else 0))
            conn.commit()
            return True

    @staticmethod
    def _row_to_credential(row: sqlite3.Row) -> Credential:
        return Credential(
            id=row["id"],
            website=row["website"],
            url=row["url"] if row["url"] else "",
            username=row["username"],
            encrypted_password=row["encrypted_password"],
            notes=row["notes"] if row["notes"] else "",
            category=row["category"] if row["category"] else "Personal",
            favorite=bool(row["favorite"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"]
        )
