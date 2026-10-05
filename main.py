"""
Passary — Secure Desktop Password Manager
Main Application Entry Point
"""

import sys
import os

# Add root folder to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database.database import DatabaseManager
from ui.app import AppWindow


def main():
    try:
        # Initialize Database Schema
        db = DatabaseManager()

        # Launch Desktop Application
        app = AppWindow()
        app.mainloop()
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)


if __name__ == "__main__":
    main()
