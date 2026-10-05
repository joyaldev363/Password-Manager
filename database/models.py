from dataclasses import dataclass
from typing import Optional


@dataclass
class User:
    id: int
    password_hash: str
    salt: bytes
    created_at: str


@dataclass
class Credential:
    id: Optional[int]
    website: str
    url: str
    username: str
    encrypted_password: str
    notes: str
    category: str
    favorite: bool
    created_at: str
    updated_at: str


@dataclass
class Settings:
    id: int
    auto_lock_minutes: int
    theme: str
    show_password_default: bool
