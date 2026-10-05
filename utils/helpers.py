import webbrowser
from datetime import datetime
import pyperclip
from PIL import Image, ImageDraw


def copy_to_clipboard(text: str) -> bool:
    """Copy text to OS clipboard using pyperclip."""
    try:
        pyperclip.copy(text)
        return True
    except Exception:
        return False


def format_iso_date(iso_str: str) -> str:
    """Format an ISO 8601 timestamp into a readable date string."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%b %d, %Y %I:%M %p")
    except Exception:
        return iso_str


def sanitize_url(url: str) -> str:
    """Ensure URL starts with http:// or https://."""
    if not url:
        return ""
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        return f"https://{url}"
    return url


def open_url_in_browser(url: str) -> bool:
    """Open URL in default system web browser."""
    clean_url = sanitize_url(url)
    if clean_url:
        try:
            webbrowser.open(clean_url)
            return True
        except Exception:
            pass
    return False


def mask_password(length: int = 10) -> str:
    """Return bullet mask string for passwords."""
    return "•" * max(6, min(length, 16))


def get_initial_badge(name: str) -> str:
    """Extract a 1 or 2 letter badge uppercase string from website name."""
    if not name:
        return "?"
    parts = name.strip().split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[1][0]).upper()
    return name[:2].upper() if len(name) >= 2 else name[0].upper()


def generate_shield_icon(target_size: int = 96) -> Image.Image:
    """
    Generate a sleek 2-tone gradient shield padlock icon matching the Passary design.
    Uses 4x supersampling and Lanczos anti-aliasing.
    """
    scale = 4
    size = target_size * scale
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    w, h = float(size), float(size)

    # 1. Left Shield Half (Darker Purple/Blue #4338ca)
    left_poly = [
        (w * 0.50, h * 0.08),
        (w * 0.15, h * 0.20),
        (w * 0.15, h * 0.52),
        (w * 0.50, h * 0.92),
    ]
    draw.polygon(left_poly, fill="#4338ca")

    # 2. Right Shield Half (Brighter Blue #6366f1)
    right_poly = [
        (w * 0.50, h * 0.08),
        (w * 0.85, h * 0.20),
        (w * 0.85, h * 0.52),
        (w * 0.50, h * 0.92),
    ]
    draw.polygon(right_poly, fill="#6366f1")

    # 3. White Padlock Shackle
    stroke = int(size * 0.065)
    shackle_bbox = (w * 0.38, h * 0.30, w * 0.62, h * 0.54)
    draw.arc(shackle_bbox, start=180, end=360, fill="white", width=stroke)

    # 4. White Padlock Body
    body_bbox = (w * 0.34, h * 0.44, w * 0.66, h * 0.68)
    draw.rounded_rectangle(body_bbox, radius=int(size * 0.04), fill="white")

    # 5. Keyhole Inner Slot
    key_top = (w * 0.46, h * 0.52, w * 0.54, h * 0.60)
    draw.ellipse(key_top, fill="#4338ca")
    key_bottom = (w * 0.48, h * 0.56, w * 0.52, h * 0.64)
    draw.rectangle(key_bottom, fill="#4338ca")

    # Downsample with Lanczos for super smooth edges
    return img.resize((target_size, target_size), Image.Resampling.LANCZOS)
