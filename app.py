import re
import math
import hashlib
import requests
from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)
app.secret_key = "change-me-in-production"

# ── Config ────────────────────────────────────────────────────────────────────
HIBP_ENABLED = True          # Set False to skip HaveIBeenPwned lookup
HISTORY_LIMIT = 5

# ── Load common-password blocklist ────────────────────────────────────────────
try:
    with open("common_passwords.txt") as f:
        COMMON_PASSWORDS = set(f.read().splitlines())
except FileNotFoundError:
    COMMON_PASSWORDS = set()

# ── Pattern constants ─────────────────────────────────────────────────────────
KEYBOARD_WALKS = [
    "qwerty", "qwertz", "azerty", "asdf", "zxcv",
    "1234", "2345", "3456", "4567", "5678", "6789",
    "abcd", "abcde",
]
SPECIAL_CHARS = r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]"


# ── Helpers ───────────────────────────────────────────────────────────────────

def calculate_entropy(password: str) -> float:
    """Shannon-style entropy based on character pool size × length."""
    pool = 0
    if re.search(r"[a-z]", password):        pool += 26
    if re.search(r"[A-Z]", password):        pool += 26
    if re.search(r"[0-9]", password):        pool += 10
    if re.search(SPECIAL_CHARS, password):   pool += 32
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


def crack_time_label(entropy: float) -> str:
    """Human-readable crack-time estimate (offline fast-hash attack ~10B/s)."""
    guesses_per_second = 1e10
    seconds = (2 ** entropy) / guesses_per_second
    thresholds = [
        (60,           "less than a minute"),
        (3_600,        "a few minutes to hours"),
        (86_400,       "hours to a day"),
        (2_592_000,    "days to a month"),
        (31_536_000,   "months to a year"),
        (3_153_600_00, "years"),
        (float("inf"), "centuries or more"),
    ]
    for limit, label in thresholds:
        if seconds < limit:
            return label
    return "centuries or more"


def has_sequential(password: str, n: int = 3) -> bool:
    """Detect runs of n+ sequential characters (e.g. abc, 123)."""
    for i in range(len(password) - n + 1):
        window = password[i:i + n]
        codes = [ord(c) for c in window]
        if all(codes[j + 1] - codes[j] == 1 for j in range(len(codes) - 1)):
            return True
    return False


def has_repeated(password: str, n: int = 3) -> bool:
    """Detect n+ repeated characters (e.g. aaa, 111)."""
    return bool(re.search(r"(.)\1{" + str(n - 1) + r",}", password))


def has_keyboard_walk(password: str) -> bool:
    low = password.lower()
    return any(walk in low for walk in KEYBOARD_WALKS)


def check_hibp(password: str) -> int:
    """Return the number of times the password has appeared in HIBP breaches.
    Uses k-anonymity — only the first 5 hex chars of the SHA-1 hash are sent."""
    if not HIBP_ENABLED:
        return 0
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=3,
        )
        if resp.status_code != 200:
            return 0
        for line in resp.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                return int(count)
        return 0
    except Exception:
        return 0


def build_criteria(password: str) -> dict:
    return {
        "length_8":    len(password) >= 8,
        "length_12":   len(password) >= 12,
        "lowercase":   bool(re.search(r"[a-z]", password)),
        "uppercase":   bool(re.search(r"[A-Z]", password)),
        "digit":       bool(re.search(r"[0-9]", password)),
        "special":     bool(re.search(SPECIAL_CHARS, password)),
        "no_repeat":   not has_repeated(password),
        "no_sequence": not has_sequential(password),
        "no_keyboard": not has_keyboard_walk(password),
    }


def check_password_strength(password: str) -> dict:
    # ── Common password check ────────────────────────────────────────────────
    if password.lower() in COMMON_PASSWORDS:
        return {
            "score": 0,
            "label": "Very Weak — common password",
            "color_class": "very-weak",
            "entropy": 0,
            "crack_time": "instant",
            "tips": ["This password is on every attacker's list. Choose something unique."],
            "criteria": build_criteria(password),
            "pwned_count": 0,
        }

    # ── Scoring ──────────────────────────────────────────────────────────────
    score = 0
    tips = []
    criteria = build_criteria(password)

    if criteria["length_8"]:    score += 1
    else: tips.append("Use at least 8 characters.")

    if criteria["length_12"]:   score += 1
    else: tips.append("12+ characters makes it significantly stronger.")

    if len(password) >= 16:     score += 1

    if criteria["lowercase"]:   score += 1
    else: tips.append("Add lowercase letters.")

    if criteria["uppercase"]:   score += 1
    else: tips.append("Add uppercase letters.")

    if criteria["digit"]:       score += 1
    else: tips.append("Include at least one number.")

    if criteria["special"]:     score += 1
    else: tips.append("Include special characters like !@#$%.")

    # ── Penalties ────────────────────────────────────────────────────────────
    if not criteria["no_repeat"]:
        score = max(0, score - 1)
        tips.append("Avoid repeated characters (e.g. aaa, 111).")

    if not criteria["no_sequence"]:
        score = max(0, score - 1)
        tips.append("Avoid sequential characters (e.g. abc, 123).")

    if not criteria["no_keyboard"]:
        score = max(0, score - 1)
        tips.append("Avoid keyboard patterns like 'qwerty' or 'asdf'.")

    # ── HIBP breach lookup ───────────────────────────────────────────────────
    pwned_count = check_hibp(password)
    if pwned_count > 0:
        score = max(0, score - 2)
        tips.insert(0, f"⚠️ This password appeared in {pwned_count:,} data breaches!")

    # ── Label + class ────────────────────────────────────────────────────────
    entropy = calculate_entropy(password)
    crack_time = crack_time_label(entropy)

    if score <= 1:
        label, color_class = "Weak", "weak"
    elif score <= 3:
        label, color_class = "Medium", "medium"
    elif score <= 5:
        label, color_class = "Strong", "strong"
    else:
        label, color_class = "Very Strong", "very-strong"

    return {
        "score": score,
        "label": label,
        "color_class": color_class,
        "entropy": entropy,
        "crack_time": crack_time,
        "tips": tips,
        "criteria": criteria,
        "pwned_count": pwned_count,
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    history = session.get("history", [])
    return render_template("index.html", history=history)


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided"}), 400

    result = check_password_strength(password)

    # Store masked version in session history
    history = session.get("history", [])
    masked = password[0] + "*" * (len(password) - 2) + password[-1] if len(password) > 2 else "***"
    entry = {"masked": masked, "label": result["label"], "color_class": result["color_class"]}
    history = [entry] + [h for h in history if h["masked"] != masked]
    session["history"] = history[:HISTORY_LIMIT]

    return jsonify(result)


@app.route("/clear-history", methods=["POST"])
def clear_history():
    session.pop("history", None)
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(debug=True)