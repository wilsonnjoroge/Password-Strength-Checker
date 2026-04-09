# 🔒 Password Strength Checker

A full-featured Flask web application for evaluating password security with real-time feedback, entropy analysis, breach detection, and crack-time estimation — built for cybersecurity portfolios and Python practice.

---

## ✨ Features

### Core Strength Analysis
- **Length scoring** — minimum 8 characters, bonus for 12+, extra bonus for 16+
- **Character variety** — lowercase, uppercase, digits, and a broad set of special characters
- **Entropy calculation** — bits of entropy derived from character pool size and password length
- **Crack-time estimation** — human-readable estimate (seconds → centuries) based on entropy

### Security Checks
- **Common password detection** — checked against a local `common_passwords.txt` blocklist
- **HaveIBeenPwned integration** — k-anonymity SHA-1 prefix lookup against the HIBP Pwned Passwords API (no full password is ever sent)
- **Repeated/sequential character penalties** — detects patterns like `aaaa` or `1234`
- **Keyboard walk detection** — flags patterns like `qwerty`, `asdf`

### UX & Interface
- **Real-time AJAX checking** — strength updates as you type, no page reload
- **Animated strength meter** — color-coded progress bar (Very Weak → Very Strong)
- **Show / hide password toggle**
- **Per-criterion checklist** — live ✅/❌ feedback for each rule
- **Improvement tips** — actionable suggestions when the password is weak
- **Session history** — last 5 checked passwords stored server-side (masked)
- **Copy-to-clipboard** button for quick reuse

---

## 📸 Demo

> Replace `screenshot.png` with your own screenshot of the app in action.

![Demo Screenshot](screenshot.png)

---

## 🚀 Installation

### 1. Clone the repository

```bash
git clone https://github.com/wilsonnjoroge/password-checker.git
cd password-checker
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python app.py
```

Then open your browser at:

```
http://127.0.0.1:5000
```

Type a password to see strength, entropy, crack time, and breach status update in real time.

---

## 🗂 Project Structure

```
password_checker_flask/
├── app.py                   # Flask backend — scoring, entropy, HIBP lookup
├── common_passwords.txt     # Blocklist of common/leaked passwords
├── requirements.txt         # Python dependencies
├── README.md
├── templates/
│   └── index.html           # Jinja2 template with live-update JS
└── static/
    ├── style.css            # Responsive, dark-themed UI
    └── script.js            # AJAX debounce + DOM updates
```

---

## ⚙️ How It Works

1. Password input triggers a debounced `fetch()` call to `/check` (POST, JSON).
2. Flask backend evaluates:
   - Character set entropy → estimated crack time
   - Rule checklist (length, case, digits, symbols)
   - Common password blocklist
   - Repeated / sequential / keyboard-walk pattern penalties
   - Optional HIBP k-anonymity breach lookup
3. Returns JSON: `{ score, label, color_class, entropy, crack_time, tips, criteria, pwned_count }`.
4. Frontend updates the strength bar, checklist, tips, and breach badge — all without a page reload.

---

## 🔧 Customization

| What | Where |
|---|---|
| Add common passwords | `common_passwords.txt` |
| Adjust scoring thresholds | `check_password_strength()` in `app.py` |
| Disable HIBP lookup | Set `HIBP_ENABLED = False` in `app.py` |
| Change the UI theme | CSS variables at the top of `static/style.css` |
| Add zxcvbn scoring | `pip install zxcvbn` and call `zxcvbn(password)` |

---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, Flask 3.1 |
| API | HaveIBeenPwned Pwned Passwords v3 |
| Frontend | HTML5, CSS3, Vanilla JS (fetch API) |
| Styling | CSS custom properties, CSS Grid/Flexbox |

---

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-improvement`
3. Commit your changes: `git commit -m "Add: my improvement"`
4. Push and open a Pull Request

---

## 📄 License

MIT License © 2026 [Wilson Njoroge Wanderi]
