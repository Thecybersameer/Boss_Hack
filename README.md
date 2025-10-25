# Malware Project

# Boss Hack — README

> Important / Short safety note (read first):
> 
> 
> This project can access webcam, screen, microphone, system info, saved Wi‑Fi profiles (Windows), and encrypt/decrypt files. Run it **only** on your own machine or a lab VM. Do **not** use it to invade others’ privacy. A stealthy/system-wide keylogger is intentionally **NOT** included — that would be unethical. If you exposed your Telegram bot token, revoke/regenerate it immediately in BotFather.
> 

---

# Table of contents

1. Project summary
2. How the software works (architecture & flow)
3. Features & bot commands (with usage examples)
4. Encryption design & file format
5. Installation & running (Windows focus)
6. Dependencies
7. Security, ethics & limitations
8. Troubleshooting & common errors
9. Testing checklist
10. Final note

---

# 1. Project summary

**Boss Hack** is a Python Telegram bot that provides multiple remote utilities for a machine where the bot runs. It enables an authorized operator (bot owner/chat) to request diagnostics and basic remote actions and receive results back via Telegram.

**Primary capabilities:**

- System info, screenshots, webcam capture, short webcam recording (stream), screen recordings
- Audio recording, clipboard contents, running processes list
- Windows-only controls: lock, shutdown, input freeze
- Extract saved Wi‑Fi profiles (Windows)
- Password-based file encryption and decryption (AES‑GCM)
- Utilities: open URL on host, beep, clean temp files, text-to-speech

**Purpose:** academic/demo use — show how remote admin tools can be implemented responsibly on owned/test systems. Not intended for malicious use.

---

# 2. How the software works (architecture & flow)

## High-level architecture

- Single Python script (Boss Hack) runs as a process on the host.
- Connects to Telegram with `python-telegram-bot` and listens for commands (long polling).
- Each command triggers a handler on the host (e.g., take screenshot, record audio).
- Results are sent back to the operator via Telegram (images, videos, audio, or text).

## Startup flow

1. Launch script.
2. Script attempts to auto-install missing Python packages (prints logs).
3. Prompts for `BOT_TOKEN` (and optionally a chat id for startup notification).
4. Builds bot `Application`, registers command handlers and runs `run_polling()`.

## Security boundaries

- All actions execute in the user process running the bot. Run only on machines you control.
- No persistence hardening (not installed as a service) — it's a process that runs while invoked.
- No stealth keylogger included — the bot intentionally refuses such functionality.

---

# 3. Features & bot commands (with usage examples)

> Replace <BOT_TOKEN> and <CHAT_ID> with your own data. Never paste your real token publicly.
> 

### `/start`

**Description:** Start greeting.

**Example:** `/start`

**Response:** 🤖 Bot is running. Use `/help` to see available commands.

### `/help [command]`

Show overall help or help for a specific command, e.g. `/help /record_screen`.

### `/info`

Returns OS, node name, processor, etc.

### `/screenshot`

Takes a screenshot (`pyautogui.screenshot()`), saves to temp and sends image.

### `/webcam`

Captures one frame from the default webcam using OpenCV. If webcam busy or absent, returns error.

### `/record_screen <seconds>`

Records the screen for `<seconds>` (default `8`) and sends `.avi` video.

- Captures ~10 FPS using `pyautogui` and writes `.avi` with OpenCV (XVID).
- CPU-heavy at high resolutions — reduce FPS/duration if needed.
    
    **Example:** `/record_screen 10`
    

### `/stream <seconds>`

Records the webcam for `<seconds>` (default `8`) and sends `.avi`.

Uses OpenCV `VideoCapture`. Returns error if camera cannot open.

### `/record_audio <seconds>`

Records microphone audio with `sounddevice` and writes `.wav` using `soundfile`.

**Example:** `/record_audio 5`

### `/clipboard`

Replies with current clipboard text (`pyperclip`). Use responsibly — clipboards can contain sensitive data.

### `/processes`

Returns a list (first 50) of running processes (`psutil.process_iter()`).

### `/open <website>`

Opens a URL on the host (launches default browser). Executes locally — be careful what you open.

### `/beep`

Plays a beep on host. On Windows uses `winsound`, otherwise a system bell fallback.

### `/clean`

Deletes files inside OS temp folder. Returns number of items removed. Use carefully.

### `/speak <text>`

Host speaks the text using `pyttsx3`. Requires audio output on host.

### `/wifi_passwords` (Windows only)

Parses `netsh wlan show profiles` and returns saved SSIDs + passwords (if retrievable). Requires appropriate permissions.

### `/search <filename>`

Searches filesystem (limited scope) and returns up to 50 matches. Can be slow on large drives; scan limits are enforced.

### `/encrypt <full_path> <password>`

Encrypts the file using AES‑GCM with PBKDF2-derived key and writes `<file>.enc`.

**Example:** `/encrypt C:\Users\you\Documents\notes.txt myStrongPass123`

### `/decrypt <path.enc> <password>`

Decrypts `.enc` files created by `/encrypt`, writes `<file>.dec`.

### `/lock`, `/shutdown`, `/freeze` (Windows only)

- `/lock` — Locks workstation (`LockWorkStation()`).
- `/shutdown` — `shutdown /s /t 1`.
- `/freeze` — Blocks input for 30 seconds using `BlockInput()`.

---

# 4. Encryption design & file format

- **KDF:** PBKDF2-HMAC-SHA256, **200,000 iterations**, random 16-byte salt.
- **Cipher:** AES-GCM via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
- **File layout for `.enc`:** `salt (16 bytes) || nonce (12 bytes) || ciphertext (remaining bytes)`.
- **Why:** AES-GCM provides authenticated encryption to detect tampering.

**Caveat:** For production use consider Argon2/scrypt, metadata/versioning, HSMs and secure key handling.

---

# 5. Installation & running (Windows focus)

> If auto-installer fails, manually create a venv and pip install dependencies.
> 
1. **Clone / copy files** into a folder, e.g. `C:\projects\pc_intrusion`.
2. **Create & activate venv (recommended):**

```powershell
cd C:\projects\pc_intrusion
"C:\Users\<you>\AppData\Local\Programs\Python\Python313\python.exe" -m venv venv
venv\Scripts\activate

```

1. **Manual installs (if needed):**

```powershell
pip install --upgrade pip
pip install requests pyautogui opencv-python pyperclip psutil pyttsx3 sounddevice soundfile python-telegram-bot==20.3 nest_asyncio cryptography numpy

```

> Note: pyautogui and opencv-python may require extra OS components or large binaries.
> 
1. **Run the bot:**

```powershell
python Boss_Hack.py

```

When prompted, paste your Bot Token from BotFather. Optionally provide your chat id to receive a startup message.

1. **If token leaked:** Revoke in BotFather or create a new bot.

---

# 6. Dependencies

**Python packages:**

- `python-telegram-bot==20.3`
- `requests`, `pyautogui`, `opencv-python`, `pyperclip`, `psutil`
- `pyttsx3`, `sounddevice`, `soundfile`, `cryptography`, `numpy`, `nest_asyncio`

**System tools (Windows):** `netsh`, `winsound` (for beep), `LockWorkStation`, `BlockInput`.

---

# 7. Security, ethics & limitations

## Ethics

- This tool can violate privacy. Use **only** on devices you own or with explicit consent. Misuse may be illegal.
- The project intentionally refuses stealth keylogger functionality.

## Token safety

- Anyone with the bot token can control the bot. Keep tokens secret; regenerate if leaked.

## AV / SmartScreen

- Auto-installer may trigger antivirus or SmartScreen. On managed devices you may not be allowed to run/install packages — use a VM.

## Operational limits

- `.avi` files use XVID codec; you can convert with `ffmpeg` for broad compatibility.
- Screen/webcam recording is CPU/memory intensive.
- Some features are Windows-only: netsh, BlockInput, winsound, LockWorkStation.

## Encryption

- Strong for demo use, but for real-world production use hardened key management and memory-hard KDFs.

---

# 8. Troubleshooting & common errors

- **Admin permissions** required for some features.
- **Auto-installer blocked**: create venv and `pip install` manually or use offline wheels.
- Commands like wifipasswords, recordaudio and recordscreen should be written as wifi_passwords, record_audio and record_screen.

---

# 9. Testing checklist

**Setup**

- Create venv and install dependencies or run auto-installer.
- Launch Boss Hack.
- Provide Bot Token at prompt. Optionally provide chat id.

**Commands to test** (run each from your Telegram client):

- `/start`, `/info`, `/screenshot`, `/webcam`, `/record_screen 5`, `/stream 5`, `/record_audio 5`,
    
    `/clipboard`, `/processes`, `/search filename.ext`, `/encrypt <path> <password>`, `/decrypt <path.enc> <password>`,
    
    `/wifi_passwords` (Windows only), `/lock`, `/shutdown` (Windows-only — test carefully).
    

**Edge cases**

- Invalid args (e.g., `/record_screen abc`) should be handled gracefully without crashing.

**Ethics check**

- Confirm `/keylogger` returns a refusal message.

---

# 10. Final note

### 📝 This tool is just made for educational purpose only. The main purpose of the tool is to learn about how a malware works. Unethical use of this tool is strongly unacceptable. 
If somebody is misusing the tool, then only the user will be responsible for any legal actions against them.
