# Secure-Chat-App
# Secure Encrypted Chat App with File Transfer, Logs & Emojis

A secure end-to-end encrypted chat application built with **Python**, using **RSA** for key exchange, **AES (EAX)** for message encryption, persistent **encrypted chat logs**, and features like file transfer, emoji parsing, typing indicators, and a clean Tkinter GUI.

> **For educational purposes only.**
> Do not use this on networks you do not own or have explicit permission to test.

---

## Features

**End-to-End Encryption**
- RSA-2048 public/private keys for secure key exchange.
- AES-128 (EAX mode) for all message & file encryption.

**Persistent Encrypted Chat Logs**
- Chat history saved encrypted on disk with a fixed AES key.
- Even if the app is restarted, old chats remain private and accessible.

**File Transfers**
- Send encrypted files easily.
- Files are decrypted and saved on the receiving machine.

**Typing Indicator**
- Shows `"Friend is typing..."` when the other party is typing.

**Timestamps + Dates**
- Displays messages with clear time & date headers.

**Emoji Support**
- Type `:smile:`, `:rocket:`, etc. and they auto-render.

**Tkinter GUI**
- Scrollable chat history
- Entry box & send button
- File transfer button

---

## Requirements

- Python 3.8+
- Install dependencies with:

```bash
pip install pycryptodome emoji
