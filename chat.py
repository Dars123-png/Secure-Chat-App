import socket
import threading
import sys
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import tkinter as tk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText
from emoji import emojize
from datetime import datetime

# =============================
# Globals
# =============================
session_key = None
sock = None
log_filename = "encrypted_chatlog.dat"
current_log_date = ""

# Persistent key for chat logs
def load_or_create_log_key():
    if not os.path.exists("log_key.bin"):
        key = get_random_bytes(16)
        with open("log_key.bin", "wb") as f:
            f.write(key)
        return key
    else:
        with open("log_key.bin", "rb") as f:
            return f.read()

log_key = load_or_create_log_key()
def get_timestamp_line(who, msg):
    global current_log_date
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M")

    # Insert new date header if date changed
    line = ""
    if date_str != current_log_date:
        current_log_date = date_str
        line += f"------ {date_str} ------\n"

    line += f"[{time_str}] {who}: {emojize(msg, language='alias')}\n"
    return line


# =============================
# Crypto functions
# =============================
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_keys(private_key, public_key):
    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)

def load_public_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def load_private_key(filename):
    with open(filename, "rb") as f:
        return RSA.import_key(f.read())

def encrypt_session_key(public_key):
    global session_key
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(session_key)

def decrypt_session_key(private_key, enc_session_key):
    global session_key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

def aes_encrypt_data(data):
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    return nonce, tag, ciphertext

def aes_decrypt_data(nonce, tag, ciphertext):
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    return cipher_aes.decrypt_and_verify(ciphertext, tag)

# =============================
# Encrypted chat log functions
# =============================
import struct

def save_to_encrypted_log(message):
    data = message.encode('utf-8')
    cipher_aes = AES.new(log_key, AES.MODE_EAX)
    nonce = cipher_aes.nonce
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    combined = nonce + tag + ciphertext
    with open(log_filename, "ab") as f:
        f.write(struct.pack("I", len(combined)))  # 4 bytes length
        f.write(combined)


def load_encrypted_log():
    if not os.path.exists(log_filename):
        return ""
    content = ""
    with open(log_filename, "rb") as f:
        while True:
            len_bytes = f.read(4)
            if not len_bytes:
                break
            (length,) = struct.unpack("I", len_bytes)
            combined = f.read(length)
            nonce = combined[:16]
            tag = combined[16:32]
            ciphertext = combined[32:]
            cipher_aes = AES.new(log_key, AES.MODE_EAX, nonce=nonce)
            decrypted = cipher_aes.decrypt_and_verify(ciphertext, tag)
            content += decrypted.decode('utf-8')
    return content


# =============================
# Networking functions
# =============================
def receive_messages(conn):
    while True:
        try:
            header = conn.recv(6)
            if not header:
                break
            if header == b'TYPING':
                root.after(0, show_typing_indicator)
            elif header == b'FILE::':
                handle_incoming_file(conn)
            else:
                rest = conn.recv(96)
                full = header + rest
                nonce = full[:16]
                tag = full[16:32]
                ciphertext = full[32:]
                plaintext = aes_decrypt_data(nonce, tag, ciphertext).decode('utf-8')
                msg = get_timestamp_line("Friend",plaintext)
                save_to_encrypted_log(msg)
                root.after(0, update_chat_log, msg)
        except Exception as e:
            print(f"Receive error: {e}")
            break

def handle_incoming_file(conn):
    meta = conn.recv(128).decode('utf-8')
    filename, length = meta.split(":")
    length = int(length)
    encrypted_data = b''
    while len(encrypted_data) < length:
        chunk = conn.recv(min(4096, length - len(encrypted_data)))
        if not chunk:
            break
        encrypted_data += chunk
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    data = aes_decrypt_data(nonce, tag, ciphertext)
    save_path = f"received_{filename}"
    with open(save_path, "wb") as f:
        f.write(data)
    msg = f"Friend sent file: {save_path}\n"
    save_to_encrypted_log(msg)
    root.after(0, update_chat_log, msg)

def start_server():
    global sock
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('0.0.0.0', 9000))
    server.listen(1)
    print("Server listening on port 9000...")
    conn, addr = server.accept()
    print("Client connected:", addr)
    sock = conn

    client_pub = load_public_key("public.pem")
    enc_session_key = encrypt_session_key(client_pub)
    conn.send(enc_session_key)

    # ✅ Load chat history after session key exists
    chat_history = load_encrypted_log()
    if chat_history:
        root.after(0, update_chat_log, chat_history)

    threading.Thread(target=receive_messages, args=(conn,), daemon=True).start()

def connect_to_server(ip):
    global sock
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, 9000))
    private_key = load_private_key("private.pem")
    enc_session_key = sock.recv(256)
    decrypt_session_key(private_key, enc_session_key)

    # ✅ Load chat history after session key exists
    chat_history = load_encrypted_log()
    if chat_history:
        root.after(0, update_chat_log, chat_history)

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

# =============================
# GUI functions
# =============================
def send_message(event=None):
    global sock
    msg = entry.get()
    if msg.strip() == "":
        return
    entry.delete(0, tk.END)
    nonce, tag, ciphertext = aes_encrypt_data(msg.encode('utf-8'))
    try:
        sock.send(nonce + tag + ciphertext)
        formatted = get_timestamp_line("you",msg)
        update_chat_log(formatted)
        save_to_encrypted_log(formatted)
    except Exception as e:
        print(f"Send error: {e}")

def send_file(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        nonce, tag, ciphertext = aes_encrypt_data(data)
        encrypted_data = nonce + tag + ciphertext
        meta = f"{os.path.basename(filepath)}:{len(encrypted_data)}".encode('utf-8')
        sock.send(b'FILE::' + meta.ljust(128))
        sock.sendall(encrypted_data)
        formatted = f"You sent file: {filepath}\n"
        update_chat_log(formatted)
        save_to_encrypted_log(formatted)
    except Exception as e:
        print(f"File send error: {e}")

def send_file_gui():
    filepath = filedialog.askopenfilename()
    if filepath:
        send_file(filepath)

def on_typing(event=None):
    if sock:
        try:
            sock.send(b'TYPING')
        except:
            pass

def show_typing_indicator():
    typing_label.config(text="Friend is typing...")
    root.after(2000, lambda: typing_label.config(text=""))

def update_chat_log(message):
    chat_log.configure(state='normal')
    chat_log.insert(tk.END, message)
    chat_log.yview(tk.END)
    chat_log.configure(state='disabled')

# =============================
# GUI setup
# =============================
root = tk.Tk()
root.title("Secure Chat - Persistent Logs")
root.geometry("600x450")

chat_log = ScrolledText(root, state='disabled', wrap='word')
chat_log.pack(padx=10, pady=10, fill='both', expand=True)

typing_label = tk.Label(root, text="", fg="blue")
typing_label.pack()

entry = tk.Entry(root)
entry.pack(side='left', padx=(10, 0), pady=(0, 10), fill='x', expand=True)
entry.bind("<Return>", send_message)
entry.bind("<Key>", on_typing)

send_btn = tk.Button(root, text="Send", command=send_message)
send_btn.pack(side='right', padx=(0, 10), pady=(0, 10))

send_file_btn = tk.Button(root, text="Send File", command=send_file_gui)
send_file_btn.pack(side='right', padx=(0, 10), pady=(0, 10))

# =============================
# Start app
# =============================
if len(sys.argv) > 1 and sys.argv[1] == '--listen':
    private_key, public_key = generate_keys()
    save_keys(private_key, public_key)
    threading.Thread(target=start_server, daemon=True).start()
else:
    if len(sys.argv) != 2:
        print("Usage: python chat.py --listen  OR  python chat.py <server_ip>")
        sys.exit()
    threading.Thread(target=connect_to_server, args=(sys.argv[1],), daemon=True).start()

root.mainloop()
