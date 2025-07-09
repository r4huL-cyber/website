from flask import Flask, render_template, request
import base64, codecs, hashlib, string
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)

# === Cipher Functions ===
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

def rot13(text):
    return codecs.encode(text, 'rot_13')

def vigenere_encrypt(text, key):
    result = ''
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            offset = ord(key[key_index % len(key)]) - ord('a')
            result += caesar_encrypt(char, offset)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    result = ''
    key = key.lower()
    key_index = 0
    for char in text:
        if char.isalpha():
            offset = ord(key[key_index % len(key)]) - ord('a')
            result += caesar_decrypt(char, offset)
            key_index += 1
        else:
            result += char
    return result

def aes_encrypt(text, password):
    key = hashlib.sha256(password.encode()).digest()
    cipher = Fernet(base64.urlsafe_b64encode(key[:32]))
    return cipher.encrypt(text.encode()).decode()

def aes_decrypt(token, password):
    try:
        key = hashlib.sha256(password.encode()).digest()
        cipher = Fernet(base64.urlsafe_b64encode(key[:32]))
        return cipher.decrypt(token.encode()).decode()
    except InvalidToken:
        return "Invalid decryption password or token."

# === Encryption Type Identifier ===
def is_base64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False

def is_base32(s):
    try:
        return base64.b32encode(base64.b32decode(s)) == s.encode()
    except Exception:
        return False

def is_rot13(s):
    decoded = codecs.encode(s, 'rot_13')
    return decoded.isprintable() and decoded != s

def is_sha256(s):
    return len(s) == 64 and all(c in string.hexdigits for c in s)

def is_caesar(s):
    return all(c.isalpha() or c.isspace() for c in s)

def identify_encryption(text):
    if is_sha256(text):
        return "SHA256 (likely hash, not reversible)"
    elif is_base64(text):
        return "Base64"
    elif is_base32(text):
        return "Base32"
    elif is_rot13(text):
        return "ROT13"
    elif is_caesar(text):
        return "Caesar Cipher (or plain text)"
    else:
        return "Unknown or Custom Encryption"

# === Routes ===
@app.route("/", methods=["GET", "POST"])
def index():
    result = ""
    if request.method == "POST":
        text = request.form["text"]
        algorithm = request.form["algorithm"]
        operation = request.form["operation"]
        key = request.form.get("key", "")

        try:
            if algorithm == "base64":
                result = base64.b64encode(text.encode()).decode() if operation == "encrypt" else base64.b64decode(text).decode()
            elif algorithm == "base32":
                result = base64.b32encode(text.encode()).decode() if operation == "encrypt" else base64.b32decode(text).decode()
            elif algorithm == "caesar":
                shift = int(key) if key else 3
                result = caesar_encrypt(text, shift) if operation == "encrypt" else caesar_decrypt(text, shift)
            elif algorithm == "rot13":
                result = rot13(text)
            elif algorithm == "vigenere":
                result = vigenere_encrypt(text, key) if operation == "encrypt" else vigenere_decrypt(text, key)
            elif algorithm == "aes":
                result = aes_encrypt(text, key) if operation == "encrypt" else aes_decrypt(text, key)
            elif algorithm == "sha256":
                result = hashlib.sha256(text.encode()).hexdigest()
        except Exception as e:
            result = f"Error: {str(e)}"

    return render_template("index.html", result=result)

@app.route("/identify", methods=["GET", "POST"])
def identify():
    result = ""
    if request.method == "POST":
        encrypted_text = request.form.get("encrypted_text", "")
        result = identify_encryption(encrypted_text)
    return render_template("identify.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
