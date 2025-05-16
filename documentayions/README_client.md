
# 🛠️ `client.py` — Length Extension Attack Demonstration

## 📌 Purpose

This script demonstrates a **length extension attack** on an insecure MAC construction that uses `MD5(key || message)` — a flawed design that allows attackers to append data and generate a valid MAC without knowing the key. It's part of a broader educational project on message integrity and MAC forgery.

---

## 🚨 Background: What is a Length Extension Attack?

A length extension attack exploits the way certain hash functions (like MD5, SHA1) process messages in blocks. If the MAC is computed as:

```
MAC = MD5(secret_key || message)
```

An attacker who knows:
- the `message`
- the resulting `MAC`

...can append additional data to the original message **and** compute a valid new MAC, **without knowing the secret key**.

---

## 🔍 Script Overview

The `client.py` script simulates the role of the attacker:

- Intercepts a legitimate `(message, MAC)` pair.
- Brute-forces the length of the unknown secret key.
- Constructs padding and forges a new message.
- Reconstructs internal MD5 state and appends attacker data.
- Verifies the forged message using the original server’s verification logic.

---

## 📂 Code Structure

| Function | Purpose |
|---------|---------|
| `md5_padding(msg_len)` | Returns the appropriate MD5 padding for the original message length. |
| `parse_md5_hexdigest(h)` | Parses a hex MD5 hash into internal state format. |
| `perform_attack()` | Core function: performs the brute-force attempt and prints results. |

---

## 🔧 Usage Instructions

### ✅ Requirements

Ensure all dependencies are installed:
```bash
pip install -r requirements.txt
```

### ▶️ Run the script

```bash
python client.py
```

---

## 🧪 Sample Output

```
Trying key length: 8
Forged message (hex): 68656c6c6f5f776f726c6480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000582661646d696e3d74727565
Forged MAC: 1a58f09fe47f93cf6a29ea452e7d57c6
[SUCCESS] Forged MAC is valid! Key length: 8
Forged message: b'hello_world\x80...&admin=true'
```

---

## 🧩 Concept Diagram

```mermaid
graph LR
A[Original Message & MAC] --> B[Attacker Adds Padding]
B --> C[Appends &admin=true]
C --> D[Recalculates MAC with known state]
D --> E[Forged Message + MAC]
E --> F[Server Validates (if insecure)]
```

---

## 📚 References

- [Length Extension Attack - Wikipedia](https://en.wikipedia.org/wiki/Length_extension_attack)
- [MD5 Padding and State Recovery](https://crypto.stackexchange.com/questions/39774)

---

## 🛡️ Mitigation Reminder

This attack only works when the server uses:
```python
MAC = MD5(key || message)
```

It **does not work** if the server uses secure constructions like:
- `HMAC(key, message)`
- `AES-CMAC`
