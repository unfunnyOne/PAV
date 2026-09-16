# Cryptography stuff
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# DPAPI related stuff
import ctypes
from ctypes import wintypes
crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

# Other
from pathlib import Path
import uuid
import json
from warnings import warn

# So, the plan is:
# 1. Generate a key(duh)
# 2. Encrypt it with DPAPI and save the result to config
# 3. Decrypt it with DPAPI whenever it's needed(like moving a file to or from quarantine)
# Sounds simple, in practice might be a pain. But we'll see
# Oh, and also! DPAPI uses user's credentials as a key for encryption, so this should be launched as administrator
# for maximum security(if malware has admin access, you're already cooked anyway, so)

# All of this isn't really necessary(who would want to decrypt a malicious file, come on! If you've got malware
# trying to restore other malware, why not just make it do the job instead? That's stupid)
# The only thing I can think of is: two pieces of malware monitoring each other. If one gets quarantined, the second one
# tries to restore it before getting quarantined itself. But, like, who's gonna complicate it that much?
# Guess we'll never know. I'm doing it the hard way because it's a good practice to do so

# DPAPI communicates with DATA_BLOB's
# cbData is the number of bytes, pbData is a pointer to those bytes
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte))
    ]

def _protectKey(data: bytes):
    blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))

    # I'll be honest, I'm too lazy right now to dedicate a few hours to researching the exact mechanism of this
    # The next fragment was shamelessly copy-pasted
    blob_out = DATA_BLOB()
    if not crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)

def _unprotectKey(data: bytes):
    blob_in = DATA_BLOB(len(data), ctypes.cast(ctypes.create_string_buffer(data), ctypes.POINTER(ctypes.c_byte)))

    # The same thing as _protectKey(). Thank you, stranger on the internet from 6 years ago
    blob_out = DATA_BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)

# I'll be using a masterkey, because separate keys for each file is an overkill. Sure, it would be fuckin' funny
# to quarantine ten morbillion eicars and have the keys file weight, like, 10 GB. But it really isn't necessary
# As I said before, why would any malicious actor care about restoring malware files?
# Adding a path argument just because it's a good practice, I guess. Avoiding hardcode and all that
def _generateKey(path: Path = Path(__file__).resolve().parent.parent/"config/qkey.dat") -> bool:
    if path.exists():
        warn(f"A key already exists! Delete {path} if you want to generate a new one")
        return False

    key = get_random_bytes(32)
    try:
        with open(path, "wb") as file:
            file.write(_protectKey(key))
    except Exception as e:
        warn(f"Failed to write a protected key: {e}")
        return False
    return True

def _getKey(path: Path = Path(__file__).resolve().parent.parent/"config/qkey.dat") -> tuple[bool, bytes] | tuple[bool, None]:
    try:
        with open(path, "rb") as f:
            return True, _unprotectKey(f.read())
    except Exception as e:
        warn(f"Failed to get a key: {e}")
        return False, None

def _addMetadata(data: dict, file_id: str, key: bytes, metadir: Path = Path(__file__).resolve().parent.parent/"quarantine/meta") -> bool:
    plaintext = json.dumps(data).encode("utf-8")

    nonce = get_random_bytes(12)
    cipher = AES.new(key,AES.MODE_GCM,nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    with open(metadir/f"{file_id}.meta", "wb") as f:
        f.write(nonce+tag+ciphertext)
        return True

def _getMetadata(file_id: str, key: bytes, metadir: Path = Path(__file__).resolve().parent.parent/"quarantine/meta") -> dict | None:
    try:
        with open(metadir/f"{file_id}.meta", "rb") as f:
            data = f.read()
    except Exception as e:
        warn(f"Failed to load the meta file: {e}")
        return None

    nonce = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # It might raise an exception if the file was modified/key is wrong
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception as e:
        warn(f"Failed to decrypt and verify {metadir/f"{file_id}.meta"}: {e}")
        return None

    return json.loads(plaintext.decode("utf-8"))