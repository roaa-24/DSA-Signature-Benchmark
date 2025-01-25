import time
import hashlib
import random
import secrets

# Berechnung der Schnorr-Signatur
def schnorr_sign(message, private_key, p, q, g):
    # Zufälliger Wert k soll zwischen 1 und q-1 sein 
    k = random.randint(1, q - 1)
    
    # Berechnung von r wobei  r = (g^k mod p) mod q
    r = pow(g, k, p) % q
    
    # r in Bytes umwandeln das ist wichtig fuer die kkonkatenierte Hashing
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    
    # Berechnung von e = Hash(r || Nachricht)

    e = int(hashlib.sha256(r_bytes + message).hexdigest(), 16) % q
    
    # Berechnung der Signatur s: s = (k + e * private_key) mod q
    s = (k + e * private_key) % q
    
    return (r, s)

# Funktion zur Durchführung des Schnorr-Tests
def schnorr_test(num_signatures, key_size):
    # Parameter für Schnorr entsprechend der DSA Schlüssellänge
    if key_size == 1024:
        p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
        q = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831
    elif key_size == 2048:
        p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    elif key_size == 3072:
        p = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        q = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    else:
        raise ValueError("Unsupported key size")
    
    # Generator g (ein häufiger Wert für g ist 2)
    g = 2

    # Zufälliger privater Schlüssel und Nachricht
    private_key = secrets.randbelow(q)
    message = secrets.token_bytes(32)  # Zufällige 32-Byte-Nachricht

    # Test mit mehreren Signaturen
    for _ in range(num_signatures):
        start_time = time.time()
        signature = schnorr_sign(message, private_key, p, q, g)
        end_time = time.time()
        print(f"Signatur: {signature}, Zeit: {end_time - start_time:.6f} Sekunden")

# Beispielaufruf
schnorr_test(5, 1024)
