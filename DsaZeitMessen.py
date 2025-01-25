import time
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Berechnung der durchschnittlichen Zeit für DSA-Signaturen
def dsa_signatur_zeit(num_signatures, länge):  
    # DSA Key 
    key = DSA.generate(länge)
    signer = DSS.new(key, 'fips-186-3')
    
    # Message + Hash berechnen
    msg = b'Signature'
    h = SHA256.new(msg)
    total_time = 0

    # Mehrfache Signaturen durchführen
    for _ in range(num_signatures):
        start_time = time.time()
        signature = signer.sign(h)
        total_time += time.time() - start_time

    # Durchschnittliche Zeit/ Signatur berechnen
    avg_time = total_time / num_signatures
    return avg_time

# Vergleichs-Funktion für DSA-Signaturzeiten am besten arth um den Unterschied deutlich zu sehen.
def compare_dsa_sign_times():
    bit_lengths = [1024, 2048, 3072]
    num_signatures_list = [100, 500, 800]
    
    # Tests für jede Schlüssellänge durchführen
    for länge in bit_lengths:
        print(f"Vergleich für DSA {länge}-Bit Schlüssel:")
        for num_signatures in num_signatures_list:
            avg_time = dsa_signatur_zeit(num_signatures, länge)
            print(f"  {num_signatures} Signaturen: Durchschnittliche Zeit = {avg_time:.6f} Sekunden")

# main
if __name__ == "__main__":
    compare_dsa_sign_times()
