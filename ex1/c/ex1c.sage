import hashlib
import os

# Security parameter
_lambda = 128
lambda_bits = _lambda.nbits()


#ignora this function, it is just to make the output more readable
def truncate_large_number(number, max_digits=20):
    """Display large numbers in a more readable way by showing only parts"""
    str_num = str(number)
    if len(str_num) <= max_digits:
        return str_num
    else:
        return f"{str_num[:max_digits//2]}...{str_num[-max_digits//2:]}"
    
    
# Reuse parameter_generator and verify_parameters from ex1b.sage
def parameter_generator(_lambda):
    lower_bound = 2^(_lambda - 1)
    upper_bound = 2^_lambda - 1
    q_candidate = randint(lower_bound, upper_bound)
    q = next_prime(q_candidate)
    
    min_p_bits = _lambda * lambda_bits
    
    min_k = (2^(min_p_bits - 1) - 1) // q
    max_k = (2^min_p_bits - 1) // q
    
    p = 0
    import time
    
    start = time.time()
    while True:
        k = randint(min_k, max_k)
        p_candidate = k * q + 1
        if is_prime(p_candidate) and p_candidate.nbits() >= min_p_bits:
            p = p_candidate
            break
        k += 1
    end = time.time()
    print("Time taken to generate p: ", end - start)
        
    g = 0
    while True:
        a = randint(2, p - 2)
        g = power_mod(a, (p - 1) // q, p)
        if g != 1:
            break
        
    s = randint(1, q - 1)
    h = power_mod(g, s, p)
    
    return p, q, g, h, s

def verify_parameters(p, q, g):
    if not is_prime(p):
        print("Error: p is not prime.")
        return False
    if not is_prime(q):
        print("Error: q is not prime.")
        return False
    
    if (p - 1) % q != 0:
        print("Error: q does not divide p-1.")
        return False
    
    if power_mod(g, q, p) != 1:
        print("Error: g^q ≠ 1 mod p.")
        return False
    
    for _ in range(10):
        k = randint(2, q - 1)
        if power_mod(g, k, p) == 1:
            print(f"Error: g^{k} ≡ 1 mod p.")
            return False
    
    print("All parameters are correctly defined. \n")
    return True

def H(value, length=32):
    """
    Hash function H
    """
    return int.from_bytes(hashlib.sha256(str(value).encode()).digest(), byteorder='big') % (2^length)


def KEM_KeyGen(_lambda):
    """
    Generate public and private keys for the KEM
    
    A Key Encapsulation Mechanism (KEM) is designed specifically for securely 
    generating and communicating symmetric keys (rather than arbitrary messages).
    
    In a KEM, the key generation phase works similarly to standard asymmetric 
    encryption schemes, generating a keypair that will later be used for 
    encapsulating (protecting) a randomly generated key.
    """
    
    p, q, g, h, s = parameter_generator(_lambda)
    
    """
    The public and secret key are derived from ElGamal parameters:
    - Public key contains the group parameters (p, q, g) and the public element h
    - Secret key is the private exponent s
    
    Unlike message encryption, KEMs are specifically designed for key transport,
    where we generate and protect random keys rather than encrypting user-provided data.
    """
    
    pk = (p, q, g, h)
    sk = s
    
    return pk, sk


def KEM_Encaps(pk):
    """
    Generate a random key and its encapsulation
    
    The key difference between a KEM and standard encryption:
    - In encryption: We take a user-provided message and produce ciphertext
    - In KEM: We GENERATE a random key and produce its encapsulation
    
    This function actually has two outputs:
    1. A randomly generated key (which will be used with symmetric encryption)
    2. An encapsulation of that key (which can be sent over insecure channels)
    """
    
    p, q, g, h = pk
    
    # Generate a random key of 128 bits (16 bytes)

    key_bytes = os.urandom(16)
    key = int.from_bytes(key_bytes, byteorder='big')
    
    """
    The key generation is what makes a KEM different from regular encryption:
    - This key wasn't provided by the user
    - We generated it randomly within the KEM
    - We return both the key and its protected form (encapsulation)
    """
    
    # Fujisaki-Okamoto parameter
    r = randint(1, q - 1)
    
    # ElGamal
    gamma = power_mod(g, r, p)
    kappa = power_mod(h, r, p)
    
    # Fujisaki-Okamoto
    combined = (r << 128) + key
    
    # Encrypt 
    ciphertext = (combined * kappa) % p
    
    # Hash the random value r
    r_hash = H(r)
    
    """
    The returned values are the encapsulation and the key itself
    We encapsulate gamma, ciphertext, and r_hash
    """

    encapsulation = (gamma, ciphertext, r_hash)
    
    return encapsulation, key_bytes


def KEM_Decaps(encapsulation, sk, p, q):
    
    """
    Recover the key from its encapsulation
    
    In a KEM, decapsulation is the process of recovering the randomly generated
    symmetric key from its protected form (encapsulation).
    
    A critical feature is that it verifies the integrity of the encapsulation
    to ensure no tampering occurred during transmission.
    
    This makes KEM+symmetric encryption resistant to chosen-ciphertext attacks.
    """
    
    #ciphertext in KEM is r + key
    gamma, ciphertext, r_hash = encapsulation
    
    """
    The decapsulation process works similarly to decryption in ElGamal with
    Fujisaki-Okamoto transformation, but with a focus on recovering the
    randomly generated key rather than a user message.
    """
    
    # Compute kappa and kappa_inv using private key
    kappa = power_mod(gamma, sk, p)
    kappa_inv = power_mod(kappa, -1, p)
    
    # Decrypt the combined value
    combined = (ciphertext * kappa_inv) % p
    
    """
    Extract both the random parameter r and the key:
    - r was used to randomize the encryption and provide integrity
    - key_int is the actual symmetric key we want to recover
    """
    
    r = combined >> 128
    key_int = combined & ((1 << 128) - 1)
    
    """
    Integrity check
    """
    
    r_hash_calculated = H(r)
    
    if r_hash_calculated != r_hash:
        raise ValueError("Encapsulation integrity check failed")
    
    # Convert key_int back to bytes
    key_bytes = key_int.to_bytes(16, byteorder='big')
    
    return key_bytes


def symmetric_encrypt(message, key_bytes):
    
    """
    Data Encapsulation Mechanism (DEM) using One-Time Pad (XOR)
    """
    
    # Convert message to bytes if it's a string
    if isinstance(message, str):
        message_bytes = message.encode('utf-8')
    else:
        message_bytes = message
    
    if len(key_bytes) < len(message_bytes):
        raise ValueError("Key must be at least as long as the message for OTP")
    
    ciphertext = bytearray()
    
    for m, k in zip(message_bytes, key_bytes):
        # had to change ^ to __xor__ because of a translation error
        ciphertext.append(int(m).__xor__(int(k)))
    
    return bytes(ciphertext)

def symmetric_decrypt(ciphertext, key_bytes):
    """
    Decrypt using One-Time Pad
    """
    
    plaintext_bytes = bytearray()
    for c, k in zip(ciphertext, key_bytes):
        # had to change ^ to __xor__ because of a translation error
        plaintext_bytes.append(int(c).__xor__(int(k)))
    
    try:
        return plaintext_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return plaintext_bytes
    

if __name__ == "__main__":
    
    original_message = "Hello World!"
    print(f"Original message: {original_message}")
    
    print("\nGenerating KEM keys...\n")
    pk, sk = KEM_KeyGen(_lambda)
    p, q, g, h = pk
    
    print(f"p = {truncate_large_number(p)} ({p.nbits()} bits)")
    print(f"q = {truncate_large_number(q)} ({q.nbits()} bits)")
    print(f"g = {truncate_large_number(g)}")
    print(f"Private key s = {sk}")
    
    verify_parameters(p, q, g)
    
    print("Performing key encapsulation...\n")
    encapsulation, key = KEM_Encaps(pk)
    
    print(f"Generated key: {key.hex()}")
    
    gamma, ciphertext, r_hash = encapsulation
    print("Encapsulation:")
    print(f"gamma = {truncate_large_number(gamma)} ({gamma.nbits()} bits)")
    print(f"ciphertext = {truncate_large_number(ciphertext)} ({ciphertext.nbits()} bits)")
    print(f"H(r) = {r_hash}")
    
    # Data encryption (DEM part)
    print("\nEncrypting message with the generated key...")
    encrypted_message = symmetric_encrypt(original_message, key)
    
    print(f"Encrypted message: {encrypted_message.hex()}")
    
    print("\nSending encripted message to receiver...")
    
    # Key decapsulation (receiver)
    print("\nReceiver performing key decapsulation...")
    decapsulated_key = KEM_Decaps(encapsulation, sk, p, q)
    print(f"Recovered key: {decapsulated_key.hex()}")
    
    # Data decryption (receiver)
    print("\nDecrypting message with recovered key...")
    decrypted_message = symmetric_decrypt(encrypted_message, decapsulated_key)
    print(f"Decrypted message: {decrypted_message}")
    
    if decrypted_message == original_message:
        print("\nHybrid encryption successful!")
    else:
        print("\nError: Decrypted message does not match original!")
    
    # Test integrity check
    print("\nModifying encapsulation to test integrity check...")
    # Change encapsulation
    gamma, ciphertext, r_hash = encapsulation
    modified_encapsulation = (gamma, ciphertext + 1, r_hash)
    
    try:
        modified_key = KEM_Decaps(modified_encapsulation, sk, p, q)
        print("Error: Decapsulation succeeded with modified encapsulation")
    except ValueError as e:
        print(f"Expected error (integrity check): {e}")