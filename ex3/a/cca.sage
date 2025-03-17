from edwards25519 import Edwards25519, EdPoint
import os
from hashlib import sha256
import random

class EdwardsElGamal:
    def __init__(self, security_param=128):
        self.lambda_security = security_param
        self.curve = Edwards25519()
        self.G = self.curve.create_point()  # Generator point
        self.L, self.h = self.curve.order()  # Order of the group and cofactor
        self.ell = 8  # Bits for Koblitz encoding padding

    def keygen(self):
        s = random.randint(1, int(self.L) - 1)
        H_point = self.G.mult(s)  # Public key: H = s * G
        return (H_point, s)  # (public_key, private_key)

    def encode_message(self, combined_value):

        if not isinstance(combined_value, int):
            combined_int = int.from_bytes(combined_value.encode('utf-8'), 'big')
        else:
            combined_int = combined_value

        k_bits = self.curve.p.bit_length()
        if combined_int.bit_length() > (k_bits - 1 - self.ell):
            raise ValueError("Combined value too long to encode in one block.")
        
        x0 = combined_int << self.ell 
        for i in range(2**self.ell):
            x = x0 + i
            if x >= self.curve.p:
                break
            f_val = self.curve.K(x**3 + self.curve.constants['a4']*x + self.curve.constants['a6'])
            if f_val.is_square():
                y = f_val.sqrt()
                ec_point = self.curve.EC(x, y)
                ed_x, ed_y = self.curve.ec2ed(ec_point)
                return EdPoint(ed_x, ed_y, self.curve)
        raise ValueError("Non-encodable combined value: tried 2^ell possibilities.")

    def decode_message(self, point):
        ec_point = self.curve.ed2ec(point.x, point.y)
        x_int = int(ec_point[0])
        combined_int = x_int >> self.ell
        return combined_int

    def H(self, value, length=32):
        return int.from_bytes(sha256(str(value).encode()).digest(), 'big') % (2**length)

    def encrypt_message(self, public_key, plaintext):
        """
        Encrypt with Fujisaki-Okamoto transformation, mixing r with the message.
        """
        m_int = int.from_bytes(plaintext.encode('utf-8'), 'big')
        
        max_message_bits = 182
        if m_int.bit_length() > max_message_bits:
            raise ValueError(f"Message too long. Must be <= {max_message_bits} bits.")

        r_bits = 64
        r = random.randint(1, (1 << r_bits) - 1)
        print(f"Parameter r: {r}")

        print("Mixing r with message and encoding the result...")
        combined = (r << max_message_bits) + m_int

        M = self.encode_message(combined)

        # ElGamal encryption
        print("Encrypting encoded message...")
        Gamma = self.G.mult(r)  # Gamma = r * G
        Kappa = public_key.mult(r)  # Kappa = r * H
        C = M.add(Kappa)  # C = M + Kappa

        c_2 = self.H(r)
        c_1 = ((int(Gamma.x), int(Gamma.y)), (int(C.x), int(C.y)))

        return (c_1, c_2)

    def decrypt_message(self, private_key, ciphertext):
        """
        Decrypt with Fujisaki-Okamoto transformation, recovering r and message.
        """
  
        c_1, c_2 = ciphertext
        (gamma_x, gamma_y), (c_x, c_y) = c_1

        print("Rebuilding the curve points and recovering r...")
        Gamma = self.curve.create_point(self.curve.K(gamma_x), self.curve.K(gamma_y))
        C = self.curve.create_point(self.curve.K(c_x), self.curve.K(c_y))

        Kappa = Gamma.mult(private_key)

        Kappa_inv = Kappa.sim()
        M = C.add(Kappa_inv)

        combined = self.decode_message(M)

        r_bits = 64
        max_message_bits = 182
        r = combined >> max_message_bits
        m_int = combined & ((1 << max_message_bits) - 1)

        r_hash_calculated = self.H(r)
        if r_hash_calculated != c_2:
            raise ValueError("Ciphertext integrity check failed.")

        print(f"Decrypted r: {r}")

        byte_length = (m_int.bit_length() + 7) // 8
        m_bytes = m_int.to_bytes(byte_length, 'big')
        return m_bytes.decode('utf-8')

if __name__ == "__main__":
    elgamal = EdwardsElGamal(security_param=128)
    public_key, private_key = elgamal.keygen()

    plaintext = "Hello"
    print("=" * 40)
    print(f"Original message: {plaintext}")
    print("=" * 40)

    encrypted_data = elgamal.encrypt_message(public_key, plaintext)
    (gamma, cipher_point), c_2 = encrypted_data
    gamma_x, gamma_y = gamma
    cipher_x, cipher_y = cipher_point

    print("=" * 40)
    print("======== ENCRYPTED DATA ========")
    print(f"Gamma (curve point):")
    print(f"  x: {gamma_x}")
    print(f"  y: {gamma_y}")
    print(f"Ciphertext (curve point):")
    print(f"  x: {cipher_x}")
    print(f"  y: {cipher_y}")
    print(f"c_2 (H(r)): {c_2}")

    try:
        decrypted = elgamal.decrypt_message(private_key, encrypted_data)
        print("=" * 40)
        print(f"Decrypted message: {decrypted}")
        print(f"Success? {plaintext == decrypted}")
        print("=" * 40)
    except ValueError as e:
        print(f"Decryption error: {e}")