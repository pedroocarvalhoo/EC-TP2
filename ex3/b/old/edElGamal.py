# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports 
from edwards25519 import Edwards25519
from edwards25519 import EdPoint
import os
from hashlib import sha256
import random
from operator import xor  

############################################################################################################################################################################
class EdwardsElGamal:
    """
    Implementação do ElGamal usando a curva Edwards25519
    """
    
    def __init__(self, security_param=128):
        """
        ElGamal em curvas de Edwards 
        """
        self.lambda_security = security_param
        self.curve = Edwards25519()  
        
        """
        Geramos o gerador , calculamos a ordem do grupo e o cofator
        """
        self.G = self.curve.create_point()  
        self.L, self.h = self.curve.order()  
        self.ell = 8  # Número de bits para padding
    
    def keygen(self):
        """
        Gera um par de chaves (privada,pública) para ElGamal a partir do gerador G
        """
        s = random.randint(1, int(self.L) - 1)
        H_point = self.G.mult(s)  #(multiplicação escalar)
        return (H_point, s)
    
    def encode_message(self, message):
        """
        Encodes a fixed-length message (string) into a point on the curve using a standardized Koblitz method.
        
        Steps:
          1. Convert message to integer m.
          2. Verify m fits in (k-1-ell) bits (where k is bit-length of p).
          3. Compute x0 = m << ell.
          4. For i in 0 to 2^ell - 1, let x = x0 + i:
                - Compute f(x) = x^3 + a*x + b mod p.
                - If f(x) is a quadratic residue, let y = sqrt(f(x)) and return the point (x, y).
          5. If no candidate works, raise an error.
        """
        m_int = Integer(int.from_bytes(message.encode('utf-8'), 'big'))
        k_bits = self.curve.p.bit_length()
        if m_int.bit_length() > (k_bits - 1 - self.ell):
            raise ValueError("Message too long to encode in one block.")
        x0 = m_int << self.ell  # Append ell zero bits.
        for i in range(2**self.ell):
            x = x0 + i
            if x >= self.curve.p:
                break
            # Compute f(x) = x^3 + a*x + b mod p.
            f_val = self.curve.K(x**3 + self.curve.constants['a4']*x + self.curve.constants['a6'])
            if f_val.is_square():
                y = f_val.sqrt()
                ec_point = self.curve.EC(x, y)
                ed_x, ed_y = self.curve.ec2ed(ec_point)
                return EdPoint(ed_x, ed_y, self.curve)
        raise ValueError("Non-encodable message: tried 2^ell possibilities.")

    def decode_message(self, point):
        """
        Decodes a point on the Edwards curve back to the original message.
        
        Args:
            point: An EdPoint encoding a message
            
        Returns:
            str: The decoded message
        """
        # Convert Edwards point to Weierstrass point
        ec_point = self.curve.ed2ec(point.x, point.y)
        
        # Extract x-coordinate and remove padding
        x_int = int(ec_point[0])
        m_int = x_int >> self.ell
        
        # Convert back to bytes and then to string
        byte_length = (m_int.bit_length() + 7) // 8
        m_bytes = m_int.to_bytes(byte_length, 'big')
        
        return m_bytes.decode('utf-8')

    def encrypt_message(self, public_key, plaintext):
        """
        Encrypts a message using ElGamal with point encoding
        """
        # Encode the message as a point
        M = self.encode_message(plaintext)
        
        # Generate random value
        omega = random.randint(1, int(self.L) - 1)
        
        # Calculate Gamma = G * omega
        Gamma = self.G.mult(omega)
        
        # Calculate S = public_key * omega
        S = public_key.mult(omega)
        
        # Encrypt: C = M + S
        C = M.add(S)
        
        # Return the ciphertext as (Gamma, C)
        return ((int(Gamma.x), int(Gamma.y)), (int(C.x), int(C.y)))

    def decrypt_message(self, private_key, encrypted_data):
        """
        Decrypts a message using ElGamal with point encoding
        """
        (gamma_x, gamma_y), (c_x, c_y) = encrypted_data
        
        # Recreate the points
        Gamma = self.curve.create_point(self.curve.K(gamma_x), self.curve.K(gamma_y))
        C = self.curve.create_point(self.curve.K(c_x), self.curve.K(c_y))
        
        # Calculate S = Gamma * private_key
        S = Gamma.mult(private_key)
        
        # Get the inverse of S
        S_inv = S.sim()
        
        # Decrypt: M = C - S = C + (-S)
        M = C.add(S_inv)
        
        # Decode the point back to a message
        return self.decode_message(M)