from sage.all import *  # Importar todas as funções do SageMath
from edwards25519 import Edwards25519, EdPoint
from hashlib import sha256
import random
from operator import xor 

class EdwardsElGamal:
    """
    Implementação do ElGamal usando a curva Edwards25519 com transformação de Fujisaki-Okamoto
    """
    
    def __init__(self, security_param=128):
        """
        Inicializa o esquema ElGamal com a curva Edwards25519.
        """
        self.lambda_security = security_param
        self.curve = Edwards25519()  
        self.G = self.curve.create_point()  # Gerador da curva
        self.L, self.h = self.curve.order()  # Ordem do grupo e cofator
        self.ell = 8  # Número de bits para padding
    
    def keygen(self):
        """
        Gera um par de chaves (privada, pública) para ElGamal.
        """
        s = random.randint(1, int(self.L) - 1)  # Chave privada
        H_point = self.G.mult(s)  # Chave pública (multiplicação escalar)
        return (H_point, s)
    
    def H1(self, value, length=32):
        """
        Função hash H1 para gerar um valor de hash de tamanho fixo.
        """
        if isinstance(value, (int, Integer)):
            value_str = str(value)
        elif isinstance(value, tuple):
            value_str = f"{value[0]}:{value[1]}"
        elif isinstance(value, EdPoint):
            value_str = f"{value.x}:{value.y}"
        else:
            value_str = str(value)
        return int.from_bytes(sha256(value_str.encode()).digest(), byteorder='big') % (2**length)
    
    def H2(self, message, sigma, length=32):
        """
        Função hash H2 para derivar a aleatoriedade a partir da mensagem e sigma.
        """
        combined = f"{message}:{sigma}".encode()
        return int.from_bytes(sha256(combined).digest(), byteorder='big') % int(self.L)
    
    def H3(self, point, length=32):
        """
        Função hash H3 para gerar uma chave de cifra simétrica a partir de um ponto.
        """
        if isinstance(point, EdPoint):
            value_str = f"{point.x}:{point.y}"
        else:
            value_str = str(point)
        return int.from_bytes(sha256(value_str.encode()).digest(), byteorder='big') % (2**length)
    
    def encode_message(self, message):
        """
        Codifica uma mensagem em um ponto na curva usando o método de Koblitz.
        """
        m_int = int.from_bytes(message.encode('utf-8'), 'big')
        k_bits = self.curve.p.bit_length()
        if m_int.bit_length() > (k_bits - 1 - self.ell):
            raise ValueError("Message too long to encode in one block.")
        x0 = m_int << self.ell  # Adiciona padding de ell bits
        for i in range(2**self.ell):
            x = x0 + i
            if x >= self.curve.p:
                break
            # Calcula f(x) = x^3 + a*x + b mod p
            f_val = self.curve.K(x**3 + self.curve.constants['a4']*x + self.curve.constants['a6'])
            if f_val.is_square():
                y = f_val.sqrt()
                ec_point = self.curve.EC(x, y)
                ed_x, ed_y = self.curve.ec2ed(ec_point)
                return EdPoint(ed_x, ed_y, self.curve)
        raise ValueError("Non-encodable message: tried 2^ell possibilities.")

    def decode_message(self, point):
        """
        Decodifica um ponto na curva de volta para a mensagem original.
        """
        # Converte o ponto Edwards para Weierstrass
        ec_point = self.curve.ed2ec(point.x, point.y)
        # Extrai a coordenada x e remove o padding
        x_int = int(ec_point[0])
        m_int = x_int >> self.ell
        # Converte de volta para bytes e depois para string
        byte_length = (m_int.bit_length() + 7) // 8
        m_bytes = m_int.to_bytes(byte_length, 'big')
        return m_bytes.decode('utf-8')

    def xor_bytes(self, a, b):
        """
        Realiza XOR bit a bit entre dois valores inteiros.
        """
        # Garantir que ambos têm o mesmo comprimento em bytes
        max_len = max(a.bit_length(), b.bit_length()) // 8 + 1
        a_bytes = a.to_bytes(max_len, 'big')
        b_bytes = b.to_bytes(max_len, 'big')
        
        # Realiza o XOR byte a byte usando operator.xor
        result = bytes(map(xor, a_bytes, b_bytes))
        return int.from_bytes(result, 'big')

    def encrypt_message(self, public_key, plaintext):
        """
        Criptografa uma mensagem usando ElGamal com transformação de Fujisaki-Okamoto.
        
        1. Gera um valor aleatório sigma
        2. Deriva r = H2(plaintext, sigma)
        3. Calcula Gamma = r*G
        4. Calcula S = r*H (H é a chave pública)
        5. Calcula k = H3(S)
        6. Cifra o plaintext usando k: C = encode(plaintext) XOR k
        7. Retorna (Gamma, C, sigma)
        """
        # Gerar um valor sigma aleatório
        sigma = random.randint(1, 2**128)
        
        # Derivar r da mensagem e sigma usando H2
        r = self.H2(plaintext, sigma)
        print(f"Derived r : {r}")
        
        # Calcular Gamma = r*G
        Gamma = self.G.mult(r)
        
        # Calcular S = r*H (H é a chave pública)
        S = public_key.mult(r)
        
        # Derivar chave simétrica k = H3(S)
        k = self.H3(S)
        
        # Converter plaintext para inteiro para o XOR
        m_encoded = int.from_bytes(plaintext.encode('utf-8'), 'big')
        
        # Cifrar a mensagem: C = m XOR k
        C = self.xor_bytes(m_encoded, k)
        
        return ((int(Gamma.x), int(Gamma.y)), C, sigma)
    
    def decrypt_message(self, private_key, encrypted_data):
        """
        Decifra uma mensagem usando ElGamal com transformação de Fujisaki-Okamoto.
        
        1. Recupera (Gamma, C, sigma) do ciphertext
        2. Calcula S = s*Gamma (s é a chave privada)
        3. Deriva k = H3(S)
        4. Recupera o plaintext = C XOR k
        5. Verifica a integridade: r' = H2(plaintext, sigma)
        6. Verifica se Gamma = r'*G; se não, rejeita
        """
        (gamma_x, gamma_y), C, sigma = encrypted_data
        
        # Recria o ponto Gamma da curva
        Gamma = self.curve.create_point(self.curve.K(gamma_x), self.curve.K(gamma_y))
        
        # Calcula S = s*Gamma usando a chave privada
        S = Gamma.mult(private_key)
        
        # Deriva a chave simétrica k = H3(S)
        k = self.H3(S)
        
        # Decifra a mensagem: plaintext = C XOR k
        plaintext_int = self.xor_bytes(C, k)
        
        # Converte o inteiro de volta para texto
        byte_length = (plaintext_int.bit_length() + 7) // 8
        try:
            plaintext = plaintext_int.to_bytes(byte_length, 'big').decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Decryption failed. Invalid plaintext.")
        
        # Verifica a integridade: r' = H2(plaintext, sigma)
        r_prime = self.H2(plaintext, sigma)
        
        # Calcula Gamma' = r'*G
        Gamma_prime = self.G.mult(r_prime)
        
        # Verifica se Gamma' == Gamma
        if not (Gamma_prime.x == Gamma.x and Gamma_prime.y == Gamma.y):
            raise ValueError("Ciphertext integrity check failed. The ciphertext may have been changed.")
        
        return plaintext

if __name__ == "__main__":
    elgamal = EdwardsElGamal(security_param=128)
    
    public_key, private_key = elgamal.keygen()
    
    plaintext = "Hello World!"
    print("=" * 40)
    print(f"Mensagem original: {plaintext}")
    
    encrypted_data = elgamal.encrypt_message(public_key, plaintext)
    gamma, cipher_text, sigma = encrypted_data
    gamma_x, gamma_y = gamma
    
    print("=" * 40)
    print("==== DADOS CIFRADOS ====")
    print(f"Gamma (ponto na curva):")
    print(f"  x: {gamma_x}")
    print(f"  y: {gamma_y}")
    print(f"\nCiphertext: {cipher_text}")
    print(f"\nSigma: {sigma}")
    print("=" * 40)

    decrypted = elgamal.decrypt_message(private_key, encrypted_data)
    
    print(f"Mensagem decifrada: {decrypted}")
    print("=" * 40)
    print(f"Sucesso? {plaintext == decrypted}")
    print("=" * 40)

    # Teste de manipulação do ciphertext
    print("\nTestando integridade da cifra...")
    try:
        # Modificar o ciphertext
        manipulated_data = ((gamma_x, gamma_y), cipher_text + 1, sigma)
        decrypted = elgamal.decrypt_message(private_key, manipulated_data)
        print("FALHA: Decifrou mensagem manipulada!")
    except ValueError as e:
        print(f"SUCESSO: {e}")