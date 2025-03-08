#!/usr/bin/env sage

import hashlib
from sage.rings.finite_rings.finite_field_constructor import GF

# 1. Choose the parameters
_lambda = 128  # security parameter
lambda_bits = _lambda.nbits()

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

def generate_oblivious_criterion(n,kappa,q):
    """
    Vamos gerar o OT
    
    Parâmetros:
    - n: numero total de mensagens disponíveis
    - kappa: numero de mensagens a serem transferidas
    - q: numero primo do ElGamal
    """
    
    """
    Começamos por gerar um grupo Zq, com q primo
    Todas as operações aritméticas serão feitas neste grupo
    """
    
    Zq = GF(q)
    
    """
    Geramos a seed que será responsável por gerar A e u
    Esta seed serve como fonte de aleatoriedade para gerar A e u de forma determinística.
    O remetente conhece rho, mas o receptor não.
    """
    
    rho = randint(1, q - 1) #verificar se é este o intervalo correto
    
    
    """
    Criamos a matriz A de dimensão n x (n-kappa).
    """
    
    A = matrix(Zq, n, n-kappa)
    for i in range(n):
        for j in range(n-kappa):
            # Geramos cada elemento usando hash de rho, i, j para garantir pseudoaleatoriedade
            A[i,j] = Zq(H(str(rho) + str(i) + str(j), length=q.nbits())) 
            
    """
    Criamos o vetor u de dimensão (n-κ).
    """
    
    u = vector(Zq, n-kappa)                   
    for i in range(n-kappa):
        # Em vez de j usamos n 
        u[j] = Zq(H(str(rho) + str(n) + str(j), length=q.nbits()))
        
    """
    O par (A,u) constitui o OC.
    - A matriz A define as restrições lineares
    - O vetor u define os valores que devem ser satisfeitos
    
    Este sistema é construído de tal forma que:
    1. Para qualquer subconjunto de κ linhas da matriz A, existe uma 
       solução v (que vai ser gerado pelo recetor) tal que A_subset * v = u_subset
    2. Para qualquer subconjunto de κ+1 ou mais linhas, não existe tal solução
    
    Esta propriedade matemática é o que garante que exatamente κ mensagens
    podem ser recuperadas, nem mais nem menos.
    """
    
    return A, u, rho
    

def H(value, length=32):
    """
    Função hash H mencionada no documento
    """
    return int.from_bytes(hashlib.sha256(str(value).encode()).digest(), byteorder='big') % (2^length)


def enc(plaintext, p, q, g, h):
    # Converter mensagem para bytes se for string
    if isinstance(plaintext, str):
        m_bytes = plaintext.encode('utf-8')
    else:
        m_bytes = plaintext
    
    # Converter bytes para int
    m_int = int.from_bytes(m_bytes, byteorder='big')
    
    if m_int >= p:
        raise ValueError(f"Plaintext too large, must be less than p ({p.nbits()} bits)")
    
    r = randint(1, q - 1)
    
    print(f"Parameter r : {r}")
    print("This parameter will be used to randomize the message and add some integrity to the encryption")
    
    gamma = power_mod(g, r, p)
    kappa = power_mod(h, r, p)
    
    combined = (r << 128) + m_int

    ciphertext = (combined * kappa) % p
    
    c_2 = H(r)
    c_1 = (gamma, ciphertext)
    
    return c_1, c_2


def dec(ciphertext, private_key, p, q):
 
    c_1, c_2 = ciphertext
    gamma, encrypted_message = c_1

    
    kappa = power_mod(gamma, private_key, p)
    kappa_inv = power_mod(kappa, -1, p)
    

    combined = (encrypted_message * kappa_inv) % p
    
    r = combined >> 128 
    
    print(f"decrypted r : {r}")
    m_int = combined & ((1 << 128) - 1)
    
    r_hash_calculated = H(r)
    if r_hash_calculated != c_2:
        raise ValueError("Ciphertext integrity check failed. The ciphertext may have been changed.")
    
    try:
        m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')
        plaintext = m_bytes.decode('utf-8')
        return plaintext
    except UnicodeDecodeError:
        raise ValueError("Failed to decode the plaintext.")



if __name__ == "__main__":
    
    plaintext = "Hello World!!!!"
    
    p, q, g, h, s = parameter_generator(_lambda)
    
    print(f"p = {p} ({p.nbits()} bits)")
    print(f"q = {q} ({q.nbits()} bits)")
    print(f"g = {g}")
    print(f"s = {s}")
     
    verify_parameters(p, q, g)

    c_1, c_2 = enc(plaintext, p, q, g, h)
    
    print(f"c_1 = {c_1}")
    print(f"c_2 = {c_2}")
    
    try:
        new_plaintext = dec((c_1, c_2), s, p, q)
        print(f"Decrypted Plaintext = {new_plaintext}")
    except ValueError as e:
        print(e)