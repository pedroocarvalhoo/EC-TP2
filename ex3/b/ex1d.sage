#!/usr/bin/env sage

import hashlib
import os
from sage.rings.finite_rings.finite_field_constructor import GF
load('utils.sage')


elgamal_params = None

def matrixA(Gf, lines, cols, seed):
    A = matrix(Gf, lines, cols)
    for i in range(lines):
        for j in range(cols):
            A[i,j] = Gf(H(str(seed) + str(i) + str(j), length=q.nbits())) 
    return A

def vectorU(Gf, cols, seed):
    u = vector(Gf, cols)
    for i in range(cols):
        u[i] = Gf(H(str(seed) + str(i), length=q.nbits()))
    return u

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
    O remetente conhece rho, mas o receiver não.
    """
    
    rho1 = os.urandom(16).hex()
    rho2 = os.urandom(16).hex()
    
    """
    Criamos a matriz A de dimensão n x (n-kappa).
    """
    
    A = matrixA(Zq, n, n-kappa,rho1)
            
    """
    Criamos o vetor u de dimensão (n-k).
    """

    u = vectorU(Zq, n-kappa, rho2)                   

    """
    O par (A,u) constitui o OC.
    - A matriz A define as restrições lineares
    - O vetor u define os valores que devem ser satisfeitos
    
    Este sistema é construído de tal forma que:
    1. Para qualquer subconjunto de k linhas da matriz A, existe uma 
       solução v (que vai ser gerado pelo recetor) tal que A_subset * v = u_subset
    2. Para qualquer subconjunto de k+1 ou mais linhas, não existe tal solução
    
    Esta propriedade matemática é o que garante que exatamente k mensagens
    podem ser recuperadas, nem mais nem menos.
    """
    return A, u, (rho1, rho2)

def compute_goodKeys (selected_indices, n, elgamal_params):
    
    p_vector = [None] * n
    good_keys = {}
    
    p, q, g, h, master_private_key = elgamal_params
    
    """
    Para cada índice selecionado, geramos um par de chaves ElGamal.
    """
    
    for i in selected_indices:
        private_key = randint(1, q - 1)
        public_key = power_mod(g, private_key, p)
        good_keys[i] = (public_key, private_key)
        p_vector[i] = public_key
    
    secret = os.urandom(_lambda // 8)
    indices_bytes = b"".join([i.to_bytes(4, 'big') for i in selected_indices])
    
    tag = hashlib.sha256(indices_bytes + secret).digest()
    
    return good_keys, tag, p_vector, secret


def complete_p_vector(Zq, A, u, selected_indices,p_vector):
    
    """
    Completa o vetor p com valores aleatórios para os índices não selecionados.
    """

    n = A.nrows()
    
    all_indices = set(range(n))
    unselected_indices = sorted(list(all_indices - set(selected_indices)))
    
    R = vector(Zq, u)
    for i in selected_indices:
        if p_vector[i] is not None:  
            row = vector(Zq, A[i])
            R -= p_vector[i] * row
            
    B_rows = [vector(Zq, A[j]) for j in unselected_indices]
    B = matrix(Zq, B_rows)
    
    B_inv = B.inverse()
    X = R * B_inv
    
    for idx, j in enumerate(unselected_indices):
        p_vector[j] = int(X[idx])
        
    return p_vector
 
def generate_query_vector(A, u, selected_indices, q,p):
    """
    Gerar o vetor v, que será usado pelo provider para garantir que o recetor está a fazer uma escolha justa, e nao a tentar obter mais mensagens do que as permitidas
    """
    
    """
    Extraímos as dimensões da matriz A para determinar n e k.
    Isto é feito desta forma por consistência - ambos Provider e receiver já conhecem estes valores.
    Desta forma confirmamos que tamos a enviar A e u corretos.
    """
    
    n, n_minus_kappa = A.dimensions()
    kappa = n - n_minus_kappa
    
    """
    Verificamos se o número de índices selecionados é exatamente kappa.
    O protocolo foi projetado para funcionar apenas com k índices, nem mais nem menos.
    """
    
    if len(selected_indices) != kappa:
        raise ValueError(f"O receiver não escolheu {kappa} índices")
    
    """
    Primeiro, geramos as chaves para os índices selecionados e inicializamos o vetor p
    """
    Zq = GF(q)
    good_keys, tag, p_vector, secret = compute_goodKeys(selected_indices, n,elgamal_params)
    
    """
    Depois, completamos o vetor p com os valores para os índices não selecionados
    """
    p_vector = complete_p_vector(GF(p), A, u, selected_indices, p_vector)
    
    """
    Este vetor p tem a propriedade matemática que:
    - Para índices selecionados i: p·A[i] = u·A[i]
    - Para índices não selecionados j: p·A[j] ≠ u·A[j]
    
    Isto garante que apenas as mensagens dos índices selecionados podem ser decifradas.
    """
    
    return p_vector, tag, good_keys
        
def verify_criterion(p_vector, A, u, p):
    """
    Verifica se o vetor p satisfaz o critério oblivioso: p·A = u
    """
    Zq = GF(p)
    n = len(p_vector)
    d = len(u)
    
    total = vector(Zq, [0] * d)
    for i in range(n):
        row = vector(Zq, A[i])
        total += (p_vector[i] % p) * row
        
    u_vec = vector(Zq, u)
    return total == u_vec

def H(value, length=32):
    return int.from_bytes(hashlib.sha256(str(value).encode()).digest(), byteorder='big') % (2^length)

def encrypt_messages(messages, A, u, query_vector, tag, elgamal_params):
    """
    FASE 3: CIFRA DAS MENSAGENS (Provider)
    
    Função simplificada que cifra cada mensagem usando a chave pública correspondente
    do vetor de consulta (query_vector).
    """
    p_elgamal, q, g, h, s = elgamal_params
    
    encrypted_messages = []
    
    for i in range(len(messages)):
        try:
            # A chave pública para este índice é o elemento do query_vector
            public_key_h = query_vector[i]
            
            # Converter a mensagem para bytes se for string
            if isinstance(messages[i], str):
                m_bytes = messages[i].encode('utf-8')
            else:
                m_bytes = messages[i]
            
            # Converter para inteiro
            m_int = int.from_bytes(m_bytes, byteorder='big')
            
            # Gerar valor aleatório r
            r = randint(1, q - 1)
            print(f"Parameter r : {r}")
            
            # Componentes de cifragem
            gamma = power_mod(g, r, p_elgamal)
            kappa = power_mod(public_key_h, r, p_elgamal)
            
            # Combinar r com a mensagem
            combined = (r << 128) + m_int
            encrypted_message = (combined * kappa) % p_elgamal
            
            # Hash para integridade, incorporando tag
            c_2 = H(str(r) + str(tag.hex()))
            c_1 = (gamma, encrypted_message)
            
            encrypted_messages.append({
                'index': i,
                'ciphertext': (c_1, c_2)
            })
            
        except Exception as e:
            print(f"Erro ao cifrar mensagem {i}: {e}")
    
    return encrypted_messages

def decrypt_messages(encrypted_messages, selected_indices, good_keys, tag, elgamal_params):
    """
    FASE 4: DECIFRA AS MENSAGENS (receiver)
    """
    p_elgamal, q, g, h, s = elgamal_params
    
    decrypted_messages = {}
    
    for message_data in encrypted_messages:
        i = message_data['index']
        
        if i not in selected_indices:
            print(f"Mensagem {i}: não selecionada, ignorando")
            continue
            
        try:
            ciphertext = message_data['ciphertext']
            c_1, c_2 = ciphertext
            gamma, encrypted_message = c_1
            
            # Chave privada para este índice
            private_key = good_keys[i][1]
            
            # Decifrar
            kappa = power_mod(gamma, private_key, p_elgamal)
            kappa_inv = power_mod(kappa, -1, p_elgamal)
            
            combined = (encrypted_message * kappa_inv) % p_elgamal
            r = combined >> 128
            m_int = combined & ((1 << 128) - 1)
            
            # Verificar integridade com tag
            r_hash_calculated = H(str(r) + str(tag.hex()))
            
            if r_hash_calculated != c_2:
                print(f"  Mensagem {i}: falha na verificação de integridade")
                continue
                
            print(f"  Mensagem {i}: verificação bem-sucedida!")
            
            m_bytes = m_int.to_bytes((m_int.bit_length() + 7) // 8, byteorder='big')
            plaintext = m_bytes.decode('utf-8')
            
            decrypted_messages[i] = plaintext
            print(f"  Mensagem {i} decifrada: {plaintext}")
            
        except Exception as e:
            print(f"Não foi possível decifrar mensagem {i}: {e}")
    
    return decrypted_messages

if __name__ == "__main__":
    """
    TESTE DO PROTOCOLO OBLIVIOUS TRANSFER k-OUT-OF-n
    """
    
    print("=" * 60)
    print("TESTE DO PROTOCOLO OBLIVIOUS TRANSFER k-OUT-OF-n")
    print("=" * 60)
    

    while True:
        try:
            n = int(input("Nº total de mensagens (n): "))
            if n <= 0:
                print("O número de mensagens deve ser maior que 0.")
                continue
                
            kappa = int(input(f"Quantas mensagens quer receber? (k <= {n}): "))
            if kappa <= 0:
                print("O número de mensagens a transferir deve ser maior que 0.")
                continue
            if kappa > n:
                print(f"O número de mensagens a transferir não pode ser maior que ({n}).")
                continue       
            break
        except ValueError:
            print("Por favor, digite valores numéricos válidos.")
    
    print(f"Parâmetros: n={n}, k={kappa}")
    
    # FASE 1: CONFIGURAÇÃO (Provider)
    print("\n" + "=" * 40)
    print("FASE 1: CONFIGURAÇÃO (Provider)")
    print("=" * 40)
    
    print("A gerar parametros para o ElGamal...")
    
    _lambda = 128 
    p_elgamal, q, g, h, s = parameter_generator(_lambda)
    elgamal_params = (p_elgamal, q, g, h, s)
    
    print(f"p = {p_elgamal} ({p_elgamal.nbits()} bits)")
    print(f"q = {q} ({q.nbits()} bits)")
    print(f"g = {g}")
    print(f"h = {h}")
    print(f"s = {s} (chave privada)")
    
    print("\n A gerar o Protocolo OT (A, u)...")
    A, u, rho = generate_oblivious_criterion(n, kappa, q)
    
    print(f"Matriz A ({A.nrows()}×{A.ncols()}):")
    print(A)
    print(f"Vetor u ({len(u)} elementos):")
    print(u)
    print(f"Seed rho (secreta): {rho}")
     
    messages = [f"Mensagem {i+1}" for i in range(n)]
    print("\nMensagens disponíveis:")
    for i, msg in enumerate(messages):
        print(f"  [{i}] {msg}")
    
    # FASE 2: SELEÇÃO E CONSULTA (Receiver)
    print("\n" + "=" * 40)
    print("FASE 2: SELEÇÃO E CONSULTA (Receiver)")
    print("=" * 40)
    
    import random
    selected_indices = sorted(random.sample(range(n), kappa))
    
    print(f"Receiver escolheu os índices: {selected_indices}")
    print(f"Mensagens que devem ser enviadas:")
    for idx in selected_indices:
        print(f"  [{idx}] {messages[idx]}")
    
    # GERAR O VETOR DE CONSULTA
    print("\nA gerar vetor de consulta p...")
    query_vector, tag, good_keys = generate_query_vector(A, u, selected_indices, q,p_elgamal)
    print(f"Vetor p: {query_vector}")
    print(f"Tag: {tag.hex()}")
    
    # Verificar propriedade do vetor de consulta
    print("\nVerificando propriedade do vetor de consulta:")
    verification_result = verify_criterion(query_vector, A, u, p_elgamal)
    print(f"Verificação global: p·A = u? {verification_result}")


    # FASE 3: CIFRAR AS MENSAGENS (Provider)
    print("\n" + "=" * 40)
    print("FASE 3: CIFRAR AS MENSAGENS (Provider)")
    print("=" * 40)
    
    # Cifrar mensagens
    print("A cifrar mensagens...")
    encrypted_messages = encrypt_messages(messages, A, u, query_vector, tag, elgamal_params)
    print(f"Total de {len(encrypted_messages)} mensagens cifradas")
    
    # FASE 4: DECIFRAR AS MENSAGENS (Receiver)
    print("\n" + "=" * 40)
    print("FASE 4: DECIFRA DAS MENSAGENS (Receiver)")
    print("=" * 40)
    
    
    decrypted_messages = decrypt_messages(encrypted_messages, selected_indices, good_keys, tag, elgamal_params)
    
    # Verificar resultados
    print("\n" + "=" * 40)
    print("RESULTADOS FINAIS")
    print("=" * 40)
    print(f"Mensagens recuperadas: {len(decrypted_messages)}/{kappa}")
    
    all_recovered = len(decrypted_messages) == kappa
    correct_indices = all(idx in decrypted_messages for idx in selected_indices)
    
    if all_recovered and correct_indices:
        print("SUCESSO! O protocolo OT funcionou corretamente.")
        print("  O receiver recuperou exatamente as k mensagens selecionadas.")
    else:
        print("FALHA! O protocolo OT não funcionou como esperado.")
        print(f"  Mensagens recuperadas: {sorted(decrypted_messages.keys())}")
        print(f"  Mensagens esperadas: {selected_indices}")
    
    # Comparar mensagens originais com decifradas
    print("\nVerificação das mensagens recuperadas:")
    for idx in decrypted_messages:
        original = messages[idx]
        decrypted = decrypted_messages[idx]
        match = original == decrypted
        print(f"  [{idx}] Original: '{original}' | Decifrada: '{decrypted}' | {'YES' if match else 'NO'}")