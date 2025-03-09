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
        u[i] = Zq(H(str(rho) + str(n) + str(i), length=q.nbits()))
        
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
    
def generate_query_vector(A,u,selected_indices,q):
    """
    Gerar o vetor v, que será usado pelo provider para garantir que o recetor está a fazer uma escolha justa, e nao a tentar obter mais mensagens do que as permitidas
    """
    
    """
    Extraímos as dimensões da matriz A para determinar n e κ.
    Isto é feito desta forma por consistência - ambos Provedor e Receptor já conhecem estes valores.
    Desta forma confirmamos que tamos a enviar A e u corretos.
    """
    
    n, n_minus_kappa = A.dimensions()
    kappa = n - n_minus_kappa
    
    """
    Verificamos se o número de índices selecionados é exatamente kappa.
    O protocolo foi projetado para funcionar apenas com κ índices, nem mais nem menos.
    """
    
    if len(selected_indices) != kappa:
        raise ValueError(f"O receiver não escolheu {kappa} índices")
    
    
    """
    Criamos uma submatriz A_subset, que contém apenas as linhas selecionadas.
    """
    
    Zq = GF(q)
    A_selected = matrix(Zq, kappa, n_minus_kappa)
    for new_line, line in enumerate(selected_indices):
        A_selected[new_line] = A[line]
    
    """
    Criamos um vetor u_selected que contém os valores correspondentes de u.
    Este vetor representa os "valores-alvo" que queremos atingir com nosso vetor p.
    """
    
    u_selected = vector(Zq, kappa)
    for new_index, orig_index in enumerate(selected_indices):
        # Para cada índice selecionado i, queremos que A[i] · v = u[i]
        for j in range(n_minus_kappa):
            u_selected[new_index] += A[orig_index, j] * u[j]

    """
    Agora resolvemos o sistema de equações lineares:
    A_selected * p = u_selected
    
    Isto será equivalente a:
    A[i] · p = u[i]
    
    Esta é a propriedade matemática central do protocolo OT:
    - Para indices selecionados: A[i] · p = produtos específicos
    - Para outros indices: A[j] · p parece aleatório
    """
    
    try:
        # Resolver o sistema linear usando álgebra linear do SageMath
        p = A_selected.solve_right(u_selected)
        
        """
        O vetor p agora codifica as escolhas do receptor, sem revelar
        quais índices foram selecionados. Este vetor será enviado ao provedor.
        """
        
        return p
        
    except Exception as e:
        # Se não foi possível resolver o sistema, algo está errado com os parâmetros
        raise ValueError(f"Não foi possível gerar o vetor de consulta: {e}")
    
def H(value, length=32):
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


def encrypt_messages(messages, A, u, query_vector, elgamal_params):
    """
    FASE 3: CIFRA DAS MENSAGENS (PROVEDOR)
    """
    # Extrair parâmetros ElGamal
    p_elgamal, q, g, h, s = elgamal_params
    
    # Verificar dimensões
    n = len(messages)
    if n != A.nrows():
        raise ValueError(f"Número de mensagens ({n}) não corresponde às linhas de A ({A.nrows()})")
    
    encrypted_messages = []
    
def encrypt_messages(messages, A, u, query_vector, elgamal_params):
    """
    FASE 3: CIFRA DAS MENSAGENS (PROVEDOR)
    """
    # Extrair parâmetros ElGamal
    p_elgamal, q, g, h, s = elgamal_params
    
    # Verificar dimensões
    n = len(messages)
    if n != A.nrows():
        raise ValueError(f"Número de mensagens ({n}) não corresponde às linhas de A ({A.nrows()})")
    
    encrypted_messages = []
    
    for i in range(n):
        # Calcular o produto escalar p · A[i]
        dot_product = sum(query_vector[j] * A[i,j] for j in range(len(query_vector)))
        
        try:
            # 1. Cifrar a mensagem normalmente
            ciphertext = enc(messages[i], p_elgamal, q, g, h)
            c_1, c_2 = ciphertext
            gamma, encrypted_message = c_1
            
            # 2. Calculamos delta usando o produto escalar
            delta = (dot_product - sum(A[i,j] * u[j] for j in range(len(u)))) % q
            
            # 3. Se delta != 0 (índice não selecionado), modificamos o criptograma
            if delta != 0:
                # Para índices não selecionados, multiplicamos por um valor que impede a decifração
                modified_gamma = (gamma * power_mod(g, delta, p_elgamal)) % p_elgamal
                modified_ciphertext = ((modified_gamma, encrypted_message), c_2)
            else:
                # Para índices selecionados, mantemos o criptograma original
                modified_ciphertext = ciphertext
            
            # Armazenar a mensagem cifrada
            encrypted_messages.append({
                'index': i,
                'ciphertext': modified_ciphertext,
                'dot_product': dot_product
            })
            
        except Exception as e:
            print(f"Erro ao cifrar mensagem {i}: {e}")
    
    return encrypted_messages


def decrypt_messages(encrypted_messages, selected_indices, elgamal_params):
    """
    FASE 4: DECIFRA DAS MENSAGENS (RECEPTOR)
    """
    # Extrair parâmetros ElGamal
    p_elgamal, q, g, h, s = elgamal_params
    
    decrypted_messages = {}
    
    # Para cada mensagem cifrada
    for message_data in encrypted_messages:
        i = message_data['index']
        ciphertext = message_data['ciphertext']
        
        try:
            # Tentar decifrar - isso só funcionará para índices selecionados
            # devido à modificação feita durante a cifragem
            plaintext = dec(ciphertext, s, p_elgamal, q)
            
            decrypted_messages[i] = plaintext
            print(f"Mensagem {i} decifrada com sucesso: {plaintext}")
            
        except Exception as e:
            print(f"Não foi possível decifrar mensagem {i}: {e}")
    
    return decrypted_messages

if __name__ == "__main__":
    """
    TESTE DO PROTOCOLO OBLIVIOUS TRANSFER κ-OUT-OF-n
    
    Este script testa todas as fases do protocolo OT:
    1. Configuração (Provedor)
    2. Seleção e Consulta (Receptor)
    3. Cifra das Mensagens (Provedor)
    4. Decifra das Mensagens (Receptor)
    """
    print("=" * 60)
    print("TESTE DO PROTOCOLO OBLIVIOUS TRANSFER κ-OUT-OF-n")
    print("=" * 60)
    
    # Definir parâmetros
    n = 8  # Número total de mensagens
    kappa = 3  # Número de mensagens a transferir
    print(f"Parâmetros: n={n}, κ={kappa}")
    
    # FASE 1: CONFIGURAÇÃO (PROVEDOR)
    print("\n" + "=" * 40)
    print("FASE 1: CONFIGURAÇÃO (PROVEDOR)")
    print("=" * 40)
    
    # Gerar parâmetros ElGamal
    print("Gerando parâmetros ElGamal...")
    # Usar um lambda menor para testes mais rápidos
    test_lambda = 128  # Valor pequeno para testes rápidos
    p_elgamal, q, g, h, s = parameter_generator(test_lambda)
    
    print(f"p = {p_elgamal} ({p_elgamal.nbits()} bits)")
    print(f"q = {q} ({q.nbits()} bits)")
    print(f"g = {g}")
    print(f"h = {h}")
    print(f"s = {s} (chave privada)")
    
    # Verificar parâmetros
    verify_parameters(p_elgamal, q, g)
    
    # Gerar critério oblívio
    print("\nGerando critério oblívio (A, u)...")
    A, u, rho = generate_oblivious_criterion(n, kappa, q)
    
    print(f"Matriz A ({A.nrows()}×{A.ncols()}):")
    print(A)
    print(f"Vetor u ({len(u)} elementos):")
    print(u)
    print(f"Seed rho (secreta): {rho}")
    
    # Criar mensagens de teste
    messages = [f"Mensagem {i+1}" for i in range(n)]
    print("\nMensagens disponíveis:")
    for i, msg in enumerate(messages):
        print(f"  [{i}] {msg}")
    
    # FASE 2: SELEÇÃO E CONSULTA (RECEPTOR)
    print("\n" + "=" * 40)
    print("FASE 2: SELEÇÃO E CONSULTA (RECEPTOR)")
    print("=" * 40)
    
    # Selecionar κ índices
    # Podemos escolher índices específicos para teste ou usar aleatórios
    selected_indices = [2, 4, 7]  # Índices escolhidos pelo receptor
    print(f"Receptor escolhe índices: {selected_indices}")
    print(f"Mensagens selecionadas:")
    for idx in selected_indices:
        print(f"  [{idx}] {messages[idx]}")
    
    # GERAR O VETOR DE CONSULTA
    print("\nGerando vetor de consulta p...")
    query_vector = generate_query_vector(A, u, selected_indices, q)
    print(f"Vetor p gerado: {query_vector}")
    
    # Verificar propriedade do vetor de consulta
    print("\nVerificando propriedade do vetor de consulta:")
    for i in range(n):
        dot_product = sum(query_vector[j] * A[i,j] for j in range(len(query_vector)))
        expected = sum(A[i,j] * u[j] for j in range(len(u)))
        is_selected = i in selected_indices
        status = '✓' if (is_selected and dot_product == expected) or (not is_selected and dot_product != expected) else '✗'
        
        print(f"  Índice {i} ({'SELECIONADO' if is_selected else 'NÃO SELECIONADO'}): p·A[{i}] = {dot_product}, esperado = {expected}")
        print(f"    Match: {status}")

    # Criar tupla com parâmetros ElGamal
    elgamal_params = (p_elgamal, q, g, h, s)
    
    # FASE 3: CIFRA DAS MENSAGENS (PROVEDOR)
    print("\n" + "=" * 40)
    print("FASE 3: CIFRA DAS MENSAGENS (PROVEDOR)")
    print("=" * 40)
    
    # Cifrar mensagens
    print("Cifrando mensagens...")
    encrypted_messages = encrypt_messages(messages, A, u, query_vector, elgamal_params)
    print(f"Total de {len(encrypted_messages)} mensagens cifradas")
    
    # FASE 4: DECIFRA DAS MENSAGENS (RECEPTOR)
    print("\n" + "=" * 40)
    print("FASE 4: DECIFRA DAS MENSAGENS (RECEPTOR)")
    print("=" * 40)
    
    # Decifrar mensagens
    print("Tentando decifrar mensagens...")
    decrypted_messages = decrypt_messages(encrypted_messages, selected_indices, elgamal_params)
    
    # Verificar resultados
    print("\n" + "=" * 40)
    print("RESULTADOS FINAIS")
    print("=" * 40)
    print(f"Mensagens recuperadas: {len(decrypted_messages)}/{kappa}")
    
    # Verificar se todas as mensagens selecionadas foram decifradas
    all_recovered = len(decrypted_messages) == kappa
    correct_indices = all(idx in decrypted_messages for idx in selected_indices)
    
    if all_recovered and correct_indices:
        print("✓ SUCESSO! O protocolo OT funcionou corretamente.")
        print("  O receptor recuperou exatamente as κ mensagens selecionadas.")
    else:
        print("✗ FALHA! O protocolo OT não funcionou como esperado.")
        print(f"  Mensagens recuperadas: {sorted(decrypted_messages.keys())}")
        print(f"  Mensagens esperadas: {selected_indices}")
    
    # Comparar mensagens originais com decifradas
    print("\nVerificação das mensagens recuperadas:")
    for idx in decrypted_messages:
        original = messages[idx]
        decrypted = decrypted_messages[idx]
        match = original == decrypted
        print(f"  [{idx}] Original: '{original}' | Decifrada: '{decrypted}' | {'✓' if match else '✗'}")