#!/usr/bin/env sage

# 1. Choose the parameters
_lambda = 128  # security parameter
lambda_bits = _lambda.nbits() # 128 in binary is 10000000 -> 8 bits

def parameter_generator(_lambda):
    """
    Generate q, that needs to be approximately 2^_lambda
    """
    lower_bound = 2^(_lambda - 1)
    upper_bound = 2^_lambda - 1
    q_candidate = randint(lower_bound, upper_bound)
    q = next_prime(q_candidate)
    
 
    """
    Generate p, that needs to be prime
    F*p needs to have a subgroup of order q
    """
    
    min_p_bits = _lambda*lambda_bits # 128*8 = 1024
    
  
    
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
    print("Time taken to generate p: ", end-start)
        
 
    
    """
    Compute a generator g of the subgroup
    What is a generator?
    A generator is an element of the group that can generate all the elements of the group
    How do we compute it?
    We pick a random number a, 1 < a < p-1 and compute g = a^((p-1)/q) mod p
    and if g is not 1, we have a generator
    """
    g = 0
    while True:
        a = randint(2, p-2)
        #TO-DO check is mod p or mod q
        g = power_mod(a, (p-1) // q, p)
        if g != 1:
            break
        
 
    """
    Generate private key which is a random number between 0 and q
    """
    s = randint(0, q-1)
    
    """
    Generate the public key
    """
    h = power_mod(g, s, q)
    

    return p, q, g, h


def verify_parameters(p, q, g):
    """
    Verify if the parameters are correctly defined for ElGamal.
    """
    # 1. Check if p and q are primes
    if not is_prime(p):
        print("Error: p is not prime.")
        return False
    if not is_prime(q):
        print("Error: q is not prime.")
        return False
    
    # 2. Check if q divides p-1
    if (p - 1) % q != 0:
        print("Error: q does not divide p-1.")
        return False
    
    # 3. Check if g is a generator of the subgroup of order q
    # 3.1. Check if g^q ≡ 1 mod p
    if power_mod(g, q, p) != 1:
        print("Error: g^q ≠ 1 mod p.")
        return False
    
    # 3.2. Check if g^k ≠ 1 mod p for 1 < k < q
    # (This is computationally expensive for large q, so we sample a few k values)
    for _ in range(10):  # Test 10 random values of k
        k = randint(2, q-1)
        if power_mod(g, k, p) == 1:
            print(f"Error: g^{k} ≡ 1 mod p.")
            return False
    
    # If all checks pass
    print("All parameters are correctly defined.")
    return True


def enc(,plaintext,p,q,g,h):
    
    """
    Generate the secret key
    """

    omega = randing(0, q-1)
    
    """
    Generate new encryption parameters
    """
    
    gama = power_mod(g,omega,q)
    kappa = power_mod(h,omega,q)
    
    
    """
    Encrypt the plaintext
    """
    mapped_plaintext = plaintext.encode('utf-8')
    
    
    
    
    
if __name__ == "__main__":
    
    plaintext = "Hello World!" #deve ser convertida para um numero pertencente a Fp (0, p-1)
    
    p, q, g, s = parameter_generator(_lambda)
    
    print(f"p = {p} ({p.nbits()} bits)")
    print(f"q = {q} ({q.nbits()} bits)")
    print(f"g = {g}")
    print(f"s = {s}")
    
    verify_parameters(p, q, g, s)
    
    enc(plaintext, p, q, g, s)
    