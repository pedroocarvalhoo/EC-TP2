#!/usr/bin/env sage

# 1. Choose the parameters
_lambda = 128  # security parameter

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
    k = 2
    p = 0
    while True:
        p_candidate = k * q + 1
        if is_prime(p_candidate):
            p = p_candidate
            break
        k += 1
    
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
        g = power_mod(a, (p-1) // q, p)
        if g != 1:
            break
        
    """
    Generate private key which is a random number between 0 and q
    """
    s = randint(0, q-1)
    
    return p, q, g, s

if __name__ == "__main__":
    p, q, g, s = parameter_generator(_lambda)
    print(f"p = {p} ({p.nbits()} bits)")
    print(f"q = {q} ({q.nbits()} bits)")
    print(f"g = {g}")
    print(f"s = {s}")