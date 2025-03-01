import random
from sympy import isprime, nextprime

# 1. Choose the parameters

_lambda = 256 # security parameter

def parameter_generator(_lambda):
    
    """
    Generate q, that needs to be approximatly 2^_lambda
    """
    
    lower_bound = 2**(_lambda - 1)
    upper_bound = 2**_lambda - 1
    q_candidate = random.randint(lower_bound, upper_bound)
    q = nextprime(q_candidate)
    
    """
    Generate p, that needs to be prime
    F*p needs to have a subgroup of order q
    """
    
    k = 2 
    p = 0
    while True:
        p_candidate = k * q + 1
        if isprime(p_candidate):
            p = p_candidate
            break
        k += 1
        
    """
    Compute a generator g of the subgroup
    What is a generator?
    A generator is an element of the group that can generate all the elements of the group
    How do we compute it?
    We pick a random number a, 1 < a < p-1 and compute g = a^k mod p and if g is not 1, we have a generator
    """
    
    g = 0
    while True:
        a = random.randint(2,p-2) 
        g = pow(a,(p-1) // q,p)
        if g != 1:
            break
        
    """
    Generate private key whice is a random number between 0 and q
    """
    
    s = random.randint(0,q-1)
    
    return p,q,g,s



if __name__ == "__main__":
    p, q, g, s = parameter_generator(_lambda)
    print(f"p = {p} ({p.bit_length()} bits)")
    print(f"q = {q} ({q.bit_length()} bits)")
    print(f"g = {g}")
    print(f"s = {s}")
    