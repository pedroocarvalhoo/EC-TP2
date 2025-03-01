# ALL CREDIT GOES TO: https://github.com/Pdf0

import random
from math import pow

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class ElGamal:
    """
    ElGamal algorithm implementation
    """

    q = 0
    g = 0
    key = 0
    h = 0

    def __init__(self):
        self.r = random.SystemRandom()

        # Use randrange to avoid floating-point issues
        self.q = self.r.randrange(int(pow(10, 10)), int(pow(10, 20)))
        self.g = self.r.randrange(2, self.q)

        self.key = self._gen_key(self.q)
        self.h = self._power(self.g, self.key, self.q)

    def _gcd(self, a: int, b: int) -> int:
        """
        Calculate greatest common divisor of a and b

        :param a: int
        :param b: int

        :return: gcd of a and b
        """
        if a < b:
            return self._gcd(b, a)
        elif a % b == 0:
            return b
        else:
            return self._gcd(b, a % b)

    def _gen_key(self, q: int) -> int:
        """
        Generate key
        :param q: prime number

        :return: key
        """
        key = self.r.randrange(int(pow(10, 10)), q)
        while self._gcd(q, key) != 1:
            key = self.r.randrange(int(pow(10, 10)), q)

        return key

    def _power(self, a: int, b: int, c: int) -> int:
        """
        Modular exponentiation

        :param a: base
        :param b: exponent
        :param c: modulus

        :return: a^b mod c
        """
        x = 1
        y = a

        while b > 0:
            if b % 2 != 0:
                x = (x * y) % c
            y = (y * y) % c
            b = int(b / 2)

        return x % c

    def encrypt(self, msg: str) -> tuple[list[int], int]:
        """
        Encrypts a message with ElGamal algorithm and it's parameters

        :param msg: message to encrypt
        :param q: prime number
        :param h: public key
        :param g: generator

        :return: encrypted message and p (g^key mod q)
        """

        en_msg = []

        k = self._gen_key(self.q)
        s = self._power(self.h, k, self.q)
        p = self._power(self.g, k, self.q)
        
        for i in range(0, len(msg)):
            en_msg.append(s * ord(msg[i]))

        print("g^k used : ", p)
        print("g^ak used : ", s)
        return en_msg, p

    def decrypt(self, en_msg: list[int], p: int) -> str:
        """
        Decrypts a message with ElGamal algorithm and it's parameters

        :param en_msg: encrypted message
        :param p: g^k mod q
        :param key: private key
        :param q: prime number

        :return: decrypted message
        """

        dr_msg = []
        h = self._power(p, self.key, self.q)
        for i in range(0, len(en_msg)):
            dr_msg.append(chr(int(en_msg[i] // h)))
            
        return ''.join(dr_msg)

def main():

    print ("""
    This is a simple explanation of the ElGamal algorithm for my friend Rui.
           
    We want to encrypt the following plaintext: Hello World!
    """)

    msg = 'Hello World!'

    print(f"""
    We start by initializing the ElGamal algorithm.
          
    We generate a random prime number q and a random number g with some requirements:
        - {bcolors.BOLD}q{bcolors.ENDC} is a prime number between 10^10 and 10^20
        - {bcolors.BOLD}g{bcolors.ENDC} is a random number between 2 and {bcolors.BOLD}q{bcolors.ENDC}

    Then we generate a random key with the following requirements:
        - key is a random number between 10^10 and q
        - gcd(q, key) = 1
          
          This means that the greatest common divisor of q and key is 1, which means that they are coprime.

    We are also going to generate a public key h with the following requirements:
        - h = g^key mod q
            This means that h is the remainder of the division of g^key by q.
    """)

    elGamal = ElGamal()

    print(f"""
    Here are the generated values:
        {bcolors.BOLD}q{bcolors.ENDC}: {elGamal.q}
        {bcolors.BOLD}g{bcolors.ENDC}: {elGamal.g}
        {bcolors.BOLD}key{bcolors.ENDC}: {elGamal.key}
        {bcolors.BOLD}h{bcolors.ENDC}: {elGamal.h}
    """)

    print(f"""
    Now we are going to encrypt the message {bcolors.BOLD}{msg}{bcolors.ENDC} using the ElGamal algorithm.

    We generate a random number {bcolors.BOLD}k{bcolors.ENDC} (our secret key) with the following requirements:
        - k is a random number between 10^10 and q
        - gcd(q, k) = 1
        - it needs to be private and it's only used once

    We calculate the following values:
        - {bcolors.BOLD}s{bcolors.ENDC} = h^k mod q
        - {bcolors.BOLD}p{bcolors.ENDC} = g^k mod q
        - we multiply each character of the message by s
        - p is sent to the receiver along with the encrypted message and it is going to be used to decrypt the message.
    """)

    en_msg, p = elGamal.encrypt(msg)

    print(f"""
    Here are the encrypted message and p:
        {bcolors.BOLD}Encrypted Message{bcolors.ENDC}: {en_msg}
        {bcolors.BOLD}p{bcolors.ENDC}: {p}

    Now we are going to decrypt the message using the following formula:
        - {bcolors.BOLD}h{bcolors.ENDC} = p^key mod q
        - we divide each character of the encrypted message by {bcolors.BOLD}h{bcolors.ENDC}

    Why does this work, you might ask?

    Let's say that we have a character c and we encrypt it with the formula:
        - c' = c * s
    Now we decrypt it with the following formula:
        - c = c' / h
    
    That is because c' = c * s = c * h^k and c = c' / h = c * h^k / h = c * h^(k-1) = c * g^(key * k - key) = c * g^(key * k) / g^key = c * g^k / g^key = c * g^k / h = c
    :))
     (Esta parte é no gozo)
    """)

    msg = elGamal.decrypt(en_msg, p)

    print(f"The final decrypted message is: {msg}")

if __name__ == '__main__':
    main()