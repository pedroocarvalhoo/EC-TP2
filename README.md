# Cryptographic Structures - Practical Work #2

**Authors:** Pedro Carvalho [(Github)](https://github.com/pedroocarvalhoo), Miguel Guimarães [(Github)](https://github.com/miguel-amg).

**University of Minho** - Masters Degree in Software Engineering

**March 2025**

***

### **Tasks:**
**Task #1:** The aim is to build around an asymmetric cipher a set of cryptographic techniques designed for different purposes. Although all parts of the problem can be answered with most classical or post-quantum asymmetric ciphers, in this problem we will exemplify the process with a simple technique from the Diffie-Hellman family, namely the ElGamal asymmetric cipher with security parameters **λ**.

1. Implement a PKE scheme **ElGamal(λ)** in a prime order subgroup **q**, with **|q|≥λ**, of the multiplicative group **F\*<sub>p** with **p** a prime who checks **|p|≥λ\*|λ|**. Identify the key generator and decryption cipher algorithms in this schematic. Identify the deterministic core of the encryption algorithm.

2. Assuming the cipher you implemented is IND-CPA secure, using the Fujisaki-Okamoto transform implement a PKE that is IND-CCA secure.

3. From (1.2) construct a KEM scheme that is IND-CCA secure.

4. From (1.2) build an implementation of an authenticated *k-out-of-n* “Oblivious Transfer” protocol.

**Task #2:** Build a Python class that implements EdDSA from the FIPS186-5 standard.

1. The implementation must contain functions to digitally sign and verify the signature.

2. The class implementation must use one of the “Twisted Edwards Curves” defined in the standard and chosen at class initiation: the **“edwards25519”** or **“edwards448”** curve.

**Task #3:** Using the experience gained in solving problems 1 and 2, and using, instead of the multiplicative abelian group **F\*<sub>p**, the additive abelian group that you used in question 2:

1. Construct both secure IND-CPA and secure IND-CCA versions of the ElGamal cipher scheme on elliptic curves.

2. Build an elliptic curve implementation of an authenticated *k-out-of-n* “Oblivious Transfer” protocol.

