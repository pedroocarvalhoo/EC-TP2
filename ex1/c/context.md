# Diferença entre PKE e KEM

## PKE -Public Key Encryption

- Usa criptografia assimétrica
- $m$ é cifrada usando uma chave publica $pk$ e decifrada usando uma chave privada $sk$


## KEM - Key Encapsulation Mechanism


- Em vez de cifrar diretamente uma mensagem, um KEM encapsula uma chave simétrica usando criptografia assimétrica.

- A chave encapsulada é então usada para cifrar mensagens usando um algoritmo simétrico, como o AES.

1. $(K,c) = Encaps(pk)$ - Gera uma chave simétrica $K$ e um encapsulamento $c$. 
2. $ K = Decaps(sk,c)$ - A chave encapsulada  $c$ é aberta usando a chave privada $sk$ para recuperar $K$.
3. Usa-se $K$ para cifrar mensagens com um algoritmo simétrico
