from Crypto.Util import number
from Crypto.Random import random

def fast_power(b, exp, m):
    res = 1
    while exp > 1:
        if exp & 1:
            res = (res * b) % m
        b = b ** 2 % m
        exp >>= 1
    return (b * res) % m


def rsa_key_gen(nbits=2048) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Generates textbook rsa keys
       p: first prime
       q: second prime
       N: p*q
       e: public part
       d: secret key
    Args:
        nbits (int, optional): RSA security parameter

    Returns:
        (N, e), (N, d), (p, q)
        where
        pk = (N, e)
        sk = (N, d)
        primes = (p, q)
    """
    e = 65537

    while True:
        p = number.getPrime(nbits // 2)
        q = number.getPrime(nbits // 2)
        N = p * q
        if number.size(N) == 2048:
            break
    totient = (p - 1) * (q - 1)
    d = number.inverse(e, totient)
    pk = (N, e)
    sk = (N, d)
    primes = (p, q)

    return pk, sk, primes


def rsa_enc(pk: tuple[int, int], m: int) -> int:
    """Textbook RSA encryption

    Args:
        pk (int, int): RSA public key tuple
        m (int): the message to encrypt

    Returns:
        int: textbook rsa encryption of m
    """
    
    (N, e) = pk
    c = pow(m, e, N)

    return c



def rsa_dec(sk: tuple[int, int], c: int) -> int:
    """Textbook RSA decryption

    Args:
        sk (int,int): RSA secret key tuple
        c (int): RSA ciphertext

    Returns:
        int: Textbook RSA decryption of c
    """
    
    (N, d) = sk
    m = pow(c, d, N)
    return m
