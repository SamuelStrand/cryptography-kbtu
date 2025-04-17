import math
from utils.math_utils import generate_prime, modinv

def generate_keys(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    while q == p:
        q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def sign(message: str, private_key, hash_int: int) -> int:
    d, n = private_key
    signature = pow(hash_int, d, n)
    return signature

def verify(message: str, signature: int, public_key, hash_int: int) -> bool:
    e, n = public_key
    hash_from_signature = pow(signature, e, n)
    return hash_from_signature == hash_int
