import random
import math
from utils.math_utils import generate_prime, modinv

def generate_keys(bits=1024):
    p = generate_prime(bits)
    for g in range(2, p):
        if pow(g, (p - 1) // 2, p) != 1:
            break
    x = random.randrange(1, p - 1)
    y = pow(g, x, p)
    public_key = (p, g, y)
    private_key = x
    return public_key, private_key

def sign(message: str, private_key, public_key, hash_int: int):
    p, g, y = public_key
    x = private_key
    while True:
        k = random.randrange(1, p - 1)
        if math.gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    k_inv = modinv(k, p - 1)
    s = (k_inv * (hash_int - x * r)) % (p - 1)
    return (r, s)

def verify(message: str, signature: tuple, public_key, hash_int: int) -> bool:
    p, g, y = public_key
    r, s = signature
    if not (1 < r < p):
        return False
    v1 = (pow(y, r, p) * pow(r, s, p)) % p
    v2 = pow(g, hash_int, p)
    return v1 == v2
