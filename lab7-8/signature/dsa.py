import random
import math
from utils.math_utils import generate_prime, modinv, is_prime

def generate_parameters(L=1024, N=160):
    q = generate_prime(N)
    while True:
        k = random.getrandbits(L - N)
        if k == 0:
            continue
        p_candidate = k * q + 1
        if p_candidate.bit_length() != L:
            continue
        if is_prime(p_candidate):
            p = p_candidate
            break
    for h in range(2, p - 1):
        g = pow(h, (p - 1) // q, p)
        if g > 1:
            break
    return p, q, g

def generate_keys(L=1024, N=160):
    p, q, g = generate_parameters(L, N)
    x = random.randrange(1, q)
    y = pow(g, x, p)
    public_key = (p, q, g, y)
    private_key = x
    return public_key, private_key

def sign(message: str, private_key, public_params, hash_int: int):
    p, q, g, y = public_params
    x = private_key
    while True:
        k = random.randrange(1, q)
        if math.gcd(k, q) == 1:
            break
    r = pow(g, k, p) % q
    if r == 0:
        return sign(message, private_key, public_params, hash_int)
    k_inv = modinv(k, q)
    s = (k_inv * (hash_int + x * r)) % q
    if s == 0:
        return sign(message, private_key, public_params, hash_int)
    return (r, s)

def verify(message: str, signature: tuple, public_params, hash_int: int) -> bool:
    p, q, g, y = public_params
    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    try:
        w = modinv(s, q)
    except Exception:
        return False
    u1 = (hash_int * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r
