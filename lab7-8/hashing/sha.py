import hashlib

def compute_hash(message: str, algorithm: str) -> int:
    algo = algorithm.lower()
    if algo == "sha-256":
        digest = hashlib.sha256(message.encode('utf-8')).hexdigest()
    elif algo == "sha-384":
        digest = hashlib.sha384(message.encode('utf-8')).hexdigest()
    elif algo == "sha-512":
        digest = hashlib.sha512(message.encode('utf-8')).hexdigest()
    else:
        raise ValueError("Unsupported hash algorithm")
    return int(digest, 16)