"""
Implementation of ElGamal over elliptic curves.
This version uses hash-based approach to encrypt a message M,
in order to avoid mapping M to a curve point.
"""
from random import randint
from hashlib import sha256
from ecc import EllipticCurve, ECPoint


class ElGamal:
    def __init__(self):
        # use the secp256k1 curve
        self.a = 0
        self.b = 7
        # Large prime number
        self.p = int('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16)
        # Point on elliptic curve
        self.B = ECPoint(int('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 16),
                         int('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 16))
        # Elliptic curve
        self.G = EllipticCurve(self.p, self.B, self.a, self.b)
        # Random integer
        self.n = randint(1, self.p)
        # Generate Private key (K)
        self.K = self.keygen(1)


    def encrypt(self, message):
        """ Encryption of plaintext m.
        Parameters
        ----------
        message: The message, a point on the curve
        G: The curve
        g: The curve base point
        p: The order of the field
        h: Public part of the shared secret
        """
        y = randint(1, self.p)
        c1 = self.G.mul(self.B, y)
        s = self.G.mul(self.K, y)
        hs = sha256(repr(s).encode('utf-8')).digest()
        c2 = bytearray([i ^ j for i, j in zip(message, hs)])
        return c1, bytes(c2)

    def decrypt(self, cipher):
        """ Decryption of ciphertext c.
        Parameters
        ----------
        cipher: The ciphertext tuple, (c1, c2)
        x: The private key
        G: The curve
        """
        c1, c2 = cipher
        s = self.G.mul(c1, self.n)
        hs = sha256(repr(s).encode('utf-8')).digest()
        m = bytearray([i ^ j for i, j in zip(c2, hs)])
        return bytes(m)

    def keygen(self, bob):
        """Private key generation."""
        self.n *= bob
        self.K = self.G.mul(self.B, self.n)
        return self.K


if __name__ == '__main__':
    # 1) Introduce class
    alice = ElGamal()
    bob = ElGamal()
    # 3) Generate private keys
    alice.K = alice.keygen(1)
    bob.K = bob.keygen(1)
    # 4) Alice encrypt message
    m = "Secret message".encode('utf8')
    c = alice.encrypt(m)
    print(f'Alice Encryption:\t{c}')
    # 5) Bob decrypt message
    d = bob.decrypt(c)
    print(f'Bob Decryption:\t\t{d.decode(errors="replace")}')

    assert m == d, "Decryption failed"

''' m = input('Enter message: ').encode('utf-8')

 c = elgamal.encrypt(m)
 print(f'Encrypted:\t{c}')
 mp = elgamal.decrypt(c)
 print(f'Decrypted:\t{mp.decode(errors="replace")}')'''
