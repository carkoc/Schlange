# -*- coding: utf-8 -*-
"""
Created on Fri Nov 29 21:28:25 2024

@author: carst
"""
#C448 Testvector from RFC7748
#https://datatracker.ietf.org/doc/html/rfc7748#page-5

from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives import hashes
from binascii import unhexlify

# Alice's private key
alice_private_key_bytes = unhexlify("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")
alice_private_key = x448.X448PrivateKey.from_private_bytes(alice_private_key_bytes)

# Bob's private key
bob_private_key_bytes = unhexlify("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d")
bob_private_key = x448.X448PrivateKey.from_private_bytes(bob_private_key_bytes)

# Alice's public key
alice_public_key_bytes = unhexlify("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0")
alice_public_key = x448.X448PublicKey.from_public_bytes(alice_public_key_bytes)

# Bob's public key
bob_public_key_bytes = unhexlify("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609")
bob_public_key = x448.X448PublicKey.from_public_bytes(bob_public_key_bytes)

# Calculate shared secret
alice_shared_secret = alice_private_key.exchange(bob_public_key)
bob_shared_secret = bob_private_key.exchange(alice_public_key)

# Verify that both shared secrets are the same
assert alice_shared_secret == bob_shared_secret, "Shared secrets do not match!"

print(f"Alice's shared secret: {alice_shared_secret.hex()}")
print(f"Bob's shared secret: {bob_shared_secret.hex()}")
