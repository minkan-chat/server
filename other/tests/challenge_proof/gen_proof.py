from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import binascii

private_key = Ed25519PrivateKey.from_private_bytes(
    binascii.unhexlify(
        "40c2bcc8afae785d40918d3e8c0154fcacca1db50e555758570e2e126465ba21b1"  # private key (q) of primary key of alice NOO ITS NOT
    )
)

signature = private_key.sign(
    binascii.unhexlify(
        "4c207abfe4130dc3a76fd6e65c888431406d490bc6c727ed4fe0ee3b804e28c3"
    )
)

print(binascii.hexlify(signature))
