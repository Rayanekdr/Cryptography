# Cette fonction prendra une chaîne hexadécimale de 64 caractères (256 bits) comme clé.
def encrypt_with_serpent(plaintext, key_hex):
    # Convertissez la clé hexadécimale en une chaîne binaire de 256 bits.
    key_binary = hex.hexstring2bitstring(key_hex)
    # Convertissez le texte en une chaîne binaire de 128 bits (16 caractères hexadécimaux).
    plaintext_binary = hex.hexstring2bitstring(plaintext)
    # Appliquez l'algorithme de chiffrement Serpent.
    ciphertext_binary = encrypt(plaintext_binary, key_binary)
    # Convertissez le texte chiffré en hexadécimal pour la lisibilité.
    ciphertext_hex = hex.bitstring2hexstring(ciphertext_binary)
    return ciphertext_hex

# Cette fonction prendra une chaîne hexadécimale de 64 caractères (256 bits) comme clé.
def decrypt_with_serpent(ciphertext_hex, key_hex):
    # Convertissez la clé hexadécimale en une chaîne binaire de 256 bits.
    key_binary = hex.hexstring2bitstring(key_hex)
    # Convertissez le texte chiffré en une chaîne binaire de 128 bits (16 caractères hexadécimaux).
    ciphertext_binary = hex.hexstring2bitstring(ciphertext_hex)
    # Appliquez l'algorithme de déchiffrement Serpent.
    plaintext_binary = decrypt(ciphertext_binary, key_binary)
    # Convertissez le texte déchiffré en hexadécimal pour la lisibilité.
    plaintext_hex = hex.bitstring2hexstring(plaintext_binary)
    return plaintext_hex
