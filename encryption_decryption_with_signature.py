from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

# Function to pad the data for DES encryption
def pad_data(data):
    pad_length = 8 - (len(data) % 8)
    return data + bytes([pad_length] * pad_length)

# Function to unpad the data after DES decryption
def unpad_data(data):
    pad_length = data[-1]
    return data[:-pad_length]

# Generate a random key for DES encryption
def generate_des_key():
    return get_random_bytes(8)

# Generate a random signature key pair for Alice
alice_key_pair = RSA.generate(2048)
alice_public_key = alice_key_pair.publickey()
alice_private_key = alice_key_pair

bob_key_pair = RSA.generate(2048)
bob_public_key = bob_key_pair.publickey()
bob_private_key = bob_key_pair
# Prompt the user to enter the path of the file to sign and encrypt
file_path = input("Enter the path of the file to sign and encrypt: ")

# --- Signing Process ---

# Read the content of the file
with open(file_path, 'rb') as file:
    file_content = file.read()

# Sign the file using Alice's private key
hash_func = SHA256.new(file_content)
signature = pkcs1_15.new(alice_private_key).sign(hash_func)

# --- Encryption Process ---

# Generate a random k for DES encryption
k = generate_des_key()
print(b64encode(k))
# Encrypt k using Alice's public key (RSA encryption with PKCS1_OAEP)

cipher_rsa = PKCS1_OAEP.new(bob_public_key)
encrypted_k = cipher_rsa.encrypt(k)

# Encrypt File content using k (DES encryption)
des_cipher = DES.new(k, DES.MODE_ECB)
encrypted_file_content = des_cipher.encrypt(pad_data(file_content))

# Write encrypted data and signature to a file
with open("encrypted_data_with_signature.txt", 'wb') as encrypted_file:
    encrypted_file.write(encrypted_file_content + signature)
print("Encrypted k (C):", b64encode(encrypted_k).decode('utf-8'))

print("Encrypted File content and signature written to 'encrypted_data_with_signature.txt'.")

# --- Decryption and Verification Process ---

encrypted_k_base64 = input("Enter the encrypted k (C): ")
encrypted_k = b64decode(encrypted_k_base64)

# Read the content of the encrypted file
with open("encrypted_data_with_signature.txt", 'rb') as encrypted_file:
    encrypted_data_with_signature = encrypted_file.read()

# Separate the encrypted content and signature
encrypted_content = encrypted_data_with_signature[:-256]  # Assuming the signature is 256 bytes
received_signature = encrypted_data_with_signature[-256:]

decryptor = PKCS1_OAEP.new(bob_private_key)
decrypted_k = decryptor.decrypt(encrypted_k)
# Decrypt k using Alice's private key (RSA decryption with PKCS1_OAEP)
#decrypted_k = alice_private_key.decrypt(encrypted_k)
# Decrypt File content using decrypted k (DES decryption)
des_cipher = DES.new(decrypted_k, DES.MODE_ECB)
decrypted_file_content = des_cipher.decrypt(encrypted_content)

# Unpad the decrypted content
decrypted_file_content = unpad_data(decrypted_file_content)
# Verify the signature using Alice's public key
hash_func = SHA256.new(decrypted_file_content)
try:
    pkcs1_15.new(alice_public_key).verify(hash_func, received_signature)
    print("Signature is valid.")
except (ValueError, TypeError):
    print("Signature is invalid.")



# Write the decrypted content to a file
with open("decrypted_data.txt", 'wb') as decrypted_file:
    decrypted_file.write(decrypted_file_content)

print("Decrypted File content written to 'decrypted_data.txt'.")
