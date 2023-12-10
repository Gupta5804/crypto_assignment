from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
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

# Bob's RSA key pair (public key and private key)
bob_key_pair = RSA.generate(2048)
bob_public_key = bob_key_pair.publickey()

# Prompt the user to enter the path of the file to encrypt
file_path = input("Enter the path of the file to encrypt: ")

# --- Encryption Process ---

# Read the content of the file
with open(file_path, 'rb') as file:
    file_content = file.read()

# Generate a random k for DES encryption
k = generate_des_key()

# Encrypt k using Bob's public key (RSA encryption with PKCS1_OAEP)
cipher_rsa = PKCS1_OAEP.new(bob_public_key)
encrypted_k = cipher_rsa.encrypt(k)

# Encrypt File content using k (DES encryption)
des_cipher = DES.new(k, DES.MODE_ECB)
encrypted_file_content = des_cipher.encrypt(pad_data(file_content))

# Write encrypted data to a file
with open("encrypted_data.txt", 'wb') as encrypted_file:
    encrypted_file.write(encrypted_file_content)

print("Encrypted k (C):", b64encode(encrypted_k).decode('utf-8'))
print("Encrypted File content written to 'encrypted_data.txt'.")

# --- Decryption Process ---

# Prompt the user to enter the encrypted k (C)
encrypted_k_base64 = input("Enter the encrypted k (C): ")
encrypted_k = b64decode(encrypted_k_base64)

# Encrypted File content (C') obtained from the encryption process
encrypted_file_path = "encrypted_data.txt"

decryptor = PKCS1_OAEP.new(bob_key_pair)
decrypted_k = decryptor.decrypt(encrypted_k)
# Decrypt k using Bob's private key (RSA decryption with PKCS1_OAEP)
#decrypted_k = bob_key_pair.decrypt(encrypted_k)

# Decrypt File content using decrypted k (DES decryption)
des_cipher = DES.new(decrypted_k, DES.MODE_ECB)
with open(encrypted_file_path, 'rb') as encrypted_file:
    encrypted_file_content = encrypted_file.read()
    decrypted_file_content = des_cipher.decrypt(encrypted_file_content)

# Unpad the decrypted content
decrypted_file_content = unpad_data(decrypted_file_content)

# Write the decrypted content to a file
with open("decrypted_data.txt", 'wb') as decrypted_file:
    decrypted_file.write(decrypted_file_content)

print("Decrypted File content written to 'decrypted_data.txt'.")
