# Secure File Communication using RSA and DES

This Python script demonstrates a secure file communication process between two parties, Alice and Bob, using RSA for signature and key exchange and DES for file encryption. The script performs the following steps:

1. Alice signs the content of a file using her private RSA key.
2. A random symmetric key (k) is generated for DES encryption.
3. Alice encrypts k with Bob's public RSA key.
4. Alice encrypts the file content using the symmetric key k and DES encryption.
5. The encrypted file content and the RSA signature are written to a file.

![alt text](https://github.com/Gupta5804/crypto_assignment/blob/2298b7efc75e03a1a5d56374f8142d76c0e7d65a/CyberSecurity%20Assignment.jpg?raw=true)

To run the demo, follow the instructions below.

# Step-by-Step Instructions:

Clone the Repository:

    git clone https://github.com/Gupta5804/crypto_assignment
    cd crypto_assignment

Set up Virtual Environment:
Create and activate a virtual environment (assuming you have Python installed). If you don't have virtualenv installed, install it first:


    pip install virtualenv

Then, create and activate a virtual environment:


    virtualenv venv
    source venv/bin/activate      # On Windows: .\venv\Scripts\activate

Install Requirements:
Install the required packages from the requirements.txt file:

    pip install -r requirements.txt

Put the File to be encrypted in the same project folder and Run the Script:
Run the script using the Python interpreter:
    
    python encryption_decryption_with_signature.py

Enter File Name:
The script will prompt you to enter the name of the file(text) you want to sign and encrypt. Provide the name of the file.

View Output:
The script will output the base64-encoded symmetric key (k) and notify you that the encrypted file content and signature are written to encrypted_data_with_signature.txt.

Copy Encrypted k (C):
The script will prompt you to enter the encrypted k (C). Copy the base64-encoded k from the output.

Decryption and Verification:
The script will decrypt the symmetric key using Bob's private RSA key, then decrypt the file content using the symmetric key. It will verify the signature using Alice's public RSA key.

View Decrypted Content:
The decrypted file content will be written to decrypted_data.txt.
