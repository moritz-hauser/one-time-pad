import sys

# ---------- CHECK ARGS ----------
if len(sys.argv) != 3:
    print("Usage: python3 encrypt.py [cleartext] [key]")
    sys.exit()
file_text = sys.argv[1]
file_key = sys.argv[2]


# ---------- FUNCTIONS ----------
def encrypt(message: str, key: str) -> bytes:
    # .encode() returns bytes
    bin_message = message.encode()
    bin_key = key.encode()
    
    # check length
    if len(bin_key) < len(bin_message):
        print("Key must be longer than message!")
        sys.exit()
    
    # encrypt byte wise
    encrypted = []
    for i in range(len(bin_message)):
        encrypted_byte = bin_message[i] ^ bin_key[i]
        encrypted.append(encrypted_byte)

    return bytes(encrypted)

def decrypt(bin_message: bytes, key: str):
    # turn string into bytes
    bin_key = key.encode()

    # decrypt byte wise
    decrypted = []
    for i in range(len(bin_message)):
        decrypted_byte = bin_message[i] ^ bin_key[i]
        decrypted.append(decrypted_byte)

    return bytes(decrypted)


# ---------- MAIN ----------
print("Encrypting", file_text, "with", file_key, "...\n")

# read files
with open(file_text, 'r') as f:
    cleartext = f.read()
with open(file_key, 'r') as f:
    key = f.read()

"""
# separate lines in input file
messages = cleartext.split('\n')
print("Original messages:")
print(messages)

# encrypt and decrypt every message
for message in messages:
    print('\n')
    encrypted = encrypt(message, key)
    print("encrypted message:", encrypted)
    decrypted = decrypt(encrypted, key)
    print("decrypted message:", decrypted.decode())
"""

# write encrypted messages to file
with open("encrypted_test_data.txt", 'w') as out:
    messages = cleartext.split('\n')
    for message in messages: 
        encrypted = encrypt(message, key)
        out.write(encrypted.hex() + '\n')
print("encrypted message written to: encrypted_test_data.txt")