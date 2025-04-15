import sys 
import re
from itertools import combinations

# set true if you want to be asked permission for each match
ASK_USER = False

# ---------- CHECK ARGS ----------
if len(sys.argv) > 2:
    print("Usage: python3 crack_otp.py [-d]")
    sys.exit()

if len(sys.argv) == 2:
    if sys.argv[1] == "-d":
        # use default files
        encrypted_file = "stage_1.txt"
        crib_file = "cribs.txt"
        dict_file = "dict.txt"
    else:
        print("Usage: python3 crack_otp.py [-d]")
        sys.exit()
else:
    # read user custom files
    encrypted_file = input("File to decrypt: ")
    crib_file = input("File with cribs: ")
    dict_file = input("File with dictionary: ")


# ---------- FUNCTIONS ----------
# returns list of all messages in binary
def parse_cipher_file(file: str):
    # read file
    with open(file, 'r') as f:
        lines = f.read().strip().split('\n')

    messages = []

    for line in lines:
        line = line.strip()
        # skip lines that are not messages
        if not line or line.startswith("eavesdropped") or line.startswith("challenge"):
            continue
        else:
            messages.append(bytes.fromhex(line))

    flag = messages.pop()
    return messages, flag

# returns list of cribs from file
def parse_crib_file(file: str):
    # read file
    with open(file, 'r') as f:
        lines = f.read().strip().split('\n')

    cribs = []

    for line in lines:
        line = line.strip()
        cribs.append(line)
    
    return cribs 

def parse_dict_file(file: str):
    with open(file, 'r') as f:
        return set(word.strip().lower() for word in f if word.strip())

# drag crib over pair of messages
def crib_drag(combination: [bytes, bytes], crib: str, dictionary: set):
    """
    p1 = c1 XOR c2 XOR p2_guess
    p1 ... plaintext of message 1
    c1 ... encrypted message 1
    c2 ... encrypted message 2
    p2_guess ... created from crib 
    """
    c1 = combination[0]
    c2 = combination[1]
    p2_guess = crib.encode()

    # c12 = c1 XOR c2
    c12 = []
    for i in range(min(len(c1), len(c2))):
        byte = c1[i] ^ c2[i]
        c12.append(byte)

    # p2_guess über c12 draggen
    step_size = len(p2_guess)
    for i in range(len(c12) - step_size + 1):
        section = c12[i:i+step_size]
        result = bytes([a ^ b for a, b in zip(section, p2_guess)])
        """
        result may now contain a cleartext word
        from p1
        -> decode result and ask user whether
        the result makes sense
        """
        if verify_result(result, dictionary):
            print("Offset [", i, "] marked as hit.")
            """
            TODO
            aus offset, crib und c2 kann nun der 
            entsprechende teil des keys berechnet werden
            zb: fn calculate_key_fraction(i, p2_guess, c2)
            """

# verify section result with dictionary and user input
def verify_result(result: bytes, dictionary: set):
    try:
        ascii_result = result.decode() 
    except UnicodeDecodeError:
        return False 
    
    # move on if string contains special characters
    if not re.fullmatch(r"[a-z ]+", ascii_result):
        return False

    # move on if not in dictionary
    words = ascii_result.strip().lower().split()
    if not any(word in dictionary for word in words):
        return False

    if ASK_USER:
        # ask user confirmation
        print(ascii_result)
        user = input("Sensible word? ([ENTER]/'n'): ")
        return user.strip().lower() != 'n'



# ---------- MAIN ----------
# 1. parse input file
messages, flag = parse_cipher_file(encrypted_file)

# 2. parse crib file
cribs = parse_crib_file(crib_file)

# 3. parse dict file
dictionary = parse_dict_file(dict_file)

# 3. crib drag every word
# for every pair of messages
msg_combinations = list(combinations(messages, 2))
for i in range(len(msg_combinations)):
    # print("--- crib dragging for combination", i, "---")
    for crib in cribs:
        # print("--- with crib: ", crib, "---")
        crib_drag(msg_combinations[i], crib, dictionary)