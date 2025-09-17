import base64
import hashlib
import codecs
import random
import os
import colorama
from colorama import Style, Fore, init
import pyfiglet

init(autoreset=True)

def Base64(data):
    data_bytes = data.encode('ascii')
    base64_bytes = base64.b64encode(data_bytes)
    base64_string = base64_bytes.decode('ascii')
    print(f"Encoded to Base64 : {base64_string}")
    return base64_string

def Rot13(data):
    coded = codecs.encode(data, 'rot13')
    print(f"Encoded with Rot13: {coded}")
    return coded

def sha256(data):
    data_bytes = data.encode('utf-8')
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data_bytes)
    hex_digest = sha256_hash.hexdigest()
    print(f"Encoded Into SHA256: {hex_digest}")
    return hex_digest

def sha512(data):
    data_bytes = data.encode('utf-8')
    sha512_hash = hashlib.sha512()
    sha512_hash.update(data_bytes)
    hex_digest = sha512_hash.hexdigest()
    print(f"Encoded Into SHA512: {hex_digest}")
    return hex_digest

def MD5(data):
    m = hashlib.md5()
    m.update(data.encode('utf-8'))
    md5_hash = m.hexdigest()
    print(f"Encoded into MD5: {md5_hash}")
    return md5_hash

def sha1(data):
    m = hashlib.sha1()
    m.update(data.encode('utf-8'))
    sha1_hash = m.hexdigest()
    print(f"Encoded into SHA1: {sha1_hash}")
    return sha1_hash

def sha384(data):
    m = hashlib.sha384()
    m.update(data.encode('utf-8'))
    sha384_hash = m.hexdigest()
    print(f"Encoded Into SHA384: {sha384_hash}")
    return sha384_hash

def sha3_224(data):
    m = hashlib.sha3_224()
    m.update(data.encode('utf-8'))
    sha3_224_hash = m.hexdigest()
    print(f"Encoded Into SHA3_224: {sha3_224_hash}")
    return sha3_224_hash

def get_random_functions(num_function, all_func):
    if num_function > len(all_func) or num_function < 1:
        print(f"Invalid input. Enter number between 1 to {len(all_func)}")
        return []
    return random.sample(all_func, num_function)

def run_pipeline(initial_data, pipeline):
    current_data = initial_data
    used_algorithms = []
    for func in pipeline:
        current_data = func(current_data)
        used_algorithms.append(func.__name__)
    return current_data, used_algorithms

def main():
    all_functions = [Base64, Rot13, sha256, sha512, sha1, sha384, sha3_224, MD5]
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = pyfiglet.figlet_format("Sudo-Password", font="chunky", width=100)
    print(Fore.GREEN + banner)
    print(Fore.GREEN + "=" * 80)
    print(Fore.RED + "Store your password like never before.")
    print(Fore.RED + "Author: MrHoodie")
    print(Fore.RED + "Github: https://github.com/NotReallySerious/sudo_password")

    # Get user input for the number of functions to chain
    try:
        num_to_chain = int(input(f"How many functions would you like to randomly chain? (1-{len(all_functions)}): "))
    except ValueError:
        print("Invalid input. Please enter a valid number.")
        exit()

    # Get the random subset of functions
    selected_pipeline = get_random_functions(num_to_chain, all_functions)

    if selected_pipeline:
        # Print the names of the selected functions for clarity
        print("\nSelected pipeline (in order of execution):")
        for f in selected_pipeline:
            print(f"- {f.__name__}")

        # Get initial data from user
        initial_value = input("\nEnter the initial data to encode/hash: ")

        # Run the pipeline and get the final result and used algorithms
        final_result, used_algorithms = run_pipeline(initial_value, selected_pipeline)

        # Format the algorithm names as a comma-separated string
        algos_str = ",".join(used_algorithms)

        print(f"\nFinal Result: {final_result} - ({algos_str})")
    else:
        print("Program terminated due to invalid input.")

if __name__ == "__main__":
    main()
