import math
import random
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_prime_number():
    """Generate a random prime number"""
    # I am choosing to use the cryptography library to generate a random prime number
    # instead of using a random number generator and then checking if it is prime.
    # but for the sake of learning, I will show you how to do it yourself.
    ###############################
    # def is_prime(n):
    #     """Check if a number is prime. Efficient for simple cases, use Miller-Rabin or AKS algorithm 
    #           for large numbers"""
    #     if n <= 1:
    #         return False
    #     elif n <= 3:
    #         return True
    #     elif n % 2 == 0 or n % 3 == 0:
    #         return False
    #     else:
    #         for i in range(5, int(math.sqrt(n)) + 1, 6):
    #             if n % i == 0 or n % (i + 2) == 0:
    #                 return False
    #     return True

    # p = random.randint(100, 10000)
    # while not is_prime(p):
    #     p = random.randint(100, 10000)
    # return p

    pkey = rsa.generate_private_key(65537, 2048)
    return pkey.private_numbers().p


def generate_keys():
    """Generate a public/private key pair"""
    # Generate a random prime number
    p = generate_prime_number()

    # Generate another random prime number
    q = generate_prime_number()

    # Multiply the two prime numbers together to get our modulus for the private and public keys
    n = p * q

    # Using Euler's totient function, phi(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)

    # Choose an integer e, 1 < e < phi, such that gcd(e, phi) = 1
    e = random.randint(1, phi)
    g = math.gcd(e, phi)
    while g != 1:
        e = random.randint(1, phi)
        g = math.gcd(e, phi)
    
    # Determine d as d ≡ e−1 (mod phi), that is, d is the multiplicative inverse of e (modulo phi).
    d = pow(e, -1, phi)

    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


def encrypt(message, public_key):
    """Encrypt a message with a public key"""
    # Unpack the key into it's components
    key, n = public_key

    # Convert each letter in the message to numbers based on the character using a^b mod m
    e, n = public_key
    cipher = [pow(ord(char), e, n) for char in message]
    return cipher


def decrypt(cipher, private_key):
    """Decrypt a message with a private key"""
    # Unpack the key into its components
    key, n = private_key

    # Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr(pow(char, key, n)) for char in cipher]

    # Return the array of bytes as a string
    return ''.join(plain)


if __name__ == '__main__':
    print('RSA Encrypter/ Decrypter')
    message = "I am going to test this out."

    print('Generating your public/private keypairs now . . .')
    public, private = generate_keys()

    encrypted_msg = encrypt(message, public)
    print(f"the encrypted message is {encrypted_msg}")

    print("+----------------------------------+")

    decrypted_msg = decrypt(encrypted_msg, private)
    print(f"the decrypted message is {decrypted_msg}")
