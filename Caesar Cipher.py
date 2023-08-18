"""
Ceaser Cipher: User can either choose to encrypt, decrypt or brute force
attack to decipher messages that have been encrypted using the Caesar cipher.

Users can also input a text file to encrypt, decrypt or brute force.

"""

def encrypt(message, rotational_value):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    encrypted = ""

    for char in message:
        if char.upper() in alphabet:
            position = alphabet.find(char.upper())
            new_position = (position + rotational_value) % 26
            encrypted += alphabet[new_position]
        else:
            encrypted += char

    return encrypted

def decrypt(message, rotational_value):
    return encrypt(message, -rotational_value)

def brute_force_decrypt(message):
    decrypted_messages = []
    for rv in range(26):
        decrypted_messages.append(decrypt(message, rv))
    return decrypted_messages

def main():
    print("Would you like to decrypt, encrypt, or brute force your message?")
    mode = input().lower()

    if mode == "encrypt":
        message = get_message_input()
        rotational_value = get_rotational_value()
        encrypted_message = encrypt(message, rotational_value)
        print("Encrypted:", encrypted_message)

    elif mode == "decrypt":
        message = get_message_input()
        rotational_value = get_rotational_value()
        decrypted_message = decrypt(message, rotational_value)
        print("Decrypted:", decrypted_message)

    elif mode == "brute":
        message = get_message_input()
        decrypted_messages = brute_force_decrypt(message)
        print("Brute Force Decryption:")
        for idx, decrypted_message in enumerate(decrypted_messages):
            print(f"Rotational Value {idx}: {decrypted_message}")

    else:
        print("Invalid mode choice.")

def get_message_input():
    file_option = input("Would you like to open a file? (YES/NO): ").strip().lower()

    if file_option == "yes":
        filename = input("Enter the filename: ")
        with open(filename, "r") as file:
            message = file.read().strip()
    else:
        message = input("Enter your message: ")

    return message

def get_rotational_value():
    rotational_value = int(input("Enter a positive integer for rotational value: "))
    return rotational_value

if __name__ == "__main__":
    main()


