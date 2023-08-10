import tkinter as tk
from tkinter import messagebox
import base64

# XOR encryption key
xor_key = "secretkey"

def xor_encrypt_decrypt(message):
    encrypted_message = ""
    for i in range(len(message)):
        # XOR each character with corresponding character in the key
        key_char = xor_key[i % len(xor_key)]
        encrypted_char = chr(ord(message[i]) ^ ord(key_char))
        encrypted_message += encrypted_char
    return encrypted_message

def decrypt():
    password = code.get()
    method = method_var.get()

    if password == "1234":
        message = text1.get(1.0, tk.END)
        decode_message = message.encode("ascii")

        if method == "Base64":
            base64_bytes = base64.b64decode(decode_message)
            decrypt_message = base64_bytes.decode("ascii")
        elif method == "XOR":
            decrypt_message = xor_encrypt_decrypt(decode_message.decode("ascii"))

        create_window("Decryption", decrypt_message)

    elif password == "":
        messagebox.showerror("Decryption", "Input Password")

    else:
        messagebox.showerror("Decryption", "Invalid Password")

def encrypt():
    password = code.get()
    method = method_var.get()

    if password == "1234":
        message = text1.get(1.0, tk.END)

        if method == "Base64":
            base64_bytes = base64.b64encode(message.encode("ascii"))
            encrypt_message = base64_bytes.decode("ascii")
        elif method == "XOR":
            encrypt_message = xor_encrypt_decrypt(message)

        create_window("Encryption", encrypt_message)

    elif password == "":
        messagebox.showerror("Encryption", "Input Password")

    else:
        messagebox.showerror("Encryption", "Invalid Password")




def decrypt():
    password = code.get()

    if password == "1234":
        message = text1.get(1.0, tk.END)
        decode_message = message.encode("ascii")
        base64_bytes = base64.b64decode(decode_message)
        decrypt = base64_bytes.decode("ascii")

        create_window("Decryption", decrypt)

    elif password == "":
        messagebox.showerror("Decryption", "Input Password")

    else:
        messagebox.showerror("Decryption", "Invalid Password")

def encrypt():
    password = code.get()

    if password == "1234":
        message = text1.get(1.0, tk.END)
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        encrypt = base64_bytes.decode("ascii")

        create_window("Encryption", encrypt)

    elif password == "":
        messagebox.showerror("Encryption", "Input Password")

    else:
        messagebox.showerror("Encryption", "Invalid Password")

def create_window(title, result):
    window = tk.Toplevel(screen)
    window.title(title)
    window.geometry("400x200")
    bg_color = "#ed3833" if title == "Encryption" else "#00bd56"
    window.configure(bg=bg_color)

    label = tk.Label(window, text=title, font="Arial", fg="white", bg=bg_color)
    label.place(x=10, y=0)

    text2 = tk.Text(window, font="Roboto 10", bg="white", relief=tk.GROOVE, wrap=tk.WORD, bd=0)
    text2.place(x=10, y=40, width=380, height=150)
    text2.insert(tk.END, result)

def reset():
    code.set("")
    text1.delete(1.0, tk.END)

def main_screen():
    global screen
    global code
    global text1
    global method_var

    screen = tk.Tk()
    screen.geometry("500x490")
    screen.title("Message Encryption and Decryption")

    label1 = tk.Label(text="Enter text for encryption and decryption", fg="black", font=("Calibri", 13))
    label1.place(x=10, y=10)

    text1 = tk.Text(font="Roboto 20", bg="white", relief=tk.GROOVE, wrap=tk.WORD, bd=3)
    text1.place(x=10, y=50, width=335, height=100)

    label2 = tk.Label(text="Enter password for encryption and decryption", fg="black", font=("Calibri", 13))
    label2.place(x=10, y=170)

    code = tk.StringVar()
    entry = tk.Entry(textvariable=code, width=19, bd=3, font=("Arial", 25), show="*")
    entry.place(x=10, y=200)



    encrypt_button = tk.Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="red", bd=0, command=encrypt)
    encrypt_button.place(x=10, y=350)

    decrypt_button = tk.Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="green", bd=0, command=decrypt)
    decrypt_button.place(x=220, y=350)

    reset_button = tk.Button(text="RESET", height="2", width=23, bg="#1089ff", fg="black", bd=0, command=reset)
    reset_button.place(x=10, y=390)

    method_var = tk.StringVar()
    method_var.set("Base64")
    method_option = tk.OptionMenu(screen, method_var, "Base64", "XOR")
    method_option.place(x=190, y=285)




    screen.mainloop()

# Unit tests
import unittest

class EncryptionDecryptionTests(unittest.TestCase):
    def test_encrypt_decrypt(self):
        password = "1234"
        message = "Hello, World!"

        # Encrypt
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        encrypt = base64_bytes.decode("ascii")

        self.assertEqual(encrypt, "SGVsbG8sIFdvcmxkIQ==")

        # Decrypt
        decode_message = base64.b64decode(encrypt.encode("ascii"))
        decrypt = decode_message.decode("ascii")

        self.assertEqual(decrypt, message)

    def test_invalid_password(self):
        password = "4321"
        message = "Hello, World!"

        # Encrypt
        encode_message = message.encode("ascii")
        base64_bytes = base64.b64encode(encode_message)
        encrypt = base64_bytes.decode("ascii")

        self.assertNotEqual(encrypt, "SGVsbG8sIFdvcmxkIQ==")

        # Decrypt
        decode_message = base64.b64decode(encrypt.encode("ascii"))
        decrypt = decode_message.decode("ascii")

        self.assertNotEqual(decrypt, message)

if __name__ == '__main__':
    # Run the unit tests
    unittest.main()

# Run the application
main_screen()
