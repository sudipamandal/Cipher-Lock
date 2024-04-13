from tkinter import *
from tkinter import messagebox
import base64

def decrypt():
    selected_algorithm = algorithm_choice.get()
    message = text1.get(1.0, END)
    decrypted_message = ""
    if selected_algorithm == "Base64":
        password = code.get()
        if password == "1234":
            decrypted_message = base64_decrypt(message)
        else:
            messagebox.showerror("Decryption", "Invalid Password")
            return
    elif selected_algorithm == "Caesar Cipher":
        shift = int(shift_entry.get())  # Get the shift value from the entry
        decrypted_message = caesar_decrypt(message, shift)
    elif selected_algorithm == "XOR Cipher":
        key = key_entry.get()  # Get the key from the entry
        decrypted_message = xor_decrypt(message, key)

    screen2 = Toplevel(screen)
    screen2.title("Decryption")
    screen2.geometry("400x200")
    screen2.configure(bg="#00bd56")

    Label(screen2, text="DECRYPT", font="arial", fg="white", bg="#00bd56").place(x=10, y=0)
    text2 = Text(screen2, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text2.place(x=10, y=40, width=380, height=150)

    text2.insert(END, decrypted_message)

def encrypt():
    selected_algorithm = algorithm_choice.get()
    message = text1.get(1.0, END)

    if selected_algorithm == "Base64":
        password = code.get()
        if password == "1234":
            encrypted_message = base64_encrypt(message)
        else:
            messagebox.showerror("Encryption", "Invalid Password")
            return
    elif selected_algorithm == "Caesar Cipher":
        shift = int(shift_entry.get())  # Get the shift value from the entry
        encrypted_message = caesar_encrypt(message, shift)
    elif selected_algorithm == "XOR Cipher":
        key = key_entry.get()  # Get the key from the entry
        encrypted_message = xor_encrypt(message, key)

    screen1 = Toplevel(screen)
    screen1.title("Encryption")
    screen1.geometry("400x200")
    screen1.configure(bg="#ed3833")

    Label(screen1, text="ENCRYPT", font="arial", fg="white", bg="#ed3833").place(x=10, y=0)
    text2 = Text(screen1, font="Roboto 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text2.place(x=10, y=40, width=380, height=150)

    text2.insert(END, encrypted_message)

def base64_encrypt(message):
    encode_msg = message.encode("ascii")
    base64_bytes = base64.b64encode(encode_msg)
    encrypted_message = base64_bytes.decode("ascii")
    return encrypted_message

def base64_decrypt(message):
    decode_msg = message.encode("ascii")
    base64_bytes = base64.b64decode(decode_msg)
    decrypted_message = base64_bytes.decode("ascii")
    return decrypted_message

def caesar_encrypt(message, shift):
    encrypted_message = caesar_cipher(message, shift, "encrypt")
    return encrypted_message

def caesar_decrypt(message, shift):
    decrypted_message = caesar_cipher(message, shift, "decrypt")
    return decrypted_message

def xor_encrypt(message, key):
    encrypted_message = xor_cipher(message, key)
    return encrypted_message

def xor_decrypt(message, key):
    decrypted_message = xor_cipher(message, key)
    return decrypted_message

def caesar_cipher(text, shift, mode):
    result = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                result += chr((ord(char) - ord('a') + shift) % 26 + ord('a')) if mode == "encrypt" else chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            else:
                result += chr((ord(char) - ord('A') + shift) % 26 + ord('A')) if mode == "encrypt" else chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
        else:
            result += char
    return result

def xor_cipher(text, key):
    result = ""
    for i in range(len(text)):
        result += chr(ord(text[i]) ^ ord(key[i % len(key)]))
    return result

def reset():
    code.set("")
    text1.delete("1.0", "end")
    shift_entry.delete(0, "end")
    key_entry.delete(0, "end")

    

def main_screen():
    global screen
    global text1
    global algorithm_choice
    global code
    global key_entry
    global shift_entry

    screen = Tk()
    screen.geometry("375x398")
    screen.title("Encryption App")

    Label(text="Enter text for encryption and decryption", fg="black", font=("calibri", 13)).place(x=10, y=10)
    text1 = Text(font="Roboto 20", bg="white", relief=GROOVE, wrap=WORD, bd=0)
    text1.place(x=10, y=50, width=355, height=100)

    Label(text="Select encryption method:", fg="black", font=("calibri", 13)).place(x=10, y=170)

    algorithm_choice = StringVar()
    algorithm_choice.set("Base64")  # Default choice
    OptionMenu(screen, algorithm_choice, "Base64", "Caesar Cipher", "XOR Cipher").place(x=200, y=170)

    Label(text="Enter secret key for Base64:", fg="black", font=("calibri", 13)).place(x=10, y=200)
    code = StringVar()
    Entry(textvariable=code, width=19, bd=1, font=("arial", 14), show="*").place(x=220, y=200)

    Label(text="Enter Caesar Cipher shift (0-25):", fg="black", font=("calibri", 13)).place(x=10, y=230)
    shift_entry = Entry(width=19, bd=1, font=("arial", 14))
    shift_entry.place(x=240, y=230)

    Label(text="Enter XOR key:", fg="black", font=("calibri", 13)).place(x=10, y=260)
    key_entry = Entry(width=19, bd=1, font=("arial", 14))
    key_entry.place(x=200, y=260)

    Button(text="ENCRYPT", height="2", width=23, bg="#ed3833", fg="white", bd=0, command=encrypt).place(x=10, y=290)
    Button(text="DECRYPT", height="2", width=23, bg="#00bd56", fg="white", bd=0, command=decrypt).place(x=200, y=290)
    Button(text="RESET",height="2",width=50,bg = "#1089ff",fg="white",bd=0,command=reset).place(x=10,y=350)

    screen.mainloop()

main_screen()
