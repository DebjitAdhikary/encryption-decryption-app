import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_file(input_file, output_file, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Read the input file
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Pad the plaintext to be a multiple of AES block size
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    # Write the IV and ciphertext to the output file
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

def decrypt_file(input_file, output_file, key):
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    # Read the encrypted file
    with open(input_file, 'rb') as f:
        iv = f.read(16)  # Read the IV (first 16 bytes)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)

    try:
        # Unpad the plaintext
        plaintext = unpad(padded_plaintext, AES.block_size)
    except ValueError:
        messagebox.showerror("Error", "Incorrect decryption. Padding is incorrect.")
        return

    # Write the plaintext to the output file
    with open(output_file, 'wb') as f:
        f.write(plaintext)

def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def get_file_extension(file_type):
    if file_type == "PDF":
        return ".pdf"
    elif file_type == "Image":
        return ".jpg"  # Assuming image files are JPG for simplicity
    elif file_type == "Audio":
        return ".mp3"
    elif file_type == "Video":
        return ".mp4"
    else:
        return ""

def encrypt():
    try:
        input_file = file_entry.get()
        file_type = file_type_combobox.get()
        if not file_type:
            raise ValueError("Please select a file type.")
        
        extension = get_file_extension(file_type)
        if not input_file.endswith(extension):
            raise ValueError(f"Selected file does not match the specified file type: {file_type}")

        output_file = input_file + '.enc'
        key = key_entry.get().encode()

        encrypt_file(input_file, output_file, key)
        messagebox.showinfo("Success", f"File encrypted successfully and saved to {output_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt():
    try:
        input_file = file_entry.get()
        file_type = file_type_combobox.get()
        if not file_type:
            raise ValueError("Please select a file type.")
        
        extension = get_file_extension(file_type)
        if not input_file.endswith('.enc'):
            raise ValueError("Selected file is not an encrypted file.")

        output_file = os.path.splitext(input_file)[0] + '_decrypted' + extension
        key = key_entry.get().encode()

        decrypt_file(input_file, output_file, key)
        messagebox.showinfo("Success", f"File decrypted successfully and saved to {output_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

app = tk.Tk()
app.title("File Encryption App")

frame = tk.Frame(app)
frame.pack(padx=10, pady=10)

file_label = tk.Label(frame, text="Select File:")
file_label.grid(row=0, column=0, padx=5, pady=5)

file_entry = tk.Entry(frame, width=40)
file_entry.grid(row=0, column=1, padx=5, pady=5)

file_button = tk.Button(frame, text="Browse", command=select_file)
file_button.grid(row=0, column=2, padx=5, pady=5)

key_label = tk.Label(frame, text="Enter Encryption Key:")
key_label.grid(row=1, column=0, padx=5, pady=5)

key_entry = tk.Entry(frame, show="*", width=40)
key_entry.grid(row=1, column=1, padx=5, pady=5)

file_type_label = tk.Label(frame, text="Select File Type:")
file_type_label.grid(row=2, column=0, padx=5, pady=5)

file_type_combobox = ttk.Combobox(frame, values=["PDF", "Image", "Audio", "Video"], state="readonly")
file_type_combobox.grid(row=2, column=1, padx=5, pady=5)

encrypt_button = tk.Button(frame, text="Encrypt", command=encrypt)
encrypt_button.grid(row=3, column=0, columnspan=2, pady=10)

decrypt_button = tk.Button(frame, text="Decrypt", command=decrypt)
decrypt_button.grid(row=3, column=1, columnspan=2, pady=10)

app.mainloop()
