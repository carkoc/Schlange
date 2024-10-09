import tkinter as tk
from tkinter import filedialog, messagebox
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

# Secret key (32 bytes)
secret_key = bytes([
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 
    0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f, 
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 
    0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb
])

def sign_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Generate public key from the secret key
    signing_key = SigningKey(secret_key)
    public_key = signing_key.verify_key

    # Sign the file data
    signature = signing_key.sign(file_data).signature

    # Display the signature in the GUI
    signature_hex = signature.hex()
    signature_label.config(text=f"Signature: {signature_hex}")

    # Save the signature to a .sig file
    sig_file_path = file_path + '.sig'
    with open(sig_file_path, 'wb') as sig_file:
        sig_file.write(signature)

    # Verify the signature
    try:
        verify_key = VerifyKey(public_key.encode())
        verify_key.verify(file_data, signature)
        messagebox.showinfo("Success", "Authentication successful")
    except BadSignatureError:
        messagebox.showerror("Error", "Authentication failed")

# Create the main window
root = tk.Tk()
root.title("File Signer")

# Create a button to select and sign the file
sign_button = tk.Button(root, text="Select and Sign File", command=sign_file)
sign_button.pack(pady=20)

# Label to display the signature
signature_label = tk.Label(root, text="Signature: ")
signature_label.pack(pady=20)

# Run the Tkinter event loop
root.mainloop()
