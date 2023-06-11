# 4 praktinė užduotis: RSA skaitmeninio parašo algoritmą (DSA - Digital Signature Verification).

from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import dsa
import tkinter as tk

def siganture_generation(private_key, text):
    signature = private_key.sign(text.encode(), hashes.SHA256())
    return signature.hex()

def signature_verification(public_key, signature, text):
    try:
        signature_bytes = bytes.fromhex(signature)
        public_key.verify(signature_bytes, text.encode(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False

def signature_calculation():
    text = text_input.get()
    signature = siganture_generation(private_key, text)
    signature_output.delete(0, tk.END)
    signature_output.insert(tk.END, signature)

def verification_answer():
    text = verify_text_input.get()
    signature = signature_output.get()
    is_verified = signature_verification(public_key, signature, text)
    if is_verified:
        label_result.config(text="Verified")
    else:
        label_result.config(text="Not verified")

private_key = dsa.generate_private_key(key_size=1024)
public_key = private_key.public_key()

window = tk.Tk()
window.title("DSA Digital Signature Verification")

label_text = tk.Label(window, text="Text:")
label_text.pack()
text_input = tk.Entry(window)
text_input.pack()

button_calculate = tk.Button(window, text="Calculate Signature", command=signature_calculation)
button_calculate.pack()

label_signature = tk.Label(window, text="Digital Signature:")
label_signature.pack()
signature_output = tk.Entry(window)
signature_output.pack()

label_verify_text = tk.Label(window, text="Verify Text:")
label_verify_text.pack()
verify_text_input = tk.Entry(window)
verify_text_input.pack()

button_verify = tk.Button(window, text="Verify Signature", command=verification_answer)
button_verify.pack()

label_result = tk.Label(window, text="")
label_result.pack()

window.mainloop()
