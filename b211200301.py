from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import tkinter as tk
from tkinter import messagebox
import timeit
import tracemalloc
import psutil

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AES Şifreleme Uygulaması")

        self.label = tk.Label(root, text="Şifrelemek istediğiniz metni girin:")
        self.label.pack()

        self.text_entry = tk.Entry(root)
        self.text_entry.pack()

        self.key_label = tk.Label(root, text="Kullanılacak Anahtarı Girin (32 byte uzunluğunda):")
        self.key_label.pack()

        self.key_entry = tk.Entry(root)
        self.key_entry.pack()

        self.encrypt_button = tk.Button(root, text="Şifrele", command=self.encrypt)
        self.encrypt_button.pack()

        self.exit_button = tk.Button(root, text="Çıkış", command=self.root.destroy)
        self.exit_button.pack()

    def encrypt(self):
        plaintext = self.text_entry.get().encode()
        user_key = self.key_entry.get().encode()

        if len(user_key) != 32:
            messagebox.showerror("Hata", "Hatalı anahtar uzunluğu. 32 byte uzunluğunda bir anahtar girmelisiniz.")
        else:
            cpu_percent = psutil.cpu_percent(interval=1)

            tracemalloc.start()

            start_time = timeit.default_timer()

            ciphertext, iv = self.perform_encryption(plaintext, user_key)

            current, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            end_time = timeit.default_timer()
            elapsed_time = end_time - start_time

            messagebox.showinfo("Şifreleme Tamamlandı", f"Ciphertext: {ciphertext.hex()}\nIV: {iv.hex()}\n\n"
                                                           f"Şifrelenmiş Veri: {self.text_entry.get()}\n"
                                                           f"Anahtar: {user_key.decode()}\n"
                                                           f"Geçen Zaman: {elapsed_time} saniye\n"
                                                           f"Bellek Tüketimi: {peak / 10**6} MB\n"
                                                           f"CPU Kullanımı: {cpu_percent}%")

    def perform_encryption(self, plaintext, key):
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(plaintext, AES.block_size)
        ciphertext = cipher.encrypt(padded_data)
        iv = cipher.iv
        return ciphertext, iv

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
