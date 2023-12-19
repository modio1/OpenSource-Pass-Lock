from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, messagebox

class PasswordManagerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("OSPassLock")

        # Set window transparency (0.9 = 90% transparency)
        self.master.attributes('-alpha', 0.9)

        self.password_manager = PasswordManager()

        self.notebook = ttk.Notebook(master)
        self.notebook.pack(expand=True, fill=tk.BOTH)

        self.create_password_tab()
        self.create_decrypted_password_tab()

    def create_password_tab(self):
        password_tab = ttk.Frame(self.notebook)
        self.notebook.add(password_tab, text="Enter Password")

        label = tk.Label(password_tab, text="Enter your Password")
        label.pack(pady=10)

        password_entry = tk.Entry(password_tab, show="*")
        password_entry.pack(pady=10)

        save_button = tk.Button(password_tab, text="Add to Vault", command=lambda: self.save_password(password_entry.get()))
        save_button.pack(pady=10)

    def create_decrypted_password_tab(self):
        decrypted_tab = ttk.Frame(self.notebook)
        self.notebook.add(decrypted_tab, text="Passwords")

        show_decrypted_button = tk.Button(decrypted_tab, text="Show Passwords", command=self.show_decrypted_passwords)
        show_decrypted_button.pack(pady=10)

        clear_decrypted_button = tk.Button(decrypted_tab, text="Delete All", command=self.clear_decrypted_passwords)
        clear_decrypted_button.pack(pady=10)

        self.decrypted_text = tk.Text(decrypted_tab, wrap="word", state=tk.DISABLED)
        self.decrypted_text.pack(expand=True, fill=tk.BOTH)

    def save_password(self, password):
        if password:
            self.password_manager.encrypt_and_save_password(password)
            messagebox.showinfo("Success", "Password saved successfully!")
        else:
            messagebox.showwarning("Warning", "Please enter a password.")

    def show_decrypted_passwords(self):
        decrypted_passwords = self.password_manager.decrypt_passwords()
        if decrypted_passwords:
            decrypted_passwords_str = "\n".join(decrypted_passwords)
            self.decrypted_text.config(state=tk.NORMAL)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, decrypted_passwords_str)
            self.decrypted_text.config(state=tk.DISABLED)
        else:
            messagebox.showinfo("Info", "No passwords to display.")

    def clear_decrypted_passwords(self):
        self.password_manager.clear_passwords()
        self.show_decrypted_passwords()
        messagebox.showinfo("Info", "Decrypted passwords cleared.")

class PasswordManager:
    def __init__(self, key_file_path="key.txt", encrypted_file_path="encrypted.txt"):
        self.key_file_path = key_file_path
        self.encrypted_file_path = encrypted_file_path
        self.key = self.load_or_generate_key()
        self.fernet = Fernet(self.key)

    def load_or_generate_key(self):
        try:
            with open(self.key_file_path, 'rb') as key_file:
                return key_file.readline()
        except FileNotFoundError:
            with open(self.key_file_path, 'wb') as key_file:
                key = Fernet.generate_key()
                key_file.write(key)
                return key

    def encrypt_and_save_password(self, password):
        enc_pass = self.fernet.encrypt(password.encode())
        try:
            with open(self.encrypted_file_path, "ab") as encrypted_file:
                encrypted_file.write(enc_pass + b'\n')
        except Exception as e:
            messagebox.showerror("Error", f"Error writing to encrypted file: {e}")

    def decrypt_passwords(self):
        plain_text = []
        try:
            with open(self.encrypted_file_path, "rb") as read_enc:
                for line in read_enc:
                    plain_text.append(line.rstrip(b'\n'))
        except FileNotFoundError:
            messagebox.showinfo("File Not Found", "Encrypted file not found.")
        except Exception as e:
            messagebox.showerror("Error", f"Error reading encrypted file: {e}")

        decrypted_passwords = [self.fernet.decrypt(password).decode() for password in plain_text]
        return decrypted_passwords

    def clear_passwords(self):
        try:
            open(self.encrypted_file_path, 'w').close()
        except Exception as e:
            messagebox.showerror("Error", f"Error clearing passwords: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.geometry("400x300")  # Set a smaller window size
    root.mainloop()










