import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import crypto_utils
import os
import hashlib

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Outil Crypto - Interface Graphique")
        self.root.geometry("700x600")
        self.root.configure(bg="#f0f0f0")

        self.setup_ui()

    def setup_ui(self):
        # En-tête
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        header_frame.pack(fill="x")
        tk.Label(header_frame, text="Outil de Chiffrement / Déchiffrement", font=("Arial", 16, "bold"), fg="white", bg="#2c3e50").pack(pady=15)

        # Conteneur principal
        main_frame = tk.Frame(self.root, padx=20, pady=20, bg="#f0f0f0")
        main_frame.pack(fill="both", expand=True)

        # Sélection de l'algorithme
        algo_frame = tk.LabelFrame(main_frame, text="Algorithme", padx=10, pady=10, bg="#f0f0f0")
        algo_frame.pack(fill="x", pady=(0, 15))

        self.algo_var = tk.StringVar(value="caesar")
        algorithms = [
            ("César", "caesar"),
            ("Affine", "affine"),
            ("Vigenère", "vigenere"),
            ("RSA", "rsa"),
            ("DES", "des"),
            ("AES", "aes")
        ]

        for text, val in algorithms:
            tk.Radiobutton(algo_frame, text=text, variable=self.algo_var, value=val, command=self.update_parameters_visibility, bg="#f0f0f0").pack(side="left", padx=10)

        # Cadre des paramètres (Dynamique)
        self.params_frame = tk.LabelFrame(main_frame, text="Paramètres", padx=10, pady=10, bg="#f0f0f0")
        self.params_frame.pack(fill="x", pady=(0, 15))

        # Paramètres César
        self.caesar_frame = tk.Frame(self.params_frame, bg="#f0f0f0")
        tk.Label(self.caesar_frame, text="Décalage (Shift):", bg="#f0f0f0").pack(side="left")
        self.shift_entry = tk.Entry(self.caesar_frame, width=5)
        self.shift_entry.pack(side="left", padx=5)

        # Paramètres Affine
        self.affine_frame = tk.Frame(self.params_frame, bg="#f0f0f0")
        tk.Label(self.affine_frame, text="Coefficient a:", bg="#f0f0f0").pack(side="left")
        self.a_entry = tk.Entry(self.affine_frame, width=5)
        self.a_entry.pack(side="left", padx=5)
        tk.Label(self.affine_frame, text="Coefficient b:", bg="#f0f0f0").pack(side="left")
        self.b_entry = tk.Entry(self.affine_frame, width=5)
        self.b_entry.pack(side="left", padx=5)

        # Paramètres Clé (Vigenère, AES, DES)
        self.key_frame = tk.Frame(self.params_frame, bg="#f0f0f0")
        tk.Label(self.key_frame, text="Clé:", bg="#f0f0f0").pack(side="left")
        self.key_entry = tk.Entry(self.key_frame, width=30)
        self.key_entry.pack(side="left", padx=5)

        # Paramètres RSA
        self.rsa_frame = tk.Frame(self.params_frame, bg="#f0f0f0")
        tk.Button(self.rsa_frame, text="Générer Clés", command=self.generate_rsa_keys).pack(side="left", padx=5)
        self.pub_path_var = tk.StringVar()
        tk.Button(self.rsa_frame, text="Clé Publique", command=lambda: self.select_file(self.pub_path_var)).pack(side="left", padx=5)
        tk.Entry(self.rsa_frame, textvariable=self.pub_path_var, width=15).pack(side="left", padx=5)
        self.priv_path_var = tk.StringVar()
        tk.Button(self.rsa_frame, text="Clé Privée", command=lambda: self.select_file(self.priv_path_var)).pack(side="left", padx=5)
        tk.Entry(self.rsa_frame, textvariable=self.priv_path_var, width=15).pack(side="left", padx=5)

        self.update_parameters_visibility()

        # Cadre d'entrée
        input_frame = tk.LabelFrame(main_frame, text="Entrée (Texte ou Fichier)", padx=10, pady=10, bg="#f0f0f0")
        input_frame.pack(fill="both", expand=True, pady=(0, 15))

        self.text_input = tk.Text(input_frame, height=5)
        self.text_input.pack(fill="both", expand=True, pady=(0, 5))

        tk.Button(input_frame, text="Charger Fichier", command=self.load_input_file).pack(side="right")

        # Cadre d'action
        action_frame = tk.Frame(main_frame, bg="#f0f0f0")
        action_frame.pack(fill="x", pady=(0, 15))

        tk.Button(action_frame, text="CHIFFRER", font=("Arial", 10, "bold"), bg="#3498db", fg="white", padx=20, command=lambda: self.process_action("encrypt")).pack(side="left", padx=10)
        tk.Button(action_frame, text="DÉCHIFFRER", font=("Arial", 10, "bold"), bg="#e67e22", fg="white", padx=20, command=lambda: self.process_action("decrypt")).pack(side="left", padx=10)

        # Cadre de sortie
        output_frame = tk.LabelFrame(main_frame, text="Résultat", padx=10, pady=10, bg="#f0f0f0")
        output_frame.pack(fill="both", expand=True)

        self.text_output = tk.Text(output_frame, height=5)
        self.text_output.pack(fill="both", expand=True, pady=(0, 5))

        tk.Button(output_frame, text="Sauvegarder Résultat", command=self.save_output_file).pack(side="right")

    def update_parameters_visibility(self):
        # Masquer tout
        for frame in [self.caesar_frame, self.affine_frame, self.key_frame, self.rsa_frame]:
            frame.pack_forget()

        algo = self.algo_var.get()
        if algo == "caesar":
            self.caesar_frame.pack(anchor="w")
        elif algo == "affine":
            self.affine_frame.pack(anchor="w")
        elif algo in ["vigenere", "des", "aes"]:
            self.key_frame.pack(anchor="w")
        elif algo == "rsa":
            self.rsa_frame.pack(anchor="w")

    def select_file(self, string_var):
        path = filedialog.askopenfilename()
        if path:
            string_var.set(path)

    def load_input_file(self):
        path = filedialog.askopenfilename()
        if path:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    self.text_input.delete("1.0", tk.END)
                    self.text_input.insert(tk.END, content)
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de lire le fichier: {e}")

    def save_output_file(self):
        content = self.text_output.get("1.0", tk.END).strip()
        if not content:
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Succès", "Fichier sauvegardé avec succès.")
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de sauvegarder le fichier: {e}")

    def generate_rsa_keys(self):
        try:
            priv, pub = crypto_utils.generate_rsa_keys()
            base = filedialog.asksaveasfilename(title="Base du nom des fichiers de clés", initialfile="id_rsa")
            if base:
                with open(base, 'wb') as f:
                    f.write(priv)
                with open(base + ".pub", 'wb') as f:
                    f.write(pub)
                messagebox.showinfo("RSA", f"Clés générées : {base} et {base}.pub")
        except Exception as e:
            messagebox.showerror("Erreur RSA", str(e))

    def process_action(self, action):
        algo = self.algo_var.get()
        content = self.text_input.get("1.0", tk.END).strip()
        
        if not content:
            messagebox.showwarning("Attention", "Veuillez entrer du texte ou charger un fichier.")
            return

        try:
            result = ""
            if algo == "caesar":
                try:
                    shift = int(self.shift_entry.get())
                except ValueError:
                    raise ValueError("Le décalage doit être un nombre entier.")
                
                if action == "encrypt":
                    result = crypto_utils.caesar_encrypt(content, shift)
                else:
                    result = crypto_utils.caesar_decrypt(content, shift)

            elif algo == "affine":
                try:
                    a = int(self.a_entry.get())
                    b = int(self.b_entry.get())
                except ValueError:
                    raise ValueError("Les coefficients a et b doivent être des nombres entiers.")
                
                if action == "encrypt":
                    result = crypto_utils.affine_encrypt(content, a, b)
                else:
                    result = crypto_utils.affine_decrypt(content, a, b)

            elif algo == "vigenere":
                key = self.key_entry.get()
                if not key: raise ValueError("Clé manquante")
                if action == "encrypt":
                    result = crypto_utils.vigenere_encrypt(content, key)
                else:
                    result = crypto_utils.vigenere_decrypt(content, key)

            elif algo == "aes":
                key = self.key_entry.get()
                if not key: raise ValueError("Clé manquante")
                key_bytes = key.encode('utf-8')
                # Ajustement de la clé si nécessaire
                if len(key_bytes) not in [16, 24, 32]:
                    key_bytes = hashlib.sha256(key_bytes).digest()

                if action == "encrypt":
                    result = crypto_utils.aes_encrypt(content, key_bytes).hex()
                else:
                    try:
                        data_bytes = bytes.fromhex(content)
                        result = crypto_utils.aes_decrypt(data_bytes, key_bytes)
                    except ValueError:
                        raise ValueError("Le texte d'entrée doit être en hexadécimal pour le déchiffrement AES.")

            elif algo == "des":
                key = self.key_entry.get()
                if not key: raise ValueError("Clé manquante")
                key_bytes = key.encode('utf-8')
                if len(key_bytes) != 8:
                    # Utilisation de TripleDES avec une clé hachée
                    key_bytes = hashlib.sha256(key_bytes).digest()[:24]

                if action == "encrypt":
                    result = crypto_utils.des_encrypt(content, key_bytes).hex()
                else:
                    try:
                        data_bytes = bytes.fromhex(content)
                        result = crypto_utils.des_decrypt(data_bytes, key_bytes)
                    except ValueError:
                        raise ValueError("Le texte d'entrée doit être en hexadécimal pour le déchiffrement DES.")

            elif algo == "rsa":
                if action == "encrypt":
                    pub_path = self.pub_path_var.get()
                    if not pub_path: raise ValueError("Fichier de clé publique manquant")
                    with open(pub_path, 'rb') as f:
                        pub_key = f.read()
                    result = crypto_utils.rsa_encrypt(content, pub_key).hex()
                else:
                    priv_path = self.priv_path_var.get()
                    if not priv_path: raise ValueError("Fichier de clé privée manquant")
                    with open(priv_path, 'rb') as f:
                        priv_key = f.read()
                    try:
                        data_bytes = bytes.fromhex(content)
                        result = crypto_utils.rsa_decrypt(data_bytes, priv_key)
                    except ValueError:
                        raise ValueError("Le texte d'entrée doit être en hexadécimal pour le déchiffrement RSA.")

            self.text_output.delete("1.0", tk.END)
            self.text_output.insert(tk.END, result)

        except Exception as e:
            messagebox.showerror("Erreur de traitement", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()
