import argparse
import sys
import os
import crypto_utils

def main():
    parser = argparse.ArgumentParser(description="Crypto CLI (César, Affine, Vigenère, RSA, DES, AES)")
    parser.add_argument("method", choices=["caesar", "affine", "vigenere", "rsa", "des", "aes"], help="Méthode de chiffrement")
    parser.add_argument("action", choices=["encrypt", "decrypt", "generate-keys"], help="Action à effectuer")
    parser.add_argument("text", nargs="?", help="Texte à traiter (ou chemin du fichier d'entrée)")
    
    # Arguments classiques
    parser.add_argument("--shift", type=int, help="Décalage pour César")
    parser.add_argument("--a", type=int, help="Coefficient a pour Affine")
    parser.add_argument("--b", type=int, help="Coefficient b pour Affine")
    parser.add_argument("--key", type=str, help="Clé pour Vigenère, DES, AES")
    
    # Arguments modernes
    parser.add_argument("--pub", help="Chemin du fichier de clé publique (pour RSA)")
    parser.add_argument("--priv", help="Chemin du fichier de clé privée (pour RSA)")
    parser.add_argument("--out", help="Chemin du fichier de sortie (pour la génération RSA ou le résultat de chiffrement)")

    args = parser.parse_args()

    # Aide pour gérer le texte ou l'entrée de fichier
    content = args.text
    if args.text and os.path.isfile(args.text):
        try:
            with open(args.text, 'r', encoding='utf-8') as f:
                content = f.read()
        except:
             # If strictly binary, we might need rb, but let's stick to text for now unless RSA
             pass

    try:
        # --- Classic ---
        if args.method == "caesar":
            if args.shift is None:
                print("Erreur: --shift est requis pour César.")
                return
            if args.action == "encrypt":
                print(crypto_utils.caesar_encrypt(content, args.shift))
            elif args.action == "decrypt":
                print(crypto_utils.caesar_decrypt(content, args.shift))

        elif args.method == "affine":
            if args.a is None or args.b is None:
                print("Erreur: --a et --b sont requis pour Affine.")
                return
            if args.action == "encrypt":
                print(crypto_utils.affine_encrypt(content, args.a, args.b))
            elif args.action == "decrypt":
                print(crypto_utils.affine_decrypt(content, args.a, args.b))

        elif args.method == "vigenere":
            if not args.key:
                print("Erreur: --key est requise pour Vigenère.")
                return
            if args.action == "encrypt":
                print(crypto_utils.vigenere_encrypt(content, args.key))
            elif args.action == "decrypt":
                print(crypto_utils.vigenere_decrypt(content, args.key))

        # --- Modern ---
        elif args.method == "aes":
            if not args.key:
                print("Erreur: --key est requise pour AES.")
                return
            # Ajuster la longueur de la clé si nécessaire ou passer à la bibliothèque et laisser échouer ?
            # Clés de bibliothèque : 16, 24, 32 octets.
            # Nous encodons la clé en octets.
            key_bytes = args.key.encode('utf-8')
            # Compléter ou tronquer la clé à 16/24/32 octets pour la commodité de l'utilisateur (hachage simple)
            if len(key_bytes) not in [16, 24, 32]:
                import hashlib
                key_bytes = hashlib.sha256(key_bytes).digest() # 32 bytes

            if args.action == "encrypt":
                # Returns IV + Ciphertext (binary) -> hex for display
                encrypted_bytes = crypto_utils.aes_encrypt(content, key_bytes)
                print(encrypted_bytes.hex())
            elif args.action == "decrypt":
                # Input must be hex
                try:
                    data_bytes = bytes.fromhex(content)
                except ValueError:
                    print("Erreur: Pour le déchiffrement, le texte d'entrée doit être une chaîne hexadécimale.")
                    return
                print(crypto_utils.aes_decrypt(data_bytes, key_bytes))

        elif args.method == "des":
            if not args.key:
                print("Erreur: --key est requise pour DES.")
                return
            key_bytes = args.key.encode('utf-8')
            if len(key_bytes) != 8:
                 # DES/3DES key adjustment if needed. 3DES needs 16 or 24 bytes often.
                 # Our utils uses TripleDES. Let's use SHA256 then take first 16 or 24 bytes? 
                 # Or just 24 bytes = 192 bits.
                 import hashlib
                 dig = hashlib.sha256(key_bytes).digest()
                 key_bytes = dig[:24]

            if args.action == "encrypt":
                encrypted_bytes = crypto_utils.des_encrypt(content, key_bytes)
                print(encrypted_bytes.hex())
            elif args.action == "decrypt":
                try:
                    data_bytes = bytes.fromhex(content)
                except ValueError:
                    print("Erreur: Pour le déchiffrement, le texte d'entrée doit être une chaîne hexadécimale.")
                    return
                print(crypto_utils.des_decrypt(data_bytes, key_bytes))

        elif args.method == "rsa":
            if args.action == "generate-keys":
                priv, pub = crypto_utils.generate_rsa_keys()
                # Use --out for base filename or default
                base = args.out if args.out else "id_rsa"
                with open(base, 'wb') as f:
                    f.write(priv)
                with open(base + ".pub", 'wb') as f:
                    f.write(pub)
                print(f"Clés générées: {base} et {base}.pub")
            
            elif args.action == "encrypt":
                if not args.pub:
                    print("Erreur: --pub <fichier_clé_publique> est requis pour le chiffrement RSA.")
                    return
                with open(args.pub, 'rb') as f:
                    pub_key = f.read()
                
                encrypted_bytes = crypto_utils.rsa_encrypt(content, pub_key)
                print(encrypted_bytes.hex())

            elif args.action == "decrypt":
                if not args.priv:
                    print("Erreur: --priv <fichier_clé_privée> est requis pour le déchiffrement RSA.")
                    return
                with open(args.priv, 'rb') as f:
                    priv_key = f.read()
                
                try:
                    data_bytes = bytes.fromhex(content)
                except ValueError:
                    print("Erreur: Le texte d'entrée doit être une chaîne hexadécimale pour le déchiffrement.")
                    return
                
                print(crypto_utils.rsa_decrypt(data_bytes, priv_key))

    except Exception as e:
        print(f"Une erreur est survenue: {e}")

if __name__ == "__main__":
    main()
