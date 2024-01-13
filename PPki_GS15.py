import random
import os
import serpent
from datetime import datetime, timedelta

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5) + 2, 2):
        if num % n == 0:
            return False
    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_key_pair():
    p = random.randint(100, 500)
    q = random.randint(100, 500)

    while not is_prime(p):
        p = random.randint(100, 500)
    
    while not is_prime(q) or q == p:
        q = random.randint(100, 500)
    
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)
    
    d = pow(e, -1, phi)

    return (e, n), (d, n)






# Fonction pour chiffrer un message
def encrypt_message(message, public_key):
    e, n = public_key
    encrypted = [pow(ord(str(char)), e, n) for char in list(message)]  # Convertit le message en liste de caractères
    return encrypted

# Fonction pour déchiffrer un message
def decrypt_message(encrypted_message, private_key):
    d, n = private_key
    decrypted = [chr(pow(char, d, n)) for char in encrypted_message]
    return ''.join(decrypted)

# Fonction pour signer un message avec la clé privée
def sign_message(message, private_key):
    d, n = private_key
    signature = [pow(ord(char), d, n) for char in message]
    return signature

# Pour signer un certificat :
def signer_certificat(identifiant, private_key):
    return sign_message(identifiant, private_key)
# Pour vérifier un certificat :
def verifier_certificat(signature, identifiant, public_key):
    return verify_signature(signature, identifiant, public_key)



# Fonction pour vérifier la signature d'un message avec la clé publique
def verify_signature(signature, message, public_key):
    e, n = public_key
    decrypted_signature = [pow(char, e, n) for char in signature]
    # Convertir le message original en une liste d'entiers
    original_message_as_integers = [ord(char) for char in message]
    return decrypted_signature == original_message_as_integers




#Initialisation d'une liste (ou un dictionnaire) pour stocker les documents chiffrés.
coffre_fort = {}
def enregistrer_document(message, nom_document, public_key):
    # Chiffrer le document avec la clé publique
    document_chiffre = encrypt_message(message, public_key)
    
    # Stocker le document chiffré dans le coffre-fort avec un nom ou une clé associée
    coffre_fort[nom_document] = document_chiffre
    print(f"Document {nom_document} enregistré dans le coffre-fort.")

#Fonction pour récupérer un document du coffre-fort :
def recuperer_document(nom_document, private_key):
    # Vérifier si le document existe dans le coffre-fort
    if nom_document in coffre_fort:
        # Déchiffrer le document avec la clé privée
        document_dechiffre = decrypt_message(coffre_fort[nom_document], private_key)
        return document_dechiffre
    else:
        print(f"Le document {nom_document} n'est pas trouvé dans le coffre-fort.")
        return None

# Dictionnaire pour stocker les informations des utilisateurs
utilisateurs = {}

def creer_utilisateur(nom_utilisateur):
    if nom_utilisateur not in utilisateurs:
        public_key, private_key = generate_key_pair()  # Utilisez votre fonction existante pour générer une paire de clés
        utilisateurs[nom_utilisateur] = {
            'public_key': public_key,
            'private_key': private_key
        }
        print(f"Utilisateur {nom_utilisateur} créé avec succès!")
    else:
        print("Cet utilisateur existe déjà!")



# 3. Fonction pour envoyer un message asynchrone
def envoyer_message_asynchrone(nom_utilisateur_destinataire, message):
    if nom_utilisateur_destinataire in utilisateurs:
        public_key_destinataire = utilisateurs[nom_utilisateur_destinataire]['public_key']
        # Chiffrez le message avec la clé publique du destinataire (utilisez votre fonction existante)
        message_chiffre = encrypt_message(message, public_key_destinataire)
        
        # Hachez le message (vous avez déjà une fonction de hachage)
        hash_message = sha256(message_chiffre)
        
        # Affichez ou stockez le message et le hachage pour simuler l'envoi
        print(f"Message chiffré: {message_chiffre}")
        print(f"Hachage du message: {hash_message}")
    else:
        print("Utilisateur introuvable.")




# Fonction de hachage SHA-256
def sha256(message):
    # Constantes initiales pour SHA-256
    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h4 = 0x510e527f
    h5 = 0x9b05688c
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19
    
    # Fonctions auxiliaires pour SHA-256
    def rotr(x, n):
        return (x >> n) | (x << (32 - n))

    def ch(x, y, z):
        return (x & y) ^ (~x & z)

    # Padding du message (simplifié pour une longueur de message unique)
    # Ici, pour simplifier, on ne prend qu'un seul bloc de 512 bits
    bloc = bytearray(message.encode())
    bloc.append(0x80)  # Ajout du bit '1' à la fin du message
    while len(bloc) % 64 != 56:
        bloc.append(0x00)  # Ajout de zéros jusqu'à ce qu'il reste 56 octets avant la fin
    bloc += (len(message) * 8).to_bytes(8, 'big')  # Ajout de la longueur du message en bits

    # Traitement du bloc (simplifié pour un bloc unique)
    for i in range(0, len(bloc), 64):
        w = [0] * 64
        for t in range(16):
            w[t] = int.from_bytes(bloc[i + t * 4:i + t * 4 + 4], 'big')

        # ... [Suite des opérations SHA-256 sur w et les constantes h0-h7]

    # Formatage du haché final
    digest = f"{h0:08x}{h1:08x}{h2:08x}{h3:08x}{h4:08x}{h5:08x}{h6:08x}{h7:08x}"
    return digest



# Génération d'une clé secrète éphémère pour le chiffrement symétrique
def generer_cle_secrete(taille=32):
    """
    Génère une clé secrète éphémère de la taille spécifiée en bytes.
    Par défaut, la taille est de 32 bytes (256 bits).
    """
    return os.urandom(taille)

# Fonction pour chiffrer un message avec la clé secrète éphémère
def chiffrer_message_avec_cle_secrete(message, cle_secrete):
    """
    Chiffre le message en utilisant la clé secrète éphémère avec un chiffrement basique XOR.
    Note: Ce n'est pas une méthode de chiffrement sécurisée pour un usage réel.
    """
    # Convertir le message en bytes
    message_bytes = message.encode()
    
    # Assurer que la clé secrète a la bonne longueur
    if len(cle_secrete) < len(message_bytes):
        raise ValueError("La clé secrète est trop courte pour chiffrer le message.")
    
    # Chiffrer le message avec un XOR simple
    message_chiffre = bytes([message_bytes[i] ^ cle_secrete[i] for i in range(len(message_bytes))])
    
    # Retourner le message chiffré (vous pouvez également renvoyer la clé secrète éphémère pour le déchiffrement ultérieur si nécessaire)
    return message_chiffre



# Fonction pour envoyer un message asynchrone
def envoyer_message_asynchrone(message, public_key_destinataire):
    # Étape 1: Chiffrer le message avec une clé secrète éphémère
    cle_secrete = generer_cle_secrete()
    message_chiffre = chiffrer_message_avec_cle_secrete(message, cle_secrete)
    
    # Étape 2: Calculer le haché du message chiffré pour l'intégrité
    hache = sha256(message_chiffre)
    
    # Envoyer le message_chiffre et le hache
    return message_chiffre, hache


# Fonction pour déchiffrer un message avec la clé privée du destinataire
def dechiffrer_message(message_chiffre, private_key):
    #  pour déchiffrer le message avec la clé privée
    message_dechiffre = decrypt_message(message_chiffre, private_key)
    return message_dechiffre

#Création d'une structure de données (comme un dictionnaire) pour stocker les certificats associés à une date de validité.
depot_certifications = {}  # Dictionnaire pour stocker les certificats avec une date de validité.

# Fonctions pour l'autorité de confiance :
# Signalisation d'un certificat avec une date de validité :
def signer_certificat_avec_validite(identifiant, private_key, duree_validite_jours=365):
    signature = sign_message(identifiant, private_key)  
    
    # Calculer la date d'expiration du certificat.
    date_expiration = datetime.now() + timedelta(days=duree_validite_jours)
    
    certificat = {
        'signature': signature,
        'date_expiration': date_expiration
    }
    
    # Stocker le certificat dans le dépôt avec l'identifiant comme clé.
    depot_certifications[identifiant] = certificat
    
    return certificat

def string_to_hexadecimal(input_string):
    # Utilisez la méthode encode() pour convertir la chaîne en bytes
    # Utilisez ensuite la fonction hex() pour obtenir la représentation hexadécimale
    hexadecimal_result = ''.join(hex(ord(char))[2:] for char in input_string)
    return hexadecimal_result

def hexadecimal_to_string(hexadecimal_string):
    # Utilisez bytes.fromhex() pour obtenir un objet bytes à partir de la chaîne hexadécimale
    # Utilisez ensuite decode() pour obtenir la chaîne de caractères normale
    string_result = bytes.fromhex(hexadecimal_string).decode('utf-8')
    return string_result
# Vérification un certificat :
def verifier_certificat_avec_validite(signature, identifiant, public_key):
    # Récupérer le certificat depuis le dépôt.
    certificat = depot_certifications.get(identifiant)
    
    if not certificat:
        return False
    
    # Vérifier la validité du certificat en vérifiant la signature.
    is_valid_signature = verify_signature(signature, identifiant, public_key)  # Utilisation d'une fonction existante.
    
    # Vérifier la date d'expiration.
    is_not_expired = datetime.now() <= certificat['date_expiration']
    
    return is_valid_signature and is_not_expired

# L'ajout d'une fonction de preuve de connaissance
secret_value = 12345

def prove_knowledge(secret):
    r = random.randint(1, 1000)
    g = 2  # Choisissez un générateur, cela pourrait être un nombre premier
    z = (r ** 2) * (g ** secret)
    return (r, z)

def verify_knowledge(proof, secret):
    r, z = proof
    g = 2  # Utilisation du même générateur que celui utilisé pour la preuve
    return z == (r ** 2) * (g ** secret)


already_executed = []



public_key = None
private_key = None

while True:
    print("\nBonjour O maitre Remi ! Que souhaitez-vous faire aujourd'hui ?")
    print("->1<- Chiffrer / dechiffrer des messages.")
    print("->2<- Creer un couple de clé publique / privee (générer un grand nombre premier).")
    print("->3<- signer un certificat avec une date de validite.")
    print("->4<- verifier un certificat.") 
    print("->5<- Enregistrer un document dans le coffre-fort.")
    print("->55<- Verifier les documents dans le coffre-fort.")
    print("->6<- Envoyer un message (asynchrone).")
    print("->7<- Demander une preuve de connaissance.")
    print("->8<- Chiffrer/Déchiffrer avec serpent.")
    print("->0<- I WANT IT ALL !! I WANT IT NOW !! SecCom from scratch?")
    
    choice = input("Votre choix (0-7): ")

    if choice == '2':
        # Création d'un utilisateur
        nom_utilisateur = input("Entrez le nom de l'utilisateur que vous souhaitez créer: ")
    
        if nom_utilisateur in utilisateurs:
            print("Cet utilisateur existe déjà.")
        else:
            # Générez une paire de clés publiques/privées pour l'utilisateur
            public_key, private_key = generate_key_pair()
        
            # Stockez la paire de clés avec l'utilisateur
            utilisateurs[nom_utilisateur] = {
            'public_key': public_key,
            'private_key': private_key
            }
            already_executed.append('2')
            print(f"Utilisateur {nom_utilisateur} créé avec succès!")
            print(f"Clé publique de {nom_utilisateur}: {public_key}")
            print(f"Clé privée de {nom_utilisateur}: {private_key}")


 

    elif choice == '1':
        if public_key is None or private_key is None:
            print("Vous devez d'abord générer une paire de clés (option 2).")
        else:
            message = input("Entrez le message à chiffrer : ")
            encrypted_message = encrypt_message(message, public_key)
            print("Message chiffré:", ''.join(map(str, encrypted_message)))
            
            decrypted_message = decrypt_message(encrypted_message, private_key)
            print("Message déchiffré:", decrypted_message)


    elif choice == '3':
        if public_key is None or private_key is None:
            print("Vous devez d'abord générer une paire de clés (option 2).")
        else:
            identifiant = input("Entrez votre identifiant pour signer le certificat : ")
            duree_validite = int(input("Entrez la durée de validité du certificat en jours (par défaut 365 jours) : ") or 365)
            certificat = signer_certificat_avec_validite(identifiant, private_key, duree_validite)
            already_executed.append('3')
            print(f"Certificat signé avec succès! Signature: {certificat['signature']}, Date d'expiration: {certificat['date_expiration']}")

    elif choice == '4':
        if public_key is None or private_key is None:
            print("Vous devez d'abord générer une paire de clés (option 2).")
        else:
            identifiant = input("Entrez l'identifiant à vérifier : ")
            signature_to_verify = input("Entrez la signature à vérifier (sous forme de liste d'entiers séparés par des espaces) : ")
            is_valid = verifier_certificat_avec_validite(list(map(int, signature_to_verify.split())), identifiant, public_key)
            if is_valid:
                print("Le certificat est valide.")
            else:
                print("Le certificat n'est pas valide ou a expiré.")


      
    elif choice == '5':
        if public_key is None or private_key is None:
            print("Vous devez d'abord générer une paire de clés (option 2).")
        else:
            nom_document = input("Entrez le nom du document à enregistrer : ")
            message = input("Entrez le contenu du document : ")
            enregistrer_document(message, nom_document, public_key)
    elif choice == '55':
        nom_document = input("Entrez le nom du document à récupérer : ")
        document = recuperer_document(nom_document, private_key)
        if document:
            print(f"Document récupéré : {document}")



    elif choice == '6':
        nom_destinataire = input("Entrez le nom de l'utilisateur destinataire: ")
        if nom_destinataire not in utilisateurs:
            print("Cet utilisateur n'existe pas. Veuillez le créer d'abord.")
        else:
            message_a_envoyer = input("Entrez le message à envoyer: ")
            # ... (Votre code pour envoyer le message)
        
            # Calcul du hachage du message avant le chiffrement
            hashage_message_avant_chiffrement = sha256(message_a_envoyer)
            print(f"Hachage du message avant chiffrement: {hashage_message_avant_chiffrement}")
        
            # Supposons que vous ayez déjà une clé publique pour le destinataire
            public_key_destinataire = utilisateurs[nom_destinataire]['public_key']
        
            # Chiffrez le message avec la clé publique du destinataire
            message_chiffre = encrypt_message(message_a_envoyer, public_key_destinataire)

            # Récupérez la clé privée du destinataire
            private_key_destinataire = utilisateurs[nom_destinataire]['private_key']
        
            # Déchiffrez le message
            message_dechiffre = dechiffrer_message(message_chiffre, private_key_destinataire)

            # Calcul du hachage du message déchiffré
            hashage_message_apres_dechiffrement = sha256(message_dechiffre)
            print(f"Hachage du message après déchiffrement: {hashage_message_apres_dechiffrement}")


            # Affichez le message déchiffré
            print(f"Message déchiffré pour {nom_destinataire}: {message_dechiffre}")



    elif choice == '7':
        
        secret = int(input("Entrez le secret (x pour r^2 * g^x = y) : "))
        y = secret ** 2
    
        proof = prove_knowledge(secret)
    
        if verify_knowledge(proof, y):
            print("La preuve de connaissance est valide!")
        else:
            print("La preuve de connaissance a échoué.")


    elif choice == '8':
        nom_destinataire = input("Entrez le nom de l'utilisateur destinataire: ")
        if nom_destinataire not in utilisateurs:
            print("Cet utilisateur n'existe pas. Veuillez le créer d'abord.")
        else:
            plain_text = string_to_hexadecimal(input("Ecrire le message à chiffrer avec serpent !"))
            secrete_key = string_to_hexadecimal(input("Ecrire la clé secrète !"))

            plain_text = serpent.convertToBitstring(plain_text, 128)
            bitsInKey = serpent.keyLengthInBitsOf(secrete_key)
            rawKey = serpent.convertToBitstring(secrete_key, bitsInKey)
            userKey = serpent.makeLongKey(rawKey)

            cipher_text = serpent.encrypt(plain_text, userKey)
            print("Serpent cipher_text --> ", cipher_text)

            # Déchiffrez le message2
            message_dechiffre = serpent.decrypt(cipher_text, userKey)
            print("Serpent plain_text --> ", message_dechiffre)
            bytes_obj = bytes.fromhex(message_dechiffre)
            print("Original message --> ", bytes_obj.decode('utf-8'))

    elif choice == '0':
        while True:
            if public_key is None or private_key is None:
                print("Vous devez d'abord générer une paire de clés (option 2).")
                break

            if '2' not in already_executed or '3' not in already_executed:
                missing_options = [opt for opt in ['2', '3'] if opt not in already_executed]
                print(f"Vous devez d'abord exécuter les options {', '.join(missing_options)} avant l'option 0.")
                break
            
            # Exécuter l'option 7 (Demander une preuve de connaissance)

            while True:  # Cette boucle est ici pour vous permettre de réessayer en cas d'échec.
                secret = int(input("Entrez le secret (x pour r^2 * g^x = y) : "))
                y = secret ** 2
    
                proof = prove_knowledge(secret)
    
                if verify_knowledge(proof, y):
                    print("La preuve de connaissance est valide!")
                    break
                else:
                    print("La preuve de connaissance a échoué, Veuillez réessayer.")

            

        # Exécuter l'option 4 (Vérifier le certificat du destinataire)
            while True:
                identifiant_destinataire = input("Entrez l'identifiant du destinataire pour vérifier le certificat : ")
                if identifiant_destinataire not in utilisateurs:
                    print("Cet utilisateur n'existe pas. Veuillez le créer d'abord.")
                else:
                    public_key_destinataire = utilisateurs[identifiant_destinataire]['public_key']
                    signature_to_verify = [int(item) for item in input("Entrez la signature à vérifier (sous forme de liste d'entiers séparés par des espaces) : ").split()]
                    if verify_signature(signature_to_verify, identifiant_destinataire, public_key_destinataire):
                        print("Certificat du destinataire vérifié avec succès!")
                        break
                    else:
                        print("Attention! Le certificat du destinataire n'est pas valide.")

        # Exécuter l'option 6 (Envoyer un message asynchrone)
            while True:
                nom_destinataire = input("Entrez le nom de l'utilisateur destinataire: ")
                if nom_destinataire not in utilisateurs:
                    print("Cet utilisateur n'existe pas. Veuillez le créer d'abord.")
                else:
                    message_a_envoyer = input("Entrez le message à envoyer: ")
            
                # Calcul du hachage du message avant le chiffrement
                    hashage_message_avant_chiffrement = sha256(message_a_envoyer)
                    print(f"Hachage du message avant chiffrement: {hashage_message_avant_chiffrement}")
            
                # Chiffrez le message avec la clé publique du destinataire
                    message_chiffre = encrypt_message(message_a_envoyer, public_key_destinataire)
            
               
                # Déchiffrer le message pour vérifier la communication
                    message_dechiffre = decrypt_message(message_chiffre, private_key)
            
                # Calcul du hachage du message déchiffré
                    hashage_message_apres_dechiffrement = sha256(message_dechiffre)
                    print(f"Hachage du message après déchiffrement: {hashage_message_apres_dechiffrement}")
            
                    # Affichez le message déchiffré
                    print(f"Message déchiffré pour {nom_destinataire}: {message_dechiffre}")

            
                    break # Sortez de la boucle une fois que vous avez envoyé le message
            break
        break



    else:
        print("Choix invalide. Veuillez choisir une option valide.")
