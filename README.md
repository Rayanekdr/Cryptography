Le but de ce projet informatique est de vous faire créer une technologique similaire à une «mini PKI», Public
Key Infrastructure, ou Infrastructure (de gestion) de clés publiques. L’idée étant de vous faire développer
un outil permettant de mettre en oeuvre des communications sécurisés entre deux utilisateurs.


La mise en place d’une communication sécurisée entre deux utilisateurs quelconques, sans aucune connaissance préalable, sur un réseaux non sécurisé nécessitent les opérations suivantes :
1. Authentification de la personne : pour cela il faut recevoir un certificat qui, d’une part, doit être signée par une tierce personne et, d’autre part, doit pouvoir identifier la personne (dans la vraie, le nom de domaine, dans notre cas, le numéro de téléphone ou l’email ou autre ...).
2. Vérifier la validité du certificat en interrogeant un dépot de certificat et de clé publique.
3. Enfin sécurisé la communication en utilisant (1) pour la confidentialité, des clés secrètes éphémères pour le chiffrement symétrique et (2) pour l’intégrité, une fonction de hashage, (Hmac ou simple Hash)

On va utiliser, pour le chiffrement symétrique, l’algorithme SERPENT
