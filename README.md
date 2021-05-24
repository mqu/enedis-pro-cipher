# enedis-pro-cipher
application de codage-décodage de fichiers issus de ENEDIS-PRO

mots-clés: enedis, enedis-pro, enedis-entreprise, cipher, déchiffrement, AES/CBC-265

# présentation

- Cette application est un script ruby qui permet de chiffrer et déchiffrer des fichiers en provenance de ENEDIS Entreprise.
- ENEDIS fourni par mail, des fichiers de données chiffrés au format AES/CBC-265 dont le format est le suivant :
  - bloc IV de 256 tiré aléatoirement ; il s'agit d'un perturbateur dans l'algorithme permettant d'amélioré la qualité du chiffrement
  - suivent ensuite les données chiffrées en AES/CBC-256.
- pour ce que j'en connais, le fichier extrait est au format ZIP 2.0 et compatible avec 7zip (7z l enedis.zip)
- le manuel de référence concernant le format d'échange est spécifié dans le document [Enedis-NOI-CF_107E.pdf](https://www.enedis.fr/sites/default/files/Enedis-NOI-CF_107E.pdf)

# Installation

- cloner ce dépot logiciel
- installer ruby et la dépendance openssl
- voici la procédure du PF Linux/Debian, Ubuntu

```
sudo apt install ruby
sudo gem install openssl
```

# Utilisation

Le script ruby peut être lancé manuellement de cette façon et accepte des actions avec ou sans arguments:

```
usage:
 enedis-pro-cipher.rb action opts

 actions:
    dec key          OK
    dec key in out   OK
    enc key          KO
    enc key in out   OK
    iv in            OK
    test             : à compléter.

 - in, out sont des fichiers 
 - si les fichiers ne sont pas spécifiés, l'action est réalisée sur les fluxs stdin, stdout via des pipes
 - l'action iv permet d'extraire le bloc IV d'un fichier encodé au format hexa
 - formats
   - key: clé 256 bits - 32 octets binaire, 64 caractères hexa
   - iv: bloc IV (Initialisation Vector), 16 octets binaires, 32 octets hexa
   - les fichiers en provenance de Enedis-pro :
     - contiennent un bloc IV,
     - suivi des données encodées AES/CBC/256.
     - pour ce que j'en connais, le fichier décompressé est un ZIP 2.0 compatible 7zip.
```

------

*documentation rédigée avec [Typora](https://typora.io/)*

