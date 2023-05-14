# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 13:44:40 2020

@author: Mr ABBAS-TURKI, Mr THEUREL
"""

import binascii
import hashlib
import random


def home_crt(c, q, p, d, n):  # q < p
    # c: le message chiffré
    # q: le premier facteur de n
    # p: le deuxième facteur de n
    # d: l'exposant privé
    # n: le modulo
    #
    # Retourne le message déchiffré

    # Verification q < p
    if q > p:
        q, p = p, q

    q_inv = home_ext_euclide(n, q)

    d_q = d % (q - 1)
    d_p = d % (p - 1)

    m_q = home_mod_exponent(c, d_q, q)
    m_p = home_mod_exponent(c, d_p, p)

    h = ((m_p - m_q) * q_inv) % p
    m = (m_q + h * q) % n

    return m


def home_mod_exponent(x, y, n):  # exponentiation modulaire
    # x: le nombre à multiplier
    # y: la puissance
    # n: le modulo
    a = y
    r1 = 1
    r2 = x
    while a > 0:
        if a % 2 == 1:
            r1 = (r1 * r2) % n
        r2 = (r2 ** 2) % n
        a = a // 2
    return r1


def home_ext_euclide(y, b):  # algorithme d'euclide étendu pour la recherche de l'exposant secret
    # y: le modulo
    (t, nouvt, r, nouvr) = (0, 1, y, b)
    while nouvr > 1:
        quotient = r // nouvr
        (r, nouvr) = (nouvr, (r - quotient * nouvr))
        (t, nouvt) = (nouvt, (t - quotient * nouvt))
    return nouvt % y


def home_pgcd(a, b):  # recherche du pgcd
    if b == 0:
        return a
    else:
        return home_pgcd(b, a % b)


def home_string_to_int(x):  # pour transformer un string en int
    z = 0
    for i in reversed(range(len(x))):
        z = int(ord(x[i])) * pow(2, (8 * i)) + z
    return z


def home_int_to_string(x):  # pour transformer un int en string
    txt = ''
    res1 = x
    while res1 > 0:
        res = res1 % (pow(2, 8))
        res1 = (res1 - res) // (pow(2, 8))
        txt = txt + chr(res)
    return txt


def mot10char():  # entrer le secret
    secret = input("donner un secret : ")
    while len(secret) == 0:
        secret = input("c'est beaucoup trop court, donner un secret : ")
    return secret

#Initialisation du generateur aleatoire
random.seed()

# voici les éléments de la clé d'Alice
# x1a = 2010942103422233250095259520183  # p
# x2a = 3503815992030544427564583819137  # q
x1a = 4055377032919001713559410399132757135868461138859622978303063066882484166760369480203594630889520081  # p
x2a = 3214458190740581670596948740121747577765121916540557428563119716257050281825067922840560673357473447  # q
na = x1a * x2a  # n
phia = ((x1a - 1) * (x2a - 1)) // home_pgcd(x1a - 1, x2a - 1)
ea = 1617137  # exposant public
# ea = 17  # exposant public
da = home_ext_euclide(phia, ea)  # exposant privé // max des 2 derniers éléments du tuple retourné
# voici les éléments de la clé de bob
# x1b = 9434659759111223227678316435911  # p
# x2b = 8842546075387759637728590482297  # q
x1b = 8850483113752123658129047269990265423739938098381647179963539533166924508810902120291421861464532379  # p
x2b = 9910774072897521668962975754388757265226046944074037010130279323051891221497929051128677304541626499  # q
nb = x1b * x2b  # n
phib = ((x1b - 1) * (x2b - 1)) // home_pgcd(x1b - 1, x2b - 1)
eb = 7627157  # exposants public
# eb = 23  # exposants public
db = home_ext_euclide(phib, eb)  # exposant privé // max des 2 derniers éléments du tuple retourné
k = 20  # limite arbitraire de la taille de chaque bloc

print("Vous êtes Bob, vous souhaitez envoyer un secret à Alice")
print("voici votre clé publique que tout le monde a le droit de consulter")
print("n =", nb)
print("exposant :", eb)
print("voici votre précieux secret")
print("d =", db)

print("*******************************************************************")

print("Voici aussi la clé publique d'Alice que tout le monde peut conslter")
print("n =", na)
print("exposent :", ea)

print("*******************************************************************")

print("il est temps de lui envoyer votre secret ")

print("*******************************************************************")

x = input("appuyer sur entrer")
secret = mot10char()

print("*******************************************************************")

print("voici la version en nombre décimal de ", secret, " : ")
num_sec = home_string_to_int(secret)
print(num_sec)

# Convertir le secret en bytes
bin_sec = num_sec.to_bytes((num_sec.bit_length() + 7) // 8, 'little')
print("voici la version en binaire de ", secret, " : ")
print(bin_sec)

print("*******************************************************************")

# Découpage en blocs
j = k // 2
list_block = []
print("voici la version en blocs de " + str(j) + " octets")
for i in range(0, len(bin_sec), j):
    list_block.append(bin_sec[i:i + j])
print(list_block)

print("*******************************************************************")

# Bourrage des blocs avec la forme suivante: : 00‖02‖𝑥‖00‖𝑚𝑖‖ où x est un nombre aléatoire et mi est le message
print("voici la version en bloc avec bourrage")
list_fill = []
for i in range(len(list_block)):
    j = len(list_block[i])
    x_rand = random.randbytes(k - j - 3)
    list_fill.append(b'\x00\x02' + x_rand + b'\x00' + list_block[i])
print(list_block)

print("*******************************************************************")

list_chif = []

print("voici le message chiffré avec la publique d'Alice : ")
for i in range(len(list_fill)):
    chif = home_mod_exponent(int.from_bytes(list_fill[i], 'little'), ea, na)
    list_chif.append(chif.to_bytes((chif.bit_length() + 7) // 8, 'little'))
print(list_chif)

print("*******************************************************************")

print("On utilise la fonction de hashage SHA256 pour obtenir le hash du message", secret)
Bhachis0 = hashlib.sha256(secret.encode(encoding='UTF-8', errors='strict')).digest()  # SHA256 du message
print("voici le hash en nombre décimal ")
Bhachis1 = binascii.b2a_uu(Bhachis0)
Bhachis2 = Bhachis1.decode()  # en string
Bhachis3 = home_string_to_int(Bhachis2)
print(Bhachis3)
print("voici la signature avec la clé privée de Bob du hachis")
signe = home_mod_exponent(Bhachis3, db, nb)
print(signe)

print("*******************************************************************")

print("Bob envoie \n \t 1-le message chiffré avec la clé public d'Alice \n", list_chif, "\n \t 2-et le hash signé \n",
      signe)

print("*******************************************************************")

x = input("appuyer sur entrer")

print("*******************************************************************")

print("Alice déchiffre le message chiffré \n", list_chif, "\nce qui donne ")

# On utilise le Théorème du Reste Chinois pour déchiffrer le message de Bob
# On déchiffre par bloc
dechif = ""
message = ""
for i in range(len(list_chif)):
    dechif = home_crt(int.from_bytes(list_chif[i], 'little'), x1a, x2a, da, na)
    dechif = dechif.to_bytes((dechif.bit_length() + 7) // 8, 'little')

    j = len(dechif)

    while dechif[j - 1] != 0:
        j = j - 1

    message = message + "".join(dechif[j:].decode())
print(message)
dechif = message

print("*******************************************************************")

print("Alice déchiffre la signature de Bob \n", signe, "\n ce qui donne  en décimal")
designe = home_mod_exponent(signe, eb, nb)
print(designe)
print("Alice vérifie si elle obtient la même chose avec le hash de ", dechif)
Ahachis0 = hashlib.sha256(dechif.encode(encoding='UTF-8', errors='strict')).digest()
Ahachis1 = binascii.b2a_uu(Ahachis0)
Ahachis2 = Ahachis1.decode()
Ahachis3 = home_string_to_int(Ahachis2)
print(Ahachis3)
print("La différence =", Ahachis3 - designe)
if Ahachis3 - designe == 0:
    print("Alice : Bob m'a envoyé : ", dechif)
else:
    print("oups")
