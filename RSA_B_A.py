# -*- coding: utf-8 -*-
"""
Created on Fri Apr 17 13:44:40 2020

@author: Mr ABBAS-TURKI
"""

import binascii
import hashlib


def home_mod_exponent(x, y, n):  # exponentiation modulaire
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
    secret = input("donner un secret de 10 caractères au maximum : ")
    while len(secret) > 11:
        secret = input("c'est beaucoup trop long, 10 caractères S.V.P : ")
    return secret


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
print("voici le message chiffré avec la publique d'Alice : ")
chif = home_mod_exponent(num_sec, ea, na)
print(chif)

print("*******************************************************************")

print("On utilise la fonction de hashage SHA256 pour obtenir le hash du message", secret)
Bhachis0 = hashlib.sha256(secret.encode(encoding='UTF-8', errors='strict')).digest()  # MD5 du message
print("voici le hash en nombre décimal ")
Bhachis1 = binascii.b2a_uu(Bhachis0)
Bhachis2 = Bhachis1.decode()  # en string
Bhachis3 = home_string_to_int(Bhachis2)
print(Bhachis3)
print("voici la signature avec la clé privée de Bob du hachis")
signe = home_mod_exponent(Bhachis3, db, nb)
print(signe)

print("*******************************************************************")

print("Bob envoie \n \t 1-le message chiffré avec la clé public d'Alice \n", chif, "\n \t 2-et le hash signé \n", signe)

print("*******************************************************************")

x = input("appuyer sur entrer")

print("*******************************************************************")

print("Alice déchiffre le message chiffré \n", chif, "\nce qui donne ")
dechif = home_int_to_string(home_mod_exponent(chif, da, na))
print(dechif)

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
