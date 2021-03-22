#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message with a WEP key"""

__author__      = "Robin Cuénoud Mülhauser Florian"
__version__ 	= "1.0"
__status__ 		= "Prototype"

from scapy.all import *
import binascii

from scapy.layers.l2 import ARP

from rc4 import RC4
#Cle wep CA:AA:FF:EE:EE
key= b'\xca\xaa\xff\xee\xee'

# import pour avoir un modèle
arp = rdpcap('arp.cap')[0]

# le message de la capture originale dechiffrée
# 0000   aa aa 03 00 00 00 08 06 00 01 08 00 06 [0806 arp] 04 00 01
# 0010   90 27 e4 ea 61 f2 c0 a8 01 64 00 00 00 00 00 00
# 0020   c0 a8 01 c8
# on crée donc une frame avec le même début (arp)
# et ensuite création d'une trame arp avec scapy
cleartext = '\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06'+str(ARP(op="who-has",psrc="192.168.1.100", pdst="192.168.1.200").payload)
clear_icv = binascii.crc32(bytes(cleartext,'utf-8')).to_bytes(4,byteorder='little')
# rc4 seed est composé de IV+clé
seed = arp.iv+key

# recuperation de icv dans le message (arp.icv) (en chiffre) -- je passe au format "text". Il y a d'autres manières de faire ceci...
icv_encrypted='{:x}'.format(arp.icv)

# text chiffré y-compris l'icv
message_encrypted=arp.wepdata+bytes.fromhex(icv_encrypted)

# déchiffrement rc4
cipher = RC4(seed, streaming=False)

cleartext=cipher.crypt(message_encrypted)

# le ICV est les derniers 4 octets - je le passe en format Long big endian
icv_enclair=cleartext[-4:]
icv_enclair = icv_enclair
icv_numerique=struct.unpack('!L', icv_enclair)

# le message sans le ICV
text_enclair=cleartext[:-4]
print (''.join(format(x, '02x') for x in cleartext))
print ('Text: ' + text_enclair.hex())
print ('icv:  ' + icv_enclair.hex())
print ('icv(num): ' + str(icv_numerique))
