from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# key generation User1
privateKey = RSA.generate(2048)
f = open('User1PrivateKey.txt', 'wb')
f.write(bytes(privateKey.exportKey('PEM')))
f.close()

publicKey = privateKey.publickey()
f = open('User1PublicKey.txt', 'wb')
f.write(bytes(publicKey.exportKey('PEM')))
f.close()

# key generation User2
privateKey = RSA.generate(2048)
f = open('User2PrivateKey.txt', 'wb')
f.write(bytes(privateKey.exportKey('PEM')))
f.close()

publicKey = privateKey.publickey()
f = open('User2PublicKey.txt', 'wb')
f.write(bytes(publicKey.exportKey('PEM')))
f.close()
