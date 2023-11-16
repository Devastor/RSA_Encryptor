from Crypto.PublicKey import RSA

# key generation User1
privateKey = RSA.generate(2048)
f = open('UserPrivateKey.txt', 'wb')
f.write(bytes(privateKey.exportKey('PEM')))
f.close()

publicKey = privateKey.publickey()
f = open('UserPublicKey.txt', 'wb')
f.write(bytes(publicKey.exportKey('PEM')))
f.close()

