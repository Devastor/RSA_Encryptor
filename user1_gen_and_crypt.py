from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# creation 256 bit session key
sessionKey = Random.new().read(32)  # 256 bit


# encryption AES of the message
f = open('sampleText.txt', 'rb')
sample = f.read()
f.close()

iv = Random.new().read(16)  # 128 bit
obj = AES.new(sessionKey, AES.MODE_CFB, iv)
cipherText = iv + obj.encrypt(sample)

f = open('sampleText.txt', 'wb')
f.write(bytes(cipherText))
f.close()


# encryption RSA of the session key
publicKey = RSA.importKey(open('User2PublicKey.txt', 'rb').read())
cipherRSA = PKCS1_OAEP.new(publicKey)
sessionKey = cipherRSA.encrypt(sessionKey)

f = open('sessionKey.txt', 'wb')
f.write(bytes(sessionKey))
f.close()
