from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# decryption session key
privateKey = RSA.importKey(open('User2PrivateKey.txt', 'rb').read())
cipherRSA = PKCS1_OAEP.new(privateKey)

f = open('sessionKey.txt', 'rb')
sessionKey = f.read()
f.close()

sessionKey = cipherRSA.decrypt(sessionKey)


# decryption message

f = open('sampleText.txt', 'rb')
cipherText = f.read()
f.close()

iv = cipherText[:16]
obj = AES.new(sessionKey, AES.MODE_CFB, iv)
sampleText = obj.decrypt(cipherText)
sampleText = sampleText[16:]

f = open('sampleText.txt', 'wb')
f.write(bytes(sampleText))
f.close()
