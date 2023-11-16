from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# creation of signature
f = open('sampleText.txt', 'rb')
sampleText = f.read()
f.close()

privateKey = RSA.importKey(open('User1PrivateKey.txt', 'rb').read())
myHash = SHA.new(sampleText)
signature = PKCS1_v1_5.new(privateKey)
signature = signature.sign(myHash)


# signature encrypt
publicKey = RSA.importKey(open('User2PublicKey.txt', 'rb').read())
cipherRSA = PKCS1_OAEP.new(publicKey)
sig = cipherRSA.encrypt(signature[:128])
sig = sig + cipherRSA.encrypt(signature[128:])

f = open('signature.txt', 'wb')
f.write(bytes(sig))
f.close()
