from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# decryption signature
f = open('signature.txt', 'rb')
signature = f.read()
f.close()

privateKey = RSA.importKey(open('User2PrivateKey.txt', 'rb').read())
cipherRSA = PKCS1_OAEP.new(privateKey)
sig = cipherRSA.decrypt(signature[:256])
sig = sig + cipherRSA.decrypt(signature[256:])

# signature verification
f = open('sampleText.txt', 'rb')
sampleText = f.read()
f.close()

publicKey = RSA.importKey(open('User1PublicKey.txt', 'rb').read())
myHash = SHA.new(sampleText)
signature = PKCS1_v1_5.new(publicKey)
test = signature.verify(myHash, sig)

print(test)

