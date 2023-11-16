import sys, os
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QFileDialog
import crypto_design
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
from Crypto.Cipher import AES

class CryptApp(QtWidgets.QMainWindow, crypto_design.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.btn_GenKeys.clicked.connect(self.generateKeys)
        self.btn_CheckSign.setEnabled(False)
        self.btn_LoadPubKey.clicked.connect(self.loadPublicKey)
        self.btn_LoadMsg.clicked.connect(self.loadMessage)
        self.btn_SignMsg.clicked.connect(self.signMessage)
        self.btn_CryptSign.clicked.connect(self.cryptSign)
        self.btn_CryptAll.clicked.connect(self.genSessionKeyAndCryptAll)
        self.btn_DecrSessionKey.clicked.connect(self.decryptSessionKey)
        self.btn_DecrMessage.clicked.connect(self.decryptMessage)
        self.btn_DecrSign.clicked.connect(self.decryptSign)

    def generateKeys(self):
        self.privateKey = RSA.generate(2048)
        self.publicKey = self.privateKey.publickey()
        self.txt_UserPrivateKey.setText(
            str((bytes(self.privateKey.exportKey('PEM'))).decode('utf-8')))
        self.txt_UserPublicKey.setText(
            str((bytes(self.publicKey.exportKey('PEM'))).decode('utf-8')))
        self.txt_UserPrivateKey.repaint()

    def loadPublicKey(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self, "QFileDialog.getOpenFileName()", "",
                                                  "Txt files (*.txt)", options=options)

        if fileName:
            data = open(fileName).read()
            self.recievedKey = RSA.importKey(data)
            self.txt_ReceivedKey.setText(data)

    def loadMessage(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self, "QFileDialog.getOpenFileName()", "",
                                                  "Txt files (*.txt)", options=options)
        if fileName:
            self.txt_MsgPath.setText(fileName)

            f = open(fileName, 'rb')
            data = f.read()
            f.close()

            f = open('message.txt', 'wb')
            f.write(bytes(data))
            f.close()

    def signMessage(self):
        #privateKey = RSA.importKey(open('UserPrivateKey.txt', 'rb').read())
        f = open('message.txt', 'rb')
        self.message = f.read()
        f.close()

        myHash = SHA.new(self.message)
        self.signature = PKCS1_v1_5.new(self.privateKey)
        print(type(self.signature))
        self.signature = self.signature.sign(myHash)
        print(type(self.signature))

    def cryptSign(self):
        #publicKey = RSA.importKey(open('ReceivedKey.txt', 'rb').read())
        cipherRSA = PKCS1_OAEP.new(self.recievedKey)
        sig = cipherRSA.encrypt(self.signature[:128])
        sig = sig + cipherRSA.encrypt(self.signature[128:])

        f = open('signature.txt', 'wb')
        f.write(bytes(sig))
        f.close()

    def genSessionKeyAndCryptAll(self):
        sessionKey = Random.new().read(32)  # 256 bit

        f = open('message.txt', 'rb')
        sample = f.read()
        f.close()

        iv = Random.new().read(16)  # 128 bit
        obj = AES.new(sessionKey, AES.MODE_CFB, iv)
        cipherText = iv + obj.encrypt(sample)

        f = open('message.txt', 'wb')
        f.write(bytes(cipherText))
        f.close()

        #publicKey = RSA.importKey(open('ReceivedKey.txt', 'rb').read())
        cipherRSA = PKCS1_OAEP.new(self.recievedKey)
        sessionKey = cipherRSA.encrypt(sessionKey)

        f = open('sessionKey.txt', 'wb')
        f.write(bytes(sessionKey))
        f.close()

    def decryptSessionKey(self):
        # decryption session key
        cipherRSA = PKCS1_OAEP.new(self.privateKey)

        # open received crypted sessionKey
        f = open('sessionKey.txt', 'rb')
        sessionKey = f.read()
        f.close()

        self.sessionKey = cipherRSA.decrypt(sessionKey)

    def decryptMessage(self):
        # decryption message

        # open received crypted message
        f = open('message.txt', 'rb')
        cipherText = f.read()
        f.close()

        iv = cipherText[:16]
        obj = AES.new(self.sessionKey, AES.MODE_CFB, iv)
        self.message = obj.decrypt(cipherText)
        self.message = self.message[16:]

        f = open('message.txt', 'wb')
        f.write(bytes(self.message))
        f.close()

    def decryptSign(self):
        # decryption signature
        f = open('signature.txt', 'rb')
        signature = f.read()
        f.close()

        #privateKey = RSA.importKey(open('UserPrivateKey.txt', 'rb').read())
        cipherRSA = PKCS1_OAEP.new(self.privateKey)
        self.sig = cipherRSA.decrypt(signature[:256])
        self.sig = self.sig + cipherRSA.decrypt(signature[256:])

    def checkSign(self):
        # signature verification
        f = open('sampleText.txt', 'rb')
        self.message = f.read()
        f.close()

        #publicKey = RSA.importKey(open('ReceivedPublicKey.txt', 'rb').read())
        myHash = SHA.new(self.message)
        signature = PKCS1_v1_5.new(self.recievedKey)
        test = signature.verify(myHash, self.sig)

        print(test)

def main():
    app = QtWidgets.QApplication(sys.argv)  # new QApplication object
    window = CryptApp()
    window.show()
    app.exec_()                             # launch application

if __name__ == '__main__':
    main()
