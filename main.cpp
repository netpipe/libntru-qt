#include <QCoreApplication>
#include <QDebug>
#include "NtruEncryptQt.h"
#include <qdebug.h>
#include <QCoreApplication>
#include <QDebug>
#include "NtruEncryptQt.h"

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    QByteArray publicKey, privateKey;
    if (!NtruEncryptQt::generateKeyPair(publicKey, privateKey)) {
        qCritical() << "Key generation failed.";
        return 1;
    }

    QString message = "Hello NTRU!";
    QByteArray ciphertext = NtruEncryptQt::encryptString(message, publicKey);
    if (ciphertext.isEmpty()) {
        qCritical() << "Encryption failed.";
        return 1;
    }

    QString decrypted = NtruEncryptQt::decryptToString(ciphertext, privateKey);
    if (decrypted.isEmpty()) {
        qCritical() << "Decryption failed.";
        return 1;
    }

    qDebug().noquote() << "Original message:" << message;
    qDebug().noquote() << "Public Key (Base64):" << publicKey.toBase64();
    qDebug().noquote() << "Private Key (Base64):" << privateKey.toBase64();
    qDebug().noquote() << "Ciphertext (Hex):" << ciphertext.toHex();
    qDebug().noquote() << "Decrypted message:" << decrypted;

    return 0;
}
