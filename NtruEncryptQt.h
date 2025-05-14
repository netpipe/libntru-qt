// NtruEncryptQt.h
#ifndef NTRUENCRYPTQT_H
#define NTRUENCRYPTQT_H

#include <QString>
#include <QByteArray>
#include <QPair>

class NtruEncryptQt {
public:
    static bool generateKeyPair(QByteArray &publicKey, QByteArray &privateKey);
    static QByteArray encryptString(const QString &message, const QByteArray &publicKey);
    static QString decryptToString(const QByteArray &ciphertext, const QByteArray &privateKey);
};

#endif // NTRUENCRYPTQT_H
