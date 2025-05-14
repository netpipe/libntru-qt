#include "NtruEncryptQt.h"
#include <ntru_crypto.h>
#include <QByteArray>
#include <QString>
#include <cstring>

extern "C" {
    static uint8_t entropy_seed[28] = {
        'P','l','e','a','s','e',' ','u','s','e',' ','r','e','a','l',
        ' ','e','n','t','r','o','p','y',' ','h','e','r','e'
    };

    static size_t entropy_index = 0;

    uint8_t get_entropy(ENTROPY_CMD cmd, uint8_t* out) {
        if (cmd == INIT) {
            entropy_index = 0;
            return 1;
        }
        if (cmd == GET_NUM_BYTES_PER_BYTE_OF_ENTROPY) {
            *out = 1;
            return 1;
        }
        if (cmd == GET_BYTE_OF_ENTROPY && out) {
            if (entropy_index >= sizeof(entropy_seed)) return 0;
            *out = entropy_seed[entropy_index++];
            return 1;
        }
        return 0;
    }
}

bool NtruEncryptQt::generateKeyPair(QByteArray &publicKey, QByteArray &privateKey) {
    DRBG_HANDLE drbg;
    if (ntru_crypto_drbg_instantiate(112, nullptr, 0, get_entropy, &drbg) != DRBG_OK)
        return false;

    uint16_t pubLen = 0, privLen = 0;
    ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2, &pubLen, nullptr, &privLen, nullptr);
    publicKey.resize(pubLen);
    privateKey.resize(privLen);

    if (ntru_crypto_ntru_encrypt_keygen(drbg, NTRU_EES401EP2,
                                        &pubLen, reinterpret_cast<uint8_t*>(publicKey.data()),
                                        &privLen, reinterpret_cast<uint8_t*>(privateKey.data())) != NTRU_OK)
        return false;

    ntru_crypto_drbg_uninstantiate(drbg);
    return true;
}

QByteArray NtruEncryptQt::encryptString(const QString &message, const QByteArray &publicKey) {
    QByteArray input = message.toUtf8();
    QByteArray ciphertext;
    DRBG_HANDLE drbg;
    if (ntru_crypto_drbg_instantiate(112, nullptr, 0, get_entropy, &drbg) != DRBG_OK)
        return QByteArray();

    uint16_t cipherLen = 0;
    if (ntru_crypto_ntru_encrypt(drbg,
                                 publicKey.size(),
                                 reinterpret_cast<const uint8_t*>(publicKey.constData()),
                                 input.size(),
                                 reinterpret_cast<const uint8_t*>(input.constData()),
                                 &cipherLen, nullptr) != NTRU_OK)
        return QByteArray();

    ciphertext.resize(cipherLen);
    if (ntru_crypto_ntru_encrypt(drbg,
                                 publicKey.size(),
                                 reinterpret_cast<const uint8_t*>(publicKey.constData()),
                                 input.size(),
                                 reinterpret_cast<const uint8_t*>(input.constData()),
                                 &cipherLen,
                                 reinterpret_cast<uint8_t*>(ciphertext.data())) != NTRU_OK)
        return QByteArray();

    ntru_crypto_drbg_uninstantiate(drbg);
    return ciphertext;
}

QString NtruEncryptQt::decryptToString(const QByteArray &ciphertext, const QByteArray &privateKey) {
    QByteArray plaintext(256, 0);  // AES key or short message max
    uint16_t plainLen = 0;

    if (ntru_crypto_ntru_decrypt(privateKey.size(),
                                 reinterpret_cast<const uint8_t*>(privateKey.constData()),
                                 ciphertext.size(),
                                 reinterpret_cast<const uint8_t*>(ciphertext.constData()),
                                 &plainLen, nullptr) != NTRU_OK)
        return {};

    plaintext.resize(plainLen);
    if (ntru_crypto_ntru_decrypt(privateKey.size(),
                                 reinterpret_cast<const uint8_t*>(privateKey.constData()),
                                 ciphertext.size(),
                                 reinterpret_cast<const uint8_t*>(ciphertext.constData()),
                                 &plainLen,
                                 reinterpret_cast<uint8_t*>(plaintext.data())) != NTRU_OK)
        return {};

    return QString::fromUtf8(plaintext);
}
