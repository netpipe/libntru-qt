#ifndef NTRU_CRYPTO_HPP
#define NTRU_CRYPTO_HPP

#include <string>
#include <stdexcept>

#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
//#include <cryptopp/ntru.h>
#include "ntru.h"

class NtruCrypto {
public:
    NtruCrypto()
        : N(509), p(3), q(2048), df(85), dg(85), d(85) {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::NTRUEncrypt::GenerateKeyPair(
            rng, N, p, q, df, dg, d, publicKey, privateKey, false);
    }

    std::string encrypt(const std::string& message) {
        CryptoPP::AutoSeededRandomPool rng;
        std::string ciphertext;



        // Encode to Base64
        std::string encoded;
        CryptoPP::StringSource ss(message, true,
            new CryptoPP::Base64Encoder(
                new CryptoPP::StringSink(encoded), false
            )
        );
        ciphertext = encoded;


        return encoded;
    }

    std::string decrypt(const std::string& encodedCiphertext) {
        CryptoPP::AutoSeededRandomPool rng;



        // Decrypt
        std::string decoded;
        CryptoPP::StringSource ss(encodedCiphertext, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decoded)
            )
        );
       // decryptedMessage = decoded;


        return decoded;
    }

private:
    // NTRU parameters
    const int N;
    const int p;
    const int q;
    const int df;
    const int dg;
    const int d;

    CryptoPP::NTRUEncrypt::EncryptionPublicKey publicKey;
    CryptoPP::NTRUEncrypt::EncryptionPrivateKey privateKey;
};

#endif // NTRU_CRYPTO_HPP
