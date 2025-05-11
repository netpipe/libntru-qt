#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <stdexcept>
#include <ctime>
#include <cstdlib>
#include <cryptopp/integer.h>

using CryptoPP::Integer;

namespace NTRUCrypto {
    const size_t POLY_SIZE = 11; // polynomial degree
    const Integer p = 256;   // match byte size
    const Integer q = 8192;  // must be much larger than p


    std::vector<Integer> generateRandomPolynomial(size_t size, Integer max = Integer(10)) {
        std::vector<Integer> poly(size);
        for (size_t i = 0; i < size; ++i)
            poly[i] = Integer(std::rand() % max.ConvertToLong());
        return poly;
    }

    std::vector<Integer> multiplyPolynomials(const std::vector<Integer>& a,
                                             const std::vector<Integer>& b,
                                             const Integer& mod) {
        std::vector<Integer> result(POLY_SIZE);
        for (size_t i = 0; i < POLY_SIZE; ++i)
            for (size_t j = 0; j < POLY_SIZE; ++j)
                result[(i + j) % POLY_SIZE] = (result[(i + j) % POLY_SIZE] + a[i] * b[j]) % mod;
        return result;
    }

    std::vector<Integer> encodeMessage(const std::string& message) {
        std::vector<Integer> encoded;
        for (unsigned char c : message) {
            encoded.push_back(Integer(c));
        }
        return encoded;
    }

    std::string decodeMessage(const std::vector<Integer>& poly, const Integer& q, const Integer& p) {
        std::string message;
        for (const auto& coeff : poly) {
            // Normalize coefficient into [0, q), then reduce to byte range
            Integer val = ((coeff % q) + q) % q;
            val = val % p;
            message += static_cast<char>(val.ConvertToLong());
        }
        return message;
    }



    void generateKeyPair(std::vector<Integer>& publicKey, std::vector<Integer>& privateKey) {
        privateKey = generateRandomPolynomial(POLY_SIZE);
        publicKey = multiplyPolynomials(privateKey, generateRandomPolynomial(POLY_SIZE), q);
    }

    std::vector<CryptoPP::Integer> Encrypt(const std::string& message,
                                           const std::vector<CryptoPP::Integer>& publicKey,
                                           const CryptoPP::Integer& p,
                                           const CryptoPP::Integer& q) {
        std::vector<CryptoPP::Integer> messagePoly;
        // Convert message characters into polynomials
        for (char c : message) {
            messagePoly.push_back(CryptoPP::Integer(static_cast<CryptoPP::byte>(c)) % p);
        }

        std::vector<CryptoPP::Integer> ciphertext(publicKey.size(), 0);
        // Encrypt each coefficient of the message polynomial
        for (size_t i = 0; i < messagePoly.size(); ++i) {
            for (size_t j = 0; j < publicKey.size(); ++j) {
                size_t index = (i + j) % publicKey.size();
                ciphertext[index] = (ciphertext[index] + messagePoly[i] * publicKey[j]) % q;
            }
        }

        return ciphertext;
    }

    std::string Decrypt(const std::vector<CryptoPP::Integer>& ciphertext,
                        const std::vector<CryptoPP::Integer>& privateKey,
                        const CryptoPP::Integer& p,
                        const CryptoPP::Integer& q,
                        size_t messageLength) {
        std::vector<CryptoPP::Integer> temp(ciphertext.size(), 0);

        // Decrypt the ciphertext with the private key
        for (size_t i = 0; i < ciphertext.size(); ++i) {
            for (size_t j = 0; j < privateKey.size(); ++j) {
                size_t index = (i + j) % ciphertext.size();
                temp[index] = (temp[index] + ciphertext[i] * privateKey[j]) % q;
            }
        }

        // Now convert the result back into a string
        std::string decryptedMessage;
        for (size_t i = 0; i < messageLength; ++i) {
            CryptoPP::Integer val = ((temp[i] % q) + q) % q;  // Ensure positive value
            val = val % p;  // Use p for the message space
            decryptedMessage += static_cast<char>(val.ConvertToLong());
        }

        return decryptedMessage;
    }


}
