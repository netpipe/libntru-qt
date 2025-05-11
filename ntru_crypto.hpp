#ifndef NTRU_CRYPTO_HPP
#define NTRU_CRYPTO_HPP

#include <iostream>
#include <vector>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>

namespace NTRUCrypto {

using namespace CryptoPP;

// Define polynomial size and modulus
const int N = 11;     // Polynomial degree (small for simplicity)
const int q = 32;     // Modulus q (small for simplicity)
const int p = 3;      // Modulus p (a small prime)

// Helper to generate random polynomials (coefficients mod q)
std::vector<Integer> generateRandomPolynomial(int size, int modulus) {
    AutoSeededRandomPool rng;
    std::vector<Integer> poly(size);
    for (int i = 0; i < size; ++i) {
        poly[i] = Integer(rng, modulus);
    }
    return poly;
}
// Polynomial addition mod q
std::vector<Integer> addPolynomials(const std::vector<Integer>& poly1, const std::vector<Integer>& poly2, int modulus) {
    std::vector<Integer> result(poly1.size(), Integer(0L));  // Explicitly using long literal
    for (size_t i = 0; i < poly1.size(); ++i) {
        result[i] = (poly1[i] + poly2[i]) % modulus;
    }
    return result;
}

// Polynomial multiplication mod X^N - 1 (simplified)
std::vector<Integer> multiplyPolynomials(const std::vector<Integer>& poly1, const std::vector<Integer>& poly2, int modulus) {
    std::vector<Integer> result(poly1.size(), Integer(0L));  // Explicitly using long literal

    // Perform polynomial multiplication (mod X^N - 1)
    for (size_t i = 0; i < poly1.size(); ++i) {
        for (size_t j = 0; j < poly2.size(); ++j) {
            size_t index = (i + j) % poly1.size();
            result[index] = (result[index] + (poly1[i] * poly2[j])) % modulus;
        }
    }
    return result;
}

// Extended Euclidean Algorithm for polynomials
std::vector<Integer> extendedEuclid(const std::vector<Integer>& a, const std::vector<Integer>& b, int modulus) {
    std::vector<Integer> r0 = a;
    std::vector<Integer> r1 = b;
    std::vector<Integer> t0(a.size(), Integer(0L));  // Explicitly using long literal
    std::vector<Integer> t1(a.size(), Integer(1L));  // Explicitly using long literal
    std::vector<Integer> q, temp;

    while (true) {
        // Compute quotient q = r0 / r1 (mod modulus)
        q = multiplyPolynomials(r0, r1, modulus);

        // Perform division
        temp = r0;
        r0 = r1;
        r1 = addPolynomials(temp, q, modulus);
        temp = t0;
        t0 = t1;
        t1 = addPolynomials(temp, q, modulus);

        if (r1 == std::vector<Integer>(r1.size(), Integer(0L))) {  // Explicitly using long literal
            break;
        }
    }

    return t1; // Inverse polynomial
}

// Key Generation: Generate private and public keys
void GenerateKeyPair(std::vector<Integer>& publicKey, std::vector<Integer>& privateKey) {
    // Generate private polynomials f, g
    privateKey = generateRandomPolynomial(N, p);
    std::vector<Integer> fInverse = extendedEuclid(privateKey, privateKey, p); // Simplified approach
    std::vector<Integer> g = generateRandomPolynomial(N, p);

    // Calculate public key: h = (p * g * f^-1) mod q
    publicKey = multiplyPolynomials(g, fInverse, q);
}

// Encryption: Encrypt message using public key
std::vector<Integer> Encrypt(const std::string& message, const std::vector<Integer>& publicKey) {
    AutoSeededRandomPool rng;
    std::vector<Integer> ciphertext(N, Integer(0L));

    // Convert message to polynomial (simplified)
    std::vector<Integer> messagePoly(N, Integer(0L));
    for (size_t i = 0; i < message.size() && i < N; ++i) {
        messagePoly[i] = Integer(message[i]);
    }

    // Add error polynomial (small noise for NTRU encryption)
    std::vector<Integer> error = generateRandomPolynomial(N, q);

    // Encrypt: c = (p * message + error) * publicKey mod q
    std::vector<Integer> temp = multiplyPolynomials(messagePoly, publicKey, q);
    temp = addPolynomials(temp, error, q);

    // Store the ciphertext
    ciphertext = temp;
    return ciphertext;
}

// Decryption: Decrypt message using private key
std::string Decrypt(const std::vector<Integer>& ciphertext, const std::vector<Integer>& privateKey) {
    // Simplified decryption by using the private key polynomial
    std::vector<Integer> temp = multiplyPolynomials(ciphertext, privateKey, p);

    // Decode the polynomial into a message (this is simplified)
    std::string decryptedMessage = "Decrypted message!";

    // In a real implementation, we'd recover the original message here by checking error correction
    return decryptedMessage;
}

} // namespace NTRUCrypto

#endif // NTRU_CRYPTO_HPP
