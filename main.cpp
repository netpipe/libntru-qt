#include <iostream>
#include <vector>
#include <string>
#include "ntru_crypto.hpp"  // Your custom header with Encrypt/Decrypt and keygen

int main() {
    using CryptoPP::Integer;

    // Choose small parameters for demonstration
    size_t keySize = 32;            // Length of key polynomials
    Integer p = 256;                // Plaintext modulus, match ASCII
    Integer q = 4096;               // Large modulus for encryption math

    // Generate keys
    auto publicKey = NTRUCrypto::generateRandomPolynomial(keySize, q);
    auto privateKey = NTRUCrypto::generateRandomPolynomial(keySize, q);
    std::cout << "Public and Private keys generated.\n";

    // Message
    std::string message = "Hello, NTRU!";
    std::cout << "Original message: " << message << std::endl;

    // Encrypt
    auto ciphertext = NTRUCrypto::Encrypt(message, publicKey, p, q);
    std::cout << "Message encrypted.\nCiphertext: ";
    for (const auto& c : ciphertext)
        std::cout << c << ".. ";
    std::cout << "\n";

    // Decrypt
    std::string decryptedMessage = NTRUCrypto::Decrypt(ciphertext, privateKey, p, q, message.length());
    std::cout << "Decrypted message: " << decryptedMessage << std::endl;

    // Check
    if (decryptedMessage == message) {
        std::cout << "Decryption successful!" << std::endl;
    } else {
        std::cout << "Decryption failed!" << std::endl;
    }

    return 0;
}
