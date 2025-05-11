#include <iostream>
#include <string>
#include "ntru_crypto.hpp"

using namespace std;

int main() {
    // Step 1: Key generation
    std::vector<CryptoPP::Integer> publicKey;
    std::vector<CryptoPP::Integer> privateKey;

    // Generate the key pair (public and private keys)
    NTRUCrypto::GenerateKeyPair(publicKey, privateKey);
    cout << "Public and Private keys generated." << endl;

    // Debug: Print the public and private keys
    cout << "Public Key: ";
    for (const auto& val : publicKey) {
        cout << val << " ";
    }
    cout << endl;

    cout << "Private Key: ";
    for (const auto& val : privateKey) {
        cout << val << " ";
    }
    cout << endl;

    // Step 2: Encryption
    std::string message = "Hello, NTRU!";
    cout << "Original message: " << message << endl;

    // Encrypt the message
    std::vector<CryptoPP::Integer> ciphertext = NTRUCrypto::Encrypt(message, publicKey);
    cout << "Message encrypted." << endl;

    // Debug: Print the ciphertext
    cout << "Ciphertext: ";
    for (const auto& val : ciphertext) {
        cout << val << " ";
    }
    cout << endl;

    // Step 3: Decryption
    CryptoPP::Integer p(3);
    CryptoPP::Integer q(2048);

    std::string decryptedMessage = NTRUCrypto::Decrypt(ciphertext, privateKey, p, q);

    cout << "Decrypted message: " << decryptedMessage << endl;

    // Checking if the decrypted message matches the original
    if (message == decryptedMessage) {
        cout << "Decryption successful! The message matches the original." << endl;
    } else {
        cout << "Decryption failed! The message does not match the original." << endl;
    }

    return 0;
}
