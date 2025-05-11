#include "ntru_crypto.hpp"
#include <iostream>

int main() {
    NtruCrypto crypto;

    std::string message = "This is a secret message.";
    std::string ciphertext = crypto.encrypt(message);
    std::string decrypted = crypto.decrypt(ciphertext);

    std::cout << "Encrypted (Base64): " << ciphertext << std::endl;
    std::cout << "Decrypted Message: " << decrypted << std::endl;

    return 0;
}
