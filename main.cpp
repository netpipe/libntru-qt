#include "ntru_crypto.hpp"
#include <iostream>

int main() {
    using namespace NTRUCrypto;

    EncryptionPublicKey pub;
    EncryptionPrivateKey priv;
    GenerateKeyPair(pub, priv);

    Encryptor enc(pub);
    Decryptor dec(priv);

    std::string message = "This is a test message.";
    std::string cipher = enc.encrypt(message);
    std::string plain = dec.decrypt(cipher);

    std::cout << "Encrypted: " << cipher << std::endl;
    std::cout << "Decrypted: " << plain << std::endl;

    return 0;
}
