// src/CryptoUtils.cpp
#include "CryptoUtils.h"
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <iostream>

std::string CryptoUtils::Encrypt(const std::string& data, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    std::string cipher;
    try {
        CryptoPP::GCM<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::StringSource ss(data, true, 
            new CryptoPP::AuthenticatedEncryptionFilter(encryptor,
                new CryptoPP::StringSink(cipher)
            )
        );
    }
    catch(const std::exception& e) { // 改为捕获 std::exception
        std::cerr << "Encryption error: " << e.what() << std::endl;
        throw;
    }
    return cipher;
}

std::string CryptoUtils::Decrypt(const std::string& cipher, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    std::string recovered;
    try {
        CryptoPP::GCM<CryptoPP::AES>::Decryption decryptor;
        decryptor.SetKeyWithIV(key, key.size(), iv, iv.size());

        CryptoPP::StringSource ss(cipher, true, 
            new CryptoPP::AuthenticatedDecryptionFilter(decryptor,
                new CryptoPP::StringSink(recovered)
            )
        );
    }
    catch(const std::exception& e) { // 改为捕获 std::exception
        std::cerr << "Decryption error: " << e.what() << std::endl;
        throw;
    }
    return recovered;
}
