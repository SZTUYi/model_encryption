#pragma once
#include <string>
#include <cryptopp/secblock.h>

class CryptoUtils {
public:
    // 加密函数
    static std::string Encrypt(const std::string& data, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv);

    // 解密函数
    static std::string Decrypt(const std::string& cipher, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv);
};
