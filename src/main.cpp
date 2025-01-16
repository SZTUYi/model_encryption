#include "CryptoUtils.h"
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>
#include <cryptopp/osrng.h>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include <cstdlib>

namespace fs = std::filesystem;

// 读取文件函数
std::vector<unsigned char> ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if(!file) {
        throw std::runtime_error("无法打开文件: " + filename);
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if(!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("无法读取文件: " + filename);
    }
    return buffer;
}

// 写入文件函数
void WriteFile(const std::string& filename, const std::string& data) {
    std::cout << "Attempting to write to file: " << filename << std::endl;
    std::ofstream file(filename, std::ios::binary);
    if(!file) {
        throw std::runtime_error("无法写入文件: " + filename);
    }
    file.write(data.data(), data.size());
}

// 十六进制编码函数
std::string ByteToHex(const CryptoPP::SecByteBlock& byteBlock) {
    std::string hexStr;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hexStr));
    encoder.Put(byteBlock, byteBlock.size());
    encoder.MessageEnd();
    return hexStr;
}

// 十六进制解码函数
CryptoPP::SecByteBlock HexToByte(const std::string& hexStr, size_t byteSize) {
    CryptoPP::SecByteBlock byteBlock(byteSize);
    CryptoPP::HexDecoder decoder;
    decoder.Attach(new CryptoPP::ArraySink(byteBlock, byteBlock.size()));
    decoder.Put(reinterpret_cast<const unsigned char*>(hexStr.data()), hexStr.size());
    decoder.MessageEnd();
    return byteBlock;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " [encrypt|decrypt] [input_dir] [output_dir]" << std::endl;
        return 1;
    }

    std::string mode = argv[1];

    try {
        if (mode == "encrypt") {
            if (argc < 4) {
                std::cerr << "Usage for encrypt: " << argv[0] << " encrypt [input_dir] [output_dir]" << std::endl;
                return 1;
            }
            std::string inputDir = argv[2];
            std::string outputDir = argv[3];

            // 创建输出目录（如果不存在）
            if (!fs::exists(outputDir)) {
                if (!fs::create_directories(outputDir)) {
                    std::cerr << "无法创建输出目录: " << outputDir << std::endl;
                    return 1;
                }
            }

            // 生成密钥和 IV（AES-256，32字节密钥）
            CryptoPP::AutoSeededRandomPool prng;
            CryptoPP::SecByteBlock key(CryptoPP::AES::MAX_KEYLENGTH); // 32字节，AES-256
            CryptoPP::SecByteBlock iv(12); // GCM 推荐 12 字节 IV
            prng.GenerateBlock(key, key.size());
            prng.GenerateBlock(iv, iv.size());

            // 遍历输入目录中的所有文件
            for (const auto& entry : fs::directory_iterator(inputDir)) {
                if (entry.is_regular_file()) {
                    std::string inputFile = entry.path().string();
                    std::string filename = entry.path().filename().string();
                    std::string outputFile = outputDir + "/" + filename + ".enc";

                    std::vector<unsigned char> fileData = ReadFile(inputFile);
                    std::string fileStr(fileData.begin(), fileData.end());

                    // 加密数据
                    std::string encryptedData = CryptoUtils::Encrypt(fileStr, key, iv);

                    // 将 IV 前置到加密数据中，以便解密时使用
                    std::string cipherWithIV(reinterpret_cast<char*>(iv.data()), iv.size());
                    cipherWithIV += encryptedData;

                    // 写入加密后的文件
                    WriteFile(outputFile, cipherWithIV);

                    // 记录加密信息
                    std::cout << "Encrypted " << inputFile << " to " << outputFile << std::endl;
                }
            }

            // 输出密钥和 IV 的十六进制表示（实际应用中应妥善保存）
            std::string keyHex = ByteToHex(key);
            std::string ivHex = ByteToHex(iv);
            std::cout << "Encryption Successful!" << std::endl;
            std::cout << "Key (hex): " << keyHex << std::endl;
            std::cout << "IV (hex): " << ivHex << std::endl;

            // 保存密钥和 IV 到文件
            WriteFile("encryption_key.txt", keyHex);
            WriteFile("encryption_iv.txt", ivHex);
            std::cout << "Key and IV have been saved to encryption_key.txt and encryption_iv.txt" << std::endl;
        }
        else if (mode == "decrypt") {
            if (argc < 4) {
                std::cerr << "Usage for decrypt: " << argv[0] << " decrypt [input_dir] [output_dir]" << std::endl;
                return 1;
            }
            std::string inputDir = argv[2];
            std::string outputDir = argv[3];

            // 创建输出目录（如果不存在）
            if (!fs::exists(outputDir)) {
                if (!fs::create_directories(outputDir)) {
                    std::cerr << "无法创建输出目录: " << outputDir << std::endl;
                    return 1;
                }
            }

            // 从文件加载密钥
            std::ifstream keyFile("encryption_key.txt");
            std::string keyHex;
            if(keyFile.is_open()) {
                keyFile >> keyHex;
                keyFile.close();
            } else {
                std::cerr << "无法读取密钥文件: encryption_key.txt" << std::endl;
                return 1;
            }

            if (keyHex.size() != 64) { // 修改为64个十六进制字符
                throw std::runtime_error("密钥长度不正确，应为64个十六进制字符");
            }

            // 解码密钥
            CryptoPP::SecByteBlock key = HexToByte(keyHex, CryptoPP::AES::MAX_KEYLENGTH);

            // 遍历输入目录中的所有加密文件
            for (const auto& entry : fs::directory_iterator(inputDir)) {
                if (entry.is_regular_file()) {
                    std::string inputFile = entry.path().string();
                    std::string filename = entry.path().filename().string();

                    // 假设加密文件以 .enc 结尾
                    if (filename.size() > 4 && filename.substr(filename.size() - 4) == ".enc") {
                        std::string outputFilename = filename.substr(0, filename.size() - 4) + "_decrypted";
                        std::string outputFile = outputDir + "/" + outputFilename;

                        std::vector<unsigned char> cipherDataVec = ReadFile(inputFile);
                        std::string cipherData(cipherDataVec.begin(), cipherDataVec.end());

                        // 提取 IV 和密文
                        const size_t ivSize = 12; // 与加密时的 IV 大小一致
                        if(cipherData.size() < ivSize) {
                            std::cerr << "加密数据长度不足: " << inputFile << std::endl;
                            continue;
                        }
                        std::string ivStr = cipherData.substr(0, ivSize);
                        std::string encryptedData = cipherData.substr(ivSize);

                        // 解码 IV
                        CryptoPP::SecByteBlock iv(reinterpret_cast<const CryptoPP::byte*>(ivStr.data()), ivSize);

                        // 解密数据
                        std::string recoveredData = CryptoUtils::Decrypt(encryptedData, key, iv);

                        // 写入解密后的文件
                        WriteFile(outputFile, recoveredData);

                        // 记录解密信息
                        std::cout << "Decrypted " << inputFile << " to " << outputFile << std::endl;
                    }
                }
            }

            std::cout << "Decryption Completed!" << std::endl;
        }
        else {
            std::cerr << "未知的模式: " << mode << ". 使用 'encrypt' 或 'decrypt'." << std::endl;
            return 1;
        }
    }
    catch(const std::exception& e) { // 使用 std::exception
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
