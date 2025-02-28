#include "Encrypt.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include<iostream>

std::string EncryptSHA256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.size());
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}
// int main() {
//     std::string data = "hello world"; // 测试数据
//     std::string encryptedData = EncryptSHA256(data);
//     std::cout << "Encrypted SHA256: " << encryptedData << std::endl;
//     return 0;
// }