//bupt+wxy+2021212272 
#include <openssl/sha.h>
#include <iostream>
#include <sstream>
#include <iomanip>

std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for(unsigned char i : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)i;
    }
    return ss.str();
}

int main() {
    std::cout << "Enter a string: ";
    std::string input;
    // 获取用户输入的字符串
    std::getline(std::cin, input);
    // 计算并输出SHA256散列值
    std::string output = sha256(input);
    std::cout << "SHA256('" << input << "') = " << output << std::endl;
    return 0;
}
