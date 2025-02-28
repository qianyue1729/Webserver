//bupt+wxy+2021212272
#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <cstring>

class AESCrypter {
public:
    AESCrypter(const std::string &key, const std::string &iv)
    : key(key), iv(iv) {
        // 初始化加密上下文
        ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);
    }

    ~AESCrypter() {
        EVP_CIPHER_CTX_free(ctx);
    }

    std::string encrypt(const std::string &plaintext) {
        std::string ciphertext;
        ciphertext.resize(plaintext.size() + AES_BLOCK_SIZE); // 确保有足够的空间

        int len = 0;
        int ciphertext_len = 0;

        // 初始化加密操作
        if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, reinterpret_cast<const unsigned char*>(key.data()), reinterpret_cast<const unsigned char*>(iv.data()))) {
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        // 提供明文进行加密
        if(1 != EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.length())) {
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        ciphertext_len = len;

        // 完成加密操作
        if(1 != EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len)) {
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }
        ciphertext_len += len;

        ciphertext.resize(ciphertext_len); // 调整密文长度
        return ciphertext;
    }

private:
    EVP_CIPHER_CTX *ctx;
    std::string key;
    std::string iv;
};

int main() {
    std::string key, iv, plaintext;

    // 获取用户输入
    std::cout << "Enter key (32 bytes): ";
    std::getline(std::cin, key);
    std::cout << "Enter IV (16 bytes): ";
    std::getline(std::cin, iv);
    std::cout << "Enter plaintext: ";
    std::getline(std::cin, plaintext);

    try {
        AESCrypter aesCrypter(key, iv);
        std::string ciphertext = aesCrypter.encrypt(plaintext);

        std::cout << "Ciphertext (hex): ";
        for (unsigned char c : ciphertext) {
            std::printf("%02x", c);
        }
        std::cout << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    return 0;
}
