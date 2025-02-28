//bupt+wxy+2021212272
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <string>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// 函数，用于将签名的二进制数据转换为十六进制字符串
std::string toHex(const unsigned char *data, size_t length) {
    std::string result;
    const char hex_chars[] = "0123456789ABCDEF";

    for (size_t i = 0; i < length; ++i) {
        const unsigned char ch = data[i];
        result.append(&hex_chars[(ch & 0xF0) >> 4], 1);
        result.append(&hex_chars[ch & 0x0F], 1);
    }

    return result;
}

int main() {
    // 初始化 OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 创建 EC_KEY 结构体，选择 NID_secp256k1 曲线
    EC_KEY* eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!eckey) handleErrors();

    if (!EC_KEY_generate_key(eckey)) handleErrors();

    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) handleErrors();

    if (!EVP_PKEY_assign_EC_KEY(pkey, eckey)) handleErrors();

    // 用户输入消息
    std::string data;
    std::cout << "Enter the message to sign: ";
    std::getline(std::cin, data);

    // 创建和初始化签名上下文
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) handleErrors();

    if (1 != EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey)) handleErrors();

    size_t sig_len;
    unsigned char* sig;

    if (1 != EVP_DigestSign(ctx, nullptr, &sig_len, (const unsigned char*)data.c_str(), data.length())) handleErrors();

    sig = (unsigned char*)OPENSSL_malloc(sig_len);
    if (!sig) handleErrors();

    if (1 != EVP_DigestSign(ctx, sig, &sig_len, (const unsigned char*)data.c_str(), data.length())) handleErrors();

    std::cout << "Signature Created.\n";
    std::string signatureHex = toHex(sig, sig_len);
    std::cout << "Signature (hex): " << signatureHex << std::endl;

    if (1 != EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey)) handleErrors();

    if (1 == EVP_DigestVerify(ctx, sig, sig_len, (const unsigned char*)data.c_str(), data.length())) {
        std::cout << "Signature Verified.\n";
    } else {
        std::cout << "Signature Verification Failed.\n";
    }

    // 清理
    OPENSSL_free(sig);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey); // This will also free `eckey`
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
