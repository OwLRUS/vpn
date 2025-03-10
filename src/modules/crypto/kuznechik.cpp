#include "kuznechik.h"

using namespace std;

#define BLOCK_SIZE 16
#define IV_SIZE 16

Kuznechik::Kuznechik()
{
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");

    cipher = EVP_get_cipherbyname("kuznyechik-ctr-acpkm");
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx);
        throw runtime_error("Cipher 'kuznyechik-ctr-acpkm' not found. Check OpenSSL GOST Engine.");
    }
}

Kuznechik::~Kuznechik()
{
    EVP_CIPHER_CTX_free(ctx);
}

string Kuznechik::getAlgorithmName()
{
    return "GOST 28147-89 (Kuznechik)";
}

vector<uint8_t> Kuznechik::encrypt(const vector<uint8_t>& data, const vector<uint8_t>& key)
{
    cout << "[Kuznechik] Encrypting data..." << endl;

    if (key.size() != 32) 
    {
        throw runtime_error("Invalid key size. Kuznyechik requires a 256-bit (32-byte) key.");
    }

    vector<uint8_t> iv(IV_SIZE);
    if (RAND_bytes(iv.data(), IV_SIZE) != 1) 
    {
        throw runtime_error("Failed to generate IV");
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data())) 
    {
        throw runtime_error("EVP_EncryptInit_ex failed");
    }

    vector<uint8_t> output(data.size() + BLOCK_SIZE);
    int len = 0, final_len = 0;

    if (!EVP_EncryptUpdate(ctx, output.data(), &len, data.data(), data.size())) 
    {
        throw runtime_error("EVP_EncryptUpdate failed");
    }

    if (!EVP_EncryptFinal_ex(ctx, output.data() + len, &final_len)) 
    {
        throw runtime_error("EVP_EncryptFinal_ex failed");
    }

    output.resize(len + final_len);

    output.insert(output.begin(), iv.begin(), iv.end());

    return output;
}

vector<uint8_t> Kuznechik::decrypt(const vector<uint8_t>& data, const vector<uint8_t>& key)
{
    cout << "[Kuznechik] Decrypting data..." << endl;

    if (key.size() != 32) 
    {
        throw runtime_error("Invalid key size. Kuznyechik requires a 256-bit (32-byte) key.");
    }

    if (data.size() < IV_SIZE) 
    {
        throw runtime_error("Invalid encrypted data. Too short to contain IV.");
    }

    vector<uint8_t> iv(data.begin(), data.begin() + IV_SIZE);
    vector<uint8_t> encryptedData(data.begin() + IV_SIZE, data.end());

    if (!EVP_DecryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data())) 
    {
        throw runtime_error("EVP_DecryptInit_ex failed");
    }

    vector<uint8_t> output(encryptedData.size() + BLOCK_SIZE);
    int len = 0, final_len = 0;

    if (!EVP_DecryptUpdate(ctx, output.data(), &len, encryptedData.data(), encryptedData.size())) 
    {
        throw runtime_error("EVP_DecryptUpdate failed");
    }

    if (!EVP_DecryptFinal_ex(ctx, output.data() + len, &final_len)) 
    {
        throw runtime_error("EVP_DecryptFinal_ex failed");
    }

    output.resize(len + final_len);

    return output;
}