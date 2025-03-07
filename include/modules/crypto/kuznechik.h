#include "ICrypto.h"
#include <iostream>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

using namespace std;

class Kuznechik : public ICrypto 
{
private:
    EVP_CIPHER_CTX* ctx;
    const EVP_CIPHER* cipher;
public:
    Kuznechik();
    ~Kuznechik();

    string getAlgorithmName() override;
    vector<uint8_t> encrypt(const vector<uint8_t>& data, const vector<uint8_t>& key) override;
    vector<uint8_t> decrypt(const vector<uint8_t>& data, const vector<uint8_t>& key) override;
};

extern "C"  __declspec(dllexport) ICrypto * createCryptoModule()
{
    return new Kuznechik();
}