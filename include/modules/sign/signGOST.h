#include "ISign.h"
#include "streebog.h"
#include <iostream>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

class SignGOST : public ISign
{
private:
    Streebog hasher;
    EVP_MD_CTX* ctx;
public:
    SignGOST();
    ~SignGOST();

    string getAlgorithmName() override;
    vector<uint8_t> sign(const vector<uint8_t>& data, const vector<uint8_t>& privateKey) override;
    bool verify(const vector<uint8_t>& data, const vector<uint8_t>& signature, const vector<uint8_t>& publicKey) override;
};

extern "C" __declspec(dllexport) ISign * createSignModule()
{
    return new SignGOST();
}
