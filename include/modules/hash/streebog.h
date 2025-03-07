#include "IHash.h"
#include <iostream>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>

using namespace std;

class Streebog : public IHash
{
private:
    const EVP_MD* md;
    EVP_MD_CTX* ctx;
public:
    Streebog();
    ~Streebog();

    string getAlgorithmName() override;
    vector<uint8_t> hash(const vector<uint8_t>& data) override;
};

extern "C" __declspec(dllexport) IHash * createHashModule()
{
    return new Streebog();
}
