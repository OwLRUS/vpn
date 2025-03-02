#include "ICrypto.h"
#include <iostream>

using namespace std;

class Kuznechik : public ICrypto 
{
public:
    string getAlgorithmName() override 
    {
        return "GOST 28147-89 (Kuznechik)";
    }

    vector<uint8_t> encrypt(const vector<uint8_t>& data, const vector<uint8_t>& key) override 
    {
        cout << "[Kuznechik] Encrypting data..." << endl;
        return data;
    }

    vector<uint8_t> decrypt(const vector<uint8_t>& data, const vector<uint8_t>& key) override 
    {
        cout << "[Kuznechik] Decrypting data..." << endl;
        return data;
    }
};

extern "C"  __declspec(dllexport) ICrypto * createCryptoModule()
{
    return new Kuznechik();
}