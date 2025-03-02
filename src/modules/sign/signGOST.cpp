#include "ISign.h"
#include <iostream>

using namespace std;

class SignGOST : public ISign 
{
public:
    string getAlgorithmName() override 
    {
        return "GOST R 34.10-2012 (Sign)";
    }

    vector<uint8_t> sign(const vector<uint8_t>& data, const vector<uint8_t>& privateKey) override 
    {
        cout << "[SignGOST] Sign data..." << endl;
        return data;
    }

    bool verify(const vector<uint8_t>& data, const vector<uint8_t>& signature, const vector<uint8_t>& publicKey) override 
    {
        cout << "[SignGOST] Verify sign..." << endl;
        return true;
    }
};

extern "C"  __declspec(dllexport) ISign * createSignModule()
{
    return new SignGOST();
}