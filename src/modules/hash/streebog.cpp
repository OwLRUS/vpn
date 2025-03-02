#include "IHash.h"
#include <iostream>

using namespace std;

class Streebog : public IHash 
{
public:
    std::string getAlgorithmName() override 
    {
        return "GOST R 34.11-2012 (Streebog)";
    }

    vector<uint8_t> hash(const vector<uint8_t>& data) override 
    {
        cout << "[Streebog] Generating hash..." << endl;
        return data;
    }
};

extern "C"  __declspec(dllexport) IHash * createHashModule()
{
    return new Streebog();
}