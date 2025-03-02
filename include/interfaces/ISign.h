#ifndef ISIGN_H
#define ISIGN_H

#include <vector>
#include <string>

using namespace std;

class ISign
{
public:
    virtual ~ISign() = default;

    virtual string getAlgorithmName() = 0;

    virtual vector<uint8_t> sign(const vector<uint8_t>& data, const vector<uint8_t>& privateKey) = 0;

    virtual bool verify(const vector<uint8_t>& data, const vector<uint8_t>& signature, const vector<uint8_t>& publicKey) = 0;
};

extern "C"  __declspec(dllexport) ISign * createSignModule();

#endif