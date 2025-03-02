#ifndef ICrypto_H
#define ICrypto_H

#include <vector>
#include <string>

using namespace std;

class ICrypto
{
public:
	virtual ~ICrypto() = default;

    virtual string getAlgorithmName() = 0;

    virtual vector<uint8_t> encrypt(const vector<uint8_t>& data, const vector<uint8_t>& key) = 0;

    virtual vector<uint8_t> decrypt(const vector<uint8_t>& data, const vector<uint8_t>& key) = 0;
};

extern "C"  __declspec(dllexport) ICrypto* createCryptoModule();

#endif