#ifndef IHASH_H
#define IHASH_H

#include <vector>
#include <string>

using namespace std;

class IHash 
{
public:
    virtual ~IHash() = default;

    virtual string getAlgorithmName() = 0;

    virtual vector<uint8_t> hash(const vector<uint8_t>& data) = 0;
};

extern "C"  __declspec(dllexport) IHash * createHashModule();

#endif