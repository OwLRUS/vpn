#ifndef ICERT_H
#define ICERT_H

#include <string>

using namespace std;

class ICert {
public:
    virtual ~ICert() = default;

    virtual string getAlgorithmName() = 0;
    
    virtual string getCertificate() = 0;

    virtual bool verifyCertificate(const string& certPath) = 0;
};

extern "C"  __declspec(dllexport) ICert * createCertModule();

#endif