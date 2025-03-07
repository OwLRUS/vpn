#include "ICert.h"
#include <iostream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

using namespace std;

class CertGOST : public ICert
{
private:
    string certPEM; // how to contain?

public:
    string getAlgorithmName() override;
    string getCertificate() override;
    bool verifyCertificate(const string& certPath) override;
};

extern "C" __declspec(dllexport) ICert * createCertModule()
{
    return new CertGOST();
}
