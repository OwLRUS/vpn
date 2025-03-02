#include "ICert.h"
#include <iostream>

using namespace std;

class CertGOST : public ICert 
{
public:
    string getAlgorithmName() override 
    {
        return "X.509 (GOST)";
    }

    string getCertificate() override
    {
        return "X.509 (GOST)";
    }

    bool verifyCertificate(const string& certPath) override 
    {
        cout << "[CertGOST] Verifying certificate: " << certPath << endl;
        return true;
    }
};

extern "C"  __declspec(dllexport) ICert * createCertModule()
{
    return new CertGOST();
}