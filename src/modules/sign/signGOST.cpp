#include "signGOST.h"

using namespace std;

SignGOST::SignGOST()
{
    ctx = EVP_MD_CTX_new();
    if (!ctx) 
    {
        throw runtime_error("EVP_MD_CTX_new failed");
    }
}

SignGOST::~SignGOST()
{
    EVP_MD_CTX_free(ctx);
}

string SignGOST::getAlgorithmName()
{
    return "GOST R 34.10-2012 (Sign)";
}

vector<uint8_t> SignGOST::sign(const vector<uint8_t>& data, const vector<uint8_t>& privateKey)
{
    cout << "[SignGOST] Hashing data before signing..." << endl;
    vector<uint8_t> hash = hasher.hash(data);

    cout << "[SignGOST] Signing hash..." << endl;

    EVP_PKEY* pkey = d2i_PrivateKey(GOST_F_PKEY_GOST2012_PARAMGEN, nullptr, (const unsigned char**)&privateKey, privateKey.size());
    if (!pkey) throw runtime_error("Failed to load private key.");


    if (!EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey)) 
    { 
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestSignInit failed");
    }

    if (!EVP_DigestSignUpdate(ctx, hash.data(), hash.size())) 
    {
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestSignUpdate failed");
    }

    size_t sigLen = 0;
    if (!EVP_DigestSignFinal(ctx, nullptr, &sigLen))
    {
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestSignFinal failed (size determination)");
    }

    vector<uint8_t> signature(sigLen);
    if (!EVP_DigestSignFinal(ctx, signature.data(), &sigLen)) 
    {
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestSignFinal failed");
    }

    EVP_PKEY_free(pkey);
    return signature;
}

bool SignGOST::verify(const vector<uint8_t>& data, const vector<uint8_t>& signature, const vector<uint8_t>& publicKey)
{
    cout << "[SignGOST] Hashing data before verifying signature..." << endl;
    vector<uint8_t> hash = hasher.hash(data); 

    cout << "[SignGOST] Verifying signature..." << endl;

    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, (const unsigned char**)&publicKey, publicKey.size());
    if (!pkey) throw runtime_error("Failed to load public key.");

    if (!EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey)) 
    { 
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestVerifyInit failed");
    }

    if (!EVP_DigestVerifyUpdate(ctx, hash.data(), hash.size())) 
    {
        EVP_PKEY_free(pkey);
        throw runtime_error("EVP_DigestVerifyUpdate failed");
    }

    bool isValid = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());

    EVP_PKEY_free(pkey);
    return isValid;
}

/* -------------- Keygen. -----------------
EVP_PKEY* pkey;
T(pkey = EVP_PKEY_new());
TE(EVP_PKEY_set_type(pkey, type));
EVP_PKEY_CTX* ctx;
T(ctx = EVP_PKEY_CTX_new(pkey, NULL));
T(EVP_PKEY_keygen_init(ctx));
T(EVP_PKEY_CTX_ctrl(ctx, type, -1, EVP_PKEY_CTRL_GOST_PARAMSET, t->nid, NULL));
EVP_PKEY* priv_key = NULL;
err = EVP_PKEY_keygen(ctx, &priv_key);
printf("\tEVP_PKEY_keygen:\t");
print_test_result(err);
EVP_PKEY_CTX_free(ctx);
EVP_PKEY_free(pkey);
if (err != 1)
return -1;
*/