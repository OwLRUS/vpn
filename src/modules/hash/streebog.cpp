#include "streebog.h"

using namespace std;

string Streebog::getAlgorithmName()
{
    return "GOST R 34.11-2012 (Streebog)";
}

Streebog::Streebog()
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw runtime_error("EVP_MD_CTX_new failed");

    md = EVP_get_digestbyname("streebog256");
    if (!md)
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Hash algorithm 'streebog256' not found. Check OpenSSL GOST Engine.");
    }
}

Streebog::~Streebog()
{
    EVP_MD_CTX_free(ctx);
}

vector<uint8_t> Streebog::hash(const vector<uint8_t>& data)
{
    cout << "[Streebog] Generating hash..." << endl;

    if (!EVP_DigestInit_ex(ctx, md, nullptr))
    {
        throw runtime_error("EVP_DigestInit_ex failed");
    }

    if (!EVP_DigestUpdate(ctx, data.data(), data.size()))
    {
        throw runtime_error("EVP_DigestUpdate failed");
    }

    vector<uint8_t> hash(EVP_MD_size(md));
    unsigned int hashLen = 0;

    if (!EVP_DigestFinal_ex(ctx, hash.data(), &hashLen))
    {
        throw runtime_error("EVP_DigestFinal_ex failed");
    }

    hash.resize(hashLen);
    return hash;
}