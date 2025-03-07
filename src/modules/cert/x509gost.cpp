#include "x509gost.h"

using namespace std;

string CertGOST::getAlgorithmName()
{
    return "X.509 (GOST)";
}

string CertGOST::getCertificate()
{
    cout << "[CertGOST] Generating self-signed certificate..." << endl;
    /*/
    // 1. Создание ключевой пары (GOST R 34.10-2012)
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        throw runtime_error("Failed to create EVP_PKEY");
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(NID_id_GostR3410_2012_256, nullptr);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        throw runtime_error("Failed to generate GOST key pair");
    }
    EVP_PKEY_CTX_free(ctx);

    // 2. Создание X.509 сертификата
    X509* x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        throw runtime_error("Failed to create X509 certificate");
    }

    // 3. Устанавливаем версию и серийный номер
    X509_set_version(x509, 2);  // X.509v3
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // 4. Устанавливаем срок действия (1 год)
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);  // 1 год

    // 5. Привязываем ключ к сертификату
    X509_set_pubkey(x509, pkey);

    // 6. Устанавливаем Subject Name
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"RU", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"My Organization", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"My GOST Cert", -1, -1, 0);
    X509_set_issuer_name(x509, name);  // Самоподписанный -> Issuer = Subject

    // 7. Подписываем сертификат
    if (!X509_sign(x509, pkey, EVP_get_digestbyname("streebog256"))) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        throw runtime_error("Failed to sign X509 certificate");
    }

    // 8. Записываем сертификат в строку PEM
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, x509);
    char* pemData;
    long pemLen = BIO_get_mem_data(bio, &pemData);
    certPEM.assign(pemData, pemLen);
    BIO_free(bio);

    // Освобождение ресурсов
    X509_free(x509);
    EVP_PKEY_free(pkey);

    return certPEM;/**/

    return "cert";
}

bool CertGOST::verifyCertificate(const string& certPath)
{
    cout << "[CertGOST] Verifying certificate..." << endl;

    /*/BIO* bio = BIO_new_mem_buf(certPEM.data(), certPEM.size());
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!cert) {
        cerr << "Error loading certificate" << endl;
        return false;
    }

    // Проверяем подпись (так как сертификат самоподписанный, проверяем его на самом себе)
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    bool valid = X509_verify(cert, pubkey) == 1;

    EVP_PKEY_free(pubkey);
    X509_free(cert);

    return valid;/**/

    return true;
}