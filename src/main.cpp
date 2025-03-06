#include <iostream>
#include <memory>
#include <windows.h>

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

#include "ICrypto.h"
#include "IHash.h"
#include "ISign.h"
#include "ICert.h"

using namespace std;

template<typename T>
unique_ptr<T> loadModule(const string& libName, const string& createFunc) {
    HMODULE handle = LoadLibraryA(libName.c_str());
    if (!handle) {
        cerr << "Load Error! " << libName << ": " << GetLastError() << endl;
        return nullptr;
    }

    using CreateFunc = T* (*)();
    CreateFunc create = reinterpret_cast<CreateFunc>(GetProcAddress(handle, createFunc.c_str()));
    if (!create) {
        cerr << "Function load Error! " << createFunc << " from " << libName << endl;
        FreeLibrary(handle);
        return nullptr;
    }

    return unique_ptr<T>(create()); 
}

vector<uint8_t> stringToBytes(const string& str) 
{
    return vector<uint8_t>(str.begin(), str.end());
}

string bytesToString(const vector<uint8_t>& bytes) 
{
    return string(bytes.begin(), bytes.end());
}

vector<uint8_t> generate_random_bytes(size_t length)
{
    vector<uint8_t> buffer(length);
    if (RAND_bytes(buffer.data(), buffer.size()) != 1) 
    {
        cerr << "ERROR: failed to gen random data!\n";
        exit(1);
    }
    return buffer;
}

int main() {
    cout << "Loading cryptomodules...\n";

    auto crypto = loadModule<ICrypto>("crypto.dll", "createCryptoModule");
    auto hash = loadModule<IHash>("hash.dll", "createHashModule");
    auto sign = loadModule<ISign>("sign.dll", "createSignModule");
    auto cert = loadModule<ICert>("cert.dll", "createCertModule");

    if (!crypto || !hash || !sign || !cert) {
        cerr << "Modules load Error!\n";
        return 1;
    }

    cout << "\n--- Testing Kuznyechik ---\n";

    vector<uint8_t> data = stringToBytes("Hello, World! This is a test message.");
    vector<uint8_t> key = generate_random_bytes(32);

    cout << "Original data: " << bytesToString(data) << endl;

    try {
        vector<uint8_t> encrypted = crypto->encrypt(data, key);
        cout << "Encrypted data: " << bytesToString(encrypted) << endl;

        vector<uint8_t> decrypted = crypto->decrypt(encrypted, key);
        cout << "Decrypted data: " << bytesToString(decrypted) << endl;

        if (decrypted == data) {
            cout << "Decryption successful!" << endl;
        }
        else {
            cout << "Decryption failed!" << endl;
        }
    }
    catch (const exception& e) {
        cerr << "Exception caught: " << e.what() << endl;
    }


    vector<uint8_t> hashValue = hash->hash(data);
    cout << "Hash: " << bytesToString(hashValue) << endl;

    vector<uint8_t> signature = sign->sign(data, key);
    cout << "Sign: " << bytesToString(signature) << endl;
    cout << "Verifying sign: " << (sign->verify(data, signature, key) ? "Verify" : "Non verify") << endl;

    cout << "Certificate: " << cert->getCertificate() << endl;
    cout << "Verifying certificate: " << (cert->verifyCertificate("dir") ? "Verify" : "Non verify") << endl;

    return 0;
}