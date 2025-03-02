#include <iostream>
#include <memory>
#include <windows.h>

#include "ICrypto.h"
#include "IHash.h"
#include "ISign.h"
#include "ICert.h"

using namespace std;

template<typename T>
unique_ptr<T> loadModule(const string& libName, const string& createFunc) {
    HMODULE handle = LoadLibraryA(libName.c_str());  // Загрузка библиотеки
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

    return unique_ptr<T>(create());  // Создаём объект и возвращаем умный указатель
}

vector<uint8_t> stringToBytes(const string& str) 
{
    return vector<uint8_t>(str.begin(), str.end());
}

string bytesToString(const vector<uint8_t>& bytes) 
{
    return string(bytes.begin(), bytes.end());
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

    cout << "\n--- Testing cryptomodules ---\n";

    string dataStr = "Hello world!";
    string keyStr = "secret";

    vector<uint8_t> data = stringToBytes(dataStr);
    vector<uint8_t> key = stringToBytes(keyStr);

    vector<uint8_t> encrypted = crypto->encrypt(data, key);
    cout << "Encrypting data: " << bytesToString(encrypted) << endl;
    cout << "Decrypting data: " << bytesToString(crypto->decrypt(encrypted, key)) << endl;

    vector<uint8_t> hashValue = hash->hash(data);
    cout << "Hash: " << bytesToString(hashValue) << endl;

    vector<uint8_t> signature = sign->sign(data, key);
    cout << "Sign: " << bytesToString(signature) << endl;
    cout << "Verifying sign: " << (sign->verify(data, signature, key) ? "Verify" : "Non verify") << endl;

    cout << "Certificate: " << cert->getCertificate() << endl;
    cout << "Verifying certificate: " << (cert->verifyCertificate("dir") ? "Verify" : "Non verify") << endl;

    return 0;
}