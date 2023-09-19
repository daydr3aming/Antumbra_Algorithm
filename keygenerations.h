#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <iomanip>
#include <cstdlib>

using namespace std;

class keygenerations {
public:
  keygenerations();
  keygenerations(string userkey);
  ~keygenerations();
  vector<uint8_t> keygen();

private:
  string plainkey;
  size_t key_len;
};

keygenerations::keygenerations() {
  plainkey = "";
  key_len = 0;
}

keygenerations::keygenerations(string userkey) {
  plainkey = userkey;
  key_len = plainkey.length();
}

keygenerations::~keygenerations() {}

std::vector<uint8_t> keygenerations::keygen() {
    if (key_len > 16) {
        throw std::invalid_argument("Original key is too long");
    }

    // Semilla de la generacion de la nueva llave basada en llave introducida por el usuario
    random_device rd;
    std::mt19937_64 gen(std::hash<std::string>{}(plainkey));

    // Generamos una llave de 16 bytes
    uint64_t keyParts[2];
    for (int i = 0; i < 2; ++i) {
        keyParts[i] = gen();
    }

    // Hacemos un XOR de la llave original con la llave generada
    std::vector<uint8_t> keyBytes(16);
    for (size_t i = 0; i < plainkey.length(); ++i) {
        keyBytes[i] = keyParts[i / 8] >> (8 * (i % 8));
        keyBytes[i] ^= plainkey[i];
    }

    return keyBytes;
}
