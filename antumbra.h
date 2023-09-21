#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <iomanip>
#include <cstdlib>
#include <sstream>

using namespace std;

class antumbra{
public:
    vector<uint8_t> stringToVector(const string& input);
    string vectorToAscii(const vector<uint8_t>& data);
    string vectorToString(const std::vector<uint8_t>& input);
    void printVector(const vector<uint8_t>& input);
    std::vector<uint8_t> subKeyGen(const std::vector<uint8_t>& key);

    vector<uint8_t> encrypt(const vector<uint8_t>& key, const vector<uint8_t>& plaintext, int rounds);
    vector<uint8_t> decrypt(const vector<uint8_t>& key, const vector<uint8_t>& ciphertext, int rounds);

private:
    vector<uint8_t> XOR(const vector<uint8_t>& block, const vector<uint8_t>& key);
    uint8_t bitwisePermute(uint8_t inputByte, const std::vector<int>& permutationPattern);
    uint8_t reverseBitwisePermute(uint8_t permutedByte, const std::vector<int>& inversePermutationPattern);
    std::vector<uint8_t> reverseSubKey(const std::vector<uint8_t>& subkey);

};

// Funcion auxiliar para convertir un string a un vector de bytes
vector<uint8_t> antumbra::stringToVector(const string& input) {
    vector<uint8_t> result;
    for (char c : input) {
        result.push_back(static_cast<uint8_t>(c));
    }
    return result;
}

// Funcion auxiliar para convertir un vector de bytes a un string
string antumbra::vectorToString(const std::vector<uint8_t>& input) {
    stringstream ss;
    for (uint8_t byte : input) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

// Funcion auxiliar para imprimir un vector de bytes en hexadecimal
void antumbra::printVector(const vector<uint8_t>& input) {
    for (uint8_t byte : input) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    cout << dec << endl;
}

// Funcion auxiliar para convertir un vector de bytes a un string con codigo ASCII
string antumbra::vectorToAscii(const vector<uint8_t>& data) {
    string ascii;
    for (uint8_t byte : data) {
        ascii += static_cast<char>(byte);
    }
    return ascii;
}

// Operacion XOR, usa la llave y el bloque de texto para generar el texto cifrado.
// Un XOR mas complicado con arimetica modular y trabaja sobre un bloque entero
vector<uint8_t> antumbra::XOR(const vector<uint8_t>& block, const vector<uint8_t>& key) {
    vector<uint8_t> result;
    size_t length = min(block.size(), key.size());
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result.push_back((block[i] ^ key[i]) % 0x10000) ;
    }

    return result;
}

// Funcion auxiliar para permutar un byte
uint8_t antumbra::bitwisePermute(uint8_t inputByte, const std::vector<int>& permutationPattern) {
    uint8_t result = 0;
    for (int i = 0; i < permutationPattern.size(); ++i) {
        int sourceBitPosition = permutationPattern[i];
        uint8_t sourceBit = (inputByte >> sourceBitPosition) & 0x01;
        result |= (sourceBit << i);
    }
    return result;
}

// Funcion auxiliar para permutar un byte al reves
uint8_t antumbra::reverseBitwisePermute(uint8_t permutedByte, const std::vector<int>& inversePermutationPattern) {
    uint8_t result = 0;
    for (int i = 0; i < inversePermutationPattern.size(); ++i) {
        int destinationBitPosition = inversePermutationPattern[i];
        uint8_t sourceBit = (permutedByte >> i) & 0x01;
        result |= (sourceBit << destinationBitPosition);
    }
    return result;
}

// Generamos una subllave a partir de la llave original
std::vector<uint8_t> antumbra::subKeyGen(const std::vector<uint8_t>& key) {
    std::vector<uint8_t> subkey(key.size(), 0);
    const int rotation = 3;
    for (size_t i = 0; i < key.size(); ++i) {
        subkey[i] = (key[i] << rotation) | (key[i] >> (8 - rotation));
    }
    return subkey;
}

// Revertimos la subllave para obtener la llave original
std::vector<uint8_t> antumbra::reverseSubKey(const std::vector<uint8_t>& subkey) {
    std::vector<uint8_t> originalKey(subkey.size(), 0);
    const int rotation = 3;
    for (size_t i = 0; i < subkey.size(); ++i) {

        originalKey[i] = (subkey[i] >> rotation) | (subkey[i] << (8 - rotation));
    }
    return originalKey;
}

// Funcion de encriptacion principal de Antumbra
vector<uint8_t> antumbra::encrypt(const vector<uint8_t>& key, const vector<uint8_t>& plaintext, int rounds) {
    vector<uint8_t> encryptedText(plaintext.size(), 0); // Inicializamos el vector de resultado
    size_t textLength = plaintext.size();
    size_t keyLength = key.size();
    size_t blockCount = (textLength + 15) / 16; // Se calcula el numero de bloques de 16 bytes necesarios

    for (size_t blockNum = 0; blockNum < blockCount; ++blockNum) {
        // Creamos el bloque
        vector<uint8_t> block(16, 0);
        for (size_t i = 0; i < 16; ++i) {
            size_t index = blockNum * 16 + i;
            if (index < textLength) {
                block[i] = plaintext[index];
            }
        }

        // Paso 1: XOR modular con la llave 
        vector<uint8_t> xoredBlock = XOR(block, key);

        // Paso 2: Shift circular o rotacion (Primera operacion de difusion)
        const int rotation = 3;
        for (size_t i = 0; i < 16; ++i) {
            xoredBlock[i] = (xoredBlock[i] << rotation) | (xoredBlock[i] >> (8 - rotation));
        }

        // Paso 3: Generamos la matriz sombra
        std::vector<uint8_t> keyBytes(key.begin(), key.end());
        std::hash<std::string> hasher;
        srand(static_cast<unsigned int>(hasher(std::string(keyBytes.begin(), keyBytes.end()))));

        std::vector<int> shadowMatrix(8, 0);

        // Paso 4: Permutacion de bits (Segunda operacion de difusion)

        // Iniciamos la matriz sombra con numeros del 0 al 7
        for (int i = 0; i < 8; ++i) {
            shadowMatrix[i] = static_cast<int>(i);
        }
        // Se hace un shuffle de Fisher-Yates para permutar la matriz sombra
        for (int i = 7; i > 0; --i) {
            int j = rand() % (i + 1);
            std::swap(shadowMatrix[i], shadowMatrix[j]);
        }
        // Permutamos el bloque con la matriz sombra, cambiando de posicion
        for (size_t i = 0; i < 16; ++i) {
            xoredBlock[i] = bitwisePermute(xoredBlock[i], shadowMatrix);
        }

        // Paso 5: Hacemos XOR al bloque permutado (Segunda operacion de confusion)

        xoredBlock = XOR(xoredBlock, key);

        // Reemplazamos el texto original con todos los bloques cifrados
        for (size_t i = 0; i < 16; ++i) {
            size_t index = blockNum * 16 + i;
            if (index < textLength) {
                encryptedText[index] = xoredBlock[i];
            }
        }
    }

    if (rounds > 1) {
        // Creamos una nueva subllave y repetimos el proceso de encripcion
        return encrypt(subKeyGen(key), encryptedText, rounds - 1);
    }
    return encryptedText;
}

// Funcion de desencriptacion principal de Antumbra
vector<uint8_t> antumbra::decrypt(const vector<uint8_t>& key, const vector<uint8_t>& ciphertext, int rounds) {
    vector<uint8_t> decryptedText(ciphertext.size(), 0); // Inicializamos el vector de resultado

    size_t textLength = ciphertext.size();
    size_t keyLength = key.size();
    size_t blockCount = (textLength + 15) / 16; // Calculamos el numero de bloques de 16 bytes necesarios

    for (size_t blockNum = 0; blockNum < blockCount; ++blockNum) {
        // Creamos el bloque
        vector<uint8_t> block(16, 0);
        for (size_t i = 0; i < 16; ++i) {
            size_t index = blockNum * 16 + i;
            if (index < textLength) {
                block[i] = ciphertext[index];
            }
        }


        // Revertimos el XOR con un mismo XOR sobre la matriz sombra negada y el bloque encriptado
        vector<uint8_t> reversedBlock = XOR(block, key);


        // Generamos la matriz sombra
        std::vector<uint8_t> keyBytes(key.begin(), key.end());
        std::hash<std::string> hasher;
        srand(static_cast<unsigned int>(hasher(std::string(keyBytes.begin(), keyBytes.end()))));

        std::vector<int> shadowMatrix(8, 0);

        // Permutamos pero al revez ahora
        for (int i = 0; i < 8; ++i) {
            shadowMatrix[i] = static_cast<int>(i);
        }

        // Fisher-Yates 
        for (int i = 7; i > 0; --i) {
            int j = rand() % (i + 1);
            std::swap(shadowMatrix[i], shadowMatrix[j]);
        }

        // Creamos el patron de permutacion inverso
        std::vector<int> inversePermutationPattern(8);
        for (int i = 0; i < 8; ++i) {
            inversePermutationPattern[shadowMatrix[i]] = i;
        }

        // Regresar el bloque a su posicion original
        for (size_t i = 0; i < 16; ++i) {
            reversedBlock[i] = reverseBitwisePermute(reversedBlock[i], shadowMatrix);
        }

        // Invertimos la rotacion de bits al lado contrario por el mismo numero de rotaciones
        const int rotation = 3;
        for (size_t i = 0; i < 16; ++i) {
            reversedBlock[i] = (reversedBlock[i] >> rotation) | (reversedBlock[i] << (8 - rotation));
        }

        // Revertimos el XOR con la llave y el bloque invertido
        reversedBlock = XOR(reversedBlock, key);

        // Reemplazamos el texto original con todos los bloques desencriptados
        for (size_t i = 0; i < 16; ++i) {
            size_t index = blockNum * 16 + i;
            if (index < textLength) {
                decryptedText[index] = reversedBlock[i];
            }
        }
    }

    if (rounds > 1) {
        // Repetimos el proceso de desencripcion con la subllave revertida
        return decrypt(reverseSubKey(key), decryptedText, rounds - 1); 
    }

    return decryptedText;
}