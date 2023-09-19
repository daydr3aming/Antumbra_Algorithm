#include "keygenerations.h"

// Operacion XOR, usa la llave y el bloque de texto para generar el texto cifrado.
vector<uint8_t> XOR(const vector<uint8_t>& block, const vector<uint8_t>& key) {
    vector<uint8_t> result;
    size_t length = min(block.size(), key.size());
    result.reserve(length);

    for (size_t i = 0; i < length; ++i) {
        result.push_back(block[i] ^ key[i]);
    }

    return result;
}

// Funcion de encriptacion principal de Antumbra
vector<uint8_t> encrypt(const vector<uint8_t>& key, const vector<uint8_t>& plaintext, int rounds) {
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

        // Paso 1: XOR (Primera operacion de confusion)
        // Hacemos un XOR del bloque con la llave 
        vector<uint8_t> xoredBlock = XOR(block, key);

        // Paso 2: Rotacion de bits (Primera operacion de difusion)
        const int rotation = 3;
        for (size_t i = 0; i < 16; ++i) {
            xoredBlock[i] = (xoredBlock[i] << rotation) | (xoredBlock[i] >> (8 - rotation));
        }

        // Paso 3: Generacion de la matriz sombra
        std::vector<uint8_t> keyBytes(key.begin(), key.end());
        std::hash<std::string> hasher;
        srand(static_cast<unsigned int>(hasher(std::string(keyBytes.begin(), keyBytes.end()))));

        vector<uint8_t> shadowMatrix(16, 0);
        for (int i = 0; i < 16; ++i) {
            int randomValue = (rand() % 3) + 1; // Generamos un numero aleatorio en el rango de 1 a 3
            shadowMatrix[i] = static_cast<uint8_t>(randomValue);
        }

        // Paso 4: Negacion de la matriz sombra (Segunda operacion de difusion)
        for (int i = 0; i < 16; ++i) {
            shadowMatrix[i] = ~shadowMatrix[i];
        }

        // Paso 5: XOR del bloque con la matriz sombra (Segunda operacion de confusion)
        xoredBlock = XOR(xoredBlock, shadowMatrix);

        // Reemplazamos el texto original con todos los bloques cifrados
        for (size_t i = 0; i < 16; ++i) {
            size_t index = blockNum * 16 + i;
            if (index < textLength) {
                encryptedText[index] = xoredBlock[i];
            }
        }
    }

    if (rounds > 1) {
        // Repetimos recursivamente el proceso de encriptacion segun el numero de rondas
        return encrypt(key, encryptedText, rounds - 1);
    }

    return encryptedText;
}

// Funcion de desencriptacion principal de Antumbra
vector<uint8_t> decrypt(const vector<uint8_t>& key, const vector<uint8_t>& ciphertext, int rounds) {
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

        // Ahora haremos las operaciones de encripcion en reversa para poder desencriptar
        // Empezamos con:

        // Paso 1: Generamos la matriz sombra 
        std::vector<uint8_t> keyBytes(key.begin(), key.end());
        std::hash<std::string> hasher;
        srand(static_cast<unsigned int>(hasher(std::string(keyBytes.begin(), keyBytes.end()))));

        vector<uint8_t> shadowMatrix(16, 0);
        for (int i = 0; i < 16; ++i) {
            int randomValue = (rand() % 3) + 1; // Rango de 1 a 3
            shadowMatrix[i] = static_cast<uint8_t>(randomValue);
        }

        // Hacemos la negacion y lo podemos dejar asi, no necesitamos revetir la negacion
        for (int i = 0; i < 16; ++i) {
            shadowMatrix[i] = ~shadowMatrix[i];
        }

        // Revertimos el XOR con un mismo XOR sobre la matriz sombra negada y el bloque encriptado
        vector<uint8_t> reversedBlock = XOR(block, shadowMatrix);

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
        // Repetimos el proceso de desencripcion las mismas veces que el de encripcion
        return decrypt(key, decryptedText, rounds - 1); 
    }

    return decryptedText;
}

// Funcion auxiliar para convertir un string a un vector de bytes
std::vector<uint8_t> stringToVector(const std::string& input) {
    std::vector<uint8_t> result;
    for (char c : input) {
        result.push_back(static_cast<uint8_t>(c));
    }
    return result;
}

// Funcion auxiliar para convertir un vector de bytes a un string
std::string vectorToString(const std::vector<uint8_t>& input) {
    std::stringstream ss;
    for (uint8_t byte : input) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return ss.str();
}

// Funcion auxiliar para imprimir un vector de bytes en hexadecimal
void printVector(const std::vector<uint8_t>& input) {
    for (uint8_t byte : input) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << std::endl;
}

// Funcion auxiliar para convertir un vector de bytes a un string con codigo ASCII
std::string vectorToAscii(const std::vector<uint8_t>& data) {
    std::string ascii;
    for (uint8_t byte : data) {
        ascii += static_cast<char>(byte);
    }
    return ascii;
}

int main() {

    string key, text;

    
    std::cout << "Enter the key: ";
    std::getline(std::cin, key);  // Leemos toda la linea porque el programa hace cosas raras
    // con el cin cuando se leen strings con espacios

    /*
    std::cout << "Enter the text: ";
    std::getline(std::cin, text);  // Aqui lo mismo
    int rounds = 5;
    */

    std::ifstream input("input.txt");
    std::string line;
    while(std::getline(input, line)){
        text += line + "\n";
    }
    int rounds = 5;
    input.close();

    keygenerations keygen(key);

    vector<uint8_t> resultantkey = keygen.keygen();
    vector<uint8_t> plaintext = stringToVector(text);

    vector<uint8_t> cyphertext = encrypt(resultantkey, plaintext, rounds);
    cout << "Cyphertext: " << endl;
    printVector(cyphertext);

    ofstream encryptedoutput("encryptedoutput.txt");
    encryptedoutput << vectorToString(cyphertext);


    vector<uint8_t> decryptedtexthex = decrypt(resultantkey, cyphertext, rounds);
    string decryptedtext = vectorToAscii(decryptedtexthex);
    cout << decryptedtext << endl;

    ofstream output("output.txt");
    output << decryptedtext;
    output.close();
}