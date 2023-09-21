/*
 Compilar:
    g++ -std=c++17 main.cpp -o main
 
  Ejecucion:
    ./main
*/

#include "keygenerations.h"
#include "antumbra.h"

int main() {

    // Inicializamos las variables necesarias
    string key, text;
    antumbra incryption;
    int rounds = 5;

    cout << "Enter the key: ";
    getline(cin, key);  // Leemos toda la linea porque el programa hace cosas raras
    // con el cin cuando se leen strings con espacios

    // Leemos el archivo de texto con el texto a encriptar
    ifstream input("input.txt");
    string line;
    while(getline(input, line)){
        text += line + "\n";
    }
    input.close();


    // Generamos la llave Y pasamos el texto a un vector de bytes
    keygenerations keygen(key);
    vector<uint8_t> resultantkey = keygen.keygen();
    vector<uint8_t> plaintext = incryption.stringToVector(text);

    // Empezamos la encripcion
    vector<uint8_t> cyphertext = incryption.encrypt(resultantkey, plaintext, rounds);
    cout << "Cyphertext: " << endl;
    incryption.printVector(cyphertext);

    // Guardamos el texto encriptado en un archivo
    ofstream encryptedoutput("encryptedOutput.txt");
    encryptedoutput << incryption.vectorToString(cyphertext);


    // Solucion super ineficiente pero funciona para sacar la ultima subllave
    vector<uint8_t> decryptionkey = resultantkey;

    for(int i = 0; i < rounds - 1; i++){
        decryptionkey = incryption.subKeyGen(decryptionkey);
    }
    
    /* Debugging
    cout << "resultantkey: " << endl;
    incryption.printVector(resultantkey);
    cout << "decryptionkey: " << endl;
    incryption.printVector(decryptionkey);
    */

    // Desencriptamos el texto
    vector<uint8_t> decryptedtexthex = incryption.decrypt(decryptionkey, cyphertext, rounds);

    // Regresamos a ASCII el texto desencriptado y lo guardamos en un archivo
    string decryptedtext = incryption.vectorToAscii(decryptedtexthex);
    ofstream output("decriptedoutput.txt");  
    output << decryptedtext;
    output.close();
}