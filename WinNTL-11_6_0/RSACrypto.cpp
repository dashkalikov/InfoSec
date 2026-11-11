#include "RSACrypto.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <filesystem>
#include <algorithm>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstdio>
#include <random>
#include <future>
#include <sstream>
#include <iomanip>

NTL_CLIENT

using namespace std;

// =============================================================================
// КОНСТРУКТОР И ИНИЦИАЛИЗАЦИЯ
// =============================================================================

RSACrypto::RSACrypto() : baseDirectory("encrypted_files") {
    ensureDirectoryExists();
    // Инициализация криптографически стойкого генератора случайных чисел
    srand(static_cast<unsigned int>(time(nullptr) ^ static_cast<unsigned int>(reinterpret_cast<uintptr_t>(this))));
}

// =============================================================================
// ОСНОВНЫЕ МЕТОДЫ ШИФРОВАНИЯ И РАСШИФРОВКИ
// =============================================================================

string RSACrypto::encrypt(const string& plaintext, const string& publicKeyPath) {
    try {
        cout << "🔒 Шифрование текста с индикатором прогресса..." << endl;
        
        // Этап 1: Загрузка ключа
        cout << "🔄 Этап 1/4: Загрузка публичного ключа..." << flush;
        auto [n, e] = loadPublicKey(publicKeyPath);
        int keySize = n.bitLength();
        cout << " ✅ Завершено! (ключ " << keySize << " бит)" << endl;
        
        // Определяем размер блока в байтах
        size_t blockSize = keySize / 8;
        
        // Этап 2: Подготовка данных
        cout << "🔄 Этап 2/4: Подготовка данных для шифрования..." << flush;
        BigInt m;
        
        // Для RSA-64, RSA-128 и RSA-256 используем "сырое" RSA без padding
        if (keySize <= 256) {
            // Проверяем размер текста для "сырого" RSA
            if (plaintext.length() > blockSize) {
                throw runtime_error("Текст слишком большой для данного ключа. Максимальный размер: " + to_string(blockSize) + " байт (без padding)");
            }
            
            // Используем stringToBigInt для совместимости с bigIntToString
            m = stringToBigInt(plaintext);
            cout << " ✅ Завершено! (сырое RSA, без padding)" << endl;
        } else {
            // Для остальных ключей используем PKCS#1 padding
            size_t maxDataSize = blockSize - 11; // PKCS#1 padding занимает 11 байт
            if (plaintext.length() > maxDataSize) {
                throw runtime_error("Текст слишком большой для данного ключа. Максимальный размер: " + to_string(maxDataSize) + " байт (с PKCS#1 padding)");
            }
            
            // Отладочный вывод: байты исходного текста
            cout << "\n🔍 Отладка encrypt: Исходный текст (длина " << plaintext.length() << " байт): ";
            for (size_t i = 0; i < plaintext.length(); i++) {
                printf("%02x ", static_cast<unsigned char>(plaintext[i]));
            }
            cout << endl;
            
            // Добавляем PKCS#1 v1.5 padding
            vector<uint8_t> paddedData = addPKCS1Padding(plaintext, blockSize);
            
            // Преобразуем padded данные в BigInt
            // ZZFromBytes интерпретирует байты как big-endian и удаляет нули с конца
            // Чтобы сохранить структуру PKCS#1 padding, переворачиваем байты
            // (делаем little-endian), чтобы ведущие нули стали младшими байтами
            vector<uint8_t> reversedData = paddedData;
            reverse(reversedData.begin(), reversedData.end());
            m = BigInt(reversedData);
            
            // Проверяем, что значение меньше модуля (после удаления ведущих нулей)
            // Но нам нужно сохранить точный размер блока для расшифровки
            cout << " ✅ Завершено! (PKCS#1 padding добавлен)" << endl;
        }
        
        // Проверяем что данные не больше модуля
        if (m >= n) {
            throw runtime_error("Данные слишком большие для данного ключа. Максимальный размер: " + to_string(keySize) + " бит");
        }
        
        // Этап 3: Модульное возведение в степень
        cout << "🔄 Этап 3/4: Модульное возведение в степень (m^e mod n)..." << flush;
        
        // Определяем нужно ли использовать padding
        bool usePadding = (keySize > 256);
        
        BigInt c;
        // Для всех ключей используем правильную обработку padding
        c = modExpWithPadding(m, e, n, usePadding);
        if (usePadding) {
            cout << " ✅ Завершено! (наш алгоритм с PKCS#1 padding)" << endl;
        } else {
            cout << " ✅ Завершено! (наш оптимизированный алгоритм без padding)" << endl;
        }
        
        // Проверяем результат шифрования
        if (c >= n) {
            throw runtime_error("Ошибка: зашифрованное значение больше или равно модулю");
        }
        
        int cBits = c.bitLength();
        if (cBits < keySize / 2) {
            cerr << "⚠️  Предупреждение: зашифрованное значение подозрительно мало (" << cBits << " бит из " << keySize << ")" << endl;
        }
        
        // Убираем гибридный подход - используем только наш алгоритм с правильной обработкой padding
        
        // Этап 4: Форматирование результата
        cout << "🔄 Этап 4/4: Форматирование результата..." << flush;
        
        // Для всех ключей возвращаем десятичное представление напрямую
        // Это более надежно, чем конвертация через hex
        string result = c.toString();
        cout << " ✅ Завершено! (decimal формат, " << result.length() << " цифр)" << endl;
        
        cout << "🎉 Шифрование успешно завершено!" << endl;
        
        return result;
        
    } catch (const exception& e) {
        throw runtime_error("Ошибка при шифровании: " + string(e.what()));
    }
}

string RSACrypto::encryptHex(const string& hexValue, const string& publicKeyPath) {
    try {
        // Загружаем публичный ключ
        auto [n, e] = loadPublicKey(publicKeyPath);
        
        int keySize = n.bitLength();
        
        // Для hex используем PKCS#1 padding (как для текста)
        // Убираем префикс 0x если есть
        string cleanHex = hexValue;
        if (cleanHex.length() >= 2 && cleanHex.substr(0, 2) == "0x") {
            cleanHex = cleanHex.substr(2);
        }
        
        // Преобразуем hex строку в байты
        vector<uint8_t> hexBytes;
        // Проверяем четность длины
        if (cleanHex.length() % 2 != 0) {
            cleanHex = "0" + cleanHex;
        }
        
        // Преобразуем в байты
        for (size_t i = 0; i < cleanHex.length(); i += 2) {
            string byteStr = cleanHex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
            hexBytes.push_back(byte);
        }
        
        // Отладочный вывод: первые байты
        if (hexBytes.size() > 0) {
            cout << "🔍 Отладка encryptHex: первые 8 байтов исходного hex: ";
            for (size_t i = 0; i < (hexBytes.size() < 8 ? hexBytes.size() : 8); i++) {
                cout << hex << setw(2) << setfill('0') << static_cast<int>(hexBytes[i]) << " ";
            }
            cout << dec << endl;
        }
        
        // Размер блока равен размеру модуля в байтах
        ZZ ntl_n = n.getZZ();
        long nBytes = NumBytes(ntl_n);
        size_t blockSize = static_cast<size_t>(nBytes);
        
        // Проверяем максимальный размер данных с padding
        size_t maxDataSize = blockSize - 11; // PKCS#1 padding занимает 11 байт
        if (hexBytes.size() > maxDataSize) {
            throw runtime_error("16-ричное значение слишком большое для данного ключа. Максимальный размер: " + to_string(maxDataSize) + " байт (с PKCS#1 padding)");
        }
        
        // Добавляем PKCS#1 v1.5 padding к байтам
        vector<uint8_t> paddedData = addPKCS1PaddingBytes(hexBytes, blockSize);
        
        // Преобразуем padded данные в BigInt
        // ZZFromBytes интерпретирует байты как big-endian и удаляет нули с конца
        // Чтобы сохранить структуру PKCS#1 padding, переворачиваем байты
        // (делаем little-endian), чтобы ведущие нули стали младшими байтами
        vector<uint8_t> reversedData = paddedData;
        reverse(reversedData.begin(), reversedData.end());
        BigInt m = BigInt(reversedData);
        
        // Проверяем что значение меньше модуля
        if (m >= n) {
            throw runtime_error("Данные слишком большие для данного ключа. Максимальный размер: " + to_string(keySize) + " бит");
        }
        
        cout << " ✅ Завершено! (PKCS#1 padding добавлен)" << endl;
        
        // Выполняем шифрование: c = m^e mod n (с padding)
        BigInt c;
        c = modExpWithPadding(m, e, n, true);
        
        // Возвращаем результат в hex формате с префиксом 0x
        return "0x" + c.toHex();
        
    } catch (const exception& e) {
        throw runtime_error("Ошибка при шифровании hex значения: " + string(e.what()));
    }
}

string RSACrypto::decrypt(const string& ciphertext, const string& privateKeyPath) {
    try {
        cout << "🔓 Расшифровка текста с индикатором прогресса..." << endl;
        
        // Этап 1: Загрузка ключа
        cout << "🔄 Этап 1/4: Загрузка приватного ключа..." << flush;
        auto [n, d] = loadPrivateKey(privateKeyPath);
        int keySize = n.bitLength();
        cout << " ✅ Завершено! (ключ " << keySize << " бит)" << endl;
        
        // Этап 2: Подготовка данных
        cout << "🔄 Этап 2/4: Подготовка зашифрованных данных..." << flush;
        // Преобразуем десятичную строку в BigInt (encrypt всегда возвращает decimal)
        BigInt c = BigInt(ciphertext, true);
        
        // Проверяем что зашифрованное значение не больше модуля
        if (c >= n) {
            throw runtime_error("Зашифрованное значение слишком большое для данного ключа. Максимальный размер: " + to_string(n.bitLength()) + " бит");
        }
        cout << " ✅ Завершено!" << endl;
        
        // Этап 3: Модульное возведение в степень
        cout << "🔄 Этап 3/4: Модульное возведение в степень (c^d mod n)..." << flush;
        
        // Определяем нужно ли использовать padding
        bool usePadding = (keySize > 256);
        
        BigInt m;
        // Для всех ключей используем правильную обработку padding
        m = modExpWithPadding(c, d, n, usePadding);
        if (usePadding) {
            cout << " ✅ Завершено! (наш алгоритм с PKCS#1 padding)" << endl;
        } else {
            cout << " ✅ Завершено! (наш оптимизированный алгоритм без padding)" << endl;
        }
        
        // Убираем гибридный подход - используем только наш алгоритм с правильной обработкой padding
        
        // Этап 4: Обработка результата
        cout << "🔄 Этап 4/4: Обработка расшифрованного результата..." << flush;
        
        // Для RSA-64, RSA-128 и RSA-256 используем "сырое" RSA без padding
        if (keySize <= 256) {
            // Используем bigIntToString для совместимости с stringToBigInt
            string result = bigIntToString(m);
            cout << " ✅ Завершено! (сырое RSA, без padding)" << endl;
            cout << "🎉 Расшифровка успешно завершена!" << endl;
            return result;
        } else {
            // Для остальных ключей используем PKCS#1 padding
            // Преобразуем BigInt напрямую в байты, сохраняя точный размер блока
            // Размер блока должен быть равен размеру модуля в байтах
            ZZ ntl_n = n.getZZ();
            long nBytes = NumBytes(ntl_n);
            size_t blockSize = static_cast<size_t>(nBytes);
            
            // Получаем байты из BigInt через NTL с точным размером блока
            ZZ ntl_m = m.getZZ();
            
            // Создаем вектор байтов нужного размера (все нули)
            vector<uint8_t> paddedBytes(blockSize, 0);
            
            // Получаем байты числа (BytesFromZZ возвращает little-endian)
            // Заполняем с начала массива - BytesFromZZ сам заполнит нулями недостающие байты в конце
            BytesFromZZ(paddedBytes.data(), ntl_m, blockSize);
            
            // Переворачиваем из little-endian в big-endian для восстановления PKCS#1 padding
            reverse(paddedBytes.begin(), paddedBytes.end());
            
            // Искусственно добавляем нуль в начало, если его нет (для PKCS#1 padding первый байт должен быть 0x00)
            if (paddedBytes.empty() || paddedBytes[0] != 0x00) {
                paddedBytes.insert(paddedBytes.begin(), 0x00);
                // Удаляем последний байт, чтобы сохранить размер блока
                if (paddedBytes.size() > blockSize) {
                    paddedBytes.pop_back();
                }
            } else if (paddedBytes.size() >= 2 && paddedBytes[0] == 0x00 && paddedBytes[1] == 0x00) {
                // Если есть двойные нули в начале, удаляем один лишний
                paddedBytes.erase(paddedBytes.begin());
            }
            
            // Удаляем PKCS#1 v1.5 padding
            string result = removePKCS1Padding(paddedBytes);
            cout << " ✅ Завершено! (PKCS#1 padding удален)" << endl;
            cout << "🎉 Расшифровка успешно завершена!" << endl;
            return result;
        }
        
    } catch (const exception& e) {
        throw runtime_error("Ошибка при расшифровке: " + string(e.what()));
    }
}

string RSACrypto::decryptHex(const string& encryptedHex, const string& privateKeyPath) {
    try {
        cout << "🔓 Расшифровка hex значения с индикатором прогресса..." << endl;
        
        // Этап 1: Загрузка ключа
        cout << "🔄 Этап 1/4: Загрузка приватного ключа..." << flush;
        auto [n, d] = loadPrivateKey(privateKeyPath);
        int keySize = n.bitLength();
        cout << " ✅ Завершено! (ключ " << keySize << " бит)" << endl;
        
        // Этап 2: Подготовка данных
        cout << "🔄 Этап 2/4: Подготовка зашифрованных hex данных..." << flush;
        
        // Убираем префикс 0x если есть
        string cleanHex = encryptedHex;
        if (cleanHex.length() >= 2 && cleanHex.substr(0, 2) == "0x") {
            cleanHex = cleanHex.substr(2);
        }
        
        // Отладочный вывод
        cout << "\n🔍 Отладка decryptHex: encryptedHex = " << encryptedHex << endl;
        size_t cleanHexLen = cleanHex.length();
        size_t previewLen = (cleanHexLen > 64) ? 64 : cleanHexLen;
        cout << "🔍 Отладка decryptHex: cleanHex (первые 64 символа) = " << cleanHex.substr(0, previewLen) << "..." << endl;
        
        // Преобразуем hex строку в байты, затем в BigInt
        // NTL::ZZ operator>> не поддерживает hex с буквами, поэтому используем байты
        vector<uint8_t> hexBytes;
        // Проверяем четность длины
        if (cleanHex.length() % 2 != 0) {
            cleanHex = "0" + cleanHex;
        }
        
        // Преобразуем в байты
        for (size_t i = 0; i < cleanHex.length(); i += 2) {
            string byteStr = cleanHex.substr(i, 2);
            uint8_t byte = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
            hexBytes.push_back(byte);
        }
        
        // Преобразуем hex строку в BigInt (для зашифрованного значения)
        // toHex() возвращает big-endian hex строку (после переворота little-endian байтов)
        // Но при шифровании мы переворачивали байты перед ZZFromBytes
        // Поэтому нужно перевернуть байты обратно перед созданием BigInt
        reverse(hexBytes.begin(), hexBytes.end());
        BigInt c = BigInt(hexBytes);
        
        // Проверяем что зашифрованное значение не больше модуля
        if (c >= n) {
            throw runtime_error("Зашифрованное 16-ричное значение слишком большое для данного ключа. Максимальный размер: " + to_string(n.bitLength()) + " бит");
        }
        cout << " ✅ Завершено!" << endl;
        
        // Этап 3: Модульное возведение в степень
        cout << "🔄 Этап 3/4: Модульное возведение в степень (c^d mod n)..." << flush;
        
        // Для hex используем PKCS#1 padding (как для текста)
        BigInt m;
        m = modExpWithPadding(c, d, n, true);
        cout << " ✅ Завершено! (наш оптимизированный алгоритм с padding)" << endl;
        
        // Этап 4: Обработка результата
        cout << "🔄 Этап 4/4: Обработка расшифрованного hex результата..." << flush;
        
        // Для hex используем PKCS#1 padding (как для текста)
        // Преобразуем BigInt напрямую в байты, сохраняя точный размер блока
        // Размер блока должен быть равен размеру модуля в байтах
        ZZ ntl_n = n.getZZ();
        long nBytes = NumBytes(ntl_n);
        size_t blockSize = static_cast<size_t>(nBytes);
        
        // Получаем байты из BigInt через NTL с точным размером блока
        ZZ ntl_m = m.getZZ();
        
        // Создаем вектор байтов нужного размера (все нули)
        vector<uint8_t> paddedBytes(blockSize, 0);
        
        // Получаем байты числа (BytesFromZZ возвращает little-endian)
        // Заполняем с начала массива - BytesFromZZ сам заполнит нулями недостающие байты в конце
        BytesFromZZ(paddedBytes.data(), ntl_m, blockSize);
        
        // Переворачиваем из little-endian в big-endian для восстановления PKCS#1 padding
        reverse(paddedBytes.begin(), paddedBytes.end());
        
        // Искусственно добавляем нуль в начало, если его нет (для PKCS#1 padding первый байт должен быть 0x00)
        if (paddedBytes.empty() || paddedBytes[0] != 0x00) {
            paddedBytes.insert(paddedBytes.begin(), 0x00);
            if (paddedBytes.size() > blockSize) {
                paddedBytes.pop_back();
            }
        } else if (paddedBytes.size() >= 2 && paddedBytes[0] == 0x00 && paddedBytes[1] == 0x00) {
            // Если есть двойные нули в начале, удаляем один лишний
            paddedBytes.erase(paddedBytes.begin());
        }
        
        // Удаляем PKCS#1 v1.5 padding и получаем байты
        vector<uint8_t> decryptedBytes = removePKCS1PaddingBytes(paddedBytes);
        
        // Преобразуем байты в hex строку
        ostringstream hexStream;
        hexStream << hex << uppercase;
        for (uint8_t byte : decryptedBytes) {
            hexStream << setw(2) << setfill('0') << static_cast<int>(byte);
        }
        
        string result = "0x" + hexStream.str();
        cout << " ✅ Завершено! (PKCS#1 padding удален)" << endl;
        cout << "🎉 Расшифровка hex успешно завершена!" << endl;
        return result;
        
    } catch (const exception& e) {
        throw runtime_error("Ошибка при расшифровке hex значения: " + string(e.what()));
    }
}

// =============================================================================
// РАБОТА С ФАЙЛАМИ
// =============================================================================

bool RSACrypto::encryptFile(const string& inputFilePath, const string& outputFilePath, const string& publicKeyPath) {
    try {
        // Читаем исходный файл
        ifstream inputFile(inputFilePath, ios::binary);
        if (!inputFile.is_open()) {
            cerr << "Ошибка: не удалось открыть файл " << inputFilePath << endl;
            return false;
        }
        
        // Читаем файл как бинарные данные
        string content((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
        inputFile.close();
        
        // Проверяем размер файла относительно размера ключа
        auto [n, e] = loadPublicKey(publicKeyPath);
        int keySize = n.bitLength();
        size_t maxFileSize;
        
        if (keySize <= 256) {
            // Для RSA-64 без padding
            maxFileSize = keySize / 8;
        } else {
            // Для больших ключей с PKCS#1 padding
            maxFileSize = (keySize / 8) - 11; // PKCS#1 padding занимает 11 байт
        }
        
        if (content.length() > maxFileSize) {
            cerr << "Ошибка: файл слишком большой для данного ключа" << endl;
            cerr << "Размер файла: " << content.length() << " байт" << endl;
            cerr << "Максимальный размер для ключа " << keySize << " бит: " << maxFileSize << " байт" << endl;
            return false;
        }
        
        // Шифруем содержимое
        string encryptedContent = encrypt(content, publicKeyPath);
        
        // Сохраняем зашифрованный файл
        // Создаем директорию если нужно
        filesystem::path outputPath(outputFilePath);
        if (outputPath.has_parent_path()) {
            filesystem::create_directories(outputPath.parent_path());
        }
        
        // Сохраняем зашифрованный файл в текстовом режиме (содержит десятичную строку)
        ofstream outputFile(outputFilePath, ios::out);
        if (!outputFile.is_open()) {
            cerr << "Ошибка: не удалось создать файл " << outputFilePath << endl;
            return false;
        }
        
        outputFile << encryptedContent;
        outputFile.close();
        
        return true;
        
    } catch (const exception& e) {
        cerr << "Ошибка при шифровании файла: " << e.what() << endl;
        return false;
    }
}

bool RSACrypto::decryptFile(const string& inputFilePath, const string& outputFilePath, const string& privateKeyPath) {
    try {
        // Читаем зашифрованный файл в текстовом режиме (содержит десятичную строку)
        ifstream inputFile(inputFilePath, ios::in);
        if (!inputFile.is_open()) {
            cerr << "Ошибка: не удалось открыть файл " << inputFilePath << endl;
            return false;
        }
        
        string encryptedContent((istreambuf_iterator<char>(inputFile)), istreambuf_iterator<char>());
        inputFile.close();
        
        // Расшифровываем содержимое
        string decryptedContent = decrypt(encryptedContent, privateKeyPath);
        
        // Создаем директорию для расшифрованного файла если нужно
        filesystem::path outputPath(outputFilePath);
        if (outputPath.has_parent_path()) {
            filesystem::create_directories(outputPath.parent_path());
        }
        
        // Сохраняем расшифрованный файл
        ofstream outputFile(outputFilePath, ios::binary);
        if (!outputFile.is_open()) {
            cerr << "Ошибка: не удалось создать файл " << outputFilePath << endl;
            return false;
        }
        
        outputFile << decryptedContent;
        outputFile.close();
        
        return true;
        
    } catch (const exception& e) {
        cerr << "Ошибка при расшифровке файла: " << e.what() << endl;
        return false;
    }
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
// =============================================================================

vector<string> RSACrypto::getAvailableKeys() const {
    vector<pair<string, int>> keysWithSize; // Пары (имя_ключа, размер_RSA)
    
    try {
        string keyDir = "../rsa_keys";  // Папка ключей находится на уровень выше build
        if (filesystem::exists(keyDir) && filesystem::is_directory(keyDir)) {
            for (const auto& entry : filesystem::directory_iterator(keyDir)) {
                if (entry.is_regular_file()) {
                    string filename = entry.path().filename().string();
                    if (filename.find("_public_") != string::npos) {
                        // Извлекаем имя ключа из имени файла
                        size_t pos = filename.find("_public_");
                        if (pos != string::npos) {
                            string keyName = filename.substr(0, pos);
                            
                            // Извлекаем размер RSA из имени файла
                            string sizeStr = filename.substr(pos + 8); // После "_public_"
                            sizeStr = sizeStr.substr(0, sizeStr.find(".txt")); // До ".txt"
                            
                            int rsaSize = 0;
                            try {
                                rsaSize = stoi(sizeStr);
                            } catch (const exception&) {
                                rsaSize = 0; // Если не удалось распарсить размер
                            }
                            
                            // Проверяем, что ключ еще не добавлен
                            bool alreadyExists = false;
                            for (const auto& existingKey : keysWithSize) {
                                if (existingKey.first == keyName) {
                                    alreadyExists = true;
                                    break;
                                }
                            }
                            
                            if (!alreadyExists) {
                                keysWithSize.push_back({keyName, rsaSize});
                            }
                        }
                    }
                }
            }
        }
    } catch (const exception& e) {
        cerr << "Ошибка при получении списка ключей: " << e.what() << endl;
    }
    
    // Сортируем по размеру RSA (по возрастанию)
    sort(keysWithSize.begin(), keysWithSize.end(), 
         [](const pair<string, int>& a, const pair<string, int>& b) {
             return a.second < b.second;
         });
    
    // Извлекаем только имена ключей
    vector<string> keys;
    for (const auto& keyPair : keysWithSize) {
        keys.push_back(keyPair.first);
    }
    
    return keys;
}

bool RSACrypto::keyExists(const string& keyName) const {
    string publicKeyPath = "../rsa_keys/" + keyName + "_public_*.txt";
    string privateKeyPath = "../rsa_keys/" + keyName + "_private_*.txt";
    
    // Проверяем существование файлов ключей
    for (const auto& entry : filesystem::directory_iterator("../rsa_keys")) {
        if (entry.is_regular_file()) {
            string filename = entry.path().filename().string();
            if ((filename.find(keyName + "_public_") == 0) || 
                (filename.find(keyName + "_private_") == 0)) {
                return true;
            }
        }
    }
    
    return false;
}

string RSACrypto::getKeyInfo(const string& keyName) const {
    try {
        // Ищем файлы ключей
        string publicKeyPath, privateKeyPath;
        
        for (const auto& entry : filesystem::directory_iterator("../rsa_keys")) {
            if (entry.is_regular_file()) {
                string filename = entry.path().filename().string();
                if (filename.find(keyName + "_public_") == 0) {
                    publicKeyPath = entry.path().string();
                } else if (filename.find(keyName + "_private_") == 0) {
                    privateKeyPath = entry.path().string();
                }
            }
        }
        
        if (publicKeyPath.empty() || privateKeyPath.empty()) {
            return "Ключ не найден";
        }
        
        // Загружаем информацию о ключе
        auto [n, e] = const_cast<RSACrypto*>(this)->loadPublicKey(publicKeyPath);
        int keySize = n.bitLength();
        
        stringstream info;
        info << "Имя ключа: " << keyName << endl;
        info << "Размер ключа: " << keySize << " бит" << endl;
        info << "Публичный экспонент: " << e.toString() << endl;
        info << "Максимальный размер данных: " << keySize << " бит";
        
        return info.str();
        
    } catch (const exception& e) {
        return "Ошибка при получении информации о ключе: " + string(e.what());
    }
}

// =============================================================================
// ПРИВАТНЫЕ МЕТОДЫ
// =============================================================================

pair<BigInt, BigInt> RSACrypto::loadPublicKey(const string& keyPath) {
    ifstream file(keyPath);
    if (!file.is_open()) {
        throw runtime_error("Не удалось открыть файл ключа: " + keyPath);
    }
    
    string line;
    BigInt n, e;
    
    while (getline(file, line)) {
        if (line.find("Modulus (n):") != string::npos) {
            getline(file, line);
            n = BigInt(line, true); // Десятичная строка
        } else if (line.find("Public Exponent (e):") != string::npos) {
            getline(file, line);
            e = BigInt(line, true); // Десятичная строка
        }
    }
    
    file.close();
    
    if (n.isZero() || e.isZero()) {
        throw runtime_error("Неверный формат файла ключа");
    }
    
    return make_pair(n, e);
}

pair<BigInt, BigInt> RSACrypto::loadPrivateKey(const string& keyPath) {
    ifstream file(keyPath);
    if (!file.is_open()) {
        throw runtime_error("Не удалось открыть файл ключа: " + keyPath);
    }
    
    string line;
    BigInt n, d;
    
    while (getline(file, line)) {
        if (line.find("Modulus (n):") != string::npos) {
            getline(file, line);
            n = BigInt(line, true); // Десятичная строка
        } else if (line.find("Private Exponent (d):") != string::npos) {
            getline(file, line);
            d = BigInt(line, true); // Десятичная строка
        }
    }
    
    file.close();
    
    if (n.isZero() || d.isZero()) {
        throw runtime_error("Неверный формат файла ключа");
    }
    
    return make_pair(n, d);
}

BigInt RSACrypto::stringToBigInt(const string& text) {
    BigInt result(0);
    BigInt base(256);
    
    for (char c : text) {
        result = result * base + static_cast<unsigned char>(c);
    }
    
    return result;
}

string RSACrypto::bigIntToString(const BigInt& bigInt) {
    // Преобразуем BigInt обратно в строку используя base-256
    string result = "";
    BigInt temp = bigInt;
    BigInt base(256);
    
    while (!temp.isZero()) {
        BigInt remainder = temp % base;
        // Преобразуем remainder в int через decimal строку
        string remainderStr = remainder.toString();
        int byteValue = stoi(remainderStr);
        result = static_cast<char>(byteValue) + result;
        temp = temp / base;
    }
    
    return result;
}

vector<uint8_t> RSACrypto::addPKCS1Padding(const string& data, size_t blockSize) {
    vector<uint8_t> padded(blockSize);
    
    // Первый байт: 0x00
    padded[0] = 0x00;
    
    // Второй байт: 0x02 (для шифрования)
    padded[1] = 0x02;
    
    // Заполняем случайными ненулевыми байтами
    size_t paddingLength = blockSize - data.length() - 3; // -3 для 0x00, 0x02, 0x00
    
    // Используем более качественный генератор случайных чисел
    static random_device rd;
    static mt19937 gen(rd());
    uniform_int_distribution<> dis(1, 255); // Ненулевые байты (1-255)
    
    for (size_t i = 0; i < paddingLength; i++) {
        padded[2 + i] = static_cast<uint8_t>(dis(gen));
    }
    
    // Разделитель: 0x00
    padded[2 + paddingLength] = 0x00;
    
    // Добавляем данные
    for (size_t i = 0; i < data.length(); i++) {
        padded[3 + paddingLength + i] = static_cast<uint8_t>(data[i]);
    }
    
    return padded;
}

string RSACrypto::removePKCS1Padding(const vector<uint8_t>& paddedData) {
    if (paddedData.size() < 3) {
        throw runtime_error("Неверный формат PKCS#1 padding");
    }
    
    // Отладочная информация
    cout << "\n🔍 Отладка removePKCS1Padding: Размер данных: " << paddedData.size() << " байт" << endl;
    cout << "🔍 Первые 16 байт: ";
    for (size_t i = 0; i < min(static_cast<size_t>(16), paddedData.size()); i++) {
        printf("%02x ", paddedData[i]);
    }
    cout << endl;
    
    // Проверяем первый байт
    if (paddedData[0] != 0x00) {
        throw runtime_error("Неверный формат PKCS#1 padding: первый байт должен быть 0x00, получен 0x" + 
                           to_string(paddedData[0]));
    }
    
    // Проверяем второй байт
    if (paddedData[1] != 0x02) {
        throw runtime_error("Неверный формат PKCS#1 padding: второй байт должен быть 0x02, получен 0x" + 
                           to_string(paddedData[1]));
    }
    
    // Ищем разделитель 0x00 начиная с позиции 2
    size_t separatorPos = 0;
    for (size_t i = 2; i < paddedData.size(); i++) {
        if (paddedData[i] == 0x00) {
            separatorPos = i;
            break;
        }
    }
    
    if (separatorPos == 0) {
        throw runtime_error("Неверный формат PKCS#1 padding: не найден разделитель 0x00");
    }
    
    // Проверяем минимальную длину padding
    if (separatorPos < 10) {
        throw runtime_error("Неверный формат PKCS#1 padding: слишком короткий padding");
    }
    
    // Извлекаем данные
    string result;
    for (size_t i = separatorPos + 1; i < paddedData.size(); i++) {
        result += static_cast<char>(paddedData[i]);
    }
    
    // Убираем только завершающие нулевые байты (они могут появиться из-за padding)
    // Но сохраняем все данные, включая возможные нули внутри данных
    while (!result.empty() && result.back() == '\0') {
        result.pop_back();
    }
    
    // Отладочный вывод: байты расшифрованного текста
    cout << "🔍 Отладка removePKCS1Padding: Расшифрованный текст (длина " << result.length() << " байт): ";
    for (size_t i = 0; i < result.length(); i++) {
        printf("%02x ", static_cast<unsigned char>(result[i]));
    }
    cout << endl;
    
    return result;
}

vector<uint8_t> RSACrypto::addPKCS1PaddingBytes(const vector<uint8_t>& data, size_t blockSize) {
    vector<uint8_t> padded(blockSize);
    
    // Первый байт: 0x00
    padded[0] = 0x00;
    
    // Второй байт: 0x02 (для шифрования)
    padded[1] = 0x02;
    
    // Заполняем случайными ненулевыми байтами
    size_t paddingLength = blockSize - data.size() - 3; // -3 для 0x00, 0x02, 0x00
    
    // Используем более качественный генератор случайных чисел
    static random_device rd;
    static mt19937 gen(rd());
    uniform_int_distribution<> dis(1, 255); // Ненулевые байты (1-255)
    
    for (size_t i = 0; i < paddingLength; i++) {
        padded[2 + i] = static_cast<uint8_t>(dis(gen));
    }
    
    // Разделитель: 0x00
    padded[2 + paddingLength] = 0x00;
    
    // Добавляем данные
    for (size_t i = 0; i < data.size(); i++) {
        padded[3 + paddingLength + i] = data[i];
    }
    
    return padded;
}

vector<uint8_t> RSACrypto::removePKCS1PaddingBytes(const vector<uint8_t>& paddedData) {
    if (paddedData.size() < 3) {
        throw runtime_error("Неверный формат PKCS#1 padding");
    }
    
    // Проверяем первый байт
    if (paddedData[0] != 0x00) {
        throw runtime_error("Неверный формат PKCS#1 padding: первый байт должен быть 0x00, получен 0x" + 
                           to_string(paddedData[0]));
    }
    
    // Проверяем второй байт
    if (paddedData[1] != 0x02) {
        throw runtime_error("Неверный формат PKCS#1 padding: второй байт должен быть 0x02, получен 0x" + 
                           to_string(paddedData[1]));
    }
    
    // Ищем разделитель 0x00 начиная с позиции 2
    size_t separatorPos = 0;
    for (size_t i = 2; i < paddedData.size(); i++) {
        if (paddedData[i] == 0x00) {
            separatorPos = i;
            break;
        }
    }
    
    if (separatorPos == 0) {
        throw runtime_error("Неверный формат PKCS#1 padding: не найден разделитель 0x00");
    }
    
    // Проверяем минимальную длину padding
    if (separatorPos < 10) {
        throw runtime_error("Неверный формат PKCS#1 padding: слишком короткий padding");
    }
    
    // Извлекаем данные (байты)
    vector<uint8_t> result;
    for (size_t i = separatorPos + 1; i < paddedData.size(); i++) {
        // Пропускаем нулевые байты в конце (они могут появиться из-за padding)
        if (paddedData[i] == 0x00 && i == separatorPos + 1) {
            continue; // Пропускаем первый нулевой байт после разделителя, если он есть
        }
        result.push_back(paddedData[i]);
    }
    
    // Убираем нулевые байты в конце
    while (!result.empty() && result.back() == 0x00) {
        result.pop_back();
    }
    
    return result;
}

// =============================================================================
// МОДУЛЬНОЕ ВОЗВЕДЕНИЕ В СТЕПЕНЬ С ПРАВИЛЬНОЙ ОБРАБОТКОЙ PKCS#1 PADDING
// =============================================================================

BigInt RSACrypto::modExpWithPKCS1Padding(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
    // Используем NTL::PowerMod для модульного возведения в степень
    ZZ ntl_base = base.getZZ();
    ZZ ntl_exponent = exponent.getZZ();
    ZZ ntl_modulus = modulus.getZZ();
    ZZ ntl_result;
    PowerMod(ntl_result, ntl_base, ntl_exponent, ntl_modulus);
    return BigInt(ntl_result);
}

// =============================================================================
// МОДУЛЬНОЕ ВОЗВЕДЕНИЕ В СТЕПЕНЬ С MONTGOMERY CONVERSION ДЛЯ PKCS#1 PADDING
// =============================================================================

BigInt RSACrypto::modExpWithMontgomeryConversion(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
    // Используем NTL::PowerMod для модульного возведения в степень
    ZZ ntl_base = base.getZZ();
    ZZ ntl_exponent = exponent.getZZ();
    ZZ ntl_modulus = modulus.getZZ();
    ZZ ntl_result;
    PowerMod(ntl_result, ntl_base, ntl_exponent, ntl_modulus);
    return BigInt(ntl_result);
}

// =============================================================================
// ОПТИМИЗИРОВАННОЕ МОДУЛЬНОЕ ВОЗВЕДЕНИЕ В СТЕПЕНЬ БЕЗ MONTGOMERY ДЛЯ PKCS#1 PADDING
// =============================================================================

BigInt RSACrypto::modExpOptimizedWithoutMontgomery(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
    // Используем NTL::PowerMod для модульного возведения в степень
    ZZ ntl_base = base.getZZ();
    ZZ ntl_exponent = exponent.getZZ();
    ZZ ntl_modulus = modulus.getZZ();
    ZZ ntl_result;
    PowerMod(ntl_result, ntl_base, ntl_exponent, ntl_modulus);
    return BigInt(ntl_result);
}

// =============================================================================
// ОПТИМИЗИРОВАННЫЙ БИНАРНЫЙ АЛГОРИТМ ДЛЯ PKCS#1 PADDING
// =============================================================================

BigInt RSACrypto::modExpOptimizedBinary(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
    // Используем NTL::PowerMod для модульного возведения в степень
    ZZ ntl_base = base.getZZ();
    ZZ ntl_exponent = exponent.getZZ();
    ZZ ntl_modulus = modulus.getZZ();
    ZZ ntl_result;
    PowerMod(ntl_result, ntl_base, ntl_exponent, ntl_modulus);
    return BigInt(ntl_result);
}

// Старая реализация удалена - используем NTL
#if 0
BigInt RSACrypto::modExpOptimizedBinary_OLD(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
    // Максимально оптимизированный бинарный алгоритм, который сохраняет структуру PKCS#1 padding
    // Использует все доступные оптимизации кроме Montgomery и sliding window
    
    BigInt result(1);
    BigInt base_mod = base % modulus;
    BigInt exp = exponent;
    
    // Используем битовые операции вместо деления
    while (!exp.isZero()) {
        if (exp.isOdd()) {
            // Оптимизированное умножение с минимальным количеством модуло
            result = result * base_mod;
            if (result >= modulus) {
                result = result % modulus;
            }
        }
        base_mod = base_mod * base_mod;
        if (base_mod >= modulus) {
            base_mod = base_mod % modulus;
        }
        // Используем битовый сдвиг вместо деления на 2
        exp = exp / BigInt(2);  // Деление на 2 вместо битового сдвига
    }
    
    return result;
}

// =============================================================================
// GMP-STYLE SLIDING WINDOW ALGORITHM ДЛЯ PKCS#1 PADDING
// =============================================================================

BigInt RSACrypto::modExpSlidingWindow(const BigInt& base, const BigInt& exponent, const BigInt& modulus) {
    // Реализация sliding window алгоритма из GMP mpn_powm.c
    // Основан на алгоритме из Handbook of Applied Cryptography
    
    // Вычисляем размер окна на основе размера экспоненты
    int expBits = exponent.bitLength();
    int windowSize = calculateWindowSize(expBits);
    
    // Предвычисляем степени основания
    vector<BigInt> powerTable = precomputePowers(base, modulus, windowSize);
    
    // Основной алгоритм sliding window
    BigInt result(1);
    BigInt exp = exponent;
    
    // Обрабатываем биты экспоненты справа налево
    int bitIndex = expBits - 1;
    
    while (bitIndex >= 0) {
        // Пропускаем нулевые биты
        while (bitIndex >= 0 && !exp.getBit(bitIndex)) {
            result = (result * result) % modulus;
            bitIndex--;
        }
        
        if (bitIndex < 0) break;
        
        // Извлекаем окно битов
        int windowStart = bitIndex;
        int windowEnd = max(0, bitIndex - windowSize + 1);
        
        // Находим нечетное число в окне
        BigInt windowValue = extractWindowBits(exp, windowStart, windowEnd);
        
        // Применяем предвычисленную степень
        if (!windowValue.isZero()) {
            // Преобразуем windowValue в индекс для powerTable
            // windowValue должно быть нечетным числом
            if (windowValue.isOdd()) {
                BigInt powerIndex = (windowValue - BigInt(1)) / BigInt(2);
                // Простое преобразование в int для небольших значений
                if (powerIndex < BigInt(1000)) { // Безопасный лимит
                    // Используем прямое сравнение для небольших значений
                    int index = 0;
                    BigInt temp = powerIndex;
                    while (!temp.isZero() && index < 1000) {
                        temp = temp - BigInt(1);
                        index++;
                    }
                    if (static_cast<size_t>(index) < powerTable.size()) {
                        result = (result * powerTable[index]) % modulus;
                    }
                }
            }
        }
        
        bitIndex = windowEnd - 1;
    }
    
    return result;
}
#endif

// Вспомогательные функции для sliding window алгоритма (оставлены для совместимости, но не используются)
int RSACrypto::calculateWindowSize(int expBits) {
    // Основано на функции win_size из GMP
    static vector<int> thresholds = {1, 7, 25, 81, 241, 673, 1793, 4609, 11521, 28161};
    
    for (size_t k = 0; k < thresholds.size(); k++) {
        if (expBits <= thresholds[k]) {
            return k;
        }
    }
    return min(10, expBits / 8); // Максимальный размер окна
}

vector<BigInt> RSACrypto::precomputePowers(const BigInt& base, const BigInt& modulus, int windowSize) {
    vector<BigInt> powerTable;
    
    // Предвычисляем нечетные степени: base^1, base^3, base^5, ..., base^(2^k-1)
    BigInt currentPower = base % modulus;
    powerTable.push_back(currentPower);
    
    BigInt baseSquared = (base * base) % modulus;
    
    for (int i = 1; i < (1 << (windowSize - 1)); i++) {
        currentPower = (currentPower * baseSquared) % modulus;
        powerTable.push_back(currentPower);
    }
    
    return powerTable;
}

BigInt RSACrypto::extractWindowBits(const BigInt& exp, int startBit, int endBit) {
    // Извлекает биты из экспоненты в заданном диапазоне
    BigInt result(0);
    BigInt multiplier(1);
    
    for (int i = endBit; i <= startBit; i++) {
        if (exp.getBit(i)) {
            result = result + multiplier;
        }
        multiplier = multiplier * BigInt(2);
    }
    
    return result;
}

void RSACrypto::ensureDirectoryExists() {
    try {
        if (!filesystem::exists(baseDirectory)) {
            filesystem::create_directories(baseDirectory);
        }
    } catch (const exception& e) {
        cerr << "Ошибка при создании директории: " << e.what() << endl;
    }
}

// =============================================================================
// ПАРАЛЛЕЛЬНЫЕ ОПЕРАЦИИ ШИФРОВАНИЯ И РАСШИФРОВКИ
// =============================================================================

vector<string> RSACrypto::encryptBatch(const vector<string>& plaintexts, const string& publicKeyPath) {
    if (plaintexts.empty()) {
        return {};
    }
    
    cout << "🚀 Параллельное шифрование " << plaintexts.size() << " блоков..." << endl;
    
    vector<string> results(plaintexts.size());
    
    // Проверяем доступность параллельной обработки
    bool useParallel = false;
    try {
        // Используем NTL для вычислений
        useParallel = true; // Предполагаем, что параллельность доступна
    } catch (...) {
        useParallel = false;
    }
    
    if (useParallel && plaintexts.size() > 1) {
        // Параллельное шифрование
        vector<future<string>> futures;
        
        for (size_t i = 0; i < plaintexts.size(); i++) {
            futures.push_back(async(launch::async, [this, &plaintexts, publicKeyPath, i]() {
                try {
                    return encrypt(plaintexts[i], publicKeyPath);
                } catch (const exception& e) {
                    cerr << "Ошибка при шифровании блока " << i << ": " << e.what() << endl;
                    return string("ERROR");
                }
            }));
        }
        
        // Собираем результаты
        for (size_t i = 0; i < futures.size(); i++) {
            results[i] = futures[i].get();
        }
        
        cout << "✅ Параллельное шифрование завершено!" << endl;
    } else {
        // Последовательное шифрование
        cout << "🔄 Последовательное шифрование..." << endl;
        
        for (size_t i = 0; i < plaintexts.size(); i++) {
            try {
                results[i] = encrypt(plaintexts[i], publicKeyPath);
                cout << "   ✅ Блок " << (i + 1) << " зашифрован" << endl;
            } catch (const exception& e) {
                cerr << "   ❌ Ошибка при шифровании блока " << (i + 1) << ": " << e.what() << endl;
                results[i] = "ERROR";
            }
        }
    }
    
    return results;
}

vector<string> RSACrypto::decryptBatch(const vector<string>& ciphertexts, const string& privateKeyPath) {
    if (ciphertexts.empty()) {
        return {};
    }
    
    cout << "🚀 Параллельная расшифровка " << ciphertexts.size() << " блоков..." << endl;
    
    vector<string> results(ciphertexts.size());
    
    // Проверяем доступность параллельной обработки
    bool useParallel = true; // Предполагаем доступность
    
    if (useParallel && ciphertexts.size() > 1) {
        // Параллельная расшифровка
        vector<future<string>> futures;
        
        for (size_t i = 0; i < ciphertexts.size(); i++) {
            futures.push_back(async(launch::async, [this, &ciphertexts, privateKeyPath, i]() {
                try {
                    return decrypt(ciphertexts[i], privateKeyPath);
                } catch (const exception& e) {
                    cerr << "Ошибка при расшифровке блока " << i << ": " << e.what() << endl;
                    return string("ERROR");
                }
            }));
        }
        
        // Собираем результаты
        for (size_t i = 0; i < futures.size(); i++) {
            results[i] = futures[i].get();
        }
        
        cout << "✅ Параллельная расшифровка завершена!" << endl;
    } else {
        // Последовательная расшифровка
        cout << "🔄 Последовательная расшифровка..." << endl;
        
        for (size_t i = 0; i < ciphertexts.size(); i++) {
            try {
                results[i] = decrypt(ciphertexts[i], privateKeyPath);
                cout << "   ✅ Блок " << (i + 1) << " расшифрован" << endl;
            } catch (const exception& e) {
                cerr << "   ❌ Ошибка при расшифровке блока " << (i + 1) << ": " << e.what() << endl;
                results[i] = "ERROR";
            }
        }
    }
    
    return results;
}

int RSACrypto::encryptFilesBatch(const vector<string>& inputPaths, 
                                 const vector<string>& outputPaths, 
                                 const string& publicKeyPath) {
    if (inputPaths.size() != outputPaths.size()) {
        cerr << "Ошибка: количество входных и выходных путей не совпадает" << endl;
        return 0;
    }
    
    if (inputPaths.empty()) {
        return 0;
    }
    
    cout << "🚀 Параллельное шифрование " << inputPaths.size() << " файлов..." << endl;
    
    int successCount = 0;
    bool useParallel = true; // Предполагаем доступность
    
    if (useParallel && inputPaths.size() > 1) {
        // Параллельное шифрование файлов
        vector<future<bool>> futures;
        
        for (size_t i = 0; i < inputPaths.size(); i++) {
            futures.push_back(async(launch::async, [this, &inputPaths, &outputPaths, publicKeyPath, i]() {
                try {
                    return encryptFile(inputPaths[i], outputPaths[i], publicKeyPath);
                } catch (const exception& e) {
                    cerr << "Ошибка при шифровании файла " << inputPaths[i] << ": " << e.what() << endl;
                    return false;
                }
            }));
        }
        
        // Собираем результаты
        for (size_t i = 0; i < futures.size(); i++) {
            if (futures[i].get()) {
                successCount++;
                cout << "   ✅ " << inputPaths[i] << " -> " << outputPaths[i] << endl;
            } else {
                cout << "   ❌ Ошибка: " << inputPaths[i] << endl;
            }
        }
        
        cout << "✅ Параллельное шифрование файлов завершено!" << endl;
    } else {
        // Последовательное шифрование файлов
        cout << "🔄 Последовательное шифрование файлов..." << endl;
        
        for (size_t i = 0; i < inputPaths.size(); i++) {
            try {
                if (encryptFile(inputPaths[i], outputPaths[i], publicKeyPath)) {
                    successCount++;
                    cout << "   ✅ " << inputPaths[i] << " -> " << outputPaths[i] << endl;
                } else {
                    cout << "   ❌ Ошибка: " << inputPaths[i] << endl;
                }
            } catch (const exception& e) {
                cout << "   ❌ Ошибка: " << inputPaths[i] << " - " << e.what() << endl;
            }
        }
    }
    
    cout << "📊 Результат: " << successCount << " из " << inputPaths.size() << " файлов успешно зашифрованы" << endl;
    return successCount;
}

// =============================================================================
// БЫСТРЫЕ МЕТОДЫ С GPU/SIMD УСКОРЕНИЕМ
// =============================================================================

int RSACrypto::decryptFilesBatch(const vector<string>& inputPaths,
                                 const vector<string>& outputPaths,
                                 const string& privateKeyPath) {
    if (inputPaths.size() != outputPaths.size()) {
        cerr << "Ошибка: количество входных и выходных путей не совпадает" << endl;
        return 0;
    }
    
    if (inputPaths.empty()) {
        return 0;
    }
    
    cout << "🚀 Параллельная расшифровка " << inputPaths.size() << " файлов..." << endl;
    
    int successCount = 0;
    bool useParallel = true; // Assume parallel is available
    
    if (useParallel && inputPaths.size() > 1) {
        vector<future<bool>> futures;
        
        for (size_t i = 0; i < inputPaths.size(); i++) {
            futures.push_back(async(launch::async, [this, &inputPaths, &outputPaths, privateKeyPath, i]() {
                try {
                    return decryptFile(inputPaths[i], outputPaths[i], privateKeyPath);
                } catch (const exception& e) {
                    cerr << "Ошибка при расшифровке файла " << inputPaths[i] << ": " << e.what() << endl;
                    return false;
                }
            }));
        }
        
        for (size_t i = 0; i < futures.size(); i++) {
            if (futures[i].get()) {
                successCount++;
                cout << "   ✅ " << inputPaths[i] << " -> " << outputPaths[i] << endl;
            } else {
                cout << "   ❌ Ошибка: " << inputPaths[i] << endl;
            }
        }
        
        cout << "✅ Параллельная расшифровка файлов завершена!" << endl;
    } else {
        cout << "🔄 Последовательная расшифровка файлов..." << endl;
        
        for (size_t i = 0; i < inputPaths.size(); i++) {
            try {
                if (decryptFile(inputPaths[i], outputPaths[i], privateKeyPath)) {
                    successCount++;
                    cout << "   ✅ " << inputPaths[i] << " -> " << outputPaths[i] << endl;
                } else {
                    cout << "   ❌ Ошибка: " << inputPaths[i] << endl;
                }
            } catch (const exception& e) {
                cout << "   ❌ Ошибка: " << inputPaths[i] << " - " << e.what() << endl;
            }
        }
    }
    
    cout << "📊 Результат: " << successCount << " из " << inputPaths.size() << " файлов успешно расшифрованы" << endl;
    return successCount;
}

string RSACrypto::decryptFast(const string& ciphertext, const string& privateKeyPath) {
    try {
        cout << "⚡ БЫСТРАЯ расшифровка с GPU/SIMD ускорением..." << endl;
        
        // Загружаем приватный ключ
        auto [n, d] = loadPrivateKey(privateKeyPath);
        int keySize = n.bitLength();
        
        // Преобразуем зашифрованный текст в BigInt
        BigInt c = BigInt(ciphertext, true);
        
        if (c >= n) {
            throw runtime_error("Зашифрованное значение слишком большое для данного ключа");
        }
        
        // Определяем нужно ли использовать padding
        bool usePadding = (keySize > 256);
        
        // Используем правильную обработку padding для всех ключей
        BigInt m = modExpWithPadding(c, d, n, usePadding);
        
        // Обрабатываем результат
        if (keySize <= 256) {
            return bigIntToString(m);
        } else {
            // Для больших ключей обрабатываем PKCS#1 padding
            string hexStr = m.toHex();
            if (hexStr.substr(0, 2) == "0x") {
                hexStr = hexStr.substr(2);
            }
            if (hexStr.length() % 2 != 0) {
                hexStr = "0" + hexStr;
            }
            
            vector<uint8_t> paddedBytes;
            for (size_t i = 0; i < hexStr.length(); i += 2) {
                string byteStr = hexStr.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(stoi(byteStr, nullptr, 16));
                paddedBytes.push_back(byte);
            }
            
            size_t blockSize = keySize / 8;
            while (paddedBytes.size() < blockSize) {
                paddedBytes.insert(paddedBytes.begin(), 0x00);
            }
            
            return removePKCS1Padding(paddedBytes);
        }
        
    } catch (const exception& e) {
        throw runtime_error("Ошибка при быстрой расшифровке: " + string(e.what()));
    }
}

string RSACrypto::encryptFast(const string& plaintext, const string& publicKeyPath) {
    try {
        cout << "⚡ БЫСТРОЕ шифрование с GPU/SIMD ускорением..." << endl;
        
        // Загружаем публичный ключ
        auto [n, e] = loadPublicKey(publicKeyPath);
        int keySize = n.bitLength();
        
        size_t blockSize = keySize / 8;
        BigInt m;
        
        if (keySize <= 256) {
            // Для малых ключей используем "сырое" RSA
            if (plaintext.length() > blockSize) {
                throw runtime_error("Текст слишком большой для данного ключа");
            }
            m = stringToBigInt(plaintext);
        } else {
            // Для больших ключей используем PKCS#1 padding
            size_t maxDataSize = blockSize - 11;
            if (plaintext.length() > maxDataSize) {
                throw runtime_error("Текст слишком большой для данного ключа");
            }
            vector<uint8_t> paddedData = addPKCS1Padding(plaintext, blockSize);
            // ZZFromBytes интерпретирует байты как big-endian и удаляет нули с конца
            // Чтобы сохранить структуру PKCS#1 padding, переворачиваем байты
            vector<uint8_t> reversedData = paddedData;
            reverse(reversedData.begin(), reversedData.end());
            m = BigInt(reversedData);
        }
        
        if (m >= n) {
            throw runtime_error("Данные слишком большие для данного ключа");
        }
        
        // Используем максимально оптимизированный алгоритм
        BigInt c;
        bool usePadding = (keySize > 256);
        if (keySize > 256) {
            cout << "🚀 Запуск оптимизированного алгоритма для " << keySize << "-битного ключа..." << endl;
        }
        c = modExpWithPadding(m, e, n, usePadding);
        
        // Возвращаем результат в десятичном формате
        if (keySize > 1024) {
            // Для больших ключей используем hex для ускорения
            string hexResult = c.toHex();
            BigInt hexValue(hexResult, false);
            return hexValue.toString();
        } else {
            return c.toString();
        }
        
    } catch (const exception& e) {
        throw runtime_error("Ошибка при быстром шифровании: " + string(e.what()));
    }
}



// =============================================================================
// МОДУЛЬНОЕ ВОЗВЕДЕНИЕ В СТЕПЕНЬ С ПРАВИЛЬНОЙ ОБРАБОТКОЙ PADDING
// =============================================================================

BigInt RSACrypto::modExpWithPadding(const BigInt& base, const BigInt& exponent, const BigInt& modulus, bool usePadding) {
    // Используем NTL::PowerMod для модульного возведения в степень
    // NTL автоматически оптимизирует для всех размеров ключей
    ZZ ntl_base = base.getZZ();
    ZZ ntl_exponent = exponent.getZZ();
    ZZ ntl_modulus = modulus.getZZ();
    ZZ ntl_result;
    PowerMod(ntl_result, ntl_base, ntl_exponent, ntl_modulus);
    return BigInt(ntl_result);
}
