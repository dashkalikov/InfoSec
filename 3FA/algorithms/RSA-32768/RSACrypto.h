#ifndef RSA_CRYPTO_H
#define RSA_CRYPTO_H

#include "BigInt.h"             // Для работы с большими целыми числами
#include "RSAKeyManager.h"      // Для работы с RSA ключами
#include <string>               // Для работы со строками
#include <vector>               // Для работы с векторами

// =============================================================================
// RSA ШИФРОВАНИЕ И РАСШИФРОВКА
// =============================================================================

/**
 * @brief Класс для выполнения операций шифрования и расшифровки RSA.
 *
 * Предоставляет функциональность для:
 * - Шифрования текста с использованием публичного ключа
 * - Расшифровки зашифрованного текста с использованием приватного ключа
 * - Работы с файлами (загрузка/сохранение зашифрованных данных)
 * - Поддержки различных форматов ввода/вывода
 */
class RSACrypto {
public:
    /**
     * @brief Конструктор класса RSACrypto.
     *
     * Инициализирует базовую директорию для хранения зашифрованных файлов.
     */
    RSACrypto();

    /**
     * @brief Шифрует текст с использованием публичного ключа RSA.
     *
     * @param plaintext Исходный текст для шифрования.
     * @param publicKeyPath Путь к файлу с публичным ключом.
     * @return Зашифрованный текст в виде строки.
     */
    std::string encrypt(const std::string& plaintext, const std::string& publicKeyPath);

    /**
     * @brief Шифрует 16-ричное значение с использованием публичного ключа RSA.
     *
     * @param hexValue 16-ричное значение для шифрования.
     * @param publicKeyPath Путь к файлу с публичным ключом.
     * @return Зашифрованное значение в виде 16-ричной строки.
     */
    std::string encryptHex(const std::string& hexValue, const std::string& publicKeyPath);

    /**
     * @brief Расшифровывает текст с использованием приватного ключа RSA.
     *
     * @param ciphertext Зашифрованный текст для расшифровки.
     * @param privateKeyPath Путь к файлу с приватным ключом.
     * @return Расшифрованный текст.
     */
    std::string decrypt(const std::string& ciphertext, const std::string& privateKeyPath);

    /**
     * @brief Расшифровывает 16-ричное значение с использованием приватного ключа RSA.
     *
     * @param encryptedHex Зашифрованное 16-ричное значение для расшифровки.
     * @param privateKeyPath Путь к файлу с приватным ключом.
     * @return Расшифрованное значение в виде 16-ричной строки.
     */
    std::string decryptHex(const std::string& encryptedHex, const std::string& privateKeyPath);

    /**
     * @brief Шифрует файл с использованием публичного ключа RSA.
     *
     * @param inputFilePath Путь к исходному файлу.
     * @param outputFilePath Путь к файлу для сохранения зашифрованных данных.
     * @param publicKeyPath Путь к файлу с публичным ключом.
     * @return true, если шифрование прошло успешно, false в противном случае.
     */
    bool encryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& publicKeyPath);

    /**
     * @brief Расшифровывает файл с использованием приватного ключа RSA.
     *
     * @param inputFilePath Путь к зашифрованному файлу.
     * @param outputFilePath Путь к файлу для сохранения расшифрованных данных.
     * @param privateKeyPath Путь к файлу с приватным ключом.
     * @return true, если расшифровка прошла успешно, false в противном случае.
     */
    bool decryptFile(const std::string& inputFilePath, const std::string& outputFilePath, const std::string& privateKeyPath);

    /**
     * @brief Параллельно шифрует несколько текстовых блоков
     *
     * @param plaintexts Вектор текстов для шифрования
     * @param publicKeyPath Путь к файлу с публичным ключом
     * @return Вектор зашифрованных текстов
     */
    std::vector<std::string> encryptBatch(const std::vector<std::string>& plaintexts, const std::string& publicKeyPath);

    /**
     * @brief Параллельно расшифровывает несколько текстовых блоков
     *
     * @param ciphertexts Вектор зашифрованных текстов
     * @param privateKeyPath Путь к файлу с приватным ключом
     * @return Вектор расшифрованных текстов
     */
    std::vector<std::string> decryptBatch(const std::vector<std::string>& ciphertexts, const std::string& privateKeyPath);

    /**
     * @brief Параллельно шифрует несколько файлов
     *
     * @param inputPaths Вектор путей к исходным файлам
     * @param outputPaths Вектор путей для сохранения зашифрованных файлов
     * @param publicKeyPath Путь к файлу с публичным ключом
     * @return Количество успешно зашифрованных файлов
     */
    int encryptFilesBatch(const std::vector<std::string>& inputPaths, 
                         const std::vector<std::string>& outputPaths, 
                         const std::string& publicKeyPath);

    /**
     * @brief Получает список доступных RSA ключей.
     *
     * @return Вектор строк с именами доступных ключей.
     */
    std::vector<std::string> getAvailableKeys() const;

    /**
     * @brief Проверяет существование ключа.
     *
     * @param keyName Имя ключа (без расширения).
     * @return true, если ключ существует, false в противном случае.
     */
    bool keyExists(const std::string& keyName) const;

    /**
     * @brief Получает информацию о ключе.
     *
     * @param keyName Имя ключа (без расширения).
     * @return Строка с информацией о ключе.
     */
    std::string getKeyInfo(const std::string& keyName) const;

private:
    std::string baseDirectory;  // Базовая директория для зашифрованных файлов

    /**
     * @brief Загружает публичный ключ из файла.
     *
     * @param keyPath Путь к файлу с публичным ключом.
     * @return Пара (n, e) - модуль и публичный экспонент.
     */
    std::pair<BigInt, BigInt> loadPublicKey(const std::string& keyPath);

    /**
     * @brief Загружает приватный ключ из файла.
     *
     * @param keyPath Путь к файлу с приватным ключом.
     * @return Пара (n, d) - модуль и приватный экспонент.
     */
    std::pair<BigInt, BigInt> loadPrivateKey(const std::string& keyPath);

    /**
     * @brief Преобразует строку в BigInt для шифрования.
     *
     * @param text Исходный текст.
     * @return BigInt представление текста.
     */
    BigInt stringToBigInt(const std::string& text);

    /**
     * @brief Преобразует BigInt обратно в строку.
     *
     * @param bigInt BigInt для преобразования.
     * @return Строка.
     */
    std::string bigIntToString(const BigInt& bigInt);

    /**
     * @brief Добавляет PKCS#1 v1.5 padding к данным.
     *
     * @param data Исходные данные.
     * @param blockSize Размер блока в байтах.
     * @return Данные с padding.
     */
    std::vector<uint8_t> addPKCS1Padding(const std::string& data, size_t blockSize);

    /**
     * @brief Удаляет PKCS#1 v1.5 padding из данных.
     *
     * @param paddedData Данные с padding.
     * @return Исходные данные без padding.
     */
    std::string removePKCS1Padding(const std::vector<uint8_t>& paddedData);

    /**
     * @brief Добавляет PKCS#1 v1.5 padding к байтам.
     *
     * @param data Исходные байты.
     * @param blockSize Размер блока в байтах.
     * @return Байты с padding.
     */
    std::vector<uint8_t> addPKCS1PaddingBytes(const std::vector<uint8_t>& data, size_t blockSize);

    /**
     * @brief Удаляет PKCS#1 v1.5 padding из байтов.
     *
     * @param paddedData Байты с padding.
     * @return Исходные байты без padding.
     */
    std::vector<uint8_t> removePKCS1PaddingBytes(const std::vector<uint8_t>& paddedData);

    /**
     * @brief Создает директорию если она не существует.
     */
    void ensureDirectoryExists();

    /**
     * @brief Параллельно расшифровывает несколько файлов
     *
     * @param inputPaths Вектор путей к зашифрованным файлам
     * @param outputPaths Вектор путей для сохранения расшифрованных файлов
     * @param privateKeyPath Путь к файлу с приватным ключом
     * @return Количество успешно расшифрованных файлов
     */
    int decryptFilesBatch(const std::vector<std::string>& inputPaths,
                         const std::vector<std::string>& outputPaths,
                         const std::string& privateKeyPath);

    /**
     * @brief Быстрая расшифровка с GPU/SIMD ускорением
     *
     * @param ciphertext Зашифрованный текст
     * @param privateKeyPath Путь к приватному ключу
     * @return Расшифрованный текст
     */
    std::string decryptFast(const std::string& ciphertext, const std::string& privateKeyPath);

    /**
     * @brief Быстрое шифрование с GPU/SIMD ускорением
     *
     * @param plaintext Исходный текст
     * @param publicKeyPath Путь к публичному ключу
     * @return Зашифрованный текст
     */
    std::string encryptFast(const std::string& plaintext, const std::string& publicKeyPath);


    /**
     * @brief Модульное возведение в степень с правильной обработкой PKCS#1 padding
     *
     * @param base Основание
     * @param exponent Экспонента
     * @param modulus Модуль
     * @param usePadding Использовать ли PKCS#1 padding
     * @return Результат возведения в степень
     */
    BigInt modExpWithPadding(const BigInt& base, const BigInt& exponent, const BigInt& modulus, bool usePadding);
    BigInt modExpWithPKCS1Padding(const BigInt& base, const BigInt& exponent, const BigInt& modulus);
    BigInt modExpWithMontgomeryConversion(const BigInt& base, const BigInt& exponent, const BigInt& modulus);
    BigInt modExpOptimizedWithoutMontgomery(const BigInt& base, const BigInt& exponent, const BigInt& modulus);
    BigInt modExpSlidingWindow(const BigInt& base, const BigInt& exponent, const BigInt& modulus);
    BigInt modExpOptimizedBinary(const BigInt& base, const BigInt& exponent, const BigInt& modulus);
    
    // Вспомогательные функции для sliding window алгоритма
    int calculateWindowSize(int expBits);
    vector<BigInt> precomputePowers(const BigInt& base, const BigInt& modulus, int windowSize);
    BigInt extractWindowBits(const BigInt& exp, int startBit, int endBit);
};

#endif // RSA_CRYPTO_H
