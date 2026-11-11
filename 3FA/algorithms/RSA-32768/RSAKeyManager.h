#ifndef RSA_KEY_MANAGER_H
#define RSA_KEY_MANAGER_H

#include "BigInt.h"             // Для работы с большими целыми числами
#include "PrimeFileManager.h"   // Для работы с файлами простых чисел
#include <string>               // Для работы со строками
#include <vector>               // Для работы с векторами
#include <sstream>              // Для форматирования строк
#include <iostream>             // Для вывода ошибок

// =============================================================================
// МЕНЕДЖЕР RSA КЛЮЧЕЙ
// =============================================================================

/**
 * @brief Класс для управления RSA ключами.
 *
 * Предоставляет функциональность для генерации, сохранения, загрузки и управления
 * RSA ключами. Ключи хранятся в директории `rsa_keys/` в корневой директории проекта.
 * Поддерживает различные размеры RSA ключей (1024, 2048, 4096, 8192, 16384, 32768 бит).
 */
class RSAKeyManager {
public:
    /**
     * @brief Конструктор класса RSAKeyManager.
     *
     * Инициализирует базовую директорию для хранения RSA ключей и
     * создает ее, если она не существует.
     */
    RSAKeyManager();

    /**
     * @brief Генерирует RSA ключевую пару.
     *
     * Использует два простых числа для генерации RSA ключей.
     * Вычисляет n = p * q, φ(n) = (p-1) * (q-1), выбирает e = 65537,
     * и вычисляет d = e^(-1) mod φ(n).
     *
     * @param p Первое простое число
     * @param q Второе простое число
     * @param keySize Размер ключа в битах (для именования файлов)
     * @return true, если генерация прошла успешно, false в противном случае
     */
    bool generateRSAKeyPair(const BigInt& p, const BigInt& q, int keySize);

    /**
     * @brief Генерирует несколько пар RSA ключей параллельно
     * 
     * @param primes Вектор пар простых чисел (p, q)
     * @param keySize Размер ключей в битах
     * @param keyNames Вектор имен для ключей
     * @return Количество успешно сгенерированных пар ключей
     */
    int generateMultipleRSAKeyPairs(const std::vector<std::pair<BigInt, BigInt>>& primes, 
                                   int keySize, 
                                   const std::vector<std::string>& keyNames);

    /**
     * @brief Сохраняет RSA ключи в файлы.
     *
     * Сохраняет публичный и приватный ключи в отдельные файлы.
     * Формат файлов: {keyName}_public_{keySize}.txt и {keyName}_private_{keySize}.txt
     *
     * @param keyName Имя для ключей (без расширения)
     * @param keySize Размер ключа в битах
     * @return true, если сохранение прошло успешно, false в противном случае
     */
    bool saveRSAKeys(const std::string& keyName, int keySize) const;

    /**
     * @brief Загружает RSA ключи из файлов.
     *
     * @param keyName Имя ключей (без расширения)
     * @param keySize Размер ключа в битах
     * @return true, если загрузка прошла успешно, false в противном случае
     */
    bool loadRSAKeys(const std::string& keyName, int keySize);

    /**
     * @brief Получает список всех RSA ключей в директории.
     *
     * @return Вектор строк с именами ключей
     */
    std::vector<std::string> getAllRSAKeys() const;

    /**
     * @brief Проверяет совместимость размеров простых чисел.
     *
     * @param p Первое простое число
     * @param q Второе простое число
     * @param expectedKeySize Ожидаемый размер ключа в битах
     * @return true, если размеры совместимы, false в противном случае
     */
    bool checkPrimeCompatibility(const BigInt& p, const BigInt& q, int expectedKeySize) const;

    /**
     * @brief Получает публичный ключ (n, e).
     *
     * @return Пара (n, e) где n - модуль, e - публичная экспонента
     */
    std::pair<BigInt, BigInt> getPublicKey() const;

    /**
     * @brief Получает приватный ключ (n, d).
     *
     * @return Пара (n, d) где n - модуль, d - приватная экспонента
     */
    std::pair<BigInt, BigInt> getPrivateKey() const;

    /**
     * @brief Получает информацию о текущих ключах.
     *
     * @return Строка с информацией о ключах
     */
    std::string getKeyInfo() const;

private:
    std::string baseDirectory; // Базовая директория для хранения ключей
    
    // RSA параметры
    BigInt n;  // Модуль n = p * q
    BigInt e;  // Публичная экспонента (обычно 65537)
    BigInt d;  // Приватная экспонента d = e^(-1) mod φ(n)
    BigInt phi; // Функция Эйлера φ(n) = (p-1) * (q-1)

    /**
     * @brief Формирует полный путь к файлу ключа.
     *
     * @param keyName Имя ключа
     * @param keySize Размер ключа в битах
     * @param isPrivate true для приватного ключа, false для публичного
     * @return Полный путь к файлу
     */
    std::string createKeyFilePath(const std::string& keyName, int keySize, bool isPrivate) const;

    /**
     * @brief Проверяет существование базовой директории и создает ее, если она не существует.
     * @return true, если директория существует или успешно создана, false в противном случае
     */
    bool ensureDirectoryExists() const;

    /**
     * @brief Вычисляет модульную инверсию с использованием NTL.
     *
     * Использует NTL::InvMod для оптимизированного вычисления модульной инверсии.
     *
     * @param a Число для инверсии
     * @param m Модуль
     * @return a^(-1) mod m
     */
    BigInt modularInverse(const BigInt& a, const BigInt& m) const;

    /**
     * @brief Расширенный алгоритм Евклида с использованием NTL.
     *
     * Использует NTL::XGCD для оптимизированного вычисления расширенного алгоритма Евклида.
     *
     * @param a Первое число
     * @param b Второе число
     * @param x Коэффициент для a (выходной параметр)
     * @param y Коэффициент для b (выходной параметр)
     * @return НОД(a, b)
     */
    BigInt extendedGCD(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y) const;
};

#endif // RSA_KEY_MANAGER_H
