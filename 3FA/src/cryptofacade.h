#ifndef CRYPTOFACADE_H
#define CRYPTOFACADE_H

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVariant>
#include "kuznechikencryption.h"
#include "RSACrypto.h"
#include "RSAKeyManager.h"
#include "PrimeFileManager.h"

/**
 * @brief Фасад для работы с криптографическими алгоритмами RSA и Кузнечик
 * 
 * Предоставляет единый интерфейс для работы с алгоритмами шифрования:
 * - RSA (RSA-32768)
 * - Кузнечик (ГОСТ Р 34.12-2015)
 * 
 * Фасад скрывает детали реализации каждого алгоритма и предоставляет
 * унифицированный API для шифрования и расшифровки данных.
 */
class CryptoFacade
{
public:
    /**
     * @brief Типы алгоритмов шифрования
     */
    enum Algorithm {
        Kuznechik,  ///< Алгоритм Кузнечик (ГОСТ Р 34.12-2015)
        RSA         ///< Алгоритм RSA
    };

    /**
     * @brief Режимы работы с данными
     */
    enum DataMode {
        TextMode,   ///< Работа с текстом (UTF-8)
        HexMode,    ///< Работа с hex данными
        BinaryMode  ///< Работа с бинарными данными
    };

    /**
     * @brief Конструктор фасада
     */
    CryptoFacade();

    /**
     * @brief Деструктор фасада
     */
    ~CryptoFacade();

    // =============================================================================
    // ЕДИНЫЙ ИНТЕРФЕЙС ДЛЯ ШИФРОВАНИЯ И РАСШИФРОВКИ
    // =============================================================================

    /**
     * @brief Шифрует данные с использованием выбранного алгоритма
     * 
     * @param data Данные для шифрования
     * @param algorithm Алгоритм шифрования (Kuznechik или RSA)
     * @param keyOrKeyPath Для Kuznechik: ключ (QByteArray), для RSA: путь к публичному ключу (QString)
     * @param mode Режим работы с данными (TextMode, HexMode, BinaryMode)
     * @return Зашифрованные данные (формат зависит от режима)
     */
    QString encrypt(const QString &data, Algorithm algorithm, const QVariant &keyOrKeyPath, DataMode mode = TextMode);

    /**
     * @brief Расшифровывает данные с использованием выбранного алгоритма
     * 
     * @param encryptedData Зашифрованные данные
     * @param algorithm Алгоритм шифрования (Kuznechik или RSA)
     * @param keyOrKeyPath Для Kuznechik: ключ (QByteArray), для RSA: путь к приватному ключу (QString)
     * @param mode Режим работы с данными (TextMode, HexMode, BinaryMode)
     * @return Расшифрованные данные (формат зависит от режима)
     */
    QString decrypt(const QString &encryptedData, Algorithm algorithm, const QVariant &keyOrKeyPath, DataMode mode = TextMode);

    /**
     * @brief Шифрует бинарные данные
     * 
     * @param data Бинарные данные для шифрования
     * @param algorithm Алгоритм шифрования
     * @param keyOrKeyPath Ключ или путь к ключу
     * @return Зашифрованные бинарные данные
     */
    QByteArray encryptBinary(const QByteArray &data, Algorithm algorithm, const QVariant &keyOrKeyPath);

    /**
     * @brief Расшифровывает бинарные данные
     * 
     * @param encryptedData Зашифрованные бинарные данные
     * @param algorithm Алгоритм шифрования
     * @param keyOrKeyPath Ключ или путь к ключу
     * @return Расшифрованные бинарные данные
     */
    QByteArray decryptBinary(const QByteArray &encryptedData, Algorithm algorithm, const QVariant &keyOrKeyPath);

    // =============================================================================
    // МЕТОДЫ ДЛЯ КУЗНЕЧИКА
    // =============================================================================

    /**
     * @brief Генерирует ключ для алгоритма Кузнечик (256 бит)
     * @return Сгенерированный ключ
     */
    QByteArray generateKuznechikKey();

    /**
     * @brief Шифрует текст с использованием Кузнечика
     * @param text Текст для шифрования
     * @param key Ключ шифрования (32 байта)
     * @return Зашифрованные данные в hex формате
     */
    QString encryptKuznechikText(const QString &text, const QByteArray &key);

    /**
     * @brief Расшифровывает текст с использованием Кузнечика
     * @param encryptedHex Зашифрованные данные в hex формате
     * @param key Ключ шифрования (32 байта)
     * @return Расшифрованный текст
     */
    QString decryptKuznechikText(const QString &encryptedHex, const QByteArray &key);

    /**
     * @brief Шифрует hex данные с использованием Кузнечика
     * @param hexInput Входные данные в hex формате
     * @param key Ключ шифрования (32 байта)
     * @return Зашифрованные данные в hex формате
     */
    QString encryptKuznechikHex(const QString &hexInput, const QByteArray &key);

    /**
     * @brief Расшифровывает hex данные с использованием Кузнечика
     * @param encryptedHex Зашифрованные данные в hex формате
     * @param key Ключ шифрования (32 байта)
     * @return Расшифрованные данные в hex формате
     */
    QString decryptKuznechikHex(const QString &encryptedHex, const QByteArray &key);

    /**
     * @brief Шифрует бинарные данные с использованием Кузнечика
     * @param data Данные для шифрования
     * @param key Ключ шифрования (32 байта)
     * @return Зашифрованные данные
     */
    QByteArray encryptKuznechikBinary(const QByteArray &data, const QByteArray &key);

    /**
     * @brief Расшифровывает бинарные данные с использованием Кузнечика
     * @param encryptedData Зашифрованные данные
     * @param key Ключ шифрования (32 байта)
     * @return Расшифрованные данные
     */
    QByteArray decryptKuznechikBinary(const QByteArray &encryptedData, const QByteArray &key);

    // =============================================================================
    // МЕТОДЫ ДЛЯ RSA
    // =============================================================================

    /**
     * @brief Шифрует текст с использованием RSA
     * @param text Текст для шифрования
     * @param publicKeyPath Путь к файлу с публичным ключом
     * @return Зашифрованный текст
     */
    QString encryptRSAText(const QString &text, const QString &publicKeyPath);

    /**
     * @brief Расшифровывает текст с использованием RSA
     * @param ciphertext Зашифрованный текст
     * @param privateKeyPath Путь к файлу с приватным ключом
     * @return Расшифрованный текст
     */
    QString decryptRSAText(const QString &ciphertext, const QString &privateKeyPath);

    /**
     * @brief Шифрует hex данные с использованием RSA
     * @param hexValue Hex значение для шифрования
     * @param publicKeyPath Путь к файлу с публичным ключом
     * @return Зашифрованное значение в hex формате
     */
    QString encryptRSAHex(const QString &hexValue, const QString &publicKeyPath);

    /**
     * @brief Расшифровывает hex данные с использованием RSA
     * @param encryptedHex Зашифрованное hex значение
     * @param privateKeyPath Путь к файлу с приватным ключом
     * @return Расшифрованное значение в hex формате
     */
    QString decryptRSAHex(const QString &encryptedHex, const QString &privateKeyPath);

    /**
     * @brief Шифрует файл с использованием RSA
     * @param inputFilePath Путь к исходному файлу
     * @param outputFilePath Путь к файлу для сохранения зашифрованных данных
     * @param publicKeyPath Путь к файлу с публичным ключом
     * @return true, если шифрование прошло успешно
     */
    bool encryptRSAFile(const QString &inputFilePath, const QString &outputFilePath, const QString &publicKeyPath);

    /**
     * @brief Расшифровывает файл с использованием RSA
     * @param inputFilePath Путь к зашифрованному файлу
     * @param outputFilePath Путь к файлу для сохранения расшифрованных данных
     * @param privateKeyPath Путь к файлу с приватным ключом
     * @return true, если расшифровка прошла успешно
     */
    bool decryptRSAFile(const QString &inputFilePath, const QString &outputFilePath, const QString &privateKeyPath);

    /**
     * @brief Получает список доступных RSA ключей
     * @return Список имен доступных ключей
     */
    QStringList getAvailableRSAKeys() const;

    /**
     * @brief Проверяет существование RSA ключа
     * @param keyName Имя ключа (без расширения)
     * @return true, если ключ существует
     */
    bool rsaKeyExists(const QString &keyName) const;

    /**
     * @brief Получает информацию о RSA ключе
     * @param keyName Имя ключа (без расширения)
     * @return Строка с информацией о ключе
     */
    QString getRSAKeyInfo(const QString &keyName) const;

    // =============================================================================
    // ПРЯМОЙ ДОСТУП К ОРИГИНАЛЬНЫМ КЛАССАМ (для сохранения полного функционала)
    // =============================================================================

    /**
     * @brief Получает прямой доступ к объекту KuznechikEncryption
     * @return Указатель на объект KuznechikEncryption
     */
    KuznechikEncryption* getKuznechik() { return m_kuznechik; }

    /**
     * @brief Получает прямой доступ к объекту RSACrypto
     * @return Указатель на объект RSACrypto
     */
    RSACrypto* getRSA() { return m_rsa; }

private:
    KuznechikEncryption *m_kuznechik;  ///< Объект для работы с Кузнечиком
    RSACrypto *m_rsa;                  ///< Объект для работы с RSA

    // Вспомогательные методы
    QString convertStdStringToQString(const std::string &str) const;
    std::string convertQStringToStdString(const QString &str) const;
    QByteArray convertStdStringToQByteArray(const std::string &str) const;
    std::string convertQByteArrayToStdString(const QByteArray &data) const;
};

#endif // CRYPTOFACADE_H

