#ifndef KUZNECHIKENCRYPTION_H
#define KUZNECHIKENCRYPTION_H

#include <QByteArray>
#include <QString>
#include <vector>
#include "kuznechik_constants.h"

/**
 * @brief Qt-обертка для алгоритма шифрования Кузнечик (ГОСТ Р 34.12-2015)
 * 
 * Предоставляет удобный интерфейс для работы с алгоритмом Кузнечик,
 * используя Qt типы (QByteArray, QString) вместо стандартных C++ типов.
 */
class KuznechikEncryption
{
public:
    KuznechikEncryption();
    ~KuznechikEncryption();

    /**
     * @brief Генерирует криптографически стойкий ключ 256 бит (32 байта)
     * @return QByteArray с ключом
     */
    QByteArray generateKey();

    /**
     * @brief Шифрует данные с использованием алгоритма Кузнечик
     * @param data данные для шифрования
     * @param key ключ шифрования (32 байта)
     * @return зашифрованные данные
     */
    QByteArray encrypt(const QByteArray &data, const QByteArray &key);

    /**
     * @brief Расшифровывает данные с использованием алгоритма Кузнечик
     * @param encryptedData зашифрованные данные
     * @param key ключ шифрования (32 байта)
     * @return расшифрованные данные
     */
    QByteArray decrypt(const QByteArray &encryptedData, const QByteArray &key);

    /**
     * @brief Шифрует текст (UTF-8)
     * @param text текст для шифрования
     * @param key ключ шифрования (32 байта)
     * @return зашифрованные данные в hex формате
     */
    QString encryptText(const QString &text, const QByteArray &key);

    /**
     * @brief Расшифровывает текст (UTF-8)
     * @param encryptedHex зашифрованные данные в hex формате
     * @param key ключ шифрования (32 байта)
     * @return расшифрованный текст
     */
    QString decryptText(const QString &encryptedHex, const QByteArray &key);

    /**
     * @brief Шифрует байты (hex формат)
     * @param hexInput входные данные в hex формате
     * @param key ключ шифрования (32 байта)
     * @return зашифрованные данные в hex формате
     */
    QString encryptHex(const QString &hexInput, const QByteArray &key);

    /**
     * @brief Расшифровывает байты (hex формат)
     * @param encryptedHex зашифрованные данные в hex формате
     * @param key ключ шифрования (32 байта)
     * @return расшифрованные данные в hex формате
     */
    QString decryptHex(const QString &encryptedHex, const QByteArray &key);

    /**
     * @brief Преобразует QByteArray в hex строку
     */
    static QString toHex(const QByteArray &data);

    /**
     * @brief Преобразует hex строку в QByteArray
     */
    static QByteArray fromHex(const QString &hexString);

    /**
     * @brief Форматирует hex данные в указанном формате
     * @param data данные для форматирования
     * @param originalFormat исходная строка для определения формата
     * @return отформатированная hex строка
     */
    static QString formatHex(const QByteArray &data, const QString &originalFormat);

private:
    KuznechikConstants m_kuznechik;
    
    // Вспомогательные методы
    QByteArray padData(const QByteArray &data);
    QByteArray unpadData(const QByteArray &data);
    std::vector<Block128> dataToBlocks(const QByteArray &data);
    QByteArray blocksToData(const std::vector<Block128> &blocks);
    void computeRoundKeys(const QByteArray &key, Block128 roundKeys[10]);
};

#endif // KUZNECHIKENCRYPTION_H

