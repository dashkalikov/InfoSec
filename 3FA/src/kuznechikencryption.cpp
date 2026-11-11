#include "kuznechikencryption.h"
#include <QDebug>
#include <QRandomGenerator>

KuznechikEncryption::KuznechikEncryption()
{
}

KuznechikEncryption::~KuznechikEncryption()
{
}

QByteArray KuznechikEncryption::generateKey()
{
    // Используем Qt-генератор для быстрой генерации криптографически стойкого ключа
    QByteArray key;
    key.resize(32);
    QRandomGenerator *rng = QRandomGenerator::system();
    for (int i = 0; i < 32; i++) {
        key[i] = static_cast<char>(rng->bounded(256));
    }
    return key;
}

void KuznechikEncryption::computeRoundKeys(const QByteArray &key, Block128 roundKeys[10])
{
    if (key.size() != 32) {
        qWarning() << "Invalid key size:" << key.size() << "(expected 32 bytes)";
        return;
    }
    
    std::vector<uint8_t> keyVec(32);
    for (int i = 0; i < 32; i++) {
        keyVec[i] = static_cast<uint8_t>(key[i] & 0xFF);
    }
    
    m_kuznechik.compute_round_keys(keyVec, roundKeys);
}

std::vector<Block128> KuznechikEncryption::dataToBlocks(const QByteArray &data)
{
    std::vector<Block128> blocks;
    QByteArray padded = padData(data);
    
    for (int i = 0; i < padded.size(); i += 16) {
        Block128 block;
        for (int j = 0; j < 16; j++) {
            if (i + j < padded.size()) {
                block.set_byte(j, static_cast<unsigned char>(padded[i + j] & 0xFF));
            } else {
                block.set_byte(j, 0);
            }
        }
        blocks.push_back(block);
    }
    
    return blocks;
}

QByteArray KuznechikEncryption::blocksToData(const std::vector<Block128> &blocks)
{
    QByteArray data;
    data.reserve(blocks.size() * 16);
    
    for (const Block128 &block : blocks) {
        unsigned char bytes[16];
        block.get_all_bytes(bytes);
        for (int i = 0; i < 16; i++) {
            data.append(static_cast<char>(bytes[i]));
        }
    }
    
    return unpadData(data);
}

QByteArray KuznechikEncryption::padData(const QByteArray &data)
{
    QByteArray padded = data;
    int paddingSize = 16 - (data.size() % 16);
    if (paddingSize == 16) {
        paddingSize = 0;
    }
    
    // PKCS#7 padding
    if (paddingSize > 0) {
        for (int i = 0; i < paddingSize; i++) {
            padded.append(static_cast<char>(paddingSize));
        }
    }
    
    return padded;
}

QByteArray KuznechikEncryption::unpadData(const QByteArray &data)
{
    if (data.isEmpty()) {
        return QByteArray();
    }
    
    int paddingSize = static_cast<unsigned char>(data[data.size() - 1]);
    
    // Проверка корректности паддинга
    if (paddingSize < 1 || paddingSize > 16 || data.size() < paddingSize) {
        // Если паддинг некорректен, возвращаем данные как есть
        return data;
    }
    
    // Проверяем, что все байты паддинга одинаковы
    bool validPadding = true;
    for (int i = data.size() - paddingSize; i < data.size(); i++) {
        if (static_cast<unsigned char>(data[i]) != paddingSize) {
            validPadding = false;
            break;
        }
    }
    
    if (!validPadding) {
        return data;
    }
    
    return data.left(data.size() - paddingSize);
}

QByteArray KuznechikEncryption::encrypt(const QByteArray &data, const QByteArray &key)
{
    if (key.size() != 32) {
        qWarning() << "Invalid key size:" << key.size() << "(expected 32 bytes)";
        return QByteArray();
    }
    
    Block128 roundKeys[10];
    computeRoundKeys(key, roundKeys);
    
    // Добавляем паддинг перед разбиением на блоки
    QByteArray padded = padData(data);
    std::vector<Block128> blocks;
    
    // Разбиваем на блоки по 16 байт
    for (int i = 0; i < padded.size(); i += 16) {
        Block128 block;
        for (int j = 0; j < 16; j++) {
            block.set_byte(j, static_cast<unsigned char>(padded[i + j] & 0xFF));
        }
        blocks.push_back(block);
    }
    
    // Шифруем каждый блок
    for (auto &block : blocks) {
        m_kuznechik.encrypt_block(block, roundKeys);
    }
    
    // Преобразуем зашифрованные блоки обратно в QByteArray (с паддингом)
    QByteArray result;
    result.reserve(blocks.size() * 16);
    for (const Block128 &block : blocks) {
        unsigned char bytes[16];
        block.get_all_bytes(bytes);
        for (int i = 0; i < 16; i++) {
            result.append(static_cast<char>(bytes[i]));
        }
    }
    
    return result;
}

QByteArray KuznechikEncryption::decrypt(const QByteArray &encryptedData, const QByteArray &key)
{
    if (key.size() != 32) {
        qWarning() << "Invalid key size:" << key.size() << "(expected 32 bytes)";
        return QByteArray();
    }
    
    Block128 roundKeys[10];
    computeRoundKeys(key, roundKeys);
    
    // Преобразуем зашифрованные данные в блоки (размер должен быть кратным 16)
    if (encryptedData.size() % 16 != 0) {
        qWarning() << "Invalid encrypted data size:" << encryptedData.size() << "(must be multiple of 16)";
        return QByteArray();
    }
    
    std::vector<Block128> blocks;
    for (int i = 0; i < encryptedData.size(); i += 16) {
        Block128 block;
        for (int j = 0; j < 16; j++) {
            block.set_byte(j, static_cast<unsigned char>(encryptedData[i + j] & 0xFF));
        }
        blocks.push_back(block);
    }
    
    for (auto &block : blocks) {
        m_kuznechik.decrypt_block(block, roundKeys);
    }
    
    // Преобразуем расшифрованные блоки обратно в QByteArray и убираем паддинг
    QByteArray data;
    data.reserve(blocks.size() * 16);
    for (const Block128 &block : blocks) {
        unsigned char bytes[16];
        block.get_all_bytes(bytes);
        for (int i = 0; i < 16; i++) {
            data.append(static_cast<char>(bytes[i]));
        }
    }
    
    return unpadData(data);
}

QString KuznechikEncryption::encryptText(const QString &text, const QByteArray &key)
{
    QByteArray textBytes = text.toUtf8();
    QByteArray encrypted = encrypt(textBytes, key);
    return toHex(encrypted);
}

QString KuznechikEncryption::decryptText(const QString &encryptedHex, const QByteArray &key)
{
    QByteArray encrypted = fromHex(encryptedHex);
    QByteArray decrypted = decrypt(encrypted, key);
    return QString::fromUtf8(decrypted);
}

QString KuznechikEncryption::encryptHex(const QString &hexInput, const QByteArray &key)
{
    QByteArray input = fromHex(hexInput);
    QByteArray encrypted = encrypt(input, key);
    // Сохраняем формат входных данных для результата
    return formatHex(encrypted, hexInput);
}

QString KuznechikEncryption::decryptHex(const QString &encryptedHex, const QByteArray &key)
{
    QByteArray encrypted = fromHex(encryptedHex);
    QByteArray decrypted = decrypt(encrypted, key);
    // Сохраняем формат входных данных для результата
    return formatHex(decrypted, encryptedHex);
}

QString KuznechikEncryption::toHex(const QByteArray &data)
{
    return data.toHex(' ').toUpper();
}

QByteArray KuznechikEncryption::fromHex(const QString &hexString)
{
    QString cleaned = hexString.trimmed();
    
    // Удаляем все пробелы, дефисы и двоеточия
    cleaned.remove(QChar(' '));
    cleaned.remove(QChar('-'));
    cleaned.remove(QChar(':'));
    
    // Удаляем префиксы 0x и 0X (для поддержки формата 0x11 0x22)
    cleaned.replace("0x", "", Qt::CaseInsensitive);
    cleaned.replace("0X", "", Qt::CaseInsensitive);
    
    return QByteArray::fromHex(cleaned.toLatin1());
}

QString KuznechikEncryption::formatHex(const QByteArray &data, const QString &originalFormat)
{
    QString cleaned = originalFormat.trimmed();
    
    // Определяем формат по оригинальной строке
    bool has0xPrefix = cleaned.contains("0x", Qt::CaseInsensitive);
    bool hasSpaces = cleaned.contains(' ');
    bool hasHyphens = cleaned.contains('-');
    bool hasColons = cleaned.contains(':');
    
    // Приоритет: 0x с пробелами > пробелы > дефисы > двоеточия > без разделителей
    QString hexString = data.toHex().toUpper();
    QString result;
    
    if (has0xPrefix) {
        // Формат 0x11 0x22 ...
        for (int i = 0; i < hexString.length(); i += 2) {
            if (i > 0 && hasSpaces) {
                result += " ";
            }
            result += "0x" + hexString.mid(i, 2);
        }
    } else if (hasSpaces) {
        // Формат 11 22 33 ...
        for (int i = 0; i < hexString.length(); i += 2) {
            if (i > 0) {
                result += " ";
            }
            result += hexString.mid(i, 2);
        }
    } else if (hasHyphens) {
        // Формат 11-22-33 ...
        for (int i = 0; i < hexString.length(); i += 2) {
            if (i > 0) {
                result += "-";
            }
            result += hexString.mid(i, 2);
        }
    } else if (hasColons) {
        // Формат 11:22:33 ...
        for (int i = 0; i < hexString.length(); i += 2) {
            if (i > 0) {
                result += ":";
            }
            result += hexString.mid(i, 2);
        }
    } else {
        // Без разделителей
        result = hexString;
    }
    
    return result;
}

