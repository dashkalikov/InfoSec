#include "cryptofacade.h"
#include <QDebug>
#include <QFileInfo>
#include <QDir>
#include <vector>
#include <string>

CryptoFacade::CryptoFacade()
    : m_kuznechik(new KuznechikEncryption())
    , m_rsa(new RSACrypto())
{
}

CryptoFacade::~CryptoFacade()
{
    delete m_kuznechik;
    delete m_rsa;
}

// =============================================================================
// ЕДИНЫЙ ИНТЕРФЕЙС ДЛЯ ШИФРОВАНИЯ И РАСШИФРОВКИ
// =============================================================================

QString CryptoFacade::encrypt(const QString &data, Algorithm algorithm, const QVariant &keyOrKeyPath, DataMode mode)
{
    if (algorithm == Kuznechik) {
        QByteArray key = keyOrKeyPath.value<QByteArray>();
        if (key.isEmpty()) {
            qWarning() << "CryptoFacade: Invalid Kuznechik key";
            return QString();
        }
        
        switch (mode) {
        case TextMode:
            return encryptKuznechikText(data, key);
        case HexMode:
            return encryptKuznechikHex(data, key);
        case BinaryMode:
            return encryptKuznechikBinary(data.toUtf8(), key).toHex(' ').toUpper();
        }
    } else if (algorithm == RSA) {
        QString keyPath = keyOrKeyPath.toString();
        if (keyPath.isEmpty()) {
            qWarning() << "CryptoFacade: Invalid RSA key path";
            return QString();
        }
        
        switch (mode) {
        case TextMode:
            return encryptRSAText(data, keyPath);
        case HexMode:
            return encryptRSAHex(data, keyPath);
        case BinaryMode:
            return encryptRSAText(data, keyPath); // RSA работает со строками
        }
    }
    
    return QString();
}

QString CryptoFacade::decrypt(const QString &encryptedData, Algorithm algorithm, const QVariant &keyOrKeyPath, DataMode mode)
{
    if (algorithm == Kuznechik) {
        QByteArray key = keyOrKeyPath.value<QByteArray>();
        if (key.isEmpty()) {
            qWarning() << "CryptoFacade: Invalid Kuznechik key";
            return QString();
        }
        
        switch (mode) {
        case TextMode:
            return decryptKuznechikText(encryptedData, key);
        case HexMode:
            return decryptKuznechikHex(encryptedData, key);
        case BinaryMode:
            return QString::fromUtf8(decryptKuznechikBinary(QByteArray::fromHex(encryptedData.toLatin1()), key));
        }
    } else if (algorithm == RSA) {
        QString keyPath = keyOrKeyPath.toString();
        if (keyPath.isEmpty()) {
            qWarning() << "CryptoFacade: Invalid RSA key path";
            return QString();
        }
        
        switch (mode) {
        case TextMode:
            return decryptRSAText(encryptedData, keyPath);
        case HexMode:
            return decryptRSAHex(encryptedData, keyPath);
        case BinaryMode:
            return decryptRSAText(encryptedData, keyPath); // RSA работает со строками
        }
    }
    
    return QString();
}

QByteArray CryptoFacade::encryptBinary(const QByteArray &data, Algorithm algorithm, const QVariant &keyOrKeyPath)
{
    if (algorithm == Kuznechik) {
        QByteArray key = keyOrKeyPath.value<QByteArray>();
        if (key.isEmpty()) {
            qWarning() << "CryptoFacade: Invalid Kuznechik key";
            return QByteArray();
        }
        return encryptKuznechikBinary(data, key);
    } else if (algorithm == RSA) {
        QString keyPath = keyOrKeyPath.toString();
        if (keyPath.isEmpty()) {
            qWarning() << "CryptoFacade: Invalid RSA key path";
            return QByteArray();
        }
        // RSA работает со строками, преобразуем бинарные данные в строку
        QString text = QString::fromUtf8(data);
        QString encrypted = encryptRSAText(text, keyPath);
        return encrypted.toUtf8();
    }
    
    return QByteArray();
}

QByteArray CryptoFacade::decryptBinary(const QByteArray &encryptedData, Algorithm algorithm, const QVariant &keyOrKeyPath)
{
    if (algorithm == Kuznechik) {
        QByteArray key = keyOrKeyPath.value<QByteArray>();
        if (key.isEmpty()) {
            qWarning() << "CryptoFacade: Invalid Kuznechik key";
            return QByteArray();
        }
        return decryptKuznechikBinary(encryptedData, key);
    } else if (algorithm == RSA) {
        QString keyPath = keyOrKeyPath.toString();
        if (keyPath.isEmpty()) {
            qWarning() << "CryptoFacade: Invalid RSA key path";
            return QByteArray();
        }
        // RSA работает со строками, преобразуем бинарные данные в строку
        QString encrypted = QString::fromUtf8(encryptedData);
        QString decrypted = decryptRSAText(encrypted, keyPath);
        return decrypted.toUtf8();
    }
    
    return QByteArray();
}

// =============================================================================
// МЕТОДЫ ДЛЯ КУЗНЕЧИКА
// =============================================================================

QByteArray CryptoFacade::generateKuznechikKey()
{
    return m_kuznechik->generateKey();
}

QString CryptoFacade::encryptKuznechikText(const QString &text, const QByteArray &key)
{
    return m_kuznechik->encryptText(text, key);
}

QString CryptoFacade::decryptKuznechikText(const QString &encryptedHex, const QByteArray &key)
{
    return m_kuznechik->decryptText(encryptedHex, key);
}

QString CryptoFacade::encryptKuznechikHex(const QString &hexInput, const QByteArray &key)
{
    return m_kuznechik->encryptHex(hexInput, key);
}

QString CryptoFacade::decryptKuznechikHex(const QString &encryptedHex, const QByteArray &key)
{
    return m_kuznechik->decryptHex(encryptedHex, key);
}

QByteArray CryptoFacade::encryptKuznechikBinary(const QByteArray &data, const QByteArray &key)
{
    return m_kuznechik->encrypt(data, key);
}

QByteArray CryptoFacade::decryptKuznechikBinary(const QByteArray &encryptedData, const QByteArray &key)
{
    return m_kuznechik->decrypt(encryptedData, key);
}

// =============================================================================
// МЕТОДЫ ДЛЯ RSA
// =============================================================================

QString CryptoFacade::encryptRSAText(const QString &text, const QString &publicKeyPath)
{
    try {
        std::string result = m_rsa->encrypt(text.toStdString(), publicKeyPath.toStdString());
        return QString::fromStdString(result);
    } catch (const std::exception &e) {
        qWarning() << "RSA encryption error:" << e.what();
    return QString();
    }
}

QString CryptoFacade::decryptRSAText(const QString &ciphertext, const QString &privateKeyPath)
{
    try {
        std::string result = m_rsa->decrypt(ciphertext.toStdString(), privateKeyPath.toStdString());
        return QString::fromStdString(result);
    } catch (const std::exception &e) {
        qWarning() << "RSA decryption error:" << e.what();
    return QString();
    }
}

QString CryptoFacade::encryptRSAHex(const QString &hexValue, const QString &publicKeyPath)
{
    try {
        std::string result = m_rsa->encryptHex(hexValue.toStdString(), publicKeyPath.toStdString());
        return QString::fromStdString(result);
    } catch (const std::exception &e) {
        qWarning() << "RSA hex encryption error:" << e.what();
    return QString();
    }
}

QString CryptoFacade::decryptRSAHex(const QString &encryptedHex, const QString &privateKeyPath)
{
    try {
        std::string result = m_rsa->decryptHex(encryptedHex.toStdString(), privateKeyPath.toStdString());
        return QString::fromStdString(result);
    } catch (const std::exception &e) {
        qWarning() << "RSA hex decryption error:" << e.what();
    return QString();
    }
}

bool CryptoFacade::encryptRSAFile(const QString &inputFilePath, const QString &outputFilePath, const QString &publicKeyPath)
{
    try {
        return m_rsa->encryptFile(inputFilePath.toStdString(), outputFilePath.toStdString(), publicKeyPath.toStdString());
    } catch (const std::exception &e) {
        qWarning() << "RSA file encryption error:" << e.what();
    return false;
    }
}

bool CryptoFacade::decryptRSAFile(const QString &inputFilePath, const QString &outputFilePath, const QString &privateKeyPath)
{
    try {
        return m_rsa->decryptFile(inputFilePath.toStdString(), outputFilePath.toStdString(), privateKeyPath.toStdString());
    } catch (const std::exception &e) {
        qWarning() << "RSA file decryption error:" << e.what();
    return false;
    }
}

QStringList CryptoFacade::getAvailableRSAKeys() const
{
    QStringList result;
    std::vector<std::string> keys = m_rsa->getAvailableKeys();
    for (const auto &key : keys) {
        result.append(QString::fromStdString(key));
    }
    return result;
}

bool CryptoFacade::rsaKeyExists(const QString &keyName) const
{
    return m_rsa->keyExists(keyName.toStdString());
}

QString CryptoFacade::getRSAKeyInfo(const QString &keyName) const
{
    return QString::fromStdString(m_rsa->getKeyInfo(keyName.toStdString()));
}

// =============================================================================
// ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
// =============================================================================

QString CryptoFacade::convertStdStringToQString(const std::string &str) const
{
    return QString::fromStdString(str);
}

std::string CryptoFacade::convertQStringToStdString(const QString &str) const
{
    return str.toStdString();
}

QByteArray CryptoFacade::convertStdStringToQByteArray(const std::string &str) const
{
    return QByteArray(str.data(), static_cast<int>(str.size()));
}

std::string CryptoFacade::convertQByteArrayToStdString(const QByteArray &data) const
{
    return std::string(data.data(), static_cast<size_t>(data.size()));
}

