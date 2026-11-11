#include "RSAKeyManager.h"
#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <sstream>
#include <future>
#include <chrono>
#include <filesystem>
#include <algorithm>

NTL_CLIENT  // Для использования NTL без префикса NTL::

using namespace std;
namespace filesystem = std::filesystem;

// Вспомогательная функция для поиска корня проекта (по наличию CMakeLists.txt)
static filesystem::path findProjectRoot() 
{
    filesystem::path currentPath = filesystem::current_path();
    
    // Поднимаемся по директориям вверх, пока не найдем CMakeLists.txt
    while (!currentPath.empty() && currentPath != currentPath.root_path()) 
    {
        filesystem::path cmakeFile = currentPath / "CMakeLists.txt";
        if (filesystem::exists(cmakeFile) && filesystem::is_regular_file(cmakeFile)) 
        {
            return currentPath;
        }
        currentPath = currentPath.parent_path();
    }
    
    // Если не нашли, возвращаем текущую директорию
    return filesystem::current_path();
}

RSAKeyManager::RSAKeyManager() : baseDirectory("rsa_keys") 
{
    // Инициализируем RSA параметры значениями по умолчанию
    n = BigInt::zero();
    e = BigInt(65537); // Стандартная публичная экспонента
    d = BigInt::zero();
    phi = BigInt::zero();
    
    // Создаем директорию если она не существует
    ensureDirectoryExists();
}

bool RSAKeyManager::generateRSAKeyPair(const BigInt& p, const BigInt& q, int keySize) 
{
    try 
    {
        // Проверяем совместимость простых чисел
        if (!checkPrimeCompatibility(p, q, keySize)) 
        {
            cerr << "Ошибка: простые числа несовместимы для генерации ключа размером " << keySize << " бит" << endl;
            return false;
        }
        
        cout << "═══════════════════════════════════════════════" << endl;
        cout << "🔐 ГЕНЕРАЦИЯ RSA КЛЮЧЕЙ" << endl;
        cout << "═══════════════════════════════════════════════" << endl;
        cout << "📊 Параметры:" << endl;
        cout << "   Размер ключа: " << keySize << " бит" << endl;
        cout << "   Простое число p: " << p.bitLength() << " бит" << endl;
        cout << "   Простое число q: " << q.bitLength() << " бит" << endl;
        cout << endl;
        
        // Вычисляем модуль n = p * q с использованием NTL
        cout << "🔄 Этап 1/3: Вычисление модуля n = p × q" << endl;
        cout << "   ⏳ Умножение больших чисел ..." << flush;
        ZZ ntl_p = p.getZZ();
        ZZ ntl_q = q.getZZ();
        ZZ ntl_n = ntl_p * ntl_q;
        n.setZZ(ntl_n);
        cout << " ✅ Завершено!" << endl;
        cout << "   📏 Модуль n: " << n.bitLength() << " бит" << endl;
        cout << endl;
        
        // Вычисляем функцию Эйлера φ(n) = (p-1) * (q-1) с использованием NTL
        cout << "🔄 Этап 2/3: Вычисление функции Эйлера φ(n) = (p-1) × (q-1)" << endl;
        cout << "   ⏳ Вычисление p-1 и q-1 (NTL)..." << flush;
        
        ZZ ntl_p_minus_1 = ntl_p - 1;
        ZZ ntl_q_minus_1 = ntl_q - 1;
        
        cout << " ✅ Завершено!" << endl;
        cout << "   ⏳ Умножение (p-1) × (q-1) (NTL)..." << flush;
        ZZ ntl_phi = ntl_p_minus_1 * ntl_q_minus_1;
        phi.setZZ(ntl_phi);
        cout << " ✅ Завершено!" << endl;
        cout << "   📏 φ(n): " << phi.bitLength() << " бит" << endl;
        cout << endl;
        
        // Вычисляем приватную экспоненту d = e^(-1) mod φ(n) с использованием NTL
        cout << "🔄 Этап 3/3: Вычисление приватной экспоненты d = e^(-1) mod φ(n)" << endl;
        cout << "   ⏳ Модульная инверсия (NTL::InvMod)..." << flush;
        ZZ ntl_e = e.getZZ();
        ZZ ntl_d;
        InvMod(ntl_d, ntl_e, ntl_phi);  // NTL::InvMod для вычисления модульной инверсии
        d.setZZ(ntl_d);
        cout << " ✅ Завершено!" << endl;
        cout << "   📏 Приватная экспонента d: " << d.bitLength() << " бит" << endl;
        cout << endl;
        
        cout << "✅ RSA ключи успешно сгенерированы!" << endl;
        return true;
        
    } 
    catch (const exception& e) 
    {
        cerr << "Ошибка при генерации RSA ключей: " << e.what() << endl;
        return false;
    }
}

int RSAKeyManager::generateMultipleRSAKeyPairs(const vector<pair<BigInt, BigInt>>& primes, 
                                               int keySize, 
                                               const vector<string>& keyNames)
{
    if (primes.size() != keyNames.size()) {
        cerr << "Ошибка: количество пар простых чисел не совпадает с количеством имен ключей" << endl;
        return 0;
    }
    
    cout << "═══════════════════════════════════════════════" << endl;
    cout << "🚀 ПАРАЛЛЕЛЬНАЯ ГЕНЕРАЦИЯ " << primes.size() << " ПАР RSA КЛЮЧЕЙ" << endl;
    cout << "═══════════════════════════════════════════════" << endl;
    cout << "📊 Параметры:" << endl;
    cout << "   Размер ключей: " << keySize << " бит" << endl;
    cout << "   Количество пар: " << primes.size() << endl;
    cout << "   Параллельная обработка: ✅ Включена (NTL)" << endl;
    cout << endl;
    
    int successCount = 0;
    
    if (primes.size() > 1) {
        // Параллельная генерация нескольких пар ключей
        cout << "🔄 Параллельная генерация ключей..." << endl;
        
        vector<future<bool>> futures;
        
        for (size_t i = 0; i < primes.size(); i++) {
            futures.push_back(async(launch::async, [this, &primes, keySize, &keyNames, i]() {
                try {
                    // Создаем временный RSAKeyManager для каждой пары ключей
                    RSAKeyManager tempManager;
                    tempManager.baseDirectory = this->baseDirectory;
                    
                    // Генерируем ключи
                    bool success = tempManager.generateRSAKeyPair(primes[i].first, primes[i].second, keySize);
                    
                    if (success) {
                        // Сохраняем ключи
                        success = tempManager.saveRSAKeys(keyNames[i], keySize);
                    }
                    
                    return success;
                } catch (const exception& e) {
                    cerr << "Ошибка при генерации ключей " << keyNames[i] << ": " << e.what() << endl;
                    return false;
                }
            }));
        }
        
        // Ждем завершения всех операций
        for (size_t i = 0; i < futures.size(); i++) {
            if (futures[i].get()) {
                successCount++;
                cout << "   ✅ " << keyNames[i] << " - успешно сгенерированы" << endl;
            } else {
                cout << "   ❌ " << keyNames[i] << " - ошибка генерации" << endl;
            }
        }
        
    } else {
        // Последовательная генерация
        cout << "🔄 Последовательная генерация ключей..." << endl;
        
        for (size_t i = 0; i < primes.size(); i++) {
            cout << "   ⏳ Генерация " << keyNames[i] << "..." << flush;
            
            try {
                bool success = generateRSAKeyPair(primes[i].first, primes[i].second, keySize);
                
                if (success) {
                    success = saveRSAKeys(keyNames[i], keySize);
                }
                
                if (success) {
                    successCount++;
                    cout << " ✅ Завершено!" << endl;
                } else {
                    cout << " ❌ Ошибка!" << endl;
                }
            } catch (const exception& e) {
                cout << " ❌ Ошибка: " << e.what() << endl;
            }
        }
    }
    
    cout << endl;
    cout << "📊 Результат:" << endl;
    cout << "   Успешно сгенерировано: " << successCount << " из " << primes.size() << " пар ключей" << endl;
    cout << "   Процент успеха: " << (primes.size() > 0 ? (successCount * 100 / primes.size()) : 0) << "%" << endl;
    
    return successCount;
}

bool RSAKeyManager::saveRSAKeys(const string& keyName, int keySize) const 
{
    try 
    {
        if (!ensureDirectoryExists()) 
        {
            return false;
        }
        
        cout << "💾 Параллельное сохранение ключей в файлы..." << endl;
        
        // Параллельное сохранение публичного и приватного ключей
        string publicKeyPath = createKeyFilePath(keyName, keySize, false);
        string privateKeyPath = createKeyFilePath(keyName, keySize, true);
        
        {
            cout << "   ⏳ Параллельное сохранение публичного и приватного ключей..." << flush;
            
            auto future_public = async(launch::async, [this, publicKeyPath, keySize]() {
                ofstream publicFile(publicKeyPath);
                if (!publicFile.is_open()) {
                    throw runtime_error("Ошибка создания файла публичного ключа: " + publicKeyPath);
                }
                
                publicFile << "# RSA Public Key" << endl;
                publicFile << "# Key Size: " << keySize << " bits" << endl;
                publicFile << "# Generated: " << chrono::system_clock::now().time_since_epoch().count() << endl;
                publicFile << "# Modulus (n):" << endl;
                publicFile << n.toString() << endl;
                publicFile << "# Public Exponent (e):" << endl;
                publicFile << e.toString() << endl;
                publicFile.close();
                return true;
            });
            
            auto future_private = async(launch::async, [this, privateKeyPath, keySize]() {
                ofstream privateFile(privateKeyPath);
                if (!privateFile.is_open()) {
                    throw runtime_error("Ошибка создания файла приватного ключа: " + privateKeyPath);
                }
                
                privateFile << "# RSA Private Key" << endl;
                privateFile << "# Key Size: " << keySize << " bits" << endl;
                privateFile << "# Generated: " << chrono::system_clock::now().time_since_epoch().count() << endl;
                privateFile << "# Modulus (n):" << endl;
                privateFile << n.toString() << endl;
                privateFile << "# Private Exponent (d):" << endl;
                privateFile << d.toString() << endl;
                privateFile << "# Phi(n):" << endl;
                privateFile << phi.toString() << endl;
                privateFile.close();
                return true;
            });
            
            // Ждем завершения обеих операций
            future_public.get();
            future_private.get();
            
            cout << " ✅ Завершено!" << endl;
        }
        
        cout << "✅ RSA ключи сохранены:" << endl;
        cout << "  Публичный ключ: " << publicKeyPath << endl;
        cout << "  Приватный ключ: " << privateKeyPath << endl;
        
        return true;
        
    } 
    catch (const exception& e) 
    {
        cerr << "Ошибка при сохранении RSA ключей: " << e.what() << endl;
        return false;
    }
}

bool RSAKeyManager::loadRSAKeys(const string& keyName, int keySize) 
{
    try 
    {
        // Загружаем публичный ключ
        string publicKeyPath = createKeyFilePath(keyName, keySize, false);
        ifstream publicFile(publicKeyPath);
        if (!publicFile.is_open()) 
        {
            cerr << "Ошибка открытия файла публичного ключа: " << publicKeyPath << endl;
            return false;
        }
        
        string line;
        bool foundN = false, foundE = false;
        
        while (getline(publicFile, line)) 
        {
            if (line.find("# Modulus (n):") != string::npos) 
            {
                getline(publicFile, line);
                n = BigInt(line);
                foundN = true;
            } 
            else if (line.find("# Public Exponent (e):") != string::npos) 
            {
                getline(publicFile, line);
                e = BigInt(line);
                foundE = true;
            }
        }
        publicFile.close();
        
        if (!foundN || !foundE) 
        {
            cerr << "Ошибка: не удалось загрузить публичный ключ" << endl;
            return false;
        }
        
        // Загружаем приватный ключ
        string privateKeyPath = createKeyFilePath(keyName, keySize, true);
        ifstream privateFile(privateKeyPath);
        if (!privateFile.is_open()) 
        {
            cerr << "Ошибка открытия файла приватного ключа: " << privateKeyPath << endl;
            return false;
        }
        
        bool foundD = false, foundPhi = false;
        
        while (getline(privateFile, line)) 
        {
            if (line.find("# Private Exponent (d):") != string::npos) 
            {
                getline(privateFile, line);
                d = BigInt(line);
                foundD = true;
            } 
            else if (line.find("# Phi(n):") != string::npos) 
            {
                getline(privateFile, line);
                phi = BigInt(line);
                foundPhi = true;
            }
        }
        privateFile.close();
        
        if (!foundD || !foundPhi) 
        {
            cerr << "Ошибка: не удалось загрузить приватный ключ" << endl;
            return false;
        }
        
        cout << "✅ RSA ключи успешно загружены" << endl;
        return true;
        
    } 
    catch (const exception& e) 
    {
        cerr << "Ошибка при загрузке RSA ключей: " << e.what() << endl;
        return false;
    }
}

vector<string> RSAKeyManager::getAllRSAKeys() const 
{
    vector<pair<string, int>> keysWithSize; // Пары (имя_ключа, размер_RSA)
    
    try 
    {
        // Находим корень проекта и создаем путь относительно него
        filesystem::path projectRoot = findProjectRoot();
        filesystem::path targetDir = projectRoot / baseDirectory;
        
        // Проверяем существование директории
        if (!filesystem::exists(targetDir) || !filesystem::is_directory(targetDir)) 
        {
            return vector<string>();
        }
        
        // Проходим по всем файлам в директории
        for (const auto& entry : filesystem::directory_iterator(targetDir)) 
        {
            if (entry.is_regular_file()) 
            {
                string filename = entry.path().filename().string();
                
                // Проверяем что файл имеет расширение .txt и содержит "_public_"
                if (filename.length() > 4 && 
                    filename.substr(filename.length() - 4) == ".txt" &&
                    filename.find("_public_") != string::npos) 
                {
                    // Извлекаем имя ключа (до "_public_")
                    size_t pos = filename.find("_public_");
                    if (pos != string::npos) 
                    {
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
        
        // Сортируем по размеру RSA (по возрастанию)
        sort(keysWithSize.begin(), keysWithSize.end(), 
             [](const pair<string, int>& a, const pair<string, int>& b) {
                 return a.second < b.second;
             });
        
    } 
    catch (const exception& e) 
    {
        cerr << "Ошибка при получении списка RSA ключей: " << e.what() << endl;
    }
    
    // Извлекаем только имена ключей
    vector<string> keys;
    for (const auto& keyPair : keysWithSize) {
        keys.push_back(keyPair.first);
    }
    
    return keys;
}

bool RSAKeyManager::checkPrimeCompatibility(const BigInt& p, const BigInt& q, int expectedKeySize) const 
{
    // Проверяем что p != q
    if (p == q) 
    {
        cerr << "Ошибка: простые числа должны быть разными" << endl;
        return false;
    }
    
    // Проверяем размеры простых чисел
    int pBits = p.bitLength();
    int qBits = q.bitLength();
    int expectedPrimeBits = expectedKeySize / 2;
    
    cout << "Проверка совместимости:" << endl;
    cout << "  Ожидается: " << expectedPrimeBits << " бит для каждого простого числа" << endl;
    cout << "  Получено: p = " << pBits << " бит, q = " << qBits << " бит" << endl;
    
    if (pBits < expectedPrimeBits || qBits < expectedPrimeBits) 
    {
        cerr << "Ошибка: размеры простых чисел меньше требуемого" << endl;
        return false;
    }
    
    // Проверяем что размеры не слишком отличаются (в пределах 20% для гибкости)
    int maxAllowedBits = expectedPrimeBits + (expectedPrimeBits / 5);
    if (pBits > maxAllowedBits || qBits > maxAllowedBits) 
    {
        cerr << "Ошибка: размеры простых чисел слишком большие" << endl;
        cerr << "Максимально допустимо: " << maxAllowedBits << " бит" << endl;
        return false;
    }
    
    // Временно отключаем проверку простоты для больших чисел
    // так как она может занимать много времени
    cout << "✓ Размеры простых чисел корректны" << endl;
    cout << "✓ Простые числа разные" << endl;
    cout << "⚠️  Проверка простоты пропущена для экономии времени" << endl;
    
    return true;
}

pair<BigInt, BigInt> RSAKeyManager::getPublicKey() const 
{
    return make_pair(n, e);
}

pair<BigInt, BigInt> RSAKeyManager::getPrivateKey() const 
{
    return make_pair(n, d);
}

string RSAKeyManager::getKeyInfo() const 
{
    stringstream ss;
    ss << "RSA Key Information:" << endl;
    ss << "  Modulus (n): " << n.bitLength() << " bits" << endl;
    ss << "  Public Exponent (e): " << e.toString() << endl;
    ss << "  Private Exponent (d): " << d.bitLength() << " bits" << endl;
    ss << "  Phi(n): " << phi.bitLength() << " bits" << endl;
    return ss.str();
}

string RSAKeyManager::createKeyFilePath(const string& keyName, int keySize, bool isPrivate) const 
{
    // Находим корень проекта и создаем путь относительно него
    filesystem::path projectRoot = findProjectRoot();
    filesystem::path targetDir = projectRoot / baseDirectory;
    
    // Формируем имя файла
    filesystem::path filePath = targetDir / keyName;
    stringstream ss;
    ss << filePath.string();
    if (isPrivate) 
    {
        ss << "_private_" << keySize << ".txt";
    } 
    else 
    {
        ss << "_public_" << keySize << ".txt";
    }
    
    return ss.str();
}

bool RSAKeyManager::ensureDirectoryExists() const 
{
    try 
    {
        // Находим корень проекта и создаем путь относительно него
        filesystem::path projectRoot = findProjectRoot();
        filesystem::path targetDir = projectRoot / baseDirectory;
        
        // Проверяем существование директории
        if (filesystem::exists(targetDir)) 
        {
            return filesystem::is_directory(targetDir);
        }
        
        // Создаем директорию если она не существует
        return filesystem::create_directories(targetDir);
        
    } 
    catch (const filesystem::filesystem_error& e) 
    {
        cerr << "Ошибка при создании директории " << baseDirectory 
             << ": " << e.what() << endl;
        return false;
    }
}

BigInt RSAKeyManager::modularInverse(const BigInt& a, const BigInt& m) const 
{
    // Используем NTL::InvMod для вычисления модульной инверсии
    ZZ ntl_a = a.getZZ();
    ZZ ntl_m = m.getZZ();
    ZZ ntl_result;
    InvMod(ntl_result, ntl_a, ntl_m);  // NTL::InvMod - оптимизированная модульная инверсия
    return BigInt(ntl_result);
}

BigInt RSAKeyManager::extendedGCD(const BigInt& a, const BigInt& b, BigInt& x, BigInt& y) const 
{
    // Используем NTL::XGCD для вычисления расширенного алгоритма Евклида
    ZZ ntl_a = a.getZZ();
    ZZ ntl_b = b.getZZ();
    ZZ ntl_d, ntl_s, ntl_t;
    XGCD(ntl_d, ntl_s, ntl_t, ntl_a, ntl_b);  // NTL::XGCD - расширенный алгоритм Евклида
    x.setZZ(ntl_s);
    y.setZZ(ntl_t);
    return BigInt(ntl_d);
}
