#include "BigInt.h"             // Основной класс для работы с большими целыми числами (обертка над NTL::ZZ)
#include "PrimeFileManager.h"   // Менеджер файлов для сохранения простых чисел
#include "RSAKeyManager.h"      // Менеджер RSA ключей
#include "RSACrypto.h"          // RSA шифрование и расшифровка
#include <NTL/ZZ.h>             // NTL для генерации простых чисел
#include <iostream>             // Ввод/вывод для пользовательского интерфейса
#include <chrono>               // Высокоточное измерение времени выполнения
#include <string>               // Строки для обработки аргументов командной строки
#include <filesystem>           // Работа с файловой системой
#include <algorithm>            // Алгоритмы для поиска в контейнерах
#include <vector>               // Вектор для байтов
#include <thread>               // Потоки для индикатора прогресса
#include <atomic>               // Атомарные операции для спиннера
#include <limits>               // Для numeric_limits
#include <utility>              // Для pair

// OpenSSL библиотека для независимой верификации простоты (условная компиляция)
#ifdef OPENSSL_FOUND
#include <openssl/bn.h>
#endif

#ifdef _WIN32
extern "C" __declspec(dllimport) int __stdcall SetConsoleOutputCP(unsigned int);
extern "C" __declspec(dllimport) int __stdcall SetConsoleCP(unsigned int);
#include <io.h>                 // Для _setmode
#include <fcntl.h>              // Для _O_U8TEXT

// Объявления Windows API функций без включения windows.h (избегаем конфликта с std::byte)
typedef void* HANDLE;
typedef unsigned long DWORD;
#define STD_INPUT_HANDLE ((DWORD)-10)
#define INVALID_HANDLE_VALUE ((HANDLE)((long)-1))
extern "C" __declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
extern "C" __declspec(dllimport) int __stdcall ReadConsoleW(HANDLE, void*, DWORD, DWORD*, void*);
extern "C" __declspec(dllimport) int __stdcall WideCharToMultiByte(unsigned int, DWORD, const wchar_t*, int, char*, int, const char*, int*);
#define CP_UTF8 65001
#endif

using namespace std;
namespace filesystem = std::filesystem;  // Алиас для filesystem
NTL_CLIENT  // Для использования NTL без префикса NTL::

// Функция для очистки консоли (кроссплатформенная)
void clearConsole() 
{
#ifdef _WIN32
    system("cls");
#elif defined(__APPLE__) || defined(__linux__)
    system("clear");
#else
    // Fallback для неизвестных платформ
    cout << "\033[2J\033[1;1H"; // ANSI escape codes
#endif
}

// Функция для отображения анимированного спиннера прогресса
class ProgressSpinner {
private:
    thread spinnerThread;
    atomic<bool> running;
    string message;
    
public:
    // Порядок инициализации должен соответствовать порядку объявления полей
    ProgressSpinner(const string& msg) : running(false), message(msg) {}
    
    void start() {
        running = true;
        spinnerThread = thread([this]() {
            const char spinner[] = {'|', '/', '-', '\\'};
            int spinnerIndex = 0;
            
            while (running) {
                cout << '\r' << message << " " << spinner[spinnerIndex] << flush;
                spinnerIndex = (spinnerIndex + 1) % 4;
                this_thread::sleep_for(chrono::milliseconds(100));
            }
        });
    }
    
    void stop() {
        running = false;
        if (spinnerThread.joinable()) {
            spinnerThread.join();
        }
        // Очищаем строку со спиннером
        cout << '\r' << string(message.length() + 2, ' ') << '\r' << flush;
    }
    
    ~ProgressSpinner() {
        stop();
    }
};

// ============================================================================
// ГЛОБАЛЬНАЯ ИНИЦИАЛИЗАЦИЯ ПАРАЛЛЕЛЬНОЙ ОБРАБОТКИ
// ============================================================================

/**
 * @brief RAII инициализатор для криптографических вычислений
 * 
 * Инициализирует:
 * - NTL библиотеку для криптографических вычислений
 * 
 * Примечание: Генерация простых чисел выполняется через NTL библиотеку,
 * которая имеет встроенную многопоточную поддержку для больших чисел (>=256 бит)
 */
struct ParallelProcessingInitializer 
{
    /**
     * @brief Инициализация криптографических примитивов
     * 
     * Выполняет:
     * 1. Инициализация NTL библиотеки
     * 2. Настройка кодировки консоли для Windows
     */
    ParallelProcessingInitializer() 
    {
#ifdef _WIN32
        // Устанавливаем кодировку UTF-8 для консоли Windows ПЕРЕД любым выводом
        // Используем только SetConsoleOutputCP/SetConsoleCP для совместимости
        // _O_U8TEXT может вызывать проблемы, поэтому не используем его
        SetConsoleOutputCP(65001);  // UTF-8 кодовая страница
        SetConsoleCP(65001);        // UTF-8 для ввода
#endif
        cout << "Инициализация NTL библиотеки..." << endl;
        cout << "NTL активна (потоков: " << thread::hardware_concurrency() << ")" << endl;
    }

    /**
     * @brief Cleanup криптографических ресурсов
     * 
     * Освобождает ресурсы NTL библиотеки
     */
    ~ParallelProcessingInitializer() 
    {
        cout << "Завершение работы..." << endl;
    }
    
} parallel_init; // Глобальный экземпляр для автоматической инициализации
    

// ============================================================================
// ФУНКЦИЯ ДЛЯ ЧТЕНИЯ UTF-8 СТРОКИ ИЗ КОНСОЛИ WINDOWS
// ============================================================================

#ifdef _WIN32
/**
 * @brief Читает UTF-8 строку из консоли Windows
 * 
 * Использует Windows API для правильного чтения UTF-8 текста,
 * включая кириллицу и другие многобайтовые символы.
 * 
 * @return Прочитанная строка в UTF-8
 */
string readUTF8Line() {
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    if (hInput == INVALID_HANDLE_VALUE) {
        // Fallback на обычный getline
        string result;
        getline(cin, result);
        return result;
    }
    
    // Читаем широкие символы (UTF-16)
    wstring wstr;
    wchar_t wch;
    DWORD dwRead;
    
    while (ReadConsoleW(hInput, &wch, 1, &dwRead, NULL) && dwRead == 1) {
        if (wch == L'\n') break;
        if (wch != L'\r') {
            wstr += wch;
        }
    }
    
    // Конвертируем UTF-16 в UTF-8
    if (wstr.empty()) {
        return "";
    }
    
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), NULL, 0, NULL, NULL);
    if (size_needed <= 0) {
        return "";
    }
    
    string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.length(), &result[0], size_needed, NULL, NULL);
    return result;
}
#else
/**
 * @brief Читает строку из консоли (для не-Windows систем)
 */
string readUTF8Line() {
    string result;
    getline(cin, result);
    return result;
}
#endif

// ============================================================================
// ОСНОВНАЯ ФУНКЦИЯ ПРОГРАММЫ
// ============================================================================

/**
 * @brief Генератор криптографически стойких простых чисел
 * 
 * Алгоритм генерации использует библиотеку NTL (Number Theory Library):
 * 1. NTL::RandomPrime - криптографически стойкая генерация простых чисел
 * 2. Miller-Rabin тесты (20 раундов для высокой надежности)
 * 3. Многопоточная генерация для больших чисел (>=256 бит)
 * 4. Оптимизированные алгоритмы теории чисел из NTL
 * 
 * 
 * @param argc Количество аргументов командной строки
 * @param argv Массив аргументов командной строки
 * @return 0 при успешном выполнении, 1 при ошибке
 */
int main(int argc, char* argv[]) 
{
    // ========================================================================
    // ПРИВЕТСТВЕННОЕ СООБЩЕНИЕ
    // ========================================================================
    // Примечание: кодировка UTF-8 уже установлена в конструкторе ParallelProcessingInitializer
    cout << "===============================================" << endl;
    cout << "    Генератор простых чисел (NTL + BigInt)" << endl;
    cout << "===============================================" << endl;
        cout << endl;
    
    // ========================================================================
    // ОСНОВНОЙ ЦИКЛ ПРОГРАММЫ
    // ========================================================================
    
    // Определяем режим работы: batch (с аргументами) или interactive (без аргументов)
    bool batchMode = (argc > 1);
    bool continueGeneration = true;
    
    while (continueGeneration) 
    {
        // ========================================================================
        // ПАРСИНГ АРГУМЕНТОВ КОМАНДНОЙ СТРОКИ
        // ========================================================================
    
        int bitSize = 0; // Размер простого числа в битах (должен быть кратен 32)
        
        if (batchMode) 
        {
            // Batch mode: размер передается как аргумент для автоматизации
            try 
            {
                bitSize = stoi(argv[1]);
            } 
            catch (...) 
            {
                cerr << "Ошибка: неверный формат размера в битах" << endl;
                return 1;
            }
        } 
        else 
        {
            // Interactive mode: меню выбора
            cout << "═══════════════════════════════════════════════" << endl;
            cout << "    МЕНЮ ГЕНЕРАТОРА ПРОСТЫХ ЧИСЕЛ" << endl;
            cout << "═══════════════════════════════════════════════" << endl;
            cout << "1. Сгенерировать новое простое число" << endl;
            cout << "2. Просмотреть существующие файлы" << endl;
            cout << "3. Сгенерировать RSA ключи" << endl;
            cout << "4. Зашифровать текст/16-ричное значение" << endl;
            cout << "5. Расшифровать текст/16-ричное значение" << endl;
            cout << "6. Выход" << endl;
            cout << "═══════════════════════════════════════════════" << endl;
            cout << "Выберите опцию (1-6): ";
            
            int choice;
            if (!(cin >> choice)) 
            {
                cerr << "Ошибка: неверный формат" << endl;
                cin.clear();
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
                continue;
            }
            
            // Очищаем буфер ввода после чтения числа
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            
            if (choice == 1) 
            {
                // Генерация нового числа
                cout << "Введите размер простого числа в битах (кратно 32): ";
                if (!(cin >> bitSize)) 
                {
                    cerr << "Ошибка: неверный формат" << endl;
                    cin.clear();
                    cin.ignore(numeric_limits<streamsize>::max(), '\n');
                    continue;
                }
                cin.ignore(numeric_limits<streamsize>::max(), '\n');
            } 
            else if (choice == 2) 
            {
                // Просмотр существующих файлов
                cout << endl;
                cout << "───────────────────────────────────────────────" << endl;
                cout << "Список файлов с простыми числами:" << endl;
                cout << "───────────────────────────────────────────────" << endl;
                cout.flush(); // Принудительно выводим заголовок
                
                PrimeFileManager fileManager;
                vector<string> files = fileManager.getAllPrimeFiles();
                
                if (files.empty()) 
                {
                    cout << "Файлы с простыми числами не найдены." << endl;
                    cout.flush();
                } 
                else 
                {
                    // Сортируем файлы по размеру (извлекаем размер из имени файла)
                    vector<pair<string, int>> filesWithSize;
                    for (const string& filename : files) {
                        int size = 0;
                        // Ищем последний _ перед .txt
                        size_t lastUnderscore = filename.rfind('_');
                        if (lastUnderscore != string::npos) {
                            size_t dotPos = filename.find('.', lastUnderscore);
                            if (dotPos != string::npos) {
                                string sizeStr = filename.substr(lastUnderscore + 1, dotPos - lastUnderscore - 1);
                                try {
                                    size = stoi(sizeStr);
                                } catch (const exception&) {
                                    size = 0;
                                }
                            }
                        }
                        filesWithSize.push_back({filename, size});
                    }
                    
                    // Сортируем по размеру (по возрастанию)
                    sort(filesWithSize.begin(), filesWithSize.end(),
                         [](const pair<string, int>& a, const pair<string, int>& b) {
                             if (a.second != b.second) {
                                 return a.second < b.second;
                             }
                             // Если размеры одинаковые, сортируем по имени
                             return a.first < b.first;
                         });
                    
                    cout << "Найдено файлов: " << files.size() << endl;
                    cout << endl;
                    cout.flush();
                    
                    for (size_t i = 0; i < filesWithSize.size(); i++) 
                    {
                        cout << (i + 1) << ". " << filesWithSize[i].first;
                        if (filesWithSize[i].second > 0) {
                            cout << " (" << filesWithSize[i].second << " бит)";
                        }
                        cout << endl;
                        cout.flush(); // Принудительно выводим каждую строку
                    }
                }
                
                cout << endl;
                cout << "───────────────────────────────────────────────" << endl;
                cout << "Нажмите Enter для возврата в меню...";
                cout.flush(); // Принудительно выводим все буферы
                
                // Ждем нажатия Enter (буфер уже очищен после cin >> choice)
                cin.get(); // Ждем нажатия Enter
                
                // Очищаем консоль перед возвратом в меню
                clearConsole();
                
                // Продолжаем цикл без генерации
                continue;
            } 
            else if (choice == 3) 
            {
                // Генерация RSA ключей
                cout << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                cout << "    ГЕНЕРАЦИЯ RSA КЛЮЧЕЙ" << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                
                // Выбор размера RSA ключа
                cout << "Выберите размер RSA ключа:" << endl;
                cout << "1. RSA-64 (32 бит на простое число)" << endl;
                cout << "2. RSA-128 (64 бит на простое число)" << endl;
                cout << "3. RSA-256 (128 бит на простое число)" << endl;
                cout << "4. RSA-512 (256 бит на простое число)" << endl;
                cout << "5. RSA-1024 (512 бит на простое число)" << endl;
                cout << "6. RSA-2048 (1024 бит на простое число)" << endl;
                cout << "7. RSA-4096 (2048 бит на простое число)" << endl;
                cout << "8. RSA-8192 (4096 бит на простое число)" << endl;
                cout << "9. RSA-16384 (8192 бит на простое число)" << endl;
                cout << "10. RSA-32768 (16384 бит на простое число)" << endl;
                cout << "Выберите опцию (1-10): ";
                
                int rsaChoice;
                if (!(cin >> rsaChoice) || rsaChoice < 1 || rsaChoice > 10) 
                {
                    cout << "Неверный выбор. Возврат в меню." << endl;
                    continue;
                }
                
                int rsaKeySize, primeSize;
                switch (rsaChoice) 
                {
                    case 1: rsaKeySize = 64; primeSize = 32; break;
                    case 2: rsaKeySize = 128; primeSize = 64; break;
                    case 3: rsaKeySize = 256; primeSize = 128; break;
                    case 4: rsaKeySize = 512; primeSize = 256; break;
                    case 5: rsaKeySize = 1024; primeSize = 512; break;
                    case 6: rsaKeySize = 2048; primeSize = 1024; break;
                    case 7: rsaKeySize = 4096; primeSize = 2048; break;
                    case 8: rsaKeySize = 8192; primeSize = 4096; break;
                    case 9: rsaKeySize = 16384; primeSize = 8192; break;
                    case 10: rsaKeySize = 32768; primeSize = 16384; break;
                }
                
                cout << endl;
                cout << "Выбран размер RSA-" << rsaKeySize << " (простые числа по " << primeSize << " бит)" << endl;
                
                // Показываем список файлов с простыми числами нужного размера
                PrimeFileManager fileManager;
                vector<string> primeFiles = fileManager.getPrimeFiles(primeSize);
                
                if (primeFiles.empty()) 
                {
                    cout << "❌ Файлы с простыми числами размером " << primeSize << " бит не найдены!" << endl;
                    cout << "Сначала сгенерируйте простые числа нужного размера." << endl;
                    continue;
                }
                
                cout << endl;
                cout << "───────────────────────────────────────────────" << endl;
                cout << "Доступные файлы с простыми числами (" << primeSize << " бит):" << endl;
                cout << "───────────────────────────────────────────────" << endl;
                
                for (size_t i = 0; i < primeFiles.size(); i++) 
                {
                    cout << (i + 1) << ". " << primeFiles[i] << "_" << primeSize << ".txt" << endl;
                }
                
                // Выбор первого простого числа
                cout << endl;
                cout << "Выберите файл с первым простым числом (p) (номер или имя файла): ";
                string pInput;
                cin >> pInput;
                
                string pFilename;
                // Проверяем, является ли ввод числом
                if (isdigit(pInput[0])) 
                {
                    int pChoice = stoi(pInput);
                    if (pChoice < 1 || pChoice > (int)primeFiles.size()) 
                    {
                        cout << "Неверный номер файла. Возврат в меню." << endl;
                        continue;
                    }
                    pFilename = primeFiles[pChoice - 1];
                } 
                else 
                {
                    // Убираем расширение .txt если оно есть
                    if (pInput.length() >= 4 && pInput.substr(pInput.length() - 4) == ".txt") 
                    {
                        pInput = pInput.substr(0, pInput.length() - 4);
                    }
                    // Убираем суффикс _bitSize если он есть
                    string suffix = "_" + to_string(primeSize);
                    if (pInput.length() >= suffix.length() && pInput.substr(pInput.length() - suffix.length()) == suffix) 
                    {
                        pInput = pInput.substr(0, pInput.length() - suffix.length());
                    }
                    
                    // Ищем файл в списке
                    bool found = false;
                    for (const string& file : primeFiles) 
                    {
                        if (file == pInput) 
                        {
                            pFilename = file;
                            found = true;
                            break;
                        }
                    }
                    
                    if (!found) 
                    {
                        cout << "Файл '" << pInput << "' не найден. Возврат в меню." << endl;
                        continue;
                    }
                }
                
                BigInt p = fileManager.loadPrime(pFilename, primeSize);
                
                // Выбор второго простого числа
                cout << "Выберите файл со вторым простым числом (q) (номер или имя файла): ";
                string qInput;
                cin >> qInput;
                
                string qFilename;
                // Проверяем, является ли ввод числом
                if (isdigit(qInput[0])) 
                {
                    int qChoice = stoi(qInput);
                    if (qChoice < 1 || qChoice > (int)primeFiles.size()) 
                    {
                        cout << "Неверный номер файла. Возврат в меню." << endl;
                        continue;
                    }
                    qFilename = primeFiles[qChoice - 1];
                } 
                else 
                {
                    // Убираем расширение .txt если оно есть
                    if (qInput.length() >= 4 && qInput.substr(qInput.length() - 4) == ".txt") 
                    {
                        qInput = qInput.substr(0, qInput.length() - 4);
                    }
                    // Убираем суффикс _bitSize если он есть
                    string suffix = "_" + to_string(primeSize);
                    if (qInput.length() >= suffix.length() && qInput.substr(qInput.length() - suffix.length()) == suffix) 
                    {
                        qInput = qInput.substr(0, qInput.length() - suffix.length());
                    }
                    
                    // Ищем файл в списке
                    bool found = false;
                    for (const string& file : primeFiles) 
                    {
                        if (file == qInput) 
                        {
                            qFilename = file;
                            found = true;
                            break;
                        }
                    }
                    
                    if (!found) 
                    {
                        cout << "Файл '" << qInput << "' не найден. Возврат в меню." << endl;
                        continue;
                    }
                }
                
                BigInt q = fileManager.loadPrime(qFilename, primeSize);
                
                // Проверяем что файлы разные
                if (pFilename == qFilename) 
                {
                    cout << "❌ Ошибка: нельзя использовать один и тот же файл для обоих простых чисел!" << endl;
                    continue;
                }
                
                // Имя для RSA ключей
                cout << endl;
                cout << "Введите имя для RSA ключей (без расширения): ";
                string keyName;
                cin >> keyName;
                
                if (keyName.empty()) 
                {
                    cout << "Имя ключей не может быть пустым. Возврат в меню." << endl;
                    continue;
                }
                
                // Генерируем RSA ключи
                cout << endl;
                cout << "───────────────────────────────────────────────" << endl;
                cout << "Генерация RSA ключей..." << endl;
                cout << "───────────────────────────────────────────────" << endl;
                
                RSAKeyManager rsaManager;
                
                if (rsaManager.generateRSAKeyPair(p, q, rsaKeySize)) 
                {
                    if (rsaManager.saveRSAKeys(keyName, rsaKeySize)) 
                    {
                        cout << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "✅ RSA КЛЮЧИ УСПЕШНО СОЗДАНЫ!" << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "Размер ключа: RSA-" << rsaKeySize << endl;
                        cout << "Имя ключей: " << keyName << endl;
                        cout << "Простое число p: " << pFilename << "_" << primeSize << ".txt" << endl;
                        cout << "Простое число q: " << qFilename << "_" << primeSize << ".txt" << endl;
                        cout << rsaManager.getKeyInfo() << endl;
                        cout << endl;
                        cout << "───────────────────────────────────────────────" << endl;
                        cout << "Нажмите Enter для возврата в меню...";
                        cin.ignore();
                        cin.get();
                    } 
                    else 
                    {
                        cout << "❌ Ошибка при сохранении RSA ключей" << endl;
                        cout << endl;
                        cout << "───────────────────────────────────────────────" << endl;
                        cout << "Нажмите Enter для возврата в меню...";
                        cin.ignore();
                        cin.get();
                    }
                } 
                else 
                {
                    cout << "❌ Ошибка при генерации RSA ключей" << endl;
                    cout << endl;
                    cout << "───────────────────────────────────────────────" << endl;
                    cout << "Нажмите Enter для возврата в меню...";
                    cin.ignore();
                    cin.get();
                }
                
                // Очищаем консоль перед возвратом в меню
                clearConsole();
                
                // Продолжаем цикл без генерации
                continue;
            } 
            else if (choice == 4) 
            {
                // Шифрование текста/файла
                cout << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                cout << "    ШИФРОВАНИЕ RSA" << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                
                RSACrypto crypto;
                vector<string> availableKeys = crypto.getAvailableKeys();
                
                if (availableKeys.empty()) 
                {
                    cout << "❌ RSA ключи не найдены!" << endl;
                    cout << "Сначала сгенерируйте RSA ключи." << endl;
                    continue;
                }
                
                // Собираем ключи с их размерами для сортировки
                vector<pair<string, int>> keysWithSize;
                filesystem::path keyDir = filesystem::current_path().parent_path() / "rsa_keys";
                if (!filesystem::exists(keyDir)) {
                    // Пробуем найти корень проекта
                    filesystem::path currentPath = filesystem::current_path();
                    while (!currentPath.empty() && currentPath != currentPath.root_path()) {
                        if (filesystem::exists(currentPath / "CMakeLists.txt")) {
                            keyDir = currentPath / "rsa_keys";
                            break;
                        }
                        currentPath = currentPath.parent_path();
                    }
                }
                
                for (const string& keyName : availableKeys) {
                    int rsaSize = 0;
                    if (filesystem::exists(keyDir) && filesystem::is_directory(keyDir)) {
                        for (const auto& entry : filesystem::directory_iterator(keyDir)) {
                            if (entry.is_regular_file()) {
                                string filename = entry.path().filename().string();
                                if (filename.find(keyName + "_public_") == 0) {
                                    size_t pos = filename.find("_public_");
                                    if (pos != string::npos) {
                                        string sizeStr = filename.substr(pos + 8);
                                        sizeStr = sizeStr.substr(0, sizeStr.find(".txt"));
                                        try {
                                            rsaSize = stoi(sizeStr);
                                        } catch (const exception&) {
                                            rsaSize = 0;
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    keysWithSize.push_back({keyName, rsaSize});
                }
                
                // Сортируем по размеру (по возрастанию)
                sort(keysWithSize.begin(), keysWithSize.end(),
                     [](const pair<string, int>& a, const pair<string, int>& b) {
                         return a.second < b.second;
                     });
                
                cout << "Доступные ключи:" << endl;
                for (size_t i = 0; i < keysWithSize.size(); i++) 
                {
                    cout << (i + 1) << ". " << keysWithSize[i].first;
                    if (keysWithSize[i].second > 0) {
                        cout << " (RSA-" << keysWithSize[i].second << ")";
                    }
                    cout << endl;
                }
                
                cout << endl;
                cout << "Выберите ключ для шифрования (номер или имя): ";
                cout.flush();
                string keyInput;
                getline(cin, keyInput);
                
                string selectedKey;
                if (isdigit(keyInput[0])) 
                {
                    int keyChoice = stoi(keyInput);
                    if (keyChoice < 1 || keyChoice > (int)keysWithSize.size()) 
                    {
                        cout << "Неверный номер ключа. Возврат в меню." << endl;
                        continue;
                    }
                    selectedKey = keysWithSize[keyChoice - 1].first;
                } 
                else 
                {
                    if (find(availableKeys.begin(), availableKeys.end(), keyInput) != availableKeys.end()) 
                    {
                        selectedKey = keyInput;
                    } 
                    else 
                    {
                        cout << "Ключ '" << keyInput << "' не найден. Возврат в меню." << endl;
                        continue;
                    }
                }
                
                cout << endl;
                cout << "Выберите режим:" << endl;
                cout << "1. Шифровать текст" << endl;
                cout << "2. Шифровать 16-ричное значение" << endl;
                cout << "Выберите опцию (1-2): ";
                
                int modeChoice;
                if (!(cin >> modeChoice) || modeChoice < 1 || modeChoice > 2) 
                {
                    cout << "Неверный выбор. Возврат в меню." << endl;
                    continue;
                }
                
                if (modeChoice == 1) 
                {
                    // Шифрование текста
                    cout << endl;
                    cout << "Введите текст для шифрования: ";
                    cin.ignore();
                    string plaintext = readUTF8Line();
                    
                    if (plaintext.empty()) 
                    {
                        cout << "Текст не может быть пустым. Возврат в меню." << endl;
                        continue;
                    }
                    
                            try 
                            {
                                string publicKeyPath = "../rsa_keys/" + selectedKey + "_public_*.txt";
                                // Находим точный путь к файлу
                                for (const auto& entry : filesystem::directory_iterator("../rsa_keys")) 
                                {
                                    if (entry.is_regular_file()) 
                                    {
                                        string filename = entry.path().filename().string();
                                        if (filename.find(selectedKey + "_public_") == 0) 
                                        {
                                            publicKeyPath = entry.path().string();
                                            break;
                                        }
                                    }
                                }
                                
                                string encryptedText = crypto.encrypt(plaintext, publicKeyPath);
                        
                        cout << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "✅ ТЕКСТ УСПЕШНО ЗАШИФРОВАН!" << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "Исходный текст: " << plaintext << endl;
                        cout << "Зашифрованный текст: " << encryptedText << endl;
                        cout << "Использованный ключ: " << selectedKey << endl;
                        
                        // Автоматическая расшифровка для проверки
                        cout << endl;
                        cout << "🔄 Автоматическая расшифровка для проверки..." << endl;
                                try 
                                {
                                    string privateKeyPath = "../rsa_keys/" + selectedKey + "_private_*.txt";
                                    // Находим точный путь к файлу
                                    for (const auto& entry : filesystem::directory_iterator("../rsa_keys")) 
                                    {
                                        if (entry.is_regular_file()) 
                                        {
                                            string filename = entry.path().filename().string();
                                            if (filename.find(selectedKey + "_private_") == 0) 
                                            {
                                                privateKeyPath = entry.path().string();
                                                break;
                                            }
                                        }
                                    }
                                    
                                    string decryptedText = crypto.decrypt(encryptedText, privateKeyPath);
                            
                            cout << "✅ Расшифровка успешна!" << endl;
                            cout << "Расшифрованный текст: " << decryptedText << endl;
                            
                            if (plaintext == decryptedText) 
                            {
                                cout << "🎉 Проверка пройдена: исходный и расшифрованный тексты совпадают!" << endl;
                            } 
                            else 
                            {
                                cout << "⚠️  Внимание: исходный и расшифрованный тексты не совпадают!" << endl;
                                cout << "   Исходный (длина " << plaintext.length() << "): [" << plaintext << "]" << endl;
                                cout << "   Расшифрованный (длина " << decryptedText.length() << "): [" << decryptedText << "]" << endl;
                            }
                            
                        } 
                        catch (const exception& e) 
                        {
                            cout << "❌ Ошибка при автоматической расшифровке: " << e.what() << endl;
                        }
                        
                    } 
                    catch (const exception& e) 
                    {
                        cout << "❌ Ошибка при шифровании текста: " << e.what() << endl;
                        cout << "Проверьте размер текста и выбранный ключ." << endl;
                    }
                } 
                else if (modeChoice == 2) 
                {
                    // Шифрование 16-ричного значения
                    cout << endl;
                    cout << "Введите 16-ричное значение для шифрования (без 0x): ";
                    cin.ignore(); // Очищаем буфер после выбора режима
                    string hexValue;
                    getline(cin, hexValue);
                    
                    if (hexValue.empty()) 
                    {
                        cout << "16-ричное значение не может быть пустым. Возврат в меню." << endl;
                        continue;
                    }
                    
                    // Убираем 0x если есть
                    if (hexValue.length() >= 2 && hexValue.substr(0, 2) == "0x") 
                    {
                        hexValue = hexValue.substr(2);
                    }
                    
                    // Проверяем что это действительно hex
                    bool isValidHex = true;
                    for (char c : hexValue) 
                    {
                        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) 
                        {
                            isValidHex = false;
                            break;
                        }
                    }
                    
                    if (!isValidHex) 
                    {
                        cout << "❌ Неверный формат 16-ричного значения. Используйте только 0-9, a-f, A-F." << endl;
                        continue;
                    }
                    
                    try 
                    {
                        string publicKeyPath = "../rsa_keys/" + selectedKey + "_public_*.txt";
                        // Находим точный путь к файлу
                        for (const auto& entry : filesystem::directory_iterator("../rsa_keys")) 
                        {
                            if (entry.is_regular_file()) 
                            {
                                string filename = entry.path().filename().string();
                                if (filename.find(selectedKey + "_public_") == 0) 
                                {
                                    publicKeyPath = entry.path().string();
                                    break;
                                }
                            }
                        }
                        
                        string encryptedHex = crypto.encryptHex(hexValue, publicKeyPath);
                        
                        cout << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "✅ 16-РИЧНОЕ ЗНАЧЕНИЕ УСПЕШНО ЗАШИФРОВАНО!" << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "Исходное значение: 0x" << hexValue << endl;
                        cout << "Зашифрованное значение: " << encryptedHex << endl;
                        cout << "Использованный ключ: " << selectedKey << endl;
                        
                        // Автоматическая расшифровка для проверки
                        cout << endl;
                        cout << "🔄 Автоматическая расшифровка для проверки..." << endl;
                        try 
                        {
                            string privateKeyPath = "../rsa_keys/" + selectedKey + "_private_*.txt";
                            // Находим точный путь к файлу
                            for (const auto& entry : filesystem::directory_iterator("../rsa_keys")) 
                            {
                                if (entry.is_regular_file()) 
                                {
                                    string filename = entry.path().filename().string();
                                    if (filename.find(selectedKey + "_private_") == 0) 
                                    {
                                        privateKeyPath = entry.path().string();
                                        break;
                                    }
                                }
                            }
                            
                            string decryptedHex = crypto.decryptHex(encryptedHex, privateKeyPath);
                            
                            cout << "✅ Расшифровка успешна!" << endl;
                            cout << "Расшифрованное значение: " << decryptedHex << endl;
                            
                            // Убираем префикс "0x" из расшифрованного значения для сравнения
                            string decryptedHexClean = decryptedHex;
                            if (decryptedHexClean.length() >= 2 && decryptedHexClean.substr(0, 2) == "0x") {
                                decryptedHexClean = decryptedHexClean.substr(2);
                            }
                            
                            // Сравниваем в нижнем регистре
                            string hexValueLower = hexValue;
                            string decryptedHexLower = decryptedHexClean;
                            transform(hexValueLower.begin(), hexValueLower.end(), hexValueLower.begin(), ::tolower);
                            transform(decryptedHexLower.begin(), decryptedHexLower.end(), decryptedHexLower.begin(), ::tolower);
                            
                            if (hexValueLower == decryptedHexLower) 
                            {
                                cout << "🎉 Проверка пройдена: исходное и расшифрованное значения совпадают!" << endl;
                            } 
                            else 
                            {
                                cout << "⚠️  Внимание: исходное и расшифрованное значения не совпадают!" << endl;
                            }
                            
                        } 
                        catch (const exception& e) 
                        {
                            cout << "❌ Ошибка при автоматической расшифровке hex: " << e.what() << endl;
                        }
                        
                    } 
                    catch (const exception& e) 
                    {
                        cout << "❌ Ошибка при шифровании hex значения: " << e.what() << endl;
                    }
                }
                
                cout << endl;
                cout << "───────────────────────────────────────────────" << endl;
                cout << "Нажмите Enter для возврата в меню...";
                cin.get();
                
                // Очищаем консоль перед возвратом в меню
                clearConsole();
                
                // Продолжаем цикл без генерации
                continue;
            } 
            else if (choice == 5) 
            {
                // Расшифровка текста/файла
                cout << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                cout << "    РАСШИФРОВКА RSA" << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                
                RSACrypto crypto;
                vector<string> availableKeys = crypto.getAvailableKeys();
                
                if (availableKeys.empty()) 
                {
                    cout << "❌ RSA ключи не найдены!" << endl;
                    cout << "Сначала сгенерируйте RSA ключи." << endl;
                    continue;
                }
                
                // Собираем ключи с их размерами для сортировки
                vector<pair<string, int>> keysWithSize;
                filesystem::path keyDir = filesystem::current_path().parent_path() / "rsa_keys";
                if (!filesystem::exists(keyDir)) {
                    // Пробуем найти корень проекта
                    filesystem::path currentPath = filesystem::current_path();
                    while (!currentPath.empty() && currentPath != currentPath.root_path()) {
                        if (filesystem::exists(currentPath / "CMakeLists.txt")) {
                            keyDir = currentPath / "rsa_keys";
                            break;
                        }
                        currentPath = currentPath.parent_path();
                    }
                }
                
                for (const string& keyName : availableKeys) {
                    int rsaSize = 0;
                    if (filesystem::exists(keyDir) && filesystem::is_directory(keyDir)) {
                        for (const auto& entry : filesystem::directory_iterator(keyDir)) {
                            if (entry.is_regular_file()) {
                                string filename = entry.path().filename().string();
                                if (filename.find(keyName + "_public_") == 0) {
                                    size_t pos = filename.find("_public_");
                                    if (pos != string::npos) {
                                        string sizeStr = filename.substr(pos + 8);
                                        sizeStr = sizeStr.substr(0, sizeStr.find(".txt"));
                                        try {
                                            rsaSize = stoi(sizeStr);
                                        } catch (const exception&) {
                                            rsaSize = 0;
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                    keysWithSize.push_back({keyName, rsaSize});
                }
                
                // Сортируем по размеру (по возрастанию)
                sort(keysWithSize.begin(), keysWithSize.end(),
                     [](const pair<string, int>& a, const pair<string, int>& b) {
                         return a.second < b.second;
                     });
                
                cout << "Доступные ключи:" << endl;
                for (size_t i = 0; i < keysWithSize.size(); i++) 
                {
                    cout << (i + 1) << ". " << keysWithSize[i].first;
                    if (keysWithSize[i].second > 0) {
                        cout << " (RSA-" << keysWithSize[i].second << ")";
                    }
                    cout << endl;
                }
                
                cout << endl;
                cout << "Выберите ключ для расшифровки (номер или имя): ";
                cout.flush();
                string keyInput;
                getline(cin, keyInput);
                
                string selectedKey;
                if (isdigit(keyInput[0])) 
                {
                    int keyChoice = stoi(keyInput);
                    if (keyChoice < 1 || keyChoice > (int)keysWithSize.size()) 
                    {
                        cout << "Неверный номер ключа. Возврат в меню." << endl;
                        continue;
                    }
                    selectedKey = keysWithSize[keyChoice - 1].first;
                } 
                else 
                {
                    if (find(availableKeys.begin(), availableKeys.end(), keyInput) != availableKeys.end()) 
                    {
                        selectedKey = keyInput;
                    } 
                    else 
                    {
                        cout << "Ключ '" << keyInput << "' не найден. Возврат в меню." << endl;
                        continue;
                    }
                }
                
                cout << endl;
                cout << "Выберите режим:" << endl;
                cout << "1. Расшифровать текст" << endl;
                cout << "2. Расшифровать 16-ричное значение" << endl;
                cout << "Выберите опцию (1-2): ";
                
                int modeChoice;
                if (!(cin >> modeChoice) || modeChoice < 1 || modeChoice > 2) 
                {
                    cout << "Неверный выбор. Возврат в меню." << endl;
                    continue;
                }
                
                if (modeChoice == 1) 
                {
                    // Расшифровка текста
                    cout << endl;
                    cout << "Введите зашифрованный текст: ";
                    cin.ignore();
                    string ciphertext = readUTF8Line();
                    
                    if (ciphertext.empty()) 
                    {
                        cout << "Зашифрованный текст не может быть пустым. Возврат в меню." << endl;
                        continue;
                    }
                    
                    try 
                    {
                        string privateKeyPath = "../rsa_keys/" + selectedKey + "_private_*.txt";
                        // Находим точный путь к файлу
                        for (const auto& entry : filesystem::directory_iterator("../rsa_keys")) 
                        {
                            if (entry.is_regular_file()) 
                            {
                                string filename = entry.path().filename().string();
                                if (filename.find(selectedKey + "_private_") == 0) 
                                {
                                    privateKeyPath = entry.path().string();
                                    break;
                                }
                            }
                        }
                        
                        string decryptedText = crypto.decrypt(ciphertext, privateKeyPath);
                        
                        cout << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "✅ ТЕКСТ УСПЕШНО РАСШИФРОВАН!" << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "Зашифрованный текст: " << ciphertext << endl;
                        cout << "Расшифрованный текст: " << decryptedText << endl;
                        cout << "Использованный ключ: " << selectedKey << endl;
                        
                    } 
                    catch (const exception& e) 
                    {
                        cout << "❌ Ошибка при расшифровке: " << e.what() << endl;
                    }
                } 
                else if (modeChoice == 2) 
                {
                    // Расшифровка 16-ричного значения
                    cout << endl;
                    cout << "Введите зашифрованное 16-ричное значение (без 0x): ";
                    cin.ignore(); // Очищаем буфер после выбора режима
                    string encryptedHex;
                    getline(cin, encryptedHex);
                    
                    if (encryptedHex.empty()) 
                    {
                        cout << "Зашифрованное 16-ричное значение не может быть пустым. Возврат в меню." << endl;
                        continue;
                    }
                    
                    // Убираем 0x если есть
                    if (encryptedHex.length() >= 2 && encryptedHex.substr(0, 2) == "0x") 
                    {
                        encryptedHex = encryptedHex.substr(2);
                    }
                    
                    // Проверяем что это действительно hex
                    bool isValidHex = true;
                    for (char c : encryptedHex) 
                    {
                        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) 
                        {
                            isValidHex = false;
                            break;
                        }
                    }
                    
                    if (!isValidHex) 
                    {
                        cout << "❌ Неверный формат 16-ричного значения. Используйте только 0-9, a-f, A-F." << endl;
                        continue;
                    }
                    
                    try 
                    {
                        string privateKeyPath = "../rsa_keys/" + selectedKey + "_private_*.txt";
                        // Находим точный путь к файлу
                        for (const auto& entry : filesystem::directory_iterator("../rsa_keys")) 
                        {
                            if (entry.is_regular_file()) 
                            {
                                string filename = entry.path().filename().string();
                                if (filename.find(selectedKey + "_private_") == 0) 
                                {
                                    privateKeyPath = entry.path().string();
                                    break;
                                }
                            }
                        }
                        
                        string decryptedHex = crypto.decryptHex(encryptedHex, privateKeyPath);
                        
                        cout << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "✅ 16-РИЧНОЕ ЗНАЧЕНИЕ УСПЕШНО РАСШИФРОВАНО!" << endl;
                        cout << "═══════════════════════════════════════════════" << endl;
                        cout << "Зашифрованное значение: " << encryptedHex << endl;
                        cout << "Расшифрованное значение: " << decryptedHex << endl;
                        cout << "Использованный ключ: " << selectedKey << endl;
                        
                    } 
                    catch (const exception& e) 
                    {
                        cout << "❌ Ошибка при расшифровке hex значения: " << e.what() << endl;
                    }
                }
                
                cout << endl;
                cout << "───────────────────────────────────────────────" << endl;
                cout << "Нажмите Enter для возврата в меню...";
                cin.get();
                
                // Очищаем консоль перед возвратом в меню
                clearConsole();
                
                // Продолжаем цикл без генерации
                continue;
            } 
            else if (choice == 6) 
            {
                // Выход
                continueGeneration = false;
                cout << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                cout << "    ПРОГРАММА ЗАВЕРШЕНА" << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                cout << "Спасибо за использование генератора простых чисел!" << endl;
                break;
            } 
            else 
            {
                cout << "Неверный выбор. Попробуйте снова." << endl;
                continue;
            }
        }
    
        // Валидация размера только для batch mode или генерации нового числа
        if (batchMode || bitSize > 0) 
        {
            if (bitSize <= 0 || bitSize % 32 != 0) 
            {
                cerr << "Ошибка: размер должен быть положительным и кратным 32" << endl;
        return 1;
    }
    
            // ========================================================================
            // ЗАПРОС ИМЕНИ ФАЙЛА ДЛЯ СОХРАНЕНИЯ
            // ========================================================================
        
        string filename;
        
        if (batchMode) 
        {
            // Batch mode: используем имя по умолчанию
            filename = "prime_" + to_string(bitSize) + "bit";
            cout << "Batch mode: используется имя файла: " << filename << endl;
        } 
        else 
        {
            // Interactive mode: запрос имени файла у пользователя
            cout << "Введите имя файла для сохранения (без расширения): ";
            cin >> filename;
            
            // Проверяем что имя файла не пустое
            if (filename.empty()) 
            {
                filename = "prime_" + to_string(bitSize) + "bit";
                cout << "Используется имя по умолчанию: " << filename << endl;
            }
        }
    
    // ========================================================================
    // КРИПТОГРАФИЧЕСКАЯ ГЕНЕРАЦИЯ ПРОСТОГО ЧИСЛА
    // ========================================================================
    
    cout << endl;
    
        try 
        {
        // High-resolution timing для измерения производительности NTL генерации
        auto startTime = chrono::high_resolution_clock::now();
        
        // Запускаем индикатор прогресса
        string progressMsg = "Генерация " + to_string(bitSize) + "-битного простого числа";
        ProgressSpinner spinner(progressMsg);
        spinner.start();
        
        // Генерация простого числа с использованием NTL
        // RandomPrime - криптографически стойкая генерация с Miller-Rabin тестами
        // Для больших чисел (>=256 бит) использует многопоточную генерацию
        ZZ ntl_prime;
        RandomPrime(ntl_prime, bitSize, 20);  // 20 раундов Miller-Rabin для высокой надежности
        
        // Останавливаем индикатор прогресса
        spinner.stop();
        
        // Конвертация NTL::ZZ в BigInt (BigInt - обертка над ZZ)
        BigInt prime(ntl_prime);
        
        // Измерение времени выполнения для анализа производительности
        auto endTime = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::milliseconds>(endTime - startTime);
        
        // ========================================================================
        // ВЫВОД КРИПТОГРАФИЧЕСКИХ РЕЗУЛЬТАТОВ
        // ========================================================================
        
        cout << endl;
        cout << "═══════════════════════════════════════════════" << endl;
        cout << "✓ УСПЕШНО СГЕНЕРИРОВАНО ПРОСТОЕ ЧИСЛО" << endl;
        cout << "═══════════════════════════════════════════════" << endl;
        cout << endl;
        
        // Вывод метрик производительности
        cout << "Размер: " << prime.bitLength() << " бит" << endl;
        cout << "Время генерации: " << duration.count() << " мс";
        
        // Конвертация в секунды для больших значений времени
        if (duration.count() >= 1000) 
        {
            double seconds = duration.count() / 1000.0;
            cout << " (" << seconds << " сек)";
        }
        cout << endl;
        cout << endl;
        
        // ========================================================================
        // HEX ENCODING (стандарт для криптографических ключей)
        // ========================================================================
        
        cout << "Hex представление:" << endl;
        string hexStr = prime.toHex();
        
        // Форматирование hex строки по 64 символа (стандарт RFC для ключей)
        // Это соответствует 256 битам на строку для удобства чтения
        const size_t lineLength = 64;
        for (size_t i = 0; i < hexStr.length(); i += lineLength) 
        {
            cout << hexStr.substr(i, min(lineLength, hexStr.length() - i)) << endl;
        }
        
        // ========================================================================
        // DECIMAL ENCODING (для совместимости с математическими библиотеками)
        // ========================================================================
        
        cout << endl;
        cout << "Decimal представление:" << endl;
        string decStr = prime.toString();
        
        // Форматирование decimal строки по 80 символов
        // Decimal представление значительно длиннее hex (log10(2) ≈ 0.301)
        const size_t decLineLength = 80;
        for (size_t i = 0; i < decStr.length(); i += decLineLength) 
        {
            cout << decStr.substr(i, min(decLineLength, decStr.length() - i)) << endl;
        }
        
        // ========================================================================
        // INDEPENDENT VERIFICATION (OpenSSL BN_check_prime)
        // ========================================================================
        
#ifdef OPENSSL_FOUND
        cout << endl;
        
        // Независимая верификация с помощью OpenSSL для валидации результата NTL
        // BN_check_prime использует вероятностные тесты Miller-Rabin
        // Простое число было сгенерировано через NTL::RandomPrime с 20 раундами Miller-Rabin
        cout << "───────────────────────────────────────────────" << endl;
        cout << "Проверка через OpenSSL BN_check_prime()..." << endl;
        cout << "───────────────────────────────────────────────" << endl;
        
        // Создание OpenSSL BIGNUM объекта для криптографической проверки
        // Используем прямой способ конвертации через байты (более надежно, чем hex)
        BIGNUM* bn = BN_new();
        if (bn == nullptr) 
        {
            cerr << "Ошибка: не удалось создать BIGNUM" << endl;
        } 
        else 
        {
            // Конвертация NTL::ZZ в байты, затем в BIGNUM
            // Это более надежный способ, чем через hex строку
            long numBytes = NumBytes(ntl_prime);
            vector<unsigned char> bytes(numBytes);
            BytesFromZZ(bytes.data(), ntl_prime, numBytes);
            
            // NTL хранит числа в little-endian, OpenSSL ожидает big-endian
            // Нужно перевернуть байты
            reverse(bytes.begin(), bytes.end());
            
            // Конвертация байтов в BIGNUM
            if (BN_bin2bn(bytes.data(), numBytes, bn) == nullptr) 
            {
                cerr << "Ошибка: не удалось преобразовать байты в BIGNUM" << endl;
            } 
            else 
            {
                // Создание контекста для OpenSSL операций (BN_CTX)
                BN_CTX* ctx = BN_CTX_new();
                if (ctx == nullptr) 
                {
                    cerr << "Ошибка: не удалось создать BN_CTX" << endl;
                } 
                else 
                {
                    // Измерение времени проверки OpenSSL для сравнения производительности
                    auto opensslStart = chrono::high_resolution_clock::now();
                    
                    // Криптографическая проверка простоты:
                    // BN_check_prime использует Miller-Rabin с адаптивным количеством раундов
                    // Для больших чисел (4096 бит): ~128 раундов Miller-Rabin
                    int isPrime = BN_check_prime(bn, ctx, nullptr);
                    
                    auto opensslEnd = chrono::high_resolution_clock::now();
                    auto opensslDuration = chrono::duration_cast<chrono::milliseconds>(opensslEnd - opensslStart);
                    
                    // Интерпретация результата BN_check_prime:
                    // 1 = простое число (вероятность ошибки < 2^-128 для больших чисел)
                    // 0 = составное число (точно составное)
                    // -1 = ошибка вычисления
                    cout << endl;
                    if (isPrime == 1) 
                    {
                        cout << "✓ OpenSSL ПОДТВЕРЖДАЕТ: число ПРОСТОЕ" << endl;
                    } 
                    else if (isPrime == 0) 
                    {
                        cout << "✗ OpenSSL ОТКЛОНЯЕТ: число СОСТАВНОЕ" << endl;
                        cout << "  ВНИМАНИЕ: NTL сгенерировал число как простое, но OpenSSL считает его составным!" << endl;
                        cout << "  Это может быть ложное срабатывание или проблема конвертации." << endl;
                    } 
                    else 
                    {
                        cout << "⚠ OpenSSL: ошибка при проверке (код: " << isPrime << ")" << endl;
                    }
                    // Сравнение производительности: NTL генерация vs OpenSSL проверка
                    cout << "Время проверки OpenSSL: " << opensslDuration.count() << " мс";
                    if (opensslDuration.count() >= 1000) 
                    {
                        double seconds = opensslDuration.count() / 1000.0;
                        cout << " (" << seconds << " сек)";
                    }
                    cout << endl;
                    
                    // Освобождение OpenSSL контекста (BN_CTX_free)
                    BN_CTX_free(ctx);
                }
            }
            
            // Освобождение OpenSSL BIGNUM объекта (BN_free)
            BN_free(bn);
        }
#else
        cout << endl;
        cout << "───────────────────────────────────────────────" << endl;
        cout << "Проверка через OpenSSL недоступна" << endl;
        cout << "───────────────────────────────────────────────" << endl;
        cout << "OpenSSL не найден при компиляции" << endl;
#endif
        
        // ========================================================================
        // СОХРАНЕНИЕ ПРОСТОГО ЧИСЛА В ФАЙЛ
        // ========================================================================
        
        cout << endl;
        cout << "───────────────────────────────────────────────" << endl;
        cout << "Сохранение простого числа в файл..." << endl;
        cout << "───────────────────────────────────────────────" << endl;
        
        // Создаем менеджер файлов для работы с простыми числами
        PrimeFileManager fileManager;
        
        // Сохраняем простое число в файл с уже введенным именем
        // Используем реальный размер числа, а не введенный пользователем
        int actualBitSize = prime.bitLength();
        if (fileManager.savePrime(prime, filename, actualBitSize)) 
        {
            cout << "✓ Простое число успешно сохранено!" << endl;
            cout << "Файл: " << filename << "_" << actualBitSize << ".txt" << endl;
            cout << "Директория: generated_primes/" << endl;
        } 
        else 
        {
            cout << "✗ Ошибка при сохранении простого числа" << endl;
        }
        
        cout << endl;
        
        } // Конец try блока
        
        catch (const exception& e) 
        {
            // Обработка исключений криптографических операций:
            // - std::bad_alloc: недостаток памяти для больших чисел
            // - std::runtime_error: таймаут генерации или ошибка NTL
            // - std::invalid_argument: некорректные параметры
            cerr << "Ошибка при генерации: " << e.what() << endl;
            
            // В случае ошибки завершаем программу
            continueGeneration = false;
        }
        
        } // Конец блока генерации (только для batch mode или генерации нового числа)
        
        // ========================================================================
        // ЗАПРОС НА ПРОДОЛЖЕНИЕ ГЕНЕРАЦИИ
        // ========================================================================
        
        if (batchMode) 
        {
            // Batch mode: завершаем после одной генерации
            continueGeneration = false;
            cout << endl;
            cout << "═══════════════════════════════════════════════" << endl;
            cout << "    BATCH MODE ЗАВЕРШЕН" << endl;
            cout << "═══════════════════════════════════════════════" << endl;
        } 
        else 
        {
            // Interactive mode: спрашиваем пользователя
            cout << "───────────────────────────────────────────────" << endl;
            cout << "Хотите продолжить работу с генератором?" << endl;
            cout << "───────────────────────────────────────────────" << endl;
            cout << "Введите 'y' или 'yes' для продолжения, любой другой символ для выхода: ";
            
            string userChoice;
            cin >> userChoice;
            
            // Проверяем выбор пользователя
            if (userChoice == "y" || userChoice == "yes" || userChoice == "Y" || userChoice == "YES") 
            {
                continueGeneration = true;
                clearConsole(); // Очищаем консоль
                cout << "═══════════════════════════════════════════════" << endl;
                cout << "    ПРОДОЛЖЕНИЕ РАБОТЫ С ГЕНЕРАТОРОМ" << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                cout << endl;
            } 
            else 
            {
                continueGeneration = false;
                cout << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                cout << "    ПРОГРАММА ЗАВЕРШЕНА" << endl;
                cout << "═══════════════════════════════════════════════" << endl;
                cout << "Спасибо за использование генератора простых чисел!" << endl;
                
                // Небольшая задержка перед очисткой консоли
                this_thread::sleep_for(chrono::milliseconds(1000));
                clearConsole();
            }
        }
                        
    } // Конец основного цикла программы
    
    return 0;
}
