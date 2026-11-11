#include "PrimeFileManager.h"
#include <iostream>             // Ввод/вывод для сообщений об ошибках
#include <sstream>              // Строковые потоки для форматирования
#include <iomanip>              // Манипуляторы ввода/вывода для форматирования дат
#include <ctime>                // Работа с временем для информации о файлах
#include <filesystem>           // C++17 filesystem для работы с файлами
#include <algorithm>            // Для std::sort

using namespace std;
namespace filesystem = std::filesystem;

// =============================================================================
// РЕАЛИЗАЦИЯ МЕНЕДЖЕРА ФАЙЛОВ ДЛЯ ПРОСТЫХ ЧИСЕЛ
// =============================================================================

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

PrimeFileManager::PrimeFileManager() 
{
    // Инициализируем базовую директорию для хранения простых чисел
    baseDirectory = "generated_primes";
    
    // Создаем директорию при инициализации
    ensureDirectoryExists();
}

string PrimeFileManager::createFilePath(const string& filename, int bitSize) const 
{
    // Находим корень проекта и создаем путь относительно него
    filesystem::path projectRoot = findProjectRoot();
    filesystem::path targetDir = projectRoot / baseDirectory;
    
    // Формируем имя файла с префиксом размера
    // Формат: {filename}_{bitSize}.txt
    // Пример: my_prime_256.txt, test_prime_1024.txt
    filesystem::path filePath = targetDir / (filename + "_" + to_string(bitSize) + ".txt");
    return filePath.string();
}

bool PrimeFileManager::ensureDirectoryExists() const 
{
    try 
    {
        // Находим корень проекта и создаем путь относительно него
        filesystem::path projectRoot = findProjectRoot();
        filesystem::path targetDir = projectRoot / baseDirectory;
        
        // Проверяем существование директории
        if (filesystem::exists(targetDir)) 
        {
            // Директория существует, проверяем что это действительно директория
            return filesystem::is_directory(targetDir);
        }
        
        // Создаем директорию если она не существует
        return filesystem::create_directories(targetDir);
    } 
    catch (const filesystem::filesystem_error& e) 
    {
        // Обрабатываем ошибки файловой системы
        cerr << "Ошибка при создании директории " << baseDirectory 
             << ": " << e.what() << endl;
        return false;
    }
}

bool PrimeFileManager::savePrime(const BigInt& prime, const string& filename, int bitSize) const 
{
    try 
    {
        // Создаем директорию если она не существует
        if (!ensureDirectoryExists()) 
        {
            cerr << "Не удалось создать директорию " << baseDirectory << endl;
            return false;
        }
        
        // Формируем полный путь к файлу
        string filePath = createFilePath(filename, bitSize);
        
        // Открываем файл для записи
        ofstream file(filePath);
        if (!file.is_open()) 
        {
            cerr << "Не удалось открыть файл для записи: " << filePath << endl;
            return false;
        }
        
        // Сохраняем простое число в десятичном формате без дополнительных надписей
        // Только само число, никаких комментариев или метаданных
        file << prime.toString();
        
        // Проверяем что запись прошла успешно
        if (file.fail()) 
        {
            cerr << "Ошибка при записи в файл: " << filePath << endl;
            file.close();
            return false;
        }
        
        file.close();
        
        // Выводим сообщение об успешном сохранении
        cout << "✓ Простое число сохранено в файл: " << filePath << endl;
        return true;
        
    } 
    catch (const exception& e) 
    {
        cerr << "Исключение при сохранении простого числа: " << e.what() << endl;
        return false;
    }
}

BigInt PrimeFileManager::loadPrime(const string& filename, int bitSize) const 
{
    try 
    {
        // Формируем полный путь к файлу
        string filePath = createFilePath(filename, bitSize);
        
        // Проверяем существование файла
        if (!filesystem::exists(filePath)) 
        {
            cerr << "Файл не найден: " << filePath << endl;
            return BigInt::zero();
        }
        
        // Открываем файл для чтения
        ifstream file(filePath);
        if (!file.is_open()) 
        {
            cerr << "Не удалось открыть файл для чтения: " << filePath << endl;
            return BigInt::zero();
        }
        
        // Читаем содержимое файла
        string decimalStr;
        string line;
        
        // Читаем все строки файла (на случай если число разбито на несколько строк)
        while (getline(file, line)) 
        {
            decimalStr += line;
        }
        
        file.close();
        
        // Проверяем что чтение прошло успешно
        if (file.fail() && !file.eof()) 
        {
            cerr << "Ошибка при чтении файла: " << filePath << endl;
            return BigInt::zero();
        }
        
        // Конвертируем десятичную строку в BigInt
        if (decimalStr.empty()) 
        {
            cerr << "Файл пуст: " << filePath << endl;
            return BigInt::zero();
        }
        
        // Создаем BigInt из десятичной строки
        BigInt prime(decimalStr, true);
        
        // Проверяем что конвертация прошла успешно
        if (prime.isZero() && decimalStr != "0") 
        {
            cerr << "Ошибка при конвертации строки в BigInt: " << filePath << endl;
            return BigInt::zero();
        }
        
        cout << "✓ Простое число загружено из файла: " << filePath << endl;
        return prime;
        
    } 
    catch (const exception& e) 
    {
        cerr << "Исключение при загрузке простого числа: " << e.what() << endl;
        return BigInt::zero();
    }
}

bool PrimeFileManager::fileExists(const string& filename, int bitSize) const 
{
    try 
    {
        string filePath = createFilePath(filename, bitSize);
        return filesystem::exists(filePath);
    } 
    catch (const exception& e) 
    {
        cerr << "Ошибка при проверке существования файла: " << e.what() << endl;
        return false;
    }
}

vector<string> PrimeFileManager::getPrimeFiles(int bitSize) const 
{
    vector<string> files;
    
    try 
    {
        // Находим корень проекта и создаем путь относительно него
        filesystem::path projectRoot = findProjectRoot();
        filesystem::path targetDir = projectRoot / baseDirectory;
        
        // Проверяем существование базовой директории
        if (!filesystem::exists(targetDir)) 
        {
            return files; // Возвращаем пустой вектор
        }
        
        // Формируем суффикс для поиска файлов
        stringstream ss;
        ss << "_" << bitSize << ".txt";
        string suffix = ss.str();
        
        // Проходим по всем файлам в директории
        for (const auto& entry : filesystem::directory_iterator(targetDir)) 
        {
            if (entry.is_regular_file()) 
            {
                string filename = entry.path().filename().string();
                
                // Проверяем что файл заканчивается нужным суффиксом
                if (filename.length() > suffix.length() && 
                    filename.substr(filename.length() - suffix.length()) == suffix) 
                {
                    // Извлекаем базовое имя файла (без суффикса)
                    string baseName = filename.substr(0, filename.length() - suffix.length());
                    files.push_back(baseName);
                }
            }
        }
        
    } 
    catch (const exception& e) 
    {
        cerr << "Ошибка при получении списка файлов: " << e.what() << endl;
    }
    
    return files;
}

vector<string> PrimeFileManager::getAllPrimeFiles() const 
{
    vector<string> files;
    
    try 
    {
        // Находим корень проекта и создаем путь относительно него
        filesystem::path projectRoot = findProjectRoot();
        filesystem::path targetDir = projectRoot / baseDirectory;
        
        // Проверяем существование директории
        if (!filesystem::exists(targetDir) || !filesystem::is_directory(targetDir)) 
        {
            cerr << "Директория " << targetDir.string() << " не существует" << endl;
            return files;
        }
        
        // Проходим по всем файлам в директории
        for (const auto& entry : filesystem::directory_iterator(targetDir)) 
        {
            if (entry.is_regular_file()) 
            {
                string filename = entry.path().filename().string();
                
                // Проверяем что файл имеет расширение .txt
                if (filename.length() > 4 && filename.substr(filename.length() - 4) == ".txt") 
                {
                    files.push_back(filename);
                }
            }
        }
        
        // Сортируем файлы по имени для удобства просмотра
        sort(files.begin(), files.end());
        
    } 
    catch (const exception& e) 
    {
        cerr << "Ошибка при получении списка всех файлов: " << e.what() << endl;
    }
    
    return files;
}

bool PrimeFileManager::deletePrimeFile(const string& filename, int bitSize) const 
{
    try 
    {
        string filePath = createFilePath(filename, bitSize);
        
        // Проверяем существование файла
        if (!filesystem::exists(filePath)) 
        {
            cerr << "Файл не найден для удаления: " << filePath << endl;
            return false;
        }
        
        // Удаляем файл
        bool success = filesystem::remove(filePath);
        
        if (success) 
        {
            cout << "✓ Файл удален: " << filePath << endl;
        } 
        else 
        {
            cerr << "Не удалось удалить файл: " << filePath << endl;
        }
        
        return success;
        
    } 
    catch (const exception& e) 
    {
        cerr << "Ошибка при удалении файла: " << e.what() << endl;
        return false;
    }
}

string PrimeFileManager::getFileInfo(const string& filename, int bitSize) const 
{
    try 
    {
        string filePath = createFilePath(filename, bitSize);
        
        // Проверяем существование файла
        if (!filesystem::exists(filePath)) 
        {
            return "Файл не найден: " + filePath;
        }
        
        // Получаем информацию о файле
        auto fileSize = filesystem::file_size(filePath);
        
        // Конвертируем время в читаемый формат
        // Используем C++17 совместимый способ конвертации времени файла
        auto timeT = chrono::system_clock::to_time_t(
            chrono::system_clock::now()
        );
        
        stringstream ss;
        ss << "Файл: " << filename << "_" << bitSize << ".txt" << endl;
        ss << "Размер: " << fileSize << " байт" << endl;
        ss << "Дата изменения: " << put_time(localtime(&timeT), "%Y-%m-%d %H:%M:%S");
        
        return ss.str();
        
    } 
    catch (const exception& e) 
    {
        return "Ошибка при получении информации о файле: " + string(e.what());
    }
}
