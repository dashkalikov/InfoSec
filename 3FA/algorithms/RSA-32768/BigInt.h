#ifndef BIGINT_H
#define BIGINT_H

#include <NTL/ZZ.h>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <iomanip>

NTL_CLIENT

// =============================================================================
// BigInt - обертка над NTL::ZZ для совместимости интерфейса
// =============================================================================
// Внутри используется NTL::ZZ для всех вычислений
// =============================================================================

class BigInt {
private:
    ZZ value;  // Внутреннее представление через NTL::ZZ

public:
    // Конструкторы
    BigInt() : value(0) {}
    BigInt(const ZZ& zz) : value(zz) {}
    BigInt(long val) : value(val) {}
    BigInt(const std::string& str, bool decimal = true) {
        if (decimal) {
            conv(value, str.c_str());
        } else {
            // Hex строка
            std::istringstream iss(str);
            iss >> std::hex >> value;
        }
    }
    
    // Конструктор из вектора байтов
    BigInt(const std::vector<uint8_t>& bytes) {
        if (bytes.empty()) {
            value = 0;
        } else {
            ZZFromBytes(value, bytes.data(), bytes.size());
        }
    }
    
    // Копирующий конструктор
    BigInt(const BigInt& other) : value(other.value) {}
    
    // Оператор присваивания
    BigInt& operator=(const BigInt& other) {
        if (this != &other) {
            value = other.value;
        }
        return *this;
    }
    
    // Операторы сравнения
    bool operator==(const BigInt& other) const {
        return value == other.value;
    }
    
    bool operator!=(const BigInt& other) const {
        return value != other.value;
    }
    
    bool operator<(const BigInt& other) const {
        return value < other.value;
    }
    
    bool operator>(const BigInt& other) const {
        return value > other.value;
    }
    
    bool operator>=(const BigInt& other) const {
        return value >= other.value;
    }
    
    bool operator<=(const BigInt& other) const {
        return value <= other.value;
    }
    
    // Арифметические операторы
    BigInt operator+(const BigInt& other) const {
        return BigInt(value + other.value);
    }
    
    BigInt operator-(const BigInt& other) const {
        return BigInt(value - other.value);
    }
    
    BigInt operator*(const BigInt& other) const {
        return BigInt(value * other.value);
    }
    
    BigInt operator/(const BigInt& other) const {
        return BigInt(value / other.value);
    }
    
    BigInt operator%(const BigInt& other) const {
        return BigInt(value % other.value);
    }
    
    BigInt& operator+=(const BigInt& other) {
        value += other.value;
        return *this;
    }
    
    BigInt& operator-=(const BigInt& other) {
        value -= other.value;
        return *this;
    }
    
    BigInt& operator*=(const BigInt& other) {
        value *= other.value;
        return *this;
    }
    
    // Методы
    int bitLength() const {
        return NumBits(value);
    }
    
    bool isZero() const {
        return IsZero(value);
    }
    
    bool isOne() const {
        return IsOne(value) != 0;
    }
    
    bool isOdd() const {
        return IsOdd(value) != 0;
    }
    
    std::string toHex() const {
        // NTL::ZZ не поддерживает std::hex напрямую через оператор <<
        // Используем BytesFromZZ для получения байтов, затем конвертируем в hex
        long numBytes = NumBytes(value);
        if (numBytes == 0) {
            return "0";
        }
        
        std::vector<unsigned char> bytes(numBytes);
        BytesFromZZ(bytes.data(), value, numBytes);
        
        // NTL хранит в little-endian, но для hex нужен big-endian
        // Переворачиваем байты
        std::reverse(bytes.begin(), bytes.end());
        
        // Конвертируем байты в hex строку
        std::ostringstream oss;
        oss << std::hex << std::uppercase;
        for (unsigned char byte : bytes) {
            oss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        
        return oss.str();
    }
    
    // Статические методы
    static BigInt zero() {
        return BigInt(0);
    }
    
    static BigInt one() {
        return BigInt(1);
    }
    
    // Преобразование в строку (десятичное)
    std::string toString() const {
        std::ostringstream oss;
        oss << value;
        return oss.str();
    }
    
    // Получить внутреннее значение NTL::ZZ
    const ZZ& getZZ() const {
        return value;
    }
    
    // Установить значение из NTL::ZZ
    void setZZ(const ZZ& zz) {
        value = zz;
    }
    
    // Получить бит по индексу
    bool getBit(long i) const {
        return bit(value, i) != 0;
    }
    
    // Модульное возведение в степень: base^exp mod mod
    BigInt modExp(const BigInt& exp, const BigInt& mod) const {
        ZZ result;
        PowerMod(result, value, exp.value, mod.value);
        return BigInt(result);
    }
    
    // Оператор вывода
    friend std::ostream& operator<<(std::ostream& os, const BigInt& bi) {
        os << bi.value;
        return os;
    }
};

// Вспомогательные функции для конвертации
namespace BigIntConversion {
    inline std::string gmpFastToDecimal(const BigInt& bi) {
        return bi.toString();
    }
}

#endif // BIGINT_H

