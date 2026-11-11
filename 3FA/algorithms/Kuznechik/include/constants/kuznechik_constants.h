// ============================================================================
// ФАЙЛ KUZNECHIK_CONSTANTS.H - ЗАГОЛОВОЧНЫЙ ФАЙЛ АЛГОРИТМА КУЗНЕЧИК
// ============================================================================
// Этот файл содержит объявления классов для работы с алгоритмом блочного
// шифрования Кузнечик (ГОСТ Р 34.12-2015). Включает класс Block128 для
// представления 128-битных блоков и класс KuznechikConstants для выполнения
// криптографических операций шифрования и расшифрования

#ifndef KUZNECHIK_CONSTANTS_H
#define KUZNECHIK_CONSTANTS_H

#include <cstring>                     // для работы со строками C (memcpy, memset)
#include <vector>                      // для работы с динамическими массивами (vector)
#include <cstdint>                     // для типов uint8_t

using namespace std;


// ============================================================================
// КЛАСС BLOCK128 - ПРЕДСТАВЛЕНИЕ 128-БИТНОГО БЛОКА ДАННЫХ
// ============================================================================
// Класс для представления и работы с 128-битными блоками данных,
// используемыми в алгоритме Кузнечик. Каждый блок содержит 16 байтов
// ============================================================================

class Block128 
{
private:
    unsigned char bytes[16];                                    // массив из 16 байт для хранения 128-битного блока

public:
    Block128();                                                 // конструктор по умолчанию - все байты устанавливаются в нули
    
    // Методы доступа к отдельным байтам
    unsigned char get_byte(int index) const;                    // получить байт по индексу (0-15)
    void set_byte(int index, unsigned char value);              // установить байт по индексу (0-15)

    // Методы доступа ко всему блоку
    void get_all_bytes(unsigned char* dest) const;              // скопировать все 16 байт в массив назначения
    void set_all_bytes(const unsigned char* src);               // скопировать все 16 байт из исходного массива
    
    // Операции XOR для криптографических преобразований
    void xor_with(const Block128& other);                       // XOR с присваиванием - изменяет текущий блок
};


// ============================================================================
// КЛАСС KUZNECHIKCONSTANTS - КРИПТОГРАФИЧЕСКИЕ ОПЕРАЦИИ АЛГОРИТМА КУЗНЕЧИК
// ============================================================================
// Класс для выполнения криптографических операций алгоритма Кузнечик
// согласно ГОСТ Р 34.12-2015: вычисление ключей, шифрование и расшифрование
// ============================================================================

class KuznechikConstants 
{
public:
    KuznechikConstants();                       // конструктор - инициализирует обратную S-таблицу
    
    // Вычисление раундовых ключей из главного ключа (256 бит -> 10 раундовых ключей)
    void compute_round_keys(const vector<uint8_t>& main_key, Block128 round_keys[10]);
    
    // Шифрование и расшифрование блока данных
    void encrypt_block(Block128& block, const Block128 round_keys[10]);
    void decrypt_block(Block128& block, const Block128 round_keys[10]);
    
private:
    // Методы криптографических преобразований
    unsigned char gf256_mul(unsigned char x, unsigned char y) const;    // умножение в поле GF(2^8)
    void r_transform(Block128& block);                                  // R-преобразование (LFSR)
    void linear_transform(Block128& w);                                 // линейное преобразование L
    void s_transform(Block128& block);                                  // S-преобразование (нелинейное)
    void f_function(Block128& result, const Block128& input, const Block128& constant, const Block128& k2);
    
    // Обратные преобразования для расшифрования
    void inverse_s_transform(Block128& block);                          // обратное S-преобразование
    void inverse_linear_transform(Block128& block);                     // обратное L-преобразование
    void inverse_r_transform(Block128& block);                          // обратное R-преобразование
    
    // Вспомогательные методы
    void split_main_key(const vector<uint8_t>& main_key, Block128& K1, Block128& K2);
    void compute_round_constants(Block128 constants[32]);
};

#endif // KUZNECHIK_CONSTANTS_H
