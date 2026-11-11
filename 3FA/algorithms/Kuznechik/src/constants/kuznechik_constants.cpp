// ============================================================================
// ФАЙЛ KUZNECHIK_CONSTANTS.CPP - РЕАЛИЗАЦИЯ АЛГОРИТМА КУЗНЕЧИК
// ============================================================================
// Этот файл содержит реализацию алгоритма блочного шифрования Кузнечик
// (ГОСТ Р 34.12-2015). Включает класс Block128 для работы с 128-битными
// блоками и класс KuznechikConstants для криптографических операций

#include "../../include/constants/kuznechik_constants.h"
#include "../../include/constants/kuznechik_constants_data.h"

using namespace std;


// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА BLOCK128
// ============================================================================

Block128::Block128() 
{
    for (int i = 0; i < 16; i++) 
    {
        bytes[i] = 0;
    }
}

void Block128::xor_with(const Block128& other) 
{
    for (int i = 0; i < 16; i++) 
    {
        bytes[i] ^= other.bytes[i];
    }
}

unsigned char Block128::get_byte(int index) const 
{
    return bytes[index];
}

void Block128::set_byte(int index, unsigned char value) 
{
    bytes[index] = value;
}

void Block128::get_all_bytes(unsigned char* dest) const 
{
    for (int i = 0; i < 16; i++) 
    {
        dest[i] = bytes[i];
    }
}

void Block128::set_all_bytes(const unsigned char* src)
{
    for (int i = 0; i < 16; i++) 
    {
        bytes[i] = src[i];
    }
}


// ============================================================================
// РЕАЛИЗАЦИЯ КЛАССА KUZNECHIKCONSTANTS
// ============================================================================

KuznechikConstants::KuznechikConstants() 
{
    init_inverse_s_box();
}


// ============================================================================
// МЕТОДЫ РАБОТЫ С ПОЛИНОМАМИ В ПОЛЕ GF(2^8)
// ============================================================================

static vector<bool> byte_to_polynomial(unsigned char byte)
{
    vector<bool> poly(8, false);
    for (int i = 0; i < 8; i++) 
    {
        poly[i] = (byte >> i) & 1;
    }
    return poly;
}

static unsigned char polynomial_to_byte(const vector<bool>& poly)
{
    unsigned char result = 0;
    for (size_t i = 0; i < poly.size() && i < 8; i++) 
    {
        if (poly[i]) 
        {
            result |= (1 << i);
        }
    }
    return result;
}

static vector<bool> polynomial_multiply(const vector<bool>& a, const vector<bool>& b)
{
    vector<bool> result(a.size() + b.size() - 1, false);
    for (size_t i = 0; i < a.size(); i++) 
    {
        for (size_t j = 0; j < b.size(); j++) 
        {
            if (a[i] && b[j]) 
            {
                result[i + j] = result[i + j] ^ true;
            }
        }
    }
    return result;
}

static vector<bool> polynomial_mod(const vector<bool>& poly)
{
    vector<bool> result = poly;
    
    while (result.size() > 8) 
    {
        size_t degree = result.size() - 1;
        
        if (result[degree]) 
        {
            result[degree] = false;
            
            if (degree >= 8) 
            {
                if (degree - 1 < result.size()) result[degree - 1] = result[degree - 1] ^ true;
                if (degree - 2 < result.size()) result[degree - 2] = result[degree - 2] ^ true;
                if (degree - 7 < result.size()) result[degree - 7] = result[degree - 7] ^ true;
                if (degree - 8 < result.size()) result[degree - 8] = result[degree - 8] ^ true;
            }
        } 
        else 
        {
            result.pop_back();
        }
    }
    
    while (result.size() < 8) 
    {
        result.push_back(false);
    }
    
    return result;
}

unsigned char KuznechikConstants::gf256_mul(unsigned char a, unsigned char b) const
{
    vector<bool> poly_a = byte_to_polynomial(a);
    vector<bool> poly_b = byte_to_polynomial(b);
    vector<bool> product = polynomial_multiply(poly_a, poly_b);
    vector<bool> result = polynomial_mod(product);
    return polynomial_to_byte(result);
}


// ============================================================================
// КРИПТОГРАФИЧЕСКИЕ ПРЕОБРАЗОВАНИЯ
// ============================================================================

void KuznechikConstants::r_transform(Block128& block) 
{
    unsigned char a_15 = 0;
    
    for (int i = 15; i >= 0; --i) 
    {
        a_15 ^= gf256_mul(block.get_byte(i), kuz_lvec[i]);
        
        if (i > 0) 
        {
            block.set_byte(i, block.get_byte(i - 1));
        }
    }
    
    block.set_byte(0, a_15);
}

void KuznechikConstants::linear_transform(Block128& w) 
{
    for (int i = 0; i < 16; i++) 
    {
        r_transform(w);
    }
}

void KuznechikConstants::s_transform(Block128& block)
{
    for (int i = 0; i < 16; i++) 
    {
        block.set_byte(i, s_box[block.get_byte(i)]);
    }
}

void KuznechikConstants::f_function(Block128& result, const Block128& input, 
                                     const Block128& constant, const Block128& k2)
{
    result = input;
    result.xor_with(constant);
    s_transform(result);
    linear_transform(result);
    result.xor_with(k2);
}


// ============================================================================
// ОБРАТНЫЕ ПРЕОБРАЗОВАНИЯ ДЛЯ РАСШИФРОВАНИЯ
// ============================================================================

void KuznechikConstants::inverse_s_transform(Block128& block)
{
    for (int i = 0; i < 16; i++) 
    {
        block.set_byte(i, inverse_s_box[block.get_byte(i)]);
    }
}

void KuznechikConstants::inverse_r_transform(Block128& block)
{
    unsigned char acc = block.get_byte(0);
    
    for (int i = 0; i < 15; i++) 
    {
        block.set_byte(i, block.get_byte(i + 1));
        acc ^= gf256_mul(block.get_byte(i), kuz_lvec[i]);
    }
    
    block.set_byte(15, acc);
}

void KuznechikConstants::inverse_linear_transform(Block128& block)
{
    for (int i = 0; i < 16; i++) 
    {
        inverse_r_transform(block);
    }
}


// ============================================================================
// ГЕНЕРАЦИЯ КЛЮЧЕЙ
// ============================================================================

void KuznechikConstants::compute_round_constants(Block128 constants[32]) 
{
    for (int i = 0; i < 32; i++) 
    {
        Block128 c;
        c.set_byte(15, i + 1);
        linear_transform(c);
        constants[i] = c;
    }
}

void KuznechikConstants::split_main_key(const vector<uint8_t>& main_key, 
                                         Block128& K1, Block128& K2) 
{
    for (int i = 0; i < 16; i++) 
    {
        K1.set_byte(i, main_key[i]);
    }
    
    for (int i = 0; i < 16; i++) 
    {
        K2.set_byte(i, main_key[i + 16]);
    }
}

void KuznechikConstants::compute_round_keys(const vector<uint8_t>& main_key, 
                                             Block128 round_keys[10]) 
{
    Block128 K1, K2;
    split_main_key(main_key, K1, K2);
    
    round_keys[0] = K1;
    round_keys[1] = K2;
    
    Block128 constants[32];
    compute_round_constants(constants);
    
    Block128 current_K1 = K1;
    Block128 current_K2 = K2;
    
    for (int group = 0; group < 4; group++) 
    {
        for (int j = 0; j < 8; j++) 
        {
            int const_index = group * 8 + j;
            Block128 C = constants[const_index];
            
            Block128 temp;
            f_function(temp, current_K1, C, current_K2);
            
            Block128 old_K1 = current_K1;
            current_K1 = temp;
            current_K2 = old_K1;
        }
        
        int key_index = (group + 1) * 2;
        round_keys[key_index] = current_K1;
        round_keys[key_index + 1] = current_K2;
    }
}


// ============================================================================
// ШИФРОВАНИЕ И РАСШИФРОВАНИЕ
// ============================================================================

void KuznechikConstants::encrypt_block(Block128& block, const Block128 round_keys[10])
{
    for (int round = 0; round < 9; round++) 
    {
        block.xor_with(round_keys[round]);
        s_transform(block);
        linear_transform(block);
    }
    
    block.xor_with(round_keys[9]);
}

void KuznechikConstants::decrypt_block(Block128& block, const Block128 round_keys[10])
{
    block.xor_with(round_keys[9]);
    
    for (int round = 8; round >= 0; round--) 
    {
        inverse_linear_transform(block);
        inverse_s_transform(block);
        block.xor_with(round_keys[round]);
    }
}
