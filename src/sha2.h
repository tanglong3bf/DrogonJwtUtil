#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace tl::jwt::sha2
{

namespace constants
{
// sha224/sha256
constexpr std::array<uint32_t, 64> K32 = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2};

// sha384/sha512
constexpr std::array<uint64_t, 80> K64 = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

// init values for sha224/sha256/sha384/sha512
constexpr std::array<uint32_t, 8> sha224H = {0xc1059ed8,
                                             0x367cd507,
                                             0x3070dd17,
                                             0xf70e5939,
                                             0xffc00b31,
                                             0x68581511,
                                             0x64f98fa7,
                                             0xbefa4fa4};
constexpr std::array<uint32_t, 8> sha256H = {0x6a09e667,
                                             0xbb67ae85,
                                             0x3c6ef372,
                                             0xa54ff53a,
                                             0x510e527f,
                                             0x9b05688c,
                                             0x1f83d9ab,
                                             0x5be0cd19};
constexpr std::array<uint64_t, 8> sha384H = {0xcbbb9d5dc1059ed8,
                                             0x629a292a367cd507,
                                             0x9159015a3070dd17,
                                             0x152fecd8f70e5939,
                                             0x67332667ffc00b31,
                                             0x8eb44a8768581511,
                                             0xdb0c2e0d64f98fa7,
                                             0x47b5481dbefa4fa4};
constexpr std::array<uint64_t, 8> sha512H = {0x6a09e667f3bcc908,
                                             0xbb67ae8584caa73b,
                                             0x3c6ef372fe94f82b,
                                             0xa54ff53a5f1d36f1,
                                             0x510e527fade682d1,
                                             0x9b05688c2b3e6c1f,
                                             0x1f83d9abfb41bd6b,
                                             0x5be0cd19137e2179};
}  // namespace constants

inline uint32_t bswap32(uint32_t x)
{
    return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) |
           ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24);
}

inline uint64_t bswap64(uint64_t x)
{
    return ((x & 0xff00000000000000) >> 56) | ((x & 0x00ff000000000000) >> 40) |
           ((x & 0x0000ff0000000000) >> 24) | ((x & 0x000000ff00000000) >> 8) |
           ((x & 0x00000000ff000000) << 8) | ((x & 0x0000000000ff0000) << 24) |
           ((x & 0x000000000000ff00) << 40) | ((x & 0x00000000000000ff) << 56);
}

inline uint32_t ROTR(uint32_t X, uint8_t offset)
{
    return (X >> offset) | (X << (32 - offset));
}

inline uint32_t s0(uint32_t X)
{
    return ROTR(X, 7) ^ ROTR(X, 18) ^ (X >> 3);
}

inline uint32_t s1(uint32_t X)
{
    return ROTR(X, 17) ^ ROTR(X, 19) ^ (X >> 10);
}

inline uint32_t S0(uint32_t X)
{
    return ROTR(X, 2) ^ ROTR(X, 13) ^ ROTR(X, 22);
}

inline uint32_t S1(uint32_t X)
{
    return ROTR(X, 6) ^ ROTR(X, 11) ^ ROTR(X, 25);
}

inline uint32_t Ch(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X & Y) ^ ((~X) & Z);
}

inline uint32_t Maj(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X & Y) ^ (X & Z) ^ (Y & Z);
}

inline uint64_t ROTR(uint64_t X, uint8_t offset)
{
    return (X >> offset) | (X << (64 - offset));
}

inline uint64_t s0(uint64_t X)
{
    return ROTR(X, 1) ^ ROTR(X, 8) ^ (X >> 7);
}

inline uint64_t s1(uint64_t X)
{
    return ROTR(X, 19) ^ ROTR(X, 61) ^ (X >> 6);
}

inline uint64_t S0(uint64_t X)
{
    return ROTR(X, 28) ^ ROTR(X, 34) ^ ROTR(X, 39);
}

inline uint64_t S1(uint64_t X)
{
    return ROTR(X, 14) ^ ROTR(X, 18) ^ ROTR(X, 41);
}

inline uint64_t Ch(uint64_t X, uint64_t Y, uint64_t Z)
{
    return (X & Y) ^ ((~X) & Z);
}

inline uint64_t Maj(uint64_t X, uint64_t Y, uint64_t Z)
{
    return (X & Y) ^ (X & Z) ^ (Y & Z);
}

template <bool is224 = false>
std::string sha2_32(const std::string &input)
{
    uint64_t size = input.size();
    auto cha = 64 - (size + 9) % 64;
    if (cha == 64)
    {
        cha = 0;
    }
    size <<= 3;
    std::string data = input;
    data.append(1, 0x80);
    data.append(cha, 0x00);
    auto *pSize = reinterpret_cast<unsigned char *>(&size);
    for (int i = 7; i >= 0; --i)
    {
        data.append(1, pSize[i]);
    }

    std::array<uint32_t, 8> H;
    if constexpr (is224)
    {
        H = constants::sha224H;
    }
    else
    {
        H = constants::sha256H;
    }

    uint32_t W[64] = {0};

    for (int i = 0; i < data.size() / 64; ++i)
    {
        for (int j = 0; j < 64; j = j + 4)
        {
            uint32_t k = (i << 6) + j;
            W[j / 4] = (static_cast<uint32_t>(data[k] & 0xff) << 24) |
                       (static_cast<uint32_t>(data[k + 1] & 0xff) << 16) |
                       (static_cast<uint32_t>(data[k + 2] & 0xff) << 8) |
                       static_cast<uint32_t>(data[k + 3] & 0xff);
        }
        for (int i = 16; i < 64; i++)
        {
            W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
        }

        uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5],
                 g = H[6], h = H[7];
        for (int i = 0; i < 64; ++i)
        {
            uint32_t t1 = h + S1(e) + Ch(e, f, g) + constants::K32[i] + W[i];
            uint32_t t2 = S0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }
    H[0] = bswap32(H[0]);
    H[1] = bswap32(H[1]);
    H[2] = bswap32(H[2]);
    H[3] = bswap32(H[3]);
    H[4] = bswap32(H[4]);
    H[5] = bswap32(H[5]);
    H[6] = bswap32(H[6]);
    H[7] = bswap32(H[7]);

    std::string result;
    for (int i = 0; i < 7; ++i)
    {
        result.append(reinterpret_cast<char *>(&H[i]), 4);
    }
    if constexpr (!is224)
    {
        result.append(reinterpret_cast<char *>(&H[7]), 4);
    }
    return result;
}

template <bool is384 = false>
std::string sha2_64(const std::string &input)
{
    unsigned long long size = input.size();
    auto cha = 128 - (size + 17) % 128;
    if (cha == 128)
    {
        cha = 0;
    }
    size <<= 3;
    std::string data = input;
    data.append(1, 0x80);
    data.append(cha, 0x00);
    auto *pSize = reinterpret_cast<unsigned char *>(&size);
    data.append(8, 0x00);
    for (int i = 7; i >= 0; --i)
    {
        data.append(1, pSize[i]);
    }

    std::array<uint64_t, 8> H;
    if constexpr (is384)
    {
        H = constants::sha384H;
    }
    else
    {
        H = constants::sha512H;
    }

    uint64_t W[80] = {0};

    for (int i = 0; i < data.size() / 128; ++i)
    {
        for (int j = 0; j < 128; j = j + 8)
        {
            uint64_t k = (i << 7) + j;
            W[j / 8] = (static_cast<uint64_t>(data[k] & 0xff) << 56) |
                       (static_cast<uint64_t>(data[k + 1] & 0xff) << 48) |
                       (static_cast<uint64_t>(data[k + 2] & 0xff) << 40) |
                       (static_cast<uint64_t>(data[k + 3] & 0xff) << 32) |
                       (static_cast<uint64_t>(data[k + 4] & 0xff) << 24) |
                       (static_cast<uint64_t>(data[k + 5] & 0xff) << 16) |
                       (static_cast<uint64_t>(data[k + 6] & 0xff) << 8) |
                       (static_cast<uint64_t>(data[k + 7] & 0xff));
        }
        for (int i = 16; i < 80; i++)
        {
            W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
        }

        uint64_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5],
                 g = H[6], h = H[7];
        for (int i = 0; i < 80; ++i)
        {
            uint64_t t1 = h + S1(e) + Ch(e, f, g) + constants::K64[i] + W[i];
            uint64_t t2 = S0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }
    H[0] = bswap64(H[0]);
    H[1] = bswap64(H[1]);
    H[2] = bswap64(H[2]);
    H[3] = bswap64(H[3]);
    H[4] = bswap64(H[4]);
    H[5] = bswap64(H[5]);
    H[6] = bswap64(H[6]);
    H[7] = bswap64(H[7]);

    std::string result;
    for (int i = 0; i < 6; ++i)
    {
        result.append(reinterpret_cast<char *>(&H[i]), 8);
    }
    if constexpr (!is384)
    {
        result.append(reinterpret_cast<char *>(&H[6]), 8);
        result.append(reinterpret_cast<char *>(&H[7]), 8);
    }
    return result;
}

inline std::string sha224(const std::string &input)
{
    return sha2_32<true>(input);
}

inline std::string sha256(const std::string &input)
{
    return sha2_32(input);
}

inline std::string sha384(const std::string &input)
{
    return sha2_64<true>(input);
}

inline std::string sha512(const std::string &input)
{
    return sha2_64(input);
}
}  // namespace tl::jwt::sha2
