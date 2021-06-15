
#ifndef STARFLOW_UTIL_H
#define STARFLOW_UTIL_H

#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <stdexcept>

    namespace util {

        inline std::size_t hash_combine(const std::size_t& a_, const std::size_t& b_)
        {
            return a_ ^ (b_ + 0x9e3779b9 + (a_ << 6) + (a_ >> 2));
        }

        namespace hash {

            struct h128 {
                uint64_t  h1;
                uint64_t  h2;
            };

            inline uint64_t _rotl64(uint64_t x_, uint64_t r_)
            {
                return (x_ << r_) | (x_ >> (64 - r_));
            }

            inline uint64_t _fmix64(uint64_t k_)
            {
                k_ ^= k_ >> 33;
                k_ *= 0xff51afd7ed558ccd;
                k_ ^= k_ >> 33;
                k_ *= 0xc4ceb9fe1a85ec53;
                k_ ^= k_ >> 33;
                return k_;
            }

            static h128 murmur3(const void* key_, unsigned len_, uint32_t seed_)
            {
                auto data = (const uint8_t*) key_;
                const unsigned nblocks = len_ / 16;
                uint64_t h1 = seed_, h2 = seed_;
                const uint64_t c1 = 0x87c37b91114253d5, c2 = 0x4cf5ad432745937f;
                auto blocks = (const uint64_t *)(data);

                for (auto i = 0; i < nblocks; i++) {
                    uint64_t k1 = blocks[2*i+0], k2 = blocks[2*i+1];
                    k1 *= c1, k1 = _rotl64(k1, 31), k1 *= c2, h1 ^= k1;
                    h1 = _rotl64(h1, 27), h1 += h2, h1 = h1 * 5 + 0x52dce729;
                    k2 *= c2, k2 = _rotl64(k2,33), k2 *= c1, h2 ^= k2;
                    h2 = _rotl64(h2, 31), h2 += h1, h2 = h2 * 5 + 0x38495ab5;
                }

                auto tail = (data + nblocks * 16);
                uint64_t k1 = 0, k2 = 0;

                switch (len_ & 15) {
                    case 15: k2 ^= ((uint64_t)tail[14]) << 48;
                    case 14: k2 ^= ((uint64_t)tail[13]) << 40;
                    case 13: k2 ^= ((uint64_t)tail[12]) << 32;
                    case 12: k2 ^= ((uint64_t)tail[11]) << 24;
                    case 11: k2 ^= ((uint64_t)tail[10]) << 16;
                    case 10: k2 ^= ((uint64_t)tail[ 9]) <<  8;
                    case  9: k2 ^= ((uint64_t)tail[ 8]) <<  0;
                        k2 *= c2; k2  = _rotl64(k2,33); k2 *= c1; h2 ^= k2;
                    case  8: k1 ^= ((uint64_t)tail[ 7]) << 56;
                    case  7: k1 ^= ((uint64_t)tail[ 6]) << 48;
                    case  6: k1 ^= ((uint64_t)tail[ 5]) << 40;
                    case  5: k1 ^= ((uint64_t)tail[ 4]) << 32;
                    case  4: k1 ^= ((uint64_t)tail[ 3]) << 24;
                    case  3: k1 ^= ((uint64_t)tail[ 2]) << 16;
                    case  2: k1 ^= ((uint64_t)tail[ 1]) <<  8;
                    case  1: k1 ^= ((uint64_t)tail[ 0]) <<  0;
                        k1 *= c1; k1  = _rotl64(k1,31); k1 *= c2; h1 ^= k1;
                    default: break;
                };

                h1 ^= len_; h2 ^= len_, h1 += h2, h2 += h1;
                h1 = _fmix64(h1), h2 = _fmix64(h2), h1 += h2, h2 += h1;
                return { h1, h2 };
            }


            template <typename Key>
            inline std::size_t murmur3(Key key_)
            {
                return murmur3(key_, sizeof(key_), 0x12db5e3a).h2;
            }
        }
    }


#endif