
#ifndef STARFLOW_GPV_H
#define STARFLOW_GPV_H

#include <cstdlib>
#include <cstdint>
#include <functional>

#include "om.h"

#include "util.h"


    namespace gpv {

        static const std::size_t MAX_LEN = 32;



        struct hdr // 20
        {
            hdr();
            hdr(const hdr&)            = default;
            hdr& operator=(const hdr&) = default;

            uint32_t ip_src     = 0;
            uint32_t ip_dst     = 0;
            uint16_t tp_src     = 0;
            uint16_t tp_dst     = 0;
            uint64_t ip_proto  :  8; // 0 - 255
            uint64_t pkt_count :  5; // 0 - 32 (MAX_LEN)
            uint64_t ts_us     : 51; // 0 - 225179981368524


            bool operator==(const hdr& other_) const;
            bool operator<(const hdr& other_) const;

            std::string str_desc() const;
        };

        struct pkt // 16
        {
            pkt();
            pkt(const pkt&)            = default;
            pkt& operator=(const pkt&) = default;

            uint64_t pad                :  4;
            uint64_t pkt_len            : 12; // 0 -     4096
            uint64_t ts_delta_us        : 26; // 0 - 67108864 -> 67s
            uint64_t ts_egress_delta_us : 22; // 0 -  4194304 ->  4s

            uint16_t queue_id           :  5; // 0 -   32
            uint16_t queue_depth        : 11; // 0 - 2048

            uint16_t ip_id;
            uint32_t pd;

            std::string str_desc() const;

            inline uint64_t unix_time_stamp_us(const hdr& hdr_) const
            {
                return hdr_.ts_us + ts_delta_us;
            }

            inline uint32_t unix_time_stamp_s(const hdr& hdr_) const
            {
                return (unsigned) ((hdr_.ts_us + ts_delta_us) / 1000000);
            }

            inline unsigned us_offset(const hdr& hdr_) const
            {
                return (unsigned) ((hdr_.ts_us + ts_delta_us) % 1000000);
            }
        };
    }

    struct gpv_t // 20 - 276
    {
        gpv_t() = default;
        gpv_t(const gpv_t &) = default;
        gpv_t &operator=(const gpv_t &) = default;

        struct gpv::hdr hdr = {};
        struct gpv::pkt pkt[gpv::MAX_LEN] = {{}};

        unsigned total_bytes() const;
        uint32_t unix_time_stamp_s() const;
        uint64_t unix_time_stamp_ms() const;

    };

    namespace gpv {
        struct ipv4_5tuple // mirrors the first 13 bytes of gpv::hdr
        {
            static ipv4_5tuple from_gpv(const gpv_t& gpv_);

            uint32_t ip_src   = 0;
            uint32_t ip_dst   = 0;
            uint16_t tp_src   = 0;
            uint16_t tp_dst   = 0;
            uint8_t  ip_proto = 0;

            bool operator==(const ipv4_5tuple& other_) const;
            bool operator<(const ipv4_5tuple& other_) const;
        };
    }



inline std::ostream& operator<<(std::ostream& os_, const gpv::hdr& hdr_)
{
    return os_ << hdr_.str_desc();
}

inline std::ostream& operator<<(std::ostream& os_, const gpv::pkt& pkt_)
{
    return os_ << pkt_.str_desc();
}

inline std::ostream& operator<<(std::ostream& os_, const gpv_t& gpv_)
{
    return os_ << gpv_.hdr;
}

namespace std {
    template<> struct hash<gpv::hdr> {
        std::size_t operator()(const gpv::hdr& d_) const noexcept {
            std::size_t a = 0, b = 0;
            // pack into two different long unsigned integers
            a |= (std::size_t) d_.ip_src   << 32;
            a |= (std::size_t) d_.ip_dst   <<  0;
            b |= (std::size_t) d_.tp_src   << 24;
            b |= (std::size_t) d_.tp_dst   <<  8;
            b |= (std::size_t) d_.ip_proto <<  0;
            return util::hash_combine(a, b);
        }
    };

    template<> struct hash<gpv_t> {
        std::size_t operator()(const gpv_t &d_) const noexcept {
            return std::hash<gpv::hdr>()(d_.hdr);
        }
    };

    template<> struct hash<gpv::ipv4_5tuple> {
        std::size_t operator()(const gpv::ipv4_5tuple& d_) const noexcept {
            std::size_t a = 0, b = 0;
            // pack into two different long unsigned integers
            a |= (std::size_t) d_.ip_src   << 32;
            a |= (std::size_t) d_.ip_dst   <<  0;
            b |= (std::size_t) d_.tp_src   << 24;
            b |= (std::size_t) d_.tp_dst   <<  8;
            b |= (std::size_t) d_.ip_proto <<  0;
            return util::hash_combine(a, b);
        }
    };
}



#endif