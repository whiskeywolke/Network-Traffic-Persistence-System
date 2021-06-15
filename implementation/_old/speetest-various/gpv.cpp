
#include <string>
#include <sstream>
#include <iomanip>
#include "gpv.h"
#include "om.h"

gpv::hdr::hdr()
        : ip_src(0), ip_dst(0), tp_src(0), tp_dst(0), ip_proto(0), pkt_count(0), ts_us(0)
{ }

std::string gpv::hdr::str_desc() const
{
    std::stringstream ss;
    ss  << "starflow::gpv::hdr(ts=" << om::etc::format_timestamp((unsigned)(ts_us / 1000000))
        << "." << std::fixed << std::setw(6) << std::setfill('0') << ts_us % 1000000 << "Z, ip_src="
        << om::net::ip4_addr::from_net(ip_src) << ", ip_dst=" << om::net::ip4_addr::from_net(ip_dst)
        << ", ip_proto=" << (unsigned) ip_proto << ", tp_src=" << tp_src << ", tp_dst=" << tp_dst
        << ", pkt_count=" << (unsigned) pkt_count << ")";

    return ss.str();
}

bool gpv::hdr::operator==(const hdr& other_) const
{
    return ip_src == other_.ip_src && ip_dst == other_.ip_dst && tp_src == other_.tp_src
           && tp_dst == other_.tp_dst && ip_proto == other_.ip_proto;
}

bool gpv::hdr::operator<(const hdr& other_) const
{
    return ip_src < other_.ip_src || ip_dst < other_.ip_dst || tp_src < other_.tp_src
           || tp_dst < other_.tp_dst || ip_proto < other_.ip_proto;
}

gpv::pkt::pkt()
        : pad(0), pkt_len(0), ts_delta_us(0), ts_egress_delta_us(0), queue_id(0), queue_depth(0),
          ip_id(0), pd(0)
{ }

std::string gpv::pkt::str_desc() const
{
    std::stringstream ss;
    ss << "starflow::gpv::pkt(ts_delta=" << ts_delta_us << ", len=" << pkt_len << ", id="
       << std::hex << std::setw(4) << std::setfill('0') << ip_id << ")";
    return ss.str();
}

unsigned gpv_t::total_bytes() const
{
    unsigned total = 0;
    for (auto i = 0; i < hdr.pkt_count; i++)
        total += pkt[i].pkt_len;
    return total;
}

uint32_t gpv_t::unix_time_stamp_s() const
{
    return (uint32_t) (hdr.ts_us / 1000 / 1000);
}

uint64_t gpv_t::unix_time_stamp_ms() const
{
    return hdr.ts_us / 1000;
}

gpv::ipv4_5tuple gpv::ipv4_5tuple::from_gpv(const gpv_t& gpv_)
{
    gpv::ipv4_5tuple ipv4_5tuple;
    ipv4_5tuple.ip_proto = (uint8_t) gpv_.hdr.ip_proto;
    ipv4_5tuple.ip_src   = gpv_.hdr.ip_src;
    ipv4_5tuple.ip_dst   = gpv_.hdr.ip_dst;
    ipv4_5tuple.tp_src   = gpv_.hdr.tp_src;
    ipv4_5tuple.tp_dst   = gpv_.hdr.tp_dst;
    return ipv4_5tuple;
}

bool gpv::ipv4_5tuple::operator==(const ipv4_5tuple& other_) const
{
    return ip_src == other_.ip_src && ip_dst == other_.ip_dst && tp_src == other_.tp_src
           && tp_dst == other_.tp_dst && ip_proto == other_.ip_proto;
}

bool gpv::ipv4_5tuple::operator<(const ipv4_5tuple& other_) const
{
    return ip_src < other_.ip_src || ip_dst < other_.ip_dst || tp_src < other_.tp_src
           || tp_dst < other_.tp_dst || ip_proto < other_.ip_proto;
}