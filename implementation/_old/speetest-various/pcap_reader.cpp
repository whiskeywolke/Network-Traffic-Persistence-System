
#include "pcap_reader.h"

pcap_reader::pcap_reader(const std::string& file_name_)
        : _file_name(file_name_)

{
    if (!(_pcap = pcap_open_offline(file_name_.c_str(), _errbuf)))
        throw std::runtime_error("pcap_reader: could not open " + file_name_ + "("+_errbuf+")");
}

bool pcap_reader::done() const
{
    return _done;
}

std::string pcap_reader::file_name() const
{
    return _file_name;
}

bool pcap_reader::is_open() const
{
    return _pcap != nullptr;
}

bool pcap_reader::next(const unsigned char** buf_, unsigned long& timestamp_us_,
                                 unsigned& frame_len_, unsigned& cap_len_)
{
    _peek();
    *buf_ = _pl_buf;
    timestamp_us_ = (unsigned long) _hdr->ts.tv_sec * 1000000 + _hdr->ts.tv_usec;
    frame_len_ = _hdr->len;
    cap_len_   = _hdr->caplen;
    return !_done;
}

void pcap_reader::close()
{
    pcap_close(_pcap);
    _pcap = nullptr;
}

pcap_reader::~pcap_reader()
{
    if (is_open()) close();
}

void pcap_reader::_peek()
{
    _pcap_status = pcap_next_ex(_pcap, &_hdr, &_pl_buf);

    if (_pcap_status == -2)
        _done = true;
}