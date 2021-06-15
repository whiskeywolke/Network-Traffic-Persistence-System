
#ifndef STARFLOW_PCAP_READER_H
#define STARFLOW_PCAP_READER_H

#include <string>
#include <stdexcept>

#include <pcap/pcap.h>


    class pcap_reader
    {
    public:
        explicit pcap_reader(const std::string& file_name_);
        bool done() const;
        std::string file_name() const;
        bool is_open() const;
        bool next(const unsigned char** buf_, unsigned long& timestamp_us_, unsigned& frame_len_,
                  unsigned& cap_len_);
        void close();
        virtual ~pcap_reader();

    private:
        void _peek();

        std::string         _file_name;
        pcap*               _pcap                     = nullptr;
        struct pcap_pkthdr* _hdr                      = {};
        const u_char*       _pl_buf                   = {};
        char                _errbuf[PCAP_ERRBUF_SIZE] = {};
        int                 _pcap_status              = 0;
        bool                _done                     = false;
    };



#endif