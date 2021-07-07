Installing dependencies & building modules (tested on ubuntu 20.04.2)

    sudo apt update
    sudo apt upgrade
    sudo apt install build-essential git libboost-all-dev libpcap-dev
    git clone https://gitlab.cs.univie.ac.at/ct-student/2021-ss/ba-mente.git
    cd ba-mente/dependencies
    unzip PcapPlusPlus-20.08.zip -d ../..
    cd ../../PcapPlusPlus-20.08/
    ./configure-linux.sh --use-immediate-mode
    make
    sudo make install
    cd ../ba-mente/implementation/implementation_v3/
    make writer_build reader_build

Writer (read from pcap/device write database dump files) module example execution:
    ./build/writer/a.out -f ../testfiles/example.pcap -o ../testfiles/

Reader module example execution:
    ./build/reader/a.out -i ../testfiles/ -f "ip.addr == 88.221.154.110"


Command line flags writer module:
    -f -file                specifies path to input file (eg: -f ../testfiles/example.pcap)
    -o -out -output         specifies output directory of binary dump files (eg: -o  ../testfiles/), if not set path is ./
    -l -live                specifies live capture device (eg: -l enp0s3) requires sudo rights for access to network interface (if file input & live input is specified file input will be ignored)
    -b -benchmark           triggers benchmark mode, prints statistics in csv format to command line
    -s -sequential          sequential mode, steps in data pipeline are executed sequentially, not suitable for live capture, used for debugging purposes

Command line flags reader module:
    -i -input               specifies input directory (eg: -i ../testfiles/)
    -o -out -output         specifies output directory of pcap / csv file (eg: -o ../testfiles/) by default the same as input directory
    -f -filter              specifies a filter applied to the packets (eg: -f  "frame.len > 100") filter needs to be in quotation marks for correct interpretation of bash, query syntax explained below 
    -p -pcap                triggers creation of pcap file directed to path with -o
    -v -verbose             prints statistical information in human readable format
    -b -benchmark           prints statistical information in csv format to command line

    -a -aggregate           triggers aggregation operations with default values (sum of packet length per 1 second) (every aggregation flag overrides -pcap flag)
    -agI -intervall         sets aggregation interval in microseconds (eg: - agI 100000) default value if not set:1000000 (=1 second)
    -agOp -operator         specifies the aggregation operation performed. Possible values: sum mean min max count count_dist. (eg -agOp min) default value if not set: sum
    -agF -field             specifies the field of the stored ipTuple on which the operation is performed on. Possible values: v4Src v4Dst portSrc portDst protocol length. (eg: -agF protocol) default value if not set: length

Query/Filter Language:
    Multiple filters performed on a field of the packet can be chained together, the total query length is variable.
    Abstract Syntax:
    <IP tuple field> <comparison> <value> (<boolean operator> <IP tuple field> <comparison> <value>)*

    Values for IP Tuple Field:
        frame.time
        frame.len
        proto
        ip.src
        ip.dst
        ip.addr
        port
        port.src
        port.dst
    Note instead of writing proto == 6  one can use tcp, same goes for udp, icmp

    Values for comparison:
        ==
        !=
        <
        >
        <=
        >=

    Values for boolean operator:
        &&
        ||

    Values for Value:
        Depends on type either an IP address in formatted in standard format (eg: 10.0.0.1)
        For date it must be formatted the following : eg Jul 18, 2021 16:00:00
        Else for length, port or protocol it must be an integer

    Example Queries:
        ip.addr == 88.221.154.110
        ip.addr != 10.0.0.1 && udp
        ip.addr != 10.0.0.1 && udp ||tcp
        ip.dst == 88.221.154.110 && port == 443 && frame.len < 60
        frame.len > 0 && frame.len <= 99999999 && frame.time < Jun 15, 2021 12:00:00 && frame.time > Jun 15, 2000 12:00:00 && port >= 0 && ip.addr != 0.0.0.0

        Note that filters are evaluated from right to left:
        ip.addr != 0.0.0.0 && frame.time < Jun 15, 2021 12:00:00 || udp
        Will be interpreted as: 
        (ip.addr != 0.0.0.0 && (frame.time < Jun 15, 2021 12:00:00 || udp))





