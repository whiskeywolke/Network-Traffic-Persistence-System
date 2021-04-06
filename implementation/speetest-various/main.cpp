#include <fstream>
#include <chrono>
#include <vector>
#include <cstdint>
#include <numeric>
#include <random>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <omp.h>
#include <cstdlib>
#include <string>
#include <iostream>

#include <pcap.h>
#include "pcap_reader.h"
#include "gpv.h"
#include "Packet.h"
#include "stdlib.h"

std::vector<uint64_t> GenerateData(std::size_t bytes)
{
    assert(bytes % sizeof(uint64_t) == 0);
    std::vector<uint64_t> data(bytes / sizeof(uint64_t));
    std::iota(data.begin(), data.end(), 0);
    std::shuffle(data.begin(), data.end(), std::mt19937{ std::random_device{}() });


    return data;
}



long long option_1(std::size_t bytes)
{
    std::vector<uint64_t> data = GenerateData(bytes);

    auto startTime = std::chrono::high_resolution_clock::now();
    auto myfile = std::fstream("file.binary", std::ios::out | std::ios::binary);
    myfile.write((char*)&data[0], bytes);
    myfile.close();
    auto endTime = std::chrono::high_resolution_clock::now();

    return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
}

long long option_2(std::size_t bytes)
{
    std::vector<uint64_t> data = GenerateData(bytes);

    auto startTime = std::chrono::high_resolution_clock::now();
    FILE* file = fopen("file.binary", "wb");
    fwrite(&data[0], 1, bytes, file);
    fclose(file);
    auto endTime = std::chrono::high_resolution_clock::now();

    return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
}

long long option_3(std::size_t bytes)
{
    std::vector<uint64_t> data = GenerateData(bytes);

    std::ios_base::sync_with_stdio(false);
    auto startTime = std::chrono::high_resolution_clock::now();
    auto myfile = std::fstream("file.binary", std::ios::out | std::ios::binary);
    myfile.write((char*)&data[0], bytes);
    myfile.close();
    auto endTime = std::chrono::high_resolution_clock::now();

    return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
}

////////////////////////////

size_t calculate_length(size_t bytes){
    assert(bytes % sizeof(long long) == 0);

    size_t size = bytes/sizeof (long long);
    return size;
}

long long * makeData(std::size_t size){
    long long* data = new long long[size];
    #pragma omp parallel for
    for(size_t i = 0; i < size; ++i){
        long long p = 32;
        data[i] = p;//i%2;//rand();
    }
    return data;
}
long long write_option_1(long long* data, std::size_t from,std::size_t to, int name)
{
    auto startTime = std::chrono::high_resolution_clock::now();
    auto myfile = std::fstream("file.binary1"+ std::to_string(name), std::ios::out | std::ios::binary);
    myfile.write((char*)&data[from], to);
    myfile.close();
    auto endTime = std::chrono::high_resolution_clock::now();

    return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
}
long long write_option_1backup(long long* data, std::size_t from,std::size_t to)
{
    auto startTime = std::chrono::high_resolution_clock::now();
    auto myfile = std::fstream("file.binary1", std::ios::out | std::ios::binary);
    myfile.write((char*)&data[from], to);
    myfile.close();
    auto endTime = std::chrono::high_resolution_clock::now();

    return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
}
long long write_option_2(long long* data, std::size_t from,std::size_t to)
{
    auto startTime = std::chrono::high_resolution_clock::now();
    FILE* file = fopen("file.binary2", "wb");
    fwrite(&data[from], 1, to, file);
    fclose(file);
    auto endTime = std::chrono::high_resolution_clock::now();

    return std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
}
long long write_option_3(long long* data, std::size_t bytes) {

    //std::ios_base::sync_with_stdio(false);
    auto myfile = std::fstream("file.binary3", std::ios::out | std::ios::binary);

    size_t threadcount = 1;
    size_t blocksize = bytes / threadcount;
    size_t extra = bytes % threadcount;

    #pragma omp parallel for num_threads(threadcount)
    for (int i = 0; i < omp_get_num_threads(); ++i) {
        if (omp_get_thread_num() == 0) {
            myfile.write((char *) &data[0], blocksize + extra);
            #pragma omp critical
            std::cout << "tr0 " << 0 << " " << (blocksize + extra) / (1000 * 1000) << '\n';

        } else {
            size_t fromx{omp_get_thread_num() * blocksize + extra};
            size_t tox{fromx + blocksize};
            #pragma omp critical
            std::cout << "tr" << omp_get_thread_num() << " " << fromx / (1000 * 1000) << " " << tox / (1000 * 1000)<< '\n';

            myfile.write((char *) &data[fromx], tox);
        }
    }
    myfile.close();

    return 0;
}
int main()
{
   /* const std::size_t kB = 1000;
    const std::size_t MB = 1000 * kB;
    const std::size_t GB = 1024 * MB;

    std::cout <<"start"<<std::endl;

    std::size_t  bytes = 4000 * MB;
    size_t size = calculate_length(bytes);
    long long* data = makeData(size);

    size_t threadcount = 1;
    size_t blocksize = bytes / threadcount;
    size_t extra = bytes % threadcount;

    double_t time_1 = 0;

    std::cout<<"starting to write"<<std::endl;
    for(;threadcount<5;threadcount*=2) {
        auto startTime = std::chrono::high_resolution_clock::now();
#pragma omp parallel for num_threads(threadcount)
        for (int i = 0; i < threadcount; ++i) {
            write_option_1(data, 0, bytes / threadcount, omp_get_thread_num());
        }
        auto endTime = std::chrono::high_resolution_clock::now();

        time_1 = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

        std::cout << "option1, threads: " << threadcount << " " << bytes / MB << " MB: " << time_1 << "ms "
                  << (bytes / MB) / ((time_1) / 1000) << " MB/s" << std::endl;
    }

/*    for (std::size_t size = 1 * MB; size <= 4 * GB; size *= 2) std::cout << "option1, " << size / MB << "MB: " << option_1(size) << "ms" << std::endl;
    for (std::size_t size = 1 * MB; size <= 4 * GB; size *= 2) std::cout << "option2, " << size / MB << "MB: " << option_2(size) << "ms" << std::endl;
    for (std::size_t size = 1 * MB; size <= 4 * GB; size *= 2) std::cout << "option3, " << size / MB << "MB: " << option_3(size) << "ms" << std::endl;
*/
   std::cout<<"start"<<std::endl;


   pcap_reader reader = pcap_reader("/home/ubuntu/test.pcap");
    char                _errbuf[PCAP_ERRBUF_SIZE] = {};

    pcap_open_offline("/home/ubuntu/test.pcap", _errbuf);


   if(reader.is_open())
       std::cout<<"opened"<<std::endl;


    const unsigned char* buf = nullptr;
    unsigned long timestamp_us = 0;
    unsigned frame_len = 0, cap_len = 0;

    std::cout<<reader.is_open()<< reader.done()<<std::endl; //10

    std::vector<Packet> packets {};
    while (reader.next(&buf, timestamp_us, frame_len, cap_len))
        packets.emplace_back(buf, timestamp_us);

    std::cout<<"packet count : "<<packets.size()<<std::endl<<std::endl;

    for(auto packet: packets){
        std::cout
            <<packet.getPkt()[0]<<'\n'
            <<packet.getPkt()[1]<<'\n'
            <<packet.getPkt()[2]<<'\n'
            <<packet.getPkt()[3]<<'\n'
            <<packet.getPkt()[4]<<'\n'
            <<packet.getPkt()[5]<<'\n'
            <<packet.getPkt()[6]<<'\n'
            <<packet.getPkt()[7]<<'\n'
            <<'\n'<< packet.getTimestampUs()
            <<"\n********************\n";
    }


   // if(frame_len == 1504){
   //     std::cout<<"is equal\n";
   // }

   // std::cout << *buf << "\n" << timestamp_us << "\n" << frame_len << "ņ" << cap_len << std::endl;
   // reader.done();
   // std::cout << *buf << "\n" << timestamp_us << "\n" << frame_len << "ņ" << cap_len << std::endl;


    /*
    FILE * pFile;
    char buffer [100];

    pFile = fopen ("/home/ubuntu/reader.pcap" , "r");
    if (pFile == NULL) perror ("Error opening file");
    else
    {
        while ( ! feof (pFile) )
        {
            if ( fgets (buffer , 100 , pFile) == NULL ) break;
            fputs (buffer , stdout);
        }
        fclose (pFile);
    }

    //file = pcap_fopen_offline( &myfile , _errbuf);
*/



//    pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("/home/ubuntu/test.pcap");
  /*  if (reader == NULL)
    {
        printf("Cannot determine reader for file type\n");
        exit(1);
    }

*/
    std::cout<<"fin\n";
    return 0;
}



/*#include <iostream>
#include <vector>
#include <fstream>

using namespace std;

#define GB 1073741824;

int main() {
    std::cout << "Hello, World!2" << std::endl;
    std::ios::binary;
    //int64_t test = 0;
    //int8_t t2 = 0;
    //std::cout<< sizeof  test <<sizeof  t2 <<std::endl;

    std::vector<int64_t> vec {};
    size_t i = 0;
    while((sizeof(vec[0]) * vec.size())< 1073741824){
        int64_t temp = 34;
        vec.push_back(temp);

        ++i;
    }
    sizeof(vec[0]) * vec.size();
    cout<<sizeof(vec[0]) * vec.size()<<endl;
    cout<<vec.size()<<endl<<endl;
    //////////write to file
    int64_t* first =  vec.data();
    size_t size = vec.size();

 //   for(int i = 0; i < vec.size();++i) {
 //      cout<<first[i]<<endl;
 //  }

    ofstream fout("data.dat", ios::out | ios::binary);
    fout.write((char*)first, size);
    fout.close();

    return 0;
}
*/