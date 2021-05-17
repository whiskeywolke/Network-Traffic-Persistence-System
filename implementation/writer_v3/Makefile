#include /usr/local/etc/PcapPlusPlus.mk

# includes
PCAPPP_INCLUDES := -I/usr/local/include/pcapplusplus


# libs
PCAPPP_LIBS := -lPcap++ -lPacket++ -lCommon++

# post build
PCAPPP_POST_BUILD :=

# build flags
PCAPPP_BUILD_FLAGS :=

ifdef PCAPPP_ENABLE_CPP_FEATURE_DETECTION
	PCAPPP_BUILD_FLAGS += -DPCAPPP_CPP_FEATURE_DETECTION -std=c++11
endif

ifndef CXXFLAGS
CXXFLAGS := -O2 -g -Wall
endif

PCAPPP_BUILD_FLAGS += $(CXXFLAGS)
### LINUX ###

# includes
PCAPPP_INCLUDES += -I/usr/include/netinet

# libs
PCAPPP_LIBS += -lpcap -lpthread

# allow user to add custom LDFLAGS
PCAPPP_BUILD_FLAGS += $(LDFLAGS)

HAS_PCAP_IMMEDIATE_MODE := 1

# Boost C++ library Header
BOOST = /usr/include/boost
# Boost build location
BOOST_LIB = /usr/lib/x86_64-linux-gnu/
# Boost serialization library  (filename excluding lib and .a)
BOOST_SERIALIZATION = -lboost_serialization -lboost_iostreams

#openMP flag (include both at compile time & link time to prevent unecessary warnings)
OPENMP = -fopenmp
# All Target

WORKDIR = $(HOME)/testfiles/dir


.PHONY: all writer_build writer_run writer_runSudo clean writer_buildProfile writer_runProfile reader_build reader_run

all: writer_build writer_run writer_clean

profile: writer_buildProfile writer_runProfile

writer_build:
	if [ ! -d "./build" ]; then   mkdir build; fi
	if [ ! -d "./build/writer" ]; then   mkdir build/writer; fi
	g++ src/writer_main.cpp $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -L ${BOOST} -c -o build/writer/main.o
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/writer/a.out build/writer/main.o $(PCAPPP_LIBS) -I $(BOOST) -L $(BOOST_LIB) $(BOOST_SERIALIZATION)

writer_buildDebug: #disabled compiler optimizations (-O0)
	if [ ! -d "./build" ]; then   mkdir build; fi
	if [ ! -d "./build/writer" ]; then   mkdir build/writer; fi
	g++ src/writer_main.cpp $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -L ${BOOST} -c -o build/writer/main.o  -O0
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/writer/a.out build/writer/main.o $(PCAPPP_LIBS) -I $(BOOST) -L $(BOOST_LIB) $(BOOST_SERIALIZATION)   -O0

writer_buildProfile:
	if [ ! -d "./build" ]; then   mkdir build; fi
	if [ ! -d "./build/writer" ]; then   mkdir build/writer; fi
	g++ src/writer_main.cpp $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -L ${BOOST} -c -o build/writer/main.o  -pg
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/writer/a.out build/writer/main.o $(PCAPPP_LIBS) -I $(BOOST) -L $(BOOST_LIB) $(BOOST_SERIALIZATION)   -pg

writer_runProfile:
	./build/writer/a.out
	if [ ! -d "./build/writerProfileResults" ]; then   mkdir build/writerProfileResults; fi
	gprof ./build/writer/a.out gmon.out  > build/writerProfileResults/analysis.txt

writer_run:
	./build/writer/a.out -o $(WORKDIR) $(INPARAMS)

writer_runSudo:  #for access to network interfaces for live capture
	sudo -S ./build/writer/a.out

# Clean Target
writer_clean:
	rm ./build/writer/main.o
	rm ./build/writer/a.out

#######################
reader_build:
	if [ ! -d "./build" ]; then   mkdir build; fi
	if [ ! -d "./build/reader" ]; then   mkdir build/reader; fi
	g++ src/reader_main.cpp $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -L ${BOOST} -c -o build/reader/main.o
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/reader/a.out build/reader/main.o $(PCAPPP_LIBS) -I $(BOOST) -L $(BOOST_LIB) $(BOOST_SERIALIZATION)

reader_run:
	./build/reader/a.out -i $(WORKDIR)

reader_clean:
	rm ./build/reader/main.o
	rm ./build/reader/a.out