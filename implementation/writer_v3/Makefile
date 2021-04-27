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
BOOST_SERIALIZATION = -lboost_serialization

#openMP flag (include both at compile time & link time to prevent unecessary warnings)
OPENMP = -fopenmp
# All Target
.PHONY: all build run runSudo clean buildProfile runProfile

all: build run clean

profile: buildProfile runProfile

build:
	if [ ! -d "./build" ]; then   mkdir build; fi
	g++ src/main.cpp $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -L ${BOOST} -c -o build/main.o  -ltbb
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/a.out build/main.o $(PCAPPP_LIBS) -I $(BOOST) -L $(BOOST_LIB) $(BOOST_SERIALIZATION) -ltbb

buildDebug: #disabled compiler optimizations (-O0)
	if [ ! -d "./build" ]; then   mkdir build; fi
	g++ src/main.cpp $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -L ${BOOST} -c -o build/main.o  -O0
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/a.out build/main.o $(PCAPPP_LIBS) -I $(BOOST) -L $(BOOST_LIB) $(BOOST_SERIALIZATION)  -ltbb -O0

buildProfile:
	if [ ! -d "./build" ]; then   mkdir build; fi
	g++ src/main.cpp $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -L ${BOOST} -c -o build/main.o  -pg
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/a.out build/main.o $(PCAPPP_LIBS) -I $(BOOST) -L $(BOOST_LIB) $(BOOST_SERIALIZATION)  -ltbb -pg

runProfile:
	./build/a.out
	if [ ! -d "./profileResults" ]; then   mkdir profileResults; fi
	gprof ./build/a.out gmon.out  > profileResults/analysis.txt
run:
	./build/a.out

runSudo:  #for access to network interfaces
	sudo -S ./build/a.out

# Clean Target
clean:
	rm ./build/main.o
	rm ./build/a.out
