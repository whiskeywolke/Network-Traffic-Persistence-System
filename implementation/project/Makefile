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
all:
#	if not [ -d build ]; then mkdir build; fi
	if [ ! -d "./build" ]; then   mkdir build; fi
	g++ src/main.cpp $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -L ${BOOST} -c -o build/main.o $(OPENMP) #-O0 #TODO REMOVE -O0 (disables compiler optimizations)
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/a.out build/main.o $(PCAPPP_LIBS) -I $(BOOST) -L $(BOOST_LIB) $(BOOST_SERIALIZATION) $(OPENMP) #-O0 #TODO REMOVE -O0 (disables compiler optimizations)
	./build/a.out

# Clean Target
clean:
	rm main.o
	rm a.out
