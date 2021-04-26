//
// Created by ubuntu on 19.04.21.
//

#ifndef IMPLEMENTATION_RAWCONTAINER_H
#define IMPLEMENTATION_RAWCONTAINER_H


struct RawContainer{
    const unsigned char* buf;
    unsigned cap_len;
    struct timeval timestamp;
    unsigned hdrlen;
    pcpp::LinkLayerType linkLayerType;
};


#endif //IMPLEMENTATION_RAWCONTAINER_H
