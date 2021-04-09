//
// Created by ubuntu on 12.04.21.
//

#ifndef IMPLEMENTATION_RINGBUFFER_H
#define IMPLEMENTATION_RINGBUFFER_H

#include <mutex>
#include<chrono>
#include <atomic>
#include <condition_variable>
#include <future>


template<class T, size_t N>
class RingBuffer {
private:
    std::atomic<bool> full = false;
    size_t push_offset = 0, pop_offset = 0;
    std::array<T, N> buffer{};

    size_t next(size_t offset) {
        return (offset + 1) % N;
    }
    std::condition_variable data_cond;
    mutable std::mutex m;
public:
    void push(T&& t) {
        std::unique_lock<std::mutex> lk(m);
        while(full)
            data_cond.wait(lk);
        buffer[push_offset] = t;
        push_offset = next(push_offset);
        if(pop_offset == push_offset) {
            full = true;
        }
    }
    T pop() {
        std::unique_lock<std::mutex> lk(m);
        size_t offset = pop_offset;
        pop_offset = next(pop_offset);
        T tmp = std::move(buffer[offset]);
        full = false;
        data_cond.notify_one();
        return tmp;
    }

    bool empty(){
        return (!full && (push_offset == pop_offset));
    }
};

#endif //IMPLEMENTATION_RINGBUFFER_H
