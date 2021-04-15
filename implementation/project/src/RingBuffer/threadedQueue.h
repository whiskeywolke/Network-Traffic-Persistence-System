//
// Created by ubuntu on 13.04.21.
//

#ifndef IMPLEMENTATION_THREADEDQUEUE_H
#define IMPLEMENTATION_THREADEDQUEUE_H

#include <condition_variable>
#include <queue>
#include <mutex>
#include <iostream>
#include <memory>


template <typename T>
class threadedQueue { //inspired by https://www.youtube.com/watch?v=LqrF_nygxhY
private:
    std::queue<T> queue;

    mutable std::mutex mutex;
    std::condition_variable data_cond;
public:
    explicit threadedQueue(){};
    explicit threadedQueue(const threadedQueue& other){
        std::lock_guard<std::mutex> lock(other.mutex);
        this->queue = other.queue;
    };
    threadedQueue& operator = (const threadedQueue& rhs) = delete;
    void push(T value){
        std::lock_guard<std::mutex> lock(mutex);
        queue.push(value);
        data_cond.notify_one();
    };
    void wait_and_pop(T& value){
        std::unique_lock<std::mutex> lock(mutex);
        data_cond.wait(lock, [this]{return !queue.empty();});
        value = queue.front();
        queue.pop();
    };
  /*  std::shared_ptr<const T> wait_and_pop(){
        std::unique_lock<std::mutex> lock(mutex);
        data_cond.wait(lock, [this]{return !queue.empty();});
        std::shared_ptr<const T>retval(std::make_shared<const T>(queue.front()));
        queue.pop();
        return retval;
    };
    */
    bool try_pop(T& value){
        std::lock_guard<std::mutex> lock(mutex);
        if(queue.empty()){
            return false;
        }
        value = queue.front();
        queue.pop();
        return true;
    };
 /*   std::shared_ptr<const T> try_pop(){
        std::lock_guard<std::mutex> lock(mutex);
        if(queue.empty()){
            return nullptr;
        }
        std::shared_ptr<const T>retval(std::make_shared<const T>(queue.front()));
        queue.pop();
        return retval;
    };
    */
    bool empty() const{
        std::lock_guard<std::mutex> lock(mutex);
        return queue.empty();
    };

};


#endif //IMPLEMENTATION_THREADEDQUEUE_H
