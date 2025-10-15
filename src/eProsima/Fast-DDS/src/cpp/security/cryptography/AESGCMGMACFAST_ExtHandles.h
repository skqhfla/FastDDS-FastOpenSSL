#ifndef FASTDDS_SECURITY_CRYPTOGRAPHY_AESGCMGMACFAST_EXTHANDLES_H
#define FASTDDS_SECURITY_CRYPTOGRAPHY_AESGCMGMACFAST_EXTHANDLES_H

#include <fastdds/rtps/security/cryptography/CryptoKeyFactory.h>
#include <fastdds/rtps/attributes/PropertyPolicy.h>

#include <security/cryptography/AESGCMGMACFAST_Types.h>
#include <security/cryptography/AESGCMGMAC_Types.h>

#include <memory>
#include <atomic>
#include <chrono>
#include <thread>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

constexpr size_t KEYSTREAM_SIZE = 4096;
constexpr size_t MAX_COUNTER_BLOCK_SIZE = 7;
constexpr size_t BUFFER_SIZE = KEYSTREAM_SIZE * MAX_COUNTER_BLOCK_SIZE;
constexpr size_t AES_GCM_BLOCK_SIZE = 16;
constexpr size_t CHUNK_SIZE = 32;

struct CircularBuffer{
    unsigned char keystreams[KEYSTREAM_SIZE * MAX_COUNTER_BLOCK_SIZE][AES_GCM_BLOCK_SIZE];
    std::atomic<int> head;
    std::atomic<int> tail;
    std::atomic<bool> stop_round;
    std::atomic<int> session;
    std::atomic<int> last;
    std::ofstream log;

    CircularBuffer(int session_id) : head(0), tail(0), stop_round(false), last(0) {
        session.store(session_id, std::memory_order_release);

        auto now = std::chrono::system_clock::now();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();

        std::string filename = "/home/user/ring_buffer_" + std::to_string(session_id) + "_" + std::to_string(millis) + ".log";
        log.open(filename, std::ios::app);
    }

    size_t remain_size() const
    {
        int h = head.load();
        int t = tail.load();

        if(h > t)
            return BUFFER_SIZE - (h - t) -1;
        else
            return (t - h - 1);
    }

    size_t used_size() const
    {
        int h = head.load();
        int t = tail.load();

        if (t >= h)
            return t - h;
        else
            return BUFFER_SIZE - (h - t);
    }

    size_t get_last()
    {
        return last.load();
    }

    bool push(EVP_CIPHER_CTX* ctx)
    {

        int block_cnt;
        int session_id = session.load(std::memory_order_acquire);

        //max_blocks_per_session
        for(int round = 0; round < 32; round++){

            log << "==" << session_id << "  ROUND " << round << " start ==" << std::endl;

            stop_round.store(false, std::memory_order_release);

            //max iv counter
            for(size_t i = 0; i < KEYSTREAM_SIZE; i += CHUNK_SIZE){

                if(stop_round.load(std::memory_order_acquire)){
                    log << "[" << session_id << "  Round " << round << "] aborted due to overrun" << std::endl;

                    int h = head.load(std::memory_order_acquire);
                    tail.store(h, std::memory_order_release);
                    log << "Tail adjusted to head (" << h << ")" << std::endl;
                    break;
                }

                while(remain_size() == 0){
                    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_INTERVAL));
                }

                int cur_tail = tail.load();
                size_t space_end = BUFFER_SIZE - cur_tail;

                if(space_end >= CHUNK_SIZE){
                    jinho_EVP_EncryptUpdate(ctx, keystreams[tail.load()], &block_cnt, (const unsigned char *)"A", CHUNK_SIZE);
                } else{
                    jinho_EVP_EncryptUpdate(ctx, keystreams[tail.load()], &block_cnt, (const unsigned char *)"A", space_end);
                    jinho_EVP_EncryptUpdate(ctx, keystreams[0], &block_cnt, (const unsigned char *)"A", CHUNK_SIZE - space_end);
                }

                tail.store((cur_tail + CHUNK_SIZE) % BUFFER_SIZE);

                /*
                log << "Tail : " << cur_tail << "| Data :";
                for(size_t i = 0; i < AES_GCM_BLOCK_SIZE; i++){
                    log << std::hex << (int)keystreams[cur_tail][i] << " ";
                }
                log << std::endl;
                */
            }
        }

        return true;
    }

    void move_head(int shift){
        int h = head.load(std::memory_order_acquire);
        int t = tail.load(std::memory_order_acquire);
        
        while(stop_round.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            log << "*** move head wait moving tail head : " << h << " / tail : " << tail << " ***" << std::endl;
        } 

        int new_head = (h + shift) % BUFFER_SIZE;
        head.store(new_head, std::memory_order_release);

        if(((h < t) && (new_head >= t)) || ((h >= t) && (new_head >= t) && (new_head < h))){
            log << "[Tirgger] Overrun detected! Stop current round (" 
                      << session.load(std::memory_order_acquire) << ")" << std::endl;
            stop_round.store(true, std::memory_order_release);
        }


        log << "Keystream sync adjusted: head=" << new_head
                  << " (shift=" << shift << ")" << std::endl;
    }

    unsigned char * get_keystream(int len, int block_cnt, EVP_CIPHER_CTX * ctx)
    {
        log << "--- get_keystream : " << session.load(std::memory_order_acquire) << " | size : " << len << " ---" << std::endl;
        int blocks_needed = (len + AES_GCM_BLOCK_SIZE - 1) / AES_GCM_BLOCK_SIZE;
        unsigned char *buf = (unsigned char (*))malloc(blocks_needed * AES_GCM_BLOCK_SIZE);
        if(!buf)
            return NULL;

        unsigned char* out_ptr = buf;
        int res = blocks_needed;
        int h, t;
        int l = last.load(std::memory_order_acquire);

        int diff = block_cnt - l;

        if(diff > 1){
            int shift = (diff - 1) * KEYSTREAM_SIZE;

            move_head(shift);
        }

        if(!stop_round.load(std::memory_order_acquire)){
        
            while(res > 0){
                h = head.load(std::memory_order_acquire);
                t = tail.load(std::memory_order_acquire);

                int item_len = (h <= t) ? (t - h) : (BUFFER_SIZE - h + t);
                if(item_len <= 0) continue;

                log << "item_len : " << item_len << std::endl;

                int cnt = (item_len < res) ? item_len : res;

                int first_part = std::min<int>(cnt, BUFFER_SIZE - h);
                memcpy(out_ptr, keystreams[h], AES_GCM_BLOCK_SIZE * first_part);

                if(cnt > first_part){
                    memcpy(out_ptr + (first_part * AES_GCM_BLOCK_SIZE),
                            keystreams[0],
                            AES_GCM_BLOCK_SIZE * (cnt - first_part));
                }

                head.store((h + cnt) % BUFFER_SIZE, std::memory_order_release);
                res -= cnt;
                out_ptr += (cnt * AES_GCM_BLOCK_SIZE);
            }
        }

        log << "out while" << std::endl;

        move_head((KEYSTREAM_SIZE - blocks_needed));
        last.store(block_cnt, std::memory_order_release);

        log << "head : " << head.load(std::memory_order_acquire) << std::endl;
        log << "tail : " << tail.load(std::memory_order_acquire) << std::endl;
        log << "block count : " << block_cnt << " | get keystream : ";

        for(int i = 0; i < blocks_needed * AES_GCM_BLOCK_SIZE; i++){
            log << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]) << " ";
        }
        log << std::dec << std::endl;

        if(block_cnt == 32)
            EVP_CIPHER_CTX_free(ctx);
/*
*/
        return buf;
    }
};

struct AESGCMGMACFAST_WriterCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;
    using BaseType = HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>;

    std::shared_ptr<CircularBuffer> data_session_buffer;
    EVP_CIPHER_CTX* ctx = nullptr;
    int session;

    static AESGCMGMACFAST_WriterCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_WriterCryptoHandleImpl&>(
                BaseType::narrow(handle));
                
    }

    static BaseType& narrow_base(DatawriterCryptoHandle& handle)
    {
        return static_cast<BaseType&>(
                BaseType::narrow(handle));
    }
};
    
struct AESGCMGMACFAST_ReaderCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;

    std::shared_ptr<CircularBuffer> data_session_buffer;
    EVP_CIPHER_CTX* ctx = nullptr;

    static AESGCMGMACFAST_ReaderCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_ReaderCryptoHandleImpl&>(
                HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::narrow(handle));
    }
};

struct AESGCMGMACFAST_EntityCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;

    std::shared_ptr<CircularBuffer> data_session_buffer;
    EVP_CIPHER_CTX* ctx = nullptr;

    static AESGCMGMACFAST_EntityCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_EntityCryptoHandleImpl&>(
                HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::narrow(handle));
    }
};
typedef AESGCMGMACFAST_WriterCryptoHandleImpl AESGCMGMACFAST_WriterCryptoHandle;
typedef AESGCMGMACFAST_ReaderCryptoHandleImpl AESGCMGMACFAST_ReaderCryptoHandle;
typedef AESGCMGMACFAST_EntityCryptoHandleImpl AESGCMGMACFAST_EntityCryptoHandle;
/*
using AESGCMGMACFAST_WriterCryptoHandle = std::shared_ptr<AESGCMGMACFAST_WriterCryptoHandleImpl>;
using AESGCMGMACFAST_ReaderCryptoHandle = std::shared_ptr<AESGCMGMACFAST_ReaderCryptoHandleImpl>;
using AESGCMGMACFAST_EntityCryptoHandle = std::shared_ptr<AESGCMGMACFAST_EntityCryptoHandleImpl>;
*/
}
}
}
}

#endif
