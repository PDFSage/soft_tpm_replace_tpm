// softtpm.hpp
#ifndef SOFTTPM_HPP
#define SOFTTPM_HPP

#include <string>
#include <vector>
#include <cstdint>

struct Quote {
    std::vector<std::string> pcrs;
    std::vector<uint8_t> sig;
    std::vector<uint8_t> nonce;
};

class SoftTPM {
public:
    SoftTPM(const std::string& path = ".softtpm");
    void extendPCR(uint32_t index, const std::vector<uint8_t>& data);
    Quote quote(const std::vector<uint8_t>& nonce, const std::vector<uint32_t>& mask);
    std::vector<uint8_t> getRandom(size_t n);
    std::vector<uint8_t> hmac(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
    std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
    std::vector<uint8_t> aesEncrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& data);
    std::vector<uint8_t> aesDecrypt(const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv, const std::vector<uint8_t>& data);
    std::vector<uint8_t> ecdh(const std::vector<uint8_t>& peerPubDer);
    void nvWrite(uint32_t index, const std::vector<uint8_t>& data);
    std::vector<uint8_t> nvRead(uint32_t index);
    uint64_t incCounter();
private:
    std::string basePath;
    void initKey();
    void initPCR();
    void initCounter();
    void savePCR();
    void saveCounter();
    void loadKey();
    void saveKey();
    std::vector<std::string> pcrs;
    uint64_t counter;
    struct EVP_PKEY* privKey;
};

#endif