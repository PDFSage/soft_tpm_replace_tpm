// softtpm.cpp
#include "softtpm.hpp"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

static std::string toHex(const std::vector<uint8_t>& d){
    std::ostringstream o;
    for(auto b:d) o<<std::hex<<std::setw(2)<<std::setfill('0')<<int(b);
    return o.str();
}
static std::vector<uint8_t> fromHex(const std::string& s){
    std::vector<uint8_t> r(s.size()/2);
    for(size_t i=0;i<r.size();i++){
        unsigned int x; std::istringstream(s.substr(2*i,2))>>std::hex>>x;
        r[i]=x;
    }
    return r;
}

SoftTPM::SoftTPM(const std::string& path):basePath(path){
    std::filesystem::create_directories(basePath);
    initKey();
    initPCR();
    initCounter();
}

void SoftTPM::initKey(){
    std::string f=basePath+"/key.pem";
    if(std::filesystem::exists(f)){
        loadKey();
    } else {
        RSA* r=RSA_new();
        BIGNUM* e=BN_new(); BN_set_word(e,65537);
        RSA_generate_key_ex(r,2048,e,nullptr);
        privKey=EVP_PKEY_new(); EVP_PKEY_assign_RSA(privKey,r);
        BN_free(e);
        saveKey();
    }
}

void SoftTPM::loadKey(){
    std::string f=basePath+"/key.pem";
    FILE* fp=fopen(f.c_str(),"r");
    privKey=PEM_read_PrivateKey(fp,nullptr,nullptr,nullptr);
    fclose(fp);
}

void SoftTPM::saveKey(){
    std::string f=basePath+"/key.pem";
    FILE* fp=fopen(f.c_str(),"w");
    PEM_write_PrivateKey(fp,privKey,nullptr,nullptr,0,nullptr,nullptr);
    fclose(fp);
}

void SoftTPM::initPCR(){
    std::string f=basePath+"/pcrs.txt";
    if(std::filesystem::exists(f)){
        std::ifstream in(f);
        std::string line;
        while(std::getline(in,line)) pcrs.push_back(line);
    } else {
        for(int i=0;i<24;i++) pcrs.push_back(std::string(64,'0'));
        savePCR();
    }
}

void SoftTPM::savePCR(){
    std::ofstream out(basePath+"/pcrs.txt");
    for(auto& h:pcrs) out<<h<<"\n";
}

void SoftTPM::extendPCR(uint32_t idx,const std::vector<uint8_t>& d){
    auto old=fromHex(pcrs[idx]);
    SHA256_CTX c; SHA256_Init(&c);
    SHA256_Update(&c,old.data(),old.size());
    SHA256_Update(&c,d.data(),d.size());
    std::vector<uint8_t> out(32);
    SHA256_Final(out.data(),&c);
    pcrs[idx]=toHex(out);
    savePCR();
}

Quote SoftTPM::quote(const std::vector<uint8_t>& nonce,const std::vector<uint32_t>& mask){
    std::vector<uint8_t> concat;
    Quote q; q.nonce=nonce;
    for(auto i:mask){
        auto b=fromHex(pcrs[i]);
        concat.insert(concat.end(),b.begin(),b.end());
        q.pcrs.push_back(pcrs[i]);
    }
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx=nullptr;
    EVP_DigestSignInit(ctx,&pctx,EVP_sha256(),nullptr,privKey);
    EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_PSS_PADDING);
    EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -2);
    EVP_DigestSignUpdate(ctx,nonce.data(),nonce.size());
    EVP_DigestSignUpdate(ctx,concat.data(),concat.size());
    size_t sl; EVP_DigestSignFinal(ctx,nullptr,&sl);
    q.sig.resize(sl);
    EVP_DigestSignFinal(ctx,q.sig.data(),&sl);
    EVP_MD_CTX_free(ctx);
    return q;
}

std::vector<uint8_t> SoftTPM::getRandom(size_t n){
    std::vector<uint8_t> b(n);
    RAND_bytes(b.data(),n);
    return b;
}

std::vector<uint8_t> SoftTPM::hmac(const std::vector<uint8_t>& k,const std::vector<uint8_t>& d){
    unsigned int l;
    auto p=HMAC(EVP_sha256(),k.data(),k.size(),d.data(),d.size(),nullptr,&l);
    return std::vector<uint8_t>(p,p+l);
}

std::vector<uint8_t> SoftTPM::sha256(const std::vector<uint8_t>& d){
    std::vector<uint8_t> out(32);
    SHA256(d.data(),d.size(),out.data());
    return out;
}

std::vector<uint8_t> SoftTPM::aesEncrypt(const std::vector<uint8_t>& k,const std::vector<uint8_t>& iv,const std::vector<uint8_t>& d){
    EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c,EVP_aes_256_cbc(),nullptr,k.data(),iv.data());
    std::vector<uint8_t> out(d.size()+16);
    int len1,len2;
    EVP_EncryptUpdate(c,out.data(),&len1,d.data(),d.size());
    EVP_EncryptFinal_ex(c,out.data()+len1,&len2);
    out.resize(len1+len2);
    EVP_CIPHER_CTX_free(c);
    return out;
}

std::vector<uint8_t> SoftTPM::aesDecrypt(const std::vector<uint8_t>& k,const std::vector<uint8_t>& iv,const std::vector<uint8_t>& d){
    EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(c,EVP_aes_256_cbc(),nullptr,k.data(),iv.data());
    std::vector<uint8_t> out(d.size());
    int len1,len2;
    EVP_DecryptUpdate(c,out.data(),&len1,d.data(),d.size());
    EVP_DecryptFinal_ex(c,out.data()+len1,&len2);
    out.resize(len1+len2);
    EVP_CIPHER_CTX_free(c);
    return out;
}

std::vector<uint8_t> SoftTPM::ecdh(const std::vector<uint8_t>& peerDer){
    EC_KEY* priv=EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(priv);
    const unsigned char* p=peerDer.data();
    EC_KEY* peer=d2i_EC_PUBKEY(nullptr,&p,peerDer.size());
    std::vector<uint8_t> secret(ECDH_size(priv));
    ECDH_compute_key(secret.data(),secret.size(),EC_KEY_get0_public_key(peer),priv,nullptr);
    EC_KEY_free(priv);
    EC_KEY_free(peer);
    return secret;
}

void SoftTPM::initCounter(){
    std::string f=basePath+"/ctr.txt";
    if(std::filesystem::exists(f)){
        std::ifstream in(f); in>>counter;
    } else {
        counter=0;
        saveCounter();
    }
}

void SoftTPM::saveCounter(){
    std::ofstream out(basePath+"/ctr.txt");
    out<<counter;
}

uint64_t SoftTPM::incCounter(){
    counter++;
    saveCounter();
    return counter;
}

void SoftTPM::nvWrite(uint32_t idx,const std::vector<uint8_t>& d){
    std::ofstream out(basePath+"/nv_"+std::to_string(idx)+".bin",std::ios::binary);
    out.write(reinterpret_cast<const char*>(d.data()),d.size());
}

std::vector<uint8_t> SoftTPM::nvRead(uint32_t idx){
    std::ifstream in(basePath+"/nv_"+std::to_string(idx)+".bin",std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)),{});
}

// binding.cpp
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "softtpm.hpp"
namespace py = pybind11;
PYBIND11_MODULE(softtpm, m) {
    py::class_<SoftTPM>(m, "SoftTPM")
        .def(py::init<const std::string&>(), "path"_a=".softtpm")
        .def("extend_pcr", &SoftTPM::extendPCR, "index"_a, "data"_a)
        .def("quote", &SoftTPM::quote, "nonce"_a, "mask"_a)
        .def("get_random", &SoftTPM::getRandom, "n"_a)
        .def("hmac", &SoftTPM::hmac, "key"_a, "data"_a)
        .def("sha256", &SoftTPM::sha256, "data"_a)
        .def("aes_encrypt", &SoftTPM::aesEncrypt, "key"_a, "iv"_a, "data"_a)
        .def("aes_decrypt", &SoftTPM::aesDecrypt, "key"_a, "iv"_a, "data"_a)
        .def("ecdh", &SoftTPM::ecdh, "peer_pub"_a)
        .def("nv_write", &SoftTPM::nvWrite, "index"_a, "data"_a)
        .def("nv_read", &SoftTPM::nvRead, "index"_a)
        .def("inc_counter", &SoftTPM::incCounter);
}