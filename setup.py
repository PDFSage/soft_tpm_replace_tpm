# setup.py
from setuptools import setup, Extension
import pybind11

ext = Extension(
    "softtpm",
    ["softtpm.cpp", "binding.cpp"],
    include_dirs=[pybind11.get_include(), "."],
    libraries=["crypto"],
    extra_compile_args=["-std=c++17"]
)

setup(
    name="softtpm",
    version="0.1",
    ext_modules=[ext],
)

// tool.cpp
#include "softtpm.hpp"
#include <iostream>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

int main(int argc, char** argv) {
    SoftTPM tpm;
    if (argc<2) return std::cerr<<"cmd extend|quote|getrand|nvread|nvwrite|cnt\n",1;
    std::string c=argv[1];
    if(c=="extend"){
        std::string d=argv[2];
        tpm.extendPCR(0,std::vector<uint8_t>(d.begin(),d.end()));
    } else if(c=="quote"){
        auto q=tpm.quote(tpm.getRandom(16),{0});
        json j; j["nonce"]=q.nonce; j["pcrs"]=q.pcrs; j["sig"]=q.sig;
        std::cout<<j.dump(2)<<"\n";
    } else if(c=="getrand"){
        auto r=tpm.getRandom(16);
        for(auto b:r)printf("%02x",b);printf("\n");
    } else if(c=="nvwrite"){
        std::string d=argv[2];
        tpm.nvWrite(1,std::vector<uint8_t>(d.begin(),d.end()));
    } else if(c=="nvread"){
        auto d=tpm.nvRead(1);
        std::cout<<std::string(d.begin(),d.end())<<"\n";
    } else if(c=="cnt"){
        std::cout<<tpm.incCounter()<<"\n";
    }
    return 0;
}