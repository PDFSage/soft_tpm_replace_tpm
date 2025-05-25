# build on Kali Live
sudo apt install -y build-essential libssl-dev python3-pip python3-dev nlohmann-json-dev
pip3 install pybind11
g++ -std=c++17 -fPIC -I. -c softtpm.cpp -o softtpm.o
g++ -std=c++17 -fPIC -I/usr/include/python3.9 -I. -c binding.cpp -o binding.o
g++ -shared softtpm.o binding.o -lcrypto -o softtpm.so
g++ -std=c++17 tool.cpp softtpm.o -lcrypto -o softtpm_tool

# install python module
python3 setup.py build_ext --inplace