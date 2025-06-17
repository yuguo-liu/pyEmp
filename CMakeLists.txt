cmake_minimum_required(VERSION 3.4)
project(pyEmp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse3 -mssse3 -maes")

set(PYTHON_EXECUTABLE "/home/hugo/anaconda3/envs/client/bin/python")
set(PYTHON_INCLUDE_DIRECTORY "/home/hugo/anaconda3/envs/client/include/python3.10")

add_subdirectory(extern/pybind11)
pybind11_add_module(pyEmp bind.cpp)
# pybind11_add_module(example example.cpp)

find_package(OpenSSL REQUIRED)
target_link_libraries(pyEmp 
    PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto
    /usr/local/lib/libemp-tool.so
)