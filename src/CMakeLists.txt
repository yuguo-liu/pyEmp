cmake_minimum_required(VERSION 3.14)
project(pyEmp)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse3 -mssse3 -maes")

set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(PYTHON_EXECUTABLE "/home/hugo/anaconda3/envs/clients/bin/python")
set(PYTHON_INCLUDE_DIRECTORY "/home/hugo/anaconda3/envs/clients/include/python3.12")

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