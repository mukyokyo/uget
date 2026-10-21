# uget is a C++ project, no pyproject.toml needed, providing a CMakeLists.txt instead for alternative build systems

cmake_minimum_required(VERSION 3.10)
project(uget)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Statically link C/C++ runtimes
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_executable(uget uget.cpp)
target_link_libraries(uget winhttp bcrypt)
