# CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(EncryptionProject)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 手动设置 Crypto++ 的包含目录和库路径
set(CRYPTOPP_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include)
set(CRYPTOPP_LIBRARY ${PROJECT_SOURCE_DIR}/lib/libcryptopp.a)

# 检查 Crypto++ 的头文件是否存在（不包括 exception.h）
if(NOT EXISTS ${CRYPTOPP_INCLUDE_DIR}/cryptopp/aes.h)
    message(FATAL_ERROR "无法找到 Crypto++ 的包含目录: ${CRYPTOPP_INCLUDE_DIR}/cryptopp/aes.h")
endif()

if(NOT EXISTS ${CRYPTOPP_LIBRARY})
    message(FATAL_ERROR "无法找到 Crypto++ 的库文件: ${CRYPTOPP_LIBRARY}")
endif()

# 添加可执行文件
add_executable(EncryptEngine 
    src/main.cpp 
    src/CryptoUtils.cpp
)

# 指定目标的包含目录
target_include_directories(EncryptEngine PRIVATE ${CRYPTOPP_INCLUDE_DIR})

# 链接 Crypto++ 库
target_link_libraries(EncryptEngine 
    PRIVATE 
    ${CRYPTOPP_LIBRARY}
)
