cmake_minimum_required(VERSION 3.5)
project(sframe_mbedtls)

find_package(sframe REQUIRED)
find_package(mbedTLS REQUIRED)

add_library(${PROJECT_NAME} mbedtls.h mbedtls.cpp)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 11)
target_link_libraries(${PROJECT_NAME} PUBLIC sframe::sframe_provider MbedTLS::mbedcrypto MbedTLS::mbedtls)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

if(TESTING)
    enable_testing()
    add_subdirectory(test)
endif(TESTING)