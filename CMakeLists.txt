cmake_minimum_required(VERSION 3.5)
project(sframe-mbedtls)

# TODO: Find SFrame.
find_package(mbedTLS REQUIRED)
find_package(gsl-lite REQUIRED)

add_library(${PROJECT_NAME} mbedtls.h mbedtls.cpp)
set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 11)
target_link_libraries(${PROJECT_NAME} PRIVATE MbedTLS::mbedtls)
target_link_libraries(${PROJECT_NAME} PUBLIC gsl::gsl-lite sframe_provider)