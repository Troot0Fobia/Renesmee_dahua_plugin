cmake_minimum_required(VERSION 3.20)

project(dahua_plugin)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(dahua_plugin SHARED src/main.cpp)
target_compile_features(dahua_plugin PRIVATE cxx_std_20)
target_link_libraries(dahua_plugin PRIVATE curl crypto)
target_include_directories(dahua_plugin PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/includes)

