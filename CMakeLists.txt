cmake_minimum_required(VERSION 3.20)

project(dahua_plugin)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(dahua_plugin SHARED src/main.cpp
                                src/hasher/hasher.cpp
                                src/requester/requester.cpp
                                src/interfaces/binary_interface/binary_interface.cpp
                                src/interfaces/web_interface/web_interface.cpp)

include(FetchContent)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz)
FetchContent_MakeAvailable(json)

target_compile_features(dahua_plugin PRIVATE cxx_std_20)
target_link_libraries(dahua_plugin PRIVATE
                      curl
                      crypto
                      nlohmann_json::nlohmann_json)
target_include_directories(dahua_plugin PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/includes
                           ${CMAKE_CURRENT_SOURCE_DIR}/src
                           ${CMAKE_CURRENT_SOURCE_DIR}/src/interfaces)

