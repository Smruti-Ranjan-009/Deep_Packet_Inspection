cmake_minimum_required(VERSION 3.16)
project(DeepPacketInspection VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

include_directories(${CMAKE_SOURCE_DIR}/include)
find_package(Threads REQUIRED)

# ----------------------------------------------------------------------------
# dpi_engine - the one real entrypoint (src/dpi_mt.cpp): multi-threaded
# LB/FP pipeline, SNI extraction, app classification, blocking rules.
# ----------------------------------------------------------------------------
add_executable(dpi_engine
    src/dpi_mt.cpp
    src/pcap_reader.cpp
    src/packet_parser.cpp
    src/sni_extractor.cpp
    src/types.cpp
)
target_link_libraries(dpi_engine PRIVATE Threads::Threads)

# ----------------------------------------------------------------------------
# Tests (added once doctest cases exist - see tests/CMakeLists.txt)
# ----------------------------------------------------------------------------
enable_testing()
if(EXISTS "${CMAKE_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()
