cmake_minimum_required(VERSION 3.12)

set(CMAKE_CXX_STANDARD 17)
project(KEY_RECOVERY)

find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include ${CMAKE_CURRENT_SOURCE_DIR})

# Source files
set(COMMON_SOURCES
    src/parties.cpp
    src/utils.cpp
)

set(HJKY_SOURCES
    src/HJKY_recovery.cpp
)

set(OURS_SOURCES
    src/our_recovery.cpp
)

# Executables
add_executable(HJKY_RECOVERY ${COMMON_SOURCES} ${HJKY_SOURCES})
add_executable(OUR_RECOVERY ${COMMON_SOURCES} ${OURS_SOURCES})

# Link libraries
target_link_libraries(HJKY_RECOVERY PRIVATE ${OPENSSL_LIBRARIES})
target_link_libraries(OUR_RECOVERY PRIVATE ${OPENSSL_LIBRARIES})

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/bin)