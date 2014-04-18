#minimum version for CMake
cmake_minimum_required(VERSION 2.6)

#project name
project(MbDNS)

#see if we are in Mac
if ( CMAKE_GENERATOR STREQUAL Xcode )
  set( CMAKE_GENERATOR_IS_XCODE true )
endif()

# Check if platform is 64 bit
if( CMAKE_SIZEOF_VOID_P EQUAL 4 )
  set( 64_BIT_PLATFORM 0 )
else()
  set( 64_BIT_PLATFORM 1 )
endif()

# Force release build by default, speed is of the essence
if ( NOT CMAKE_BUILD_TYPE )
  set( CMAKE_BUILD_TYPE Release )
endif()

#MbDNS headers
set( MbDNS_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}" CACHE PATH "Path to MbDNS headers" )

set (CMAKE_C_FLAGS "--std=c99")
include_directories("${MbDNS_HEADERS}")

file( GLOB MbDNS_SRC "*.c" )

add_library(MbDNS SHARED ${MbDNS_SRC} )

target_link_libraries (MbDNS Ws2_32 )