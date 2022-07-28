# CMakeList.txt : CMake project for gateway_server, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

project("gwserver")

SET(CMAKE_CXX_STANDARD 11)
SET(Boost_USE_STATIC_LIBS ON)
SET(Boost_USE_MULTITHREAD ON)
SET(Mysqlcppconn_USE_STATIC_LIBS ON)


if(CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_definitions("_DEBUG_")
endif()

add_compile_definitions("_MSVC_" "_WBDEBUG_")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")


#set(MYSQL_ROOT "D:/DevTools/MySQLConnector")
# Settings.hpp를 사용하지 않지만 wbagent와의 소스호환성을 위해 MySQLConnector를 사용한다.
#set(MYSQL_INCLUDE_DIR "D:/DevTools/MySQLConnector/include/jdbc")
#if(CMAKE_BUILD_TYPE MATCHES DEBUG)
#    set(MYSQL_LIBRARY_DIR "D:/DevTools/MySQLConnector/debug/lib64/vs14")
#else(CMAKE_BUILD_TYPE MATCHES DEBUG)
#    set(MYSQL_LIBRARY_DIR "D:/DevTools/MySQLConnector/release/lib64/vs14")
#endif(CMAKE_BUILD_TYPE MATCHES DEBUG)

FIND_PACKAGE(Boost 1.58.0 REQUIRED COMPONENTS thread date_time log filesystem)
 if(Boost_FOUND)
    INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIRS} ${MYSQL_INCLUDE_DIR})
    LINK_DIRECTORIES(${Boost_LIBRARY_DIRS} ${MYSQL_LIBRARY_DIR})
    SET(USED_LIBS ${Boost_THREAD_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_DATE_TIME_LIBRARY} ${Boost_LOG_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
	LINK_DIRECTORIES(${Boost_LIBRARY_DIRS} ${MYSQL_LIBRARY_DIR})
    add_executable (gwserver
        "gwserver.cpp" 
        "server.cpp"
        "mediator.cpp"
        "../gwagent/seed128cbc/KISA_SEED_CBC.c" 
        )
    TARGET_LINK_LIBRARIES(gwserver ${USED_LIBS})
endif()
