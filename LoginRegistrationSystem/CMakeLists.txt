# CMakeList.txt : CMake project for LoginRegistrationSystem, include source and define
# project specific logic here.
project(LoginRegistrationSystem)

# Add source to this project's executable.
add_executable (LoginRegistrationSystem "LoginRegistrationSystem.cpp" "LoginRegistrationSystem.h" "sqlite3.c" "sqlite3.h" "encrypt.h" "encrypt.cpp")
set(CMAKE_CXX_STANDARD 11)
set(OPENSSL_INCLUDE_DIR "E:/OpenSSL-Win64/include")
# Add the include directory
include_directories(${OPENSSL_INCLUDE_DIR})
# Manually specify the paths for MySQL Connector
# Include SQLite source files (you can also download SQLite separately via git or a package manager)
set(SQLITE3_SRC sqlite3.c)
set(SQLITE3_HEADERS sqlite3.h)
# Find OpenSSL package
find_package(OpenSSL REQUIRED)
# Add the SQLite source files to the project
add_library(sqlite3 STATIC ${SQLITE3_SRC} "encrypt.h" "encrypt.cpp")
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET LoginRegistrationSystem PROPERTY CXX_STANDARD 20)
endif()
# Link the MySQL connector library to the project

# Include the SQLite header directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Link the SQLite library to your executable
target_link_libraries(LoginRegistrationSystem sqlite3 OpenSSL::Crypto OpenSSL::SSL)