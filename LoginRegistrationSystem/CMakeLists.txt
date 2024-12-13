# CMakeList.txt : CMake project for LoginRegistrationSystem, include source and define
# project specific logic here.
project(LoginRegistrationSystem)

# Add source to this project's executable.
add_executable (LoginRegistrationSystem "LoginRegistrationSystem.cpp" "LoginRegistrationSystem.h" "sqlite3.c" "sqlite3.h")
set(CMAKE_CXX_STANDARD 11)
# Manually specify the paths for MySQL Connector
# Include SQLite source files (you can also download SQLite separately via git or a package manager)
set(SQLITE3_SRC sqlite3.c)
set(SQLITE3_HEADERS sqlite3.h)

# Add the SQLite source files to the project
add_library(sqlite3 STATIC ${SQLITE3_SRC})
if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET LoginRegistrationSystem PROPERTY CXX_STANDARD 20)
endif()
# Link the MySQL connector library to the project

# Include the SQLite header directory
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Link the SQLite library to your executable
target_link_libraries(LoginRegistrationSystem sqlite3)