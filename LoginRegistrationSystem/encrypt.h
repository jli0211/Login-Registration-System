#pragma once

#include <iostream>

class Encryption {

public:
	std::string hashPasswordSha256(const std::string& password);
	std::string hashPasswordSha256Salt(const std::string& password, const std::string& salt);
	std::string generateSalt(int length);
};