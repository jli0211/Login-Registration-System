#include "encrypt.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <string>
#include <vector>

std::string Encryption::hashPasswordSha256(const std::string& password)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Perform SHA-256 hashing
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, password.c_str(), password.length());
    SHA256_Final(hash, &sha256Context);

    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    // Return the hashed password as a string
    return ss.str();
}

std::string Encryption::hashPasswordSha256Salt(const std::string& password, const std::string& salt)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Combine the password with the salt
    std::string passwordWithSalt = password + salt;

    // Perform SHA-256 hashing
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, passwordWithSalt.c_str(), passwordWithSalt.length());
    SHA256_Final(hash, &sha256Context);

    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    // Return the hashed password with salt
    return ss.str();
}

std::string Encryption::generateSalt(int length)
{
    // Use a vector to manage the memory automatically
    std::vector<unsigned char> salt(length);

    // Generate the salt using OpenSSL's RAND_bytes
    if (RAND_bytes(salt.data(), length) != 1) {
        std::cerr << "Error generating random salt!" << std::endl;
        exit(1);
    }

    // Convert the salt to a hex string
    std::stringstream ss;
    for (int i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }

    // Return the salt as a hex string
    return ss.str();
}
