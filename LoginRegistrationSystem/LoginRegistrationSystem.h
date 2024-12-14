// LoginRegistrationSystem.h : Include file for standard system include files,
// or project specific include files.

#pragma once

#include <iostream>
#include <sqlite3.h>
#include "encrypt.h"
// TODO: Reference additional headers your program requires here.
class LoginSystem {

public:
	LoginSystem() : m_userDB(nullptr), m_rc(0) {}
	
	void checkDB();

	void closeDB();

	// Register a new user
	void registerNewUser();

	// Gives the user, their password
	void forgotPassword();

	// Insert new user data into the database
	void insertNewData(const std::string& username, const std::string& password);

	// Attempt to log in with the provided credentials
	void login();

	// Start the system, e.g., display the login screen
	void startSystem();

	// Display all users from the database
	void displayAllUsers();

	// Check if the current username already exists in the database
	bool checkUsers(const std::string& username);

	// Retrieves the password, given the username
	std::string retrievePassword(const std::string& username);

	// After successfully loging in, sets the user's username and password
	void setUser(const std::string& username, const std::string& password);

	//  Get the User's username (must be login)
	std::string getUsername();

	// Get the User's password (must be login)
	std::string getPassword();

	// Login display for user's successfully logging in
	void loginSystem();

	// Sets new username for current user.
	void setNewUsername(const std::string& newUsername);

	// Sets new password for current user.
	void setNewPassword(const std::string& newPassword);

	void countTables();
private:
	std::string m_username;
	std::string m_password;
	sqlite3* m_userDB;
	int m_rc;
	void deleteTable();
	static int callback(void* NotUsed, int argc, char** argv, char** azColName);
	Encryption encryptor;
};