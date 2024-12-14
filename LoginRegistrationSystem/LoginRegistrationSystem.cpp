// LoginRegistrationSystem.cpp : Defines the entry point for the application.
//

#include "LoginRegistrationSystem.h"

using namespace std;
void LoginSystem::checkDB()
{
    char* errMessage = 0;

    // Open the database (it will be created if it doesn't exist)
    m_rc = sqlite3_open("E:/dev/LoginRegistrationSystem/LoginRegistrationSystem/user.db", &m_userDB);
    if (m_rc) {
        std::cerr << "Can't open database: " << sqlite3_errmsg(m_userDB) << std::endl;
    }
    else {
        std::cout << "Opened database successfully!" << std::endl;
    }

    // Create a table only if it doesn't exist
    const char* sql = "CREATE TABLE IF NOT EXISTS USERS("
        "USERNAME TEXT PRIMARY KEY NOT NULL,"
        "PASSWORD TEXT NOT NULL);";

    m_rc = sqlite3_exec(m_userDB, sql, 0, 0, &errMessage);
    if (m_rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMessage << std::endl;
        sqlite3_free(errMessage);
        return;
    }
    else {
        std::cout << "Table created successfully or already exists!" << std::endl;
    }
}

void LoginSystem::countTables()
{
    sqlite3_stmt* stmt;
    const char* query = "SELECT COUNT(*) FROM sqlite_master WHERE type='table';";

    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        return;
    }

    // Execute the query and retrieve the result
    m_rc = sqlite3_step(stmt);
    if (m_rc == SQLITE_ROW) {
        int tableCount = sqlite3_column_int(stmt, 0);  // First column contains the count
        std::cout << "There are " << tableCount << " tables in the database." << std::endl;
    }
    else {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(m_userDB) << std::endl;
    }

    // Clean up
    sqlite3_finalize(stmt);
}

int LoginSystem::callback(void* NotUsed, int argc, char** argv, char** azColName) {
    int i;
    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

void LoginSystem::registerNewUser()
{
    startOver:
    std::string newUsername; 
    std::cout << "Please enter a username: \n";
    std::cin >> newUsername;
    sqlite3_stmt* stmt;
    //Check if username already exists in the database
        // Prepare the SQL query
    const char* query = "SELECT COUNT(*) FROM users WHERE USERNAME = ?";  // Change table name if necessary
    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        return;
    }

    // Bind the ID value to the prepared statement
    sqlite3_bind_text(stmt, 1, newUsername.c_str(), -1, SQLITE_STATIC);
    // Execute the query and check if the ID exists
    m_rc = sqlite3_step(stmt);
    if (m_rc == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        if (count > 0) {
            std::cout << "Username exists!" << std::endl;
            goto startOver;
        }
        else {
            //std::cout << "Username does not exist!" << std::endl;
            std::cout << "Please enter a password: \n";
            std::string newPassword;
            std::cin >> newPassword;
            // Generate a salt (for example, 8 bytes)
            std::string salt = encryptor.generateSalt(8);

            // Hash the password without salt
            std::string hashedPassword = encryptor.hashPasswordSha256(newPassword);
            std::cout << "Hashed Password: " << hashedPassword << std::endl;
            insertNewData(newUsername, newPassword);

        }
    }
    else {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(m_userDB) << std::endl;
        return;
    }
    std::cout << "Ready to Login!\n";
    startSystem();
   
}
void LoginSystem::forgotPassword()
{
    std::string userInput;
    std::cout << "Please enter your username to retrieve password\n";
    std::cin >> userInput;

    sqlite3_stmt* stmt;
    //Check if username already exists in the database
    const char* query = "SELECT COUNT(*) FROM users WHERE USERNAME = ?";  // Change table name if necessary
    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        return;
    }

    // Bind the ID value to the prepared statement
    sqlite3_bind_text(stmt, 1, userInput.c_str(), -1, SQLITE_STATIC);
    // Execute the query and check if the ID exists
    m_rc = sqlite3_step(stmt);
    if (m_rc == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        if (count > 0) {
            std::cout << "Retrieving Password" << std::endl;
            std::cout << "Username: " << userInput << std::endl; 
            std::cout << "Retrieved Password: " << retrievePassword(userInput) << std::endl;
            std::cout << "Please Login Again\n";
            startSystem();
        }
        else {
            std::cout << "Username does not exist!" << std::endl;
        }
    }
    else {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(m_userDB) << std::endl;
    }
}
void LoginSystem::insertNewData(const std::string& username, const std::string& password)
{
    sqlite3_stmt* stmt;  // SQLite prepared statement

    // Prepare the SQL INSERT query
    const char* query = "INSERT INTO users (USERNAME, PASSWORD) VALUES (?, ?)";
    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        sqlite3_close(m_userDB);
        return;
    }


    // Bind the data to the prepared statement (1st placeholder for id, 2nd for name)
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);  // Bind ID as text
    sqlite3_bind_text(stmt, 2, password.c_str(), -1, SQLITE_STATIC);  // Bind Name as text

    // Execute the insert query
    m_rc = sqlite3_step(stmt);
    if (m_rc != SQLITE_DONE) {
        std::cerr << "Execution failed: " << sqlite3_errmsg(m_userDB) << std::endl;
    }
    else {
        std::cout << "User Registered Successfully!" << std::endl;
    }
    //displayAllUsers();
}
void LoginSystem::login()
{
    std::string username;
    std::cout << "Please enter your username: \n";
    std::cin >> username;
    sqlite3_stmt* stmt;
    //Check if username already exists in the database
    const char* query = "SELECT COUNT(*) FROM users WHERE USERNAME = ?";  // Change table name if necessary
    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        return;
    }

    // Bind the ID value to the prepared statement
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    m_rc = sqlite3_step(stmt);
    if (m_rc == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        if (count > 0) {
            //std::cout << "Username exists!" << std::endl;
            std::cout << "Please enter a password: \n";
            std::string newPassword;
            std::cin >> newPassword;
            if (retrievePassword(username) == newPassword) {
                std::cout << "Successfully Login!\n";
                setUser(username, newPassword);
                loginSystem();
            }
            else {
                std::cout << "Password incorrect, please try again\n";
            }
        }
        else {
            std::cout << "Username does not exist!" << std::endl;
            std::cout << "Please Register first\n";
            startSystem();
        }
    }
    else {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(m_userDB) << std::endl;
    }
}
void LoginSystem::startSystem()
{
    start:
    std::cout << "---------- Welcome to the Login Registration Sytem ----------\n";
    std::cout << "0: Login\n";
    std::cout << "1: Register New User\n";
    std::cout << "2: Forgot Password\n";
    std::cout << "3: Exit\n";
    int userResponse;
    try {
        if (!(std::cin >> userResponse)) {
            std::cin.clear(); // Clear error state
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
            throw std::runtime_error("Invalid input. Please enter an integer.");
        }
    }
    catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        goto start;
    }
    displayAllUsers();
    switch (userResponse) {
    case 0:
        login();
        break;
    case 1:
        registerNewUser();
        break;
    case 2:
        forgotPassword();
        break;
    case 3:
        exit(0);
    }
}
void LoginSystem::displayAllUsers()
{
    sqlite3_stmt* stmt;         // SQLite prepared statement
    // Prepare the SQL SELECT query to fetch all data from users table
    const char* query = "SELECT USERNAME, PASSWORD FROM users";
    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        sqlite3_close(m_userDB);
        return;
    }

    // Execute the query and iterate through all the rows
    std::cout << "Displaying all users:\n";
    while ((m_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        // Retrieve the values from the current row
        const char* username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));  // First column (id)
        const char* password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));  // Second column (name)

        // Display the row
        std::cout << "Username: " << username << ", Password: " << password << std::endl;
    }
}
bool LoginSystem::checkUsers(const std::string& username)
{
    //Check if username already exists in the database
    sqlite3_stmt* stmt;
    const char* query = "SELECT COUNT(*) FROM users WHERE USERNAME = ?";  // Change table name if necessary
    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        return false;
    }

    // Bind the username value to the prepared statement
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    m_rc = sqlite3_step(stmt);
    if (m_rc == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        if (count > 0) {
            std::cout << "Username exists!" << std::endl;
            return true;
        }
        else {
            std::cout << "Username does not exist!" << std::endl;
            return false;
        }
    }
    else {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(m_userDB) << std::endl;
    }
}
std::string LoginSystem::retrievePassword(const std::string& username)
{
    sqlite3_stmt* stmt;
    const char* query = "SELECT PASSWORD FROM users WHERE USERNAME = ?";  // Change table name if necessary
    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
    }

    // Bind the username value to the prepared statement
    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    m_rc = sqlite3_step(stmt);
    if (m_rc == SQLITE_ROW) {
        const unsigned char* password = sqlite3_column_text(stmt, 0);
        std::string str(reinterpret_cast<const char*>(password));
        return str;
    }
    else {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(m_userDB) << std::endl;
    }
}
void LoginSystem::setUser(const std::string& username, const std::string& password)
{
    m_username = username;
    m_password = password;
}
std::string LoginSystem::getUsername()
{
    return m_username;
}
std::string LoginSystem::getPassword()
{
    return m_password;
}
void LoginSystem::loginSystem()
{
start:
    std::cout << "---------- Welcome " << m_username << " ----------\n";
    std::cout << "0: Change Username\n";
    std::cout << "1: Change Password\n";
    std::cout << "2: Logout\n";
    std::cout << "3: Exit\n";
    int userResponse;
    try {
        if (!(std::cin >> userResponse)) {
            std::cin.clear(); // Clear error state
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
            throw std::runtime_error("Invalid input. Please enter an integer.");
        }
    }
    catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        goto start;
    }
    std::string userInput;
    std::string userInputPassword;
    switch (userResponse) {
    case 0:
    enterusername:
        std::cout << "Please enter new username (cannot be the same username):\n";
        std::cin >> userInput;
        if (userInput == m_username) {
            goto enterusername;
        }
        else {
            setNewUsername(userInput);
            break;
    case 1:
    enterpassword:
        std::cout << "Please enter new password (cannot be the same password):\n";
        std::cin >> userInputPassword;
        if (userInput == m_username) {
            goto enterpassword;
        }
        else {
            setNewPassword(userInputPassword);
            break;
            break;
    case 2:
        std::cout << "Logging out.\n";
        m_username = "";
        m_password = "";
        startSystem();
        break;
    case 3:
        exit(0);
        }
        }
    }
}
void LoginSystem::deleteTable()
{
    char* errMessage = 0;

    // SQL query to drop the table
    const char* sql = "DROP TABLE IF EXISTS USERS;";

    m_rc = sqlite3_exec(m_userDB, sql, 0, 0, &errMessage);
    if (m_rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMessage << std::endl;
        sqlite3_free(errMessage);
    }
    else {
        std::cout << "Table deleted successfully!" << std::endl;
    }
}
void LoginSystem::setNewUsername(const std::string& newUsername)
{
    sqlite3_stmt* stmt;         // SQLite prepared statement
    const char* checkQuery = "SELECT COUNT(*) FROM users WHERE USERNAME = ?";

    // First, check if the new username already exists in the database
    m_rc = sqlite3_prepare_v2(m_userDB, checkQuery, -1, &stmt, 0);
    if (m_rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        return;
    }

    // Bind the new username to the prepared statement
    sqlite3_bind_text(stmt, 1, newUsername.c_str(), -1, SQLITE_STATIC);

    m_rc = sqlite3_step(stmt);
    if (m_rc == SQLITE_ROW) {
        int count = sqlite3_column_int(stmt, 0);
        if (count > 0) {
            std::cerr << "Username already exists. Please choose a different one." << std::endl;
            return; // Username already taken, exit the function
        }
    }
    else {
        std::cerr << "Failed to execute query: " << sqlite3_errmsg(m_userDB) << std::endl;
        sqlite3_finalize(stmt);
        return;
    }

    // Now, proceed to update the username
    const char* updateQuery = "UPDATE users SET USERNAME = ? WHERE USERNAME = ?";

    m_rc = sqlite3_prepare_v2(m_userDB, updateQuery, -1, &stmt, 0);
    if (m_rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        sqlite3_finalize(stmt);
        return;
    }

    // Bind the new username and the current username (to identify the user)
    sqlite3_bind_text(stmt, 1, newUsername.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, m_username.c_str(), -1, SQLITE_STATIC);

    // Execute the update query
    m_rc = sqlite3_step(stmt);
    if (m_rc != SQLITE_DONE) {
        std::cerr << "Error executing query: " << sqlite3_errmsg(m_userDB) << std::endl;
        return;
    }
    else {
        std::cout << "Username updated successfully!" << std::endl;
        m_username = newUsername; // Update the current username in the object
    }

    sqlite3_finalize(stmt);  // Finalize the statement
    loginSystem();
}
void LoginSystem::setNewPassword(const std::string& newPassword)
{
    sqlite3_stmt* stmt;
    const char* query = "UPDATE users SET PASSWORD = ? WHERE USERNAME = ?";  // Correct column name

    m_rc = sqlite3_prepare_v2(m_userDB, query, -1, &stmt, 0);
    if (m_rc != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(m_userDB) << std::endl;
        sqlite3_close(m_userDB);
        return;
    }

    sqlite3_bind_text(stmt, 1, newPassword.c_str(), -1, SQLITE_STATIC);  // Bind new password
    sqlite3_bind_text(stmt, 2, m_username.c_str(), -1, SQLITE_STATIC);   // Bind the username

    m_rc = sqlite3_step(stmt);
    if (m_rc != SQLITE_DONE) {
        std::cerr << "Error executing query: " << sqlite3_errmsg(m_userDB) << std::endl;
    }
    else {
        std::cout << "Password updated successfully!" << std::endl;
        m_password = newPassword;
    }
    loginSystem();  // Re-enter the login system after updating the password
}

void LoginSystem::closeDB()
{
    sqlite3_close(m_userDB);
}


int main() {

    LoginSystem loginSystem;
    loginSystem.checkDB();
    loginSystem.countTables();
    loginSystem.startSystem();
    loginSystem.closeDB();
    //Encryption encryptor;

    //// Example password
    //std::string password = "mysecretpassword";

    //// Generate a salt (for example, 8 bytes)
    //std::string salt = encryptor.generateSalt(8);

    //// Hash the password without salt
    //std::string hashedPassword = encryptor.hashPasswordSha256(password);
    //std::cout << "Hashed Password: " << hashedPassword << std::endl;

    //// Hash the password with salt
    //std::string hashedPasswordWithSalt = encryptor.hashPasswordSha256Salt(password, salt);
    //std::cout << "Hashed Password with Salt: " << hashedPasswordWithSalt << std::endl;

    //// Print the salt
    //std::cout << "Generated Salt: " << salt << std::endl;
    return 0;
}

