#define CURL_STATICLIB
#include "eauth.h"
#include "skCrypter.h"
#include "sha/sha512.hpp"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <__msvc_chrono.hpp>
#include <filesystem>
#include <iostream>
#include <fstream>
#include "curl/curl.h"
#include <string>
#include <random>

#pragma comment(lib, "libcurl_a.lib")

#pragma comment(lib, "Normaliz.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "wldap32.lib" )
#pragma comment(lib, "crypt32.lib" )

// Required configuration
std::string APPLICATION_TOKEN = ""; // Your application token goes here
std::string APPLICATION_SECRET = ""; // Your application secret goes here;
std::string APPLICATION_VERSION = "1.0"; // Your application version goes here;

// Advanced configuration
const auto invalid_account_key_message = skCrypt("Invalid account key!");
const auto invalid_application_key_message = skCrypt("Invalid application key!");
const auto invalid_request_message = skCrypt("Invalid request!");
const auto outdated_version_message = skCrypt("Outdated version, please upgrade!");
const auto busy_sessions_message = skCrypt("Please try again later!");
const auto unavailable_session_message = skCrypt("Invalid session. Please re-launch the app!");
const auto used_session_message = skCrypt("Why did the computer go to therapy? Because it had a case of 'Request Repeatitis' and couldn't stop asking for the same thing over and over again!");
const auto overcrowded_session_message = skCrypt("Session limit exceeded. Please re-launch the app!");
const auto unauthorized_session_message = skCrypt("Unauthorized session.");
const auto expired_session_message = skCrypt("Your session has timed out. Please re-launch the app!");
const auto invalid_user_message = skCrypt("Incorrect login credentials!");
const auto invalid_file_message = skCrypt("Incorrect file credentials!");
const auto invalid_path_message = skCrypt("Oops, the bytes of the file could not be written. Please check the path of the file!");
const auto incorrect_hwid_message = skCrypt("Hardware ID mismatch. Please try again with the correct device!");
const auto expired_user_message = skCrypt("Your subscription has ended. Please renew to continue using our service!");
const auto used_name_message = skCrypt("Username already taken. Please choose a different username!");
const auto invalid_key_message = skCrypt("Invalid key. Please enter a valid key!");
const auto upgrade_your_eauth_message = skCrypt("Upgrade your Eauth plan to exceed the limits!");

// Dynamic configuration (this refers to configuration settings that can be changed during runtime)
bool init = false;
bool login = false;
bool signup = false;

std::string session_id = std::string(skCrypt(""));
std::string error_message = std::string(skCrypt(""));

std::string rank = std::string(skCrypt(""));
std::string register_date = std::string(skCrypt(""));
std::string expire_date = std::string(skCrypt(""));
std::string hwid = std::string(skCrypt(""));

std::string file_to_download = std::string(skCrypt(""));

const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// Generate pair
std::string generateRandomString(int length = 18) {
    std::string result;
    
    // Initialize random number generator
    std::random_device rd;  // Obtain a random number from hardware
    std::mt19937 gen(rd()); // Seed the generator
    std::uniform_int_distribution<> dis(0, charset.size() - 1); // Define the range

    for (int i = 0; i < length; ++i) {
        result += charset[dis(gen)]; // Append random character to result
    }
    
    return result;
}

// Function takes an input string and calculates its SHA-512 hash using the OpenSSL library
std::string hash(const std::string input) {
    return hmac_hash::sha512(input);
}

// Generate header token
std::string generateEauthHeader(const std::string& message, const std::string& app_secret) {
    return hash(app_secret + message);
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Code snippet that checks if a string contains the substring
bool containsSubstring(const std::string& str, const std::string& substr) {
    return str.find(substr) != std::string::npos;
}

// Send post request to Eauth
std::string runRequest(std::string request_data) {
    CURL* curl;
    CURLcode res;
    std::string readBuffer;
    std::string headerData;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://eauth.us.to/api/1.2/");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_data.c_str());
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        std::string user_agent = "User-Agent:" + generateEauthHeader(request_data, APPLICATION_SECRET);
        headers = curl_slist_append(headers, user_agent.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headerData);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            exit(1);
        }

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    std::string json = readBuffer;
    rapidjson::Document doc;
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();

    if (message != "invalid_request" && message != "session_unavailable" && message != "session_already_used" && message != "invalid_email") {
        size_t start = headerData.find("Eauth: ");
        if (start == std::string::npos) {
            exit(1);
        }

        size_t end = headerData.find("\n", start);
        if (end == std::string::npos) {
            exit(1);
        }
        if (generateEauthHeader(json, APPLICATION_SECRET) != headerData.substr(start + 7, end - start - 8)) {
            exit(1);
        }
    }

    return readBuffer; // Response
}

// Get HWID
std::string getHWID() {
    char volumeName[MAX_PATH + 1] = { 0 };
    char fileSystemName[MAX_PATH + 1] = { 0 };
    DWORD serialNumber = 0;
    DWORD maxComponentLen = 0;
    DWORD fileSystemFlags = 0;

    if (GetVolumeInformationA("C:\\", volumeName, ARRAYSIZE(volumeName), &serialNumber, &maxComponentLen, &fileSystemFlags, fileSystemName, ARRAYSIZE(fileSystemName))) {
        return std::to_string(serialNumber);
    }
    else {
        exit(1);
    }
}

// Report error
void raiseError(auto error) {
    error_message = error;
}

// Initialization request
bool initRequest() {
    if (init) {
        return init;
    }

    rapidjson::Document doc;
    doc.SetObject();
    auto& allocator = doc.GetAllocator();
    doc.AddMember("type", rapidjson::Value("init", allocator), allocator);
    doc.AddMember("token", rapidjson::Value(APPLICATION_TOKEN.c_str(), allocator), allocator);
    doc.AddMember("version", rapidjson::Value(APPLICATION_VERSION.c_str(), allocator), allocator);
    doc.AddMember("hwid", rapidjson::Value(getHWID().c_str(), allocator), allocator);
	doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer writer(buffer);
    doc.Accept(writer);

    std::string json = runRequest(buffer.GetString());
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();
    if (message == std::string(skCrypt("init_success"))) {
        init = true;
        session_id = doc["session_id"].GetString();
    }
    else if (message == std::string(skCrypt("invalid_request"))) {
        raiseError(invalid_request_message);
    }
    else if (message == std::string(skCrypt("version_outdated"))) {
        std::string download_link = doc["download_link"].GetString();
        if (download_link != "") {
            // Open download link in web browser
            ShellExecute(NULL, "open", download_link.c_str(), NULL, NULL, SW_SHOWNORMAL);
        }
        raiseError(outdated_version_message);
    }
    else if (message == std::string(skCrypt("maximum_sessions_reached"))) {
        raiseError(busy_sessions_message);
    }
    else if (message == std::string(skCrypt("user_is_banned"))) {
        exit(1);
    }
    else if (message == std::string(skCrypt("init_paused"))) {
        raiseError(doc["paused_message"].GetString());
    }

    return init;
}

// Login request
bool loginRequest(std::string username, std::string password, std::string key) {
    if (login) {
        return login;
    }

    rapidjson::Document doc;

    if (key.length() > 0) {
        username = password = key;
        doc.SetObject();
        auto& allocator = doc.GetAllocator();
        doc.AddMember("type", rapidjson::Value("register", allocator), allocator);
        doc.AddMember("session_id", rapidjson::Value(session_id.c_str(), allocator), allocator);
        doc.AddMember("username", rapidjson::Value(username.c_str(), allocator), allocator);
        doc.AddMember("password", rapidjson::Value(password.c_str(), allocator), allocator);
        doc.AddMember("key", rapidjson::Value(key.c_str(), allocator), allocator);
        doc.AddMember("hwid", rapidjson::Value(getHWID().c_str(), allocator), allocator);
		doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

        rapidjson::StringBuffer buffer;
        rapidjson::Writer writer(buffer);
        doc.Accept(writer);

        std::string json = runRequest(buffer.GetString());
        doc.Parse(json.c_str());

        std::string message = doc["message"].GetString();

        if (message != std::string(skCrypt("register_success")) && message != std::string(skCrypt("name_already_used"))) {
            raiseError(invalid_key_message);
        }
    }

    doc.SetObject();
    auto& allocator = doc.GetAllocator();
    doc.AddMember("type", rapidjson::Value("login", allocator), allocator);
    doc.AddMember("session_id", rapidjson::Value(session_id.c_str(), allocator), allocator);
    doc.AddMember("username", rapidjson::Value(username.c_str(), allocator), allocator);
    doc.AddMember("password", rapidjson::Value(password.c_str(), allocator), allocator);
    doc.AddMember("hwid", rapidjson::Value(getHWID().c_str(), allocator), allocator);
	doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer writer(buffer);
    doc.Accept(writer);

    std::string json = runRequest(buffer.GetString());
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();
    if (message == std::string(skCrypt("login_success"))) {
        login = true;
        rank = doc["rank"].GetString();
        register_date = doc["register_date"].GetString();
        expire_date = doc["expire_date"].GetString();
        std::string word = "later";
        std::stringstream ss(expire_date);
        std::string token;
        expire_date = "";
        while (ss >> token) {
            if (token != word) {
                expire_date += token + " ";
            }
        }
        expire_date.pop_back(); // remove the last word

        hwid = doc["hwid"].GetString();
    }
    else if (message == std::string(skCrypt("invalid_request"))) {
        raiseError(invalid_request_message);
    }
    else if (message == std::string(skCrypt("session_unavailable"))) {
        raiseError(unavailable_session_message);
    }
    else if (message == std::string(skCrypt("session_already_used"))) {
        raiseError(used_session_message);
    }
    else if (message == std::string(skCrypt("session_overcrowded"))) {
        raiseError(overcrowded_session_message);
    }
    else if (message == std::string(skCrypt("session_expired"))) {
        raiseError(expired_session_message);
    }
    else if (message == std::string(skCrypt("account_unavailable"))) {
        raiseError(invalid_user_message);
    }
    else if (message == std::string(skCrypt("user_is_banned"))) {
        exit(1);
    }
    else if (message == std::string(skCrypt("hwid_incorrect"))) {
        raiseError(incorrect_hwid_message);
    }
    else if (message == std::string(skCrypt("subscription_expired"))) {
        raiseError(expired_session_message);
    }

    return login;
}

// Register request
bool registerRequest(std::string username, std::string password, std::string key) {
    if (signup) {
        return signup;
    }

    rapidjson::Document doc;
    doc.SetObject();
    auto& allocator = doc.GetAllocator();
    doc.AddMember("type", rapidjson::Value("register", allocator), allocator);
    doc.AddMember("session_id", rapidjson::Value(session_id.c_str(), allocator), allocator);
    doc.AddMember("username", rapidjson::Value(username.c_str(), allocator), allocator);
    doc.AddMember("password", rapidjson::Value(password.c_str(), allocator), allocator);
    doc.AddMember("key", rapidjson::Value(key.c_str(), allocator), allocator);
    doc.AddMember("hwid", rapidjson::Value(getHWID().c_str(), allocator), allocator);
	doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer writer(buffer);
    doc.Accept(writer);

    std::string json = runRequest(buffer.GetString());
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();
    if (message == std::string(skCrypt("register_success"))) {
        signup = true;
    }
    else if (message == std::string(skCrypt("invalid_request"))) {
        raiseError(invalid_request_message);
    }
    else if (message == std::string(skCrypt("session_unavailable"))) {
        raiseError(unavailable_session_message);
    }
    else if (message == std::string(skCrypt("session_already_used"))) {
        raiseError(used_session_message);
    }
    else if (message == std::string(skCrypt("session_overcrowded"))) {
        raiseError(overcrowded_session_message);
    }
    else if (message == std::string(skCrypt("session_expired"))) {
        raiseError(expired_session_message);
    }
    else if (message == std::string(skCrypt("account_unavailable"))) {
        raiseError(invalid_user_message);
    }
    else if (message == std::string(skCrypt("name_already_used"))) {
        raiseError(used_name_message);
    }
    else if (message == std::string(skCrypt("key_unavailable"))) {
        raiseError(invalid_key_message);
    }
    else if (message == std::string(skCrypt("user_is_banned"))) {
        exit(1);
    }
    else if (message == std::string(skCrypt("maximum_users_reached"))) {
        raiseError(upgrade_your_eauth_message);
    }

    return signup;
}

// Download request
bool downloadsRequest(std::string fileid) {

    rapidjson::Document doc;
    doc.SetObject();
    auto& allocator = doc.GetAllocator();
    doc.AddMember("type", rapidjson::Value("download", allocator), allocator);
    doc.AddMember("fileid", rapidjson::Value(fileid.c_str(), allocator), allocator);
	doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer writer(buffer);
    doc.Accept(writer);

    std::string json = runRequest(buffer.GetString());
    doc.Parse(json.c_str());

    std::string message = doc["message"].GetString();
    if (message == std::string(skCrypt("download_success"))) {
        file_to_download = doc["link"].GetString();
        return true;
    }
    else if (message == std::string(skCrypt("invalid_account_key"))) {
        raiseError(invalid_account_key_message);
        return false;
    }
    else if (message == std::string(skCrypt("invalid_request"))) {
        raiseError(invalid_request_message);
        return false;
    }
    else if (message == std::string(skCrypt("session_unavailable"))) {
        raiseError(unavailable_session_message);
        return false;
    }
    else if (message == std::string(skCrypt("session_unauthorized"))) {
        raiseError(unauthorized_session_message);
        return false;
    }
    else if (message == std::string(skCrypt("session_expired"))) {
        raiseError(expired_session_message);
        return false;
    }
    else if (message == std::string(skCrypt("invalid_file"))) {
        raiseError(invalid_file_message);
        return false;
    }
}

// Callback function to write data into a string
static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* data = static_cast<std::string*>(userdata);
    data->append(ptr, size * nmemb);
    return size * nmemb;
}

// Write file
bool downloadRequest(std::string fileid, const std::string& filename, const std::string& path) {
    std::filesystem::create_directories(path); // Create the directory path if it doesn't exist

    if (!downloadsRequest(fileid)) {
        return false;
    }

    std::string savePath = path + "/" + filename;

    CURL* curl;
    CURLcode res;
    std::string data;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, file_to_download.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            error_message = curl_easy_strerror(res);
        }

        curl_easy_cleanup(curl);
    }

    std::ofstream file(savePath, std::ios::binary);

    if (file.is_open()) {
        file.write(data.data(), data.size());
        file.close();
    }
    else {
        std::cerr << "Unable to open file for writing: " << savePath << std::endl;
        return false;
    }

    return true;
}

// Ban the user HWID and IP
void banUser() {

    rapidjson::Document doc;
    doc.SetObject();
    auto& allocator = doc.GetAllocator();
    doc.AddMember("type", rapidjson::Value("ban_user", allocator), allocator);
    doc.AddMember("session_id", rapidjson::Value(session_id.c_str(), allocator), allocator);
    doc.AddMember("hwid", rapidjson::Value(getHWID().c_str(), allocator), allocator);
	doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer writer(buffer);
    doc.Accept(writer);

    std::string json = runRequest(buffer.GetString());

    exit(1);
}