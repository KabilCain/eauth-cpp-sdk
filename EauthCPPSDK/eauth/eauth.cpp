#define CURL_STATICLIB
#include "eauth.h"
#include "XorStr.h"
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
std::string APPLICATION_TOKEN = _XOR_(""); // Your application token goes here
std::string APPLICATION_SECRET = _XOR_(""); // Your application secret goes here;
std::string APPLICATION_VERSION = _XOR_("1.0"); // Your application version goes here;

// Advanced configuration
const auto invalid_account_key_message = _XOR_("Invalid account key!");
const std::string invalid_application_key_message = _XOR_("Invalid application key!");
const std::string invalid_request_message = _XOR_("Invalid request!");
const std::string outdated_version_message = _XOR_("Outdated version, please upgrade!");
const std::string busy_sessions_message = _XOR_("Please try again later!");
const std::string unavailable_session_message = _XOR_("Invalid session. Please re-launch the app!");
const std::string used_session_message = _XOR_("Why did the computer go to therapy? Because it had a case of 'Request Repeatitis' and couldn't stop asking for the same thing over and over again!");
const std::string overcrowded_session_message = _XOR_("Session limit exceeded. Please re-launch the app!");
const std::string unauthorized_session_message = _XOR_("Unauthorized session.");
const std::string expired_session_message = _XOR_("Your session has timed out. Please re-launch the app!");
const std::string invalid_user_message = _XOR_("Incorrect login credentials!");
const std::string invalid_file_message = _XOR_("Incorrect file credentials!");
const std::string invalid_path_message = _XOR_("Oops, the bytes of the file could not be written. Please check the path of the file!");
const std::string incorrect_hwid_message = _XOR_("Hardware ID mismatch. Please try again with the correct device!");
const std::string expired_user_message = _XOR_("Your subscription has ended. Please renew to continue using our service!");
const std::string used_name_message = _XOR_("Username already taken. Please choose a different username!");
const std::string invalid_key_message = _XOR_("Invalid key. Please enter a valid key!");
const std::string upgrade_your_eauth_message = _XOR_("Upgrade your Eauth plan to exceed the limits!");

// Dynamic configuration (this refers to configuration settings that can be changed during runtime)
bool init = false;
bool login = false;
bool signup = false;

std::string session_id = _XOR_("");
std::string error_message = _XOR_("");

std::string rank = _XOR_("");
std::string register_date = _XOR_("");
std::string expire_date = _XOR_("");
std::string hwid = _XOR_("");

std::string file_to_download = _XOR_("");

const std::string charset = _XOR_("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");

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
        curl_easy_setopt(curl, CURLOPT_URL, _XOR_("https://eauth.us.to/api/1.2/"));
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_data.c_str());
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, _XOR_("Content-Type: application/json"));
        std::string user_agent = _XOR_("User-Agent:") + generateEauthHeader(request_data, APPLICATION_SECRET);
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

    std::string message = doc[_XOR_("message")].GetString();

    if (message != _XOR_("invalid_request") && message != _XOR_("session_unavailable") && message != _XOR_("session_already_used") && message != _XOR_("invalid_email")) {
        size_t start = headerData.find(_XOR_("Eauth: "));
        if (start == std::string::npos) {
            exit(1);
        }

        size_t end = headerData.find(_XOR_("\n"), start);
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

    if (GetVolumeInformationA(_XOR_("C:\\"), volumeName, ARRAYSIZE(volumeName), &serialNumber, &maxComponentLen, &fileSystemFlags, fileSystemName, ARRAYSIZE(fileSystemName))) {
        return std::to_string(serialNumber);
    }
    else {
        exit(1);
    }
}

// Report error
void raiseError(std::string error) {
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
    doc.AddMember("type", rapidjson::Value(_XOR_("init"), allocator), allocator);
    doc.AddMember("token", rapidjson::Value(APPLICATION_TOKEN.c_str(), allocator), allocator);
    doc.AddMember("version", rapidjson::Value(APPLICATION_VERSION.c_str(), allocator), allocator);
    doc.AddMember("hwid", rapidjson::Value(getHWID().c_str(), allocator), allocator);
	doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer writer(buffer);
    doc.Accept(writer);

    std::string json = runRequest(buffer.GetString());
    doc.Parse(json.c_str());

    std::string message = doc[_XOR_("message")].GetString();
    if (message == _XOR_("init_success")) {
        init = true;
        session_id = doc[_XOR_("session_id")].GetString();
    }
    else if (message == _XOR_("invalid_request")) {
        raiseError(invalid_request_message);
    }
    else if (message == _XOR_("version_outdated")) {
        std::string download_link = doc[_XOR_("download_link")].GetString();
        if (download_link != _XOR_("")) {
            // Open download link in web browser
            ShellExecute(NULL, _XOR_("open"), download_link.c_str(), NULL, NULL, SW_SHOWNORMAL);
        }
        raiseError(outdated_version_message);
    }
    else if (message == _XOR_("maximum_sessions_reached")) {
        raiseError(busy_sessions_message);
    }
    else if (message == _XOR_("user_is_banned")) {
        exit(1);
    }
    else if (message == _XOR_("init_paused")) {
        raiseError(doc[_XOR_("paused_message")].GetString());
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
        doc.AddMember("type", rapidjson::Value(_XOR_("register"), allocator), allocator);
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

        std::string message = doc[_XOR_("message")].GetString();

        if (message != _XOR_("register_success") && message != _XOR_("name_already_used")) {
            raiseError(invalid_key_message);
        }
    }

    doc.SetObject();
    auto& allocator = doc.GetAllocator();
    doc.AddMember("type", rapidjson::Value(_XOR_("login"), allocator), allocator);
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

    std::string message = doc[_XOR_("message")].GetString();
    if (message == _XOR_("login_success")) {
        login = true;
        rank = doc["rank"].GetString();
        register_date = doc[_XOR_("register_date")].GetString();
        expire_date = doc[_XOR_("expire_date")].GetString();
        hwid = doc[_XOR_("hwid")].GetString();
    }
    else if (message == _XOR_("invalid_request")) {
        raiseError(invalid_request_message);
    }
    else if (message == _XOR_("session_unavailable")) {
        raiseError(unavailable_session_message);
    }
    else if (message == _XOR_("session_already_used")) {
        raiseError(used_session_message);
    }
    else if (message == _XOR_("session_overcrowded")) {
        raiseError(overcrowded_session_message);
    }
    else if (message == _XOR_("session_expired")) {
        raiseError(expired_session_message);
    }
    else if (message == _XOR_("account_unavailable")) {
        raiseError(invalid_user_message);
    }
    else if (message == _XOR_("user_is_banned")) {
        exit(1);
    }
    else if (message == _XOR_("hwid_incorrect")) {
        raiseError(incorrect_hwid_message);
    }
    else if (message == _XOR_("subscription_expired")) {
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
    doc.AddMember("type", rapidjson::Value(_XOR_("register"), allocator), allocator);
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

    std::string message = doc[_XOR_("message")].GetString();
    if (message == _XOR_("register_success")) {
        signup = true;
    }
    else if (message == _XOR_("invalid_request")) {
        raiseError(invalid_request_message);
    }
    else if (message == _XOR_("session_unavailable")) {
        raiseError(unavailable_session_message);
    }
    else if (message == _XOR_("session_already_used")) {
        raiseError(used_session_message);
    }
    else if (message == _XOR_("session_overcrowded")) {
        raiseError(overcrowded_session_message);
    }
    else if (message == _XOR_("session_expired")) {
        raiseError(expired_session_message);
    }
    else if (message == _XOR_("account_unavailable")) {
        raiseError(invalid_user_message);
    }
    else if (message == _XOR_("name_already_used")) {
        raiseError(used_name_message);
    }
    else if (message == _XOR_("key_unavailable")) {
        raiseError(invalid_key_message);
    }
    else if (message == _XOR_("user_is_banned")) {
        exit(1);
    }
    else if (message == _XOR_("maximum_users_reached")) {
        raiseError(upgrade_your_eauth_message);
    }

    return signup;
}

// Download request
bool downloadsRequest(std::string fileid) {

    rapidjson::Document doc;
    doc.SetObject();
    auto& allocator = doc.GetAllocator();
    doc.AddMember("type", rapidjson::Value(_XOR_("download"), allocator), allocator);
    doc.AddMember("session_id", rapidjson::Value(session_id.c_str(), allocator), allocator);
    doc.AddMember("file_id", rapidjson::Value(fileid.c_str(), allocator), allocator);
    doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer writer(buffer);
    doc.Accept(writer);

    std::string json = runRequest(buffer.GetString());
    doc.Parse(json.c_str());

    std::string message = doc[_XOR_("message")].GetString();
    if (message == _XOR_("download_success")) {
        file_to_download = doc["link"].GetString();
        return true;
    }
    else if (message == _XOR_("invalid_account_key")) {
        raiseError(invalid_account_key_message);
        return false;
    }
    else if (message == _XOR_("invalid_request")) {
        raiseError(invalid_request_message);
        return false;
    }
    else if (message == _XOR_("session_unavailable")) {
        raiseError(unavailable_session_message);
        return false;
    }
    else if (message == _XOR_("session_unauthorized")) {
        raiseError(unauthorized_session_message);
        return false;
    }
    else if (message == _XOR_("session_expired")) {
        raiseError(expired_session_message);
        return false;
    }
    else if (message == _XOR_("invalid_file")) {
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

    std::string savePath = path + _XOR_("/") + filename;

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
        std::cerr << _XOR_("Unable to open file for writing: ") << savePath << std::endl;
        return false;
    }

    return true;
}

// Ban the user HWID and IP
void banUser() {

    rapidjson::Document doc;
    doc.SetObject();
    auto& allocator = doc.GetAllocator();
    doc.AddMember("type", rapidjson::Value(_XOR_("ban_user"), allocator), allocator);
    doc.AddMember("session_id", rapidjson::Value(session_id.c_str(), allocator), allocator);
    doc.AddMember("hwid", rapidjson::Value(getHWID().c_str(), allocator), allocator);
	doc.AddMember("pair", rapidjson::Value(generateRandomString().c_str(), allocator), allocator);

    rapidjson::StringBuffer buffer;
    rapidjson::Writer writer(buffer);
    doc.Accept(writer);

    std::string json = runRequest(buffer.GetString());

    exit(1);
}
