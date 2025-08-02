What is Eauth?
==============

https://eauth.us.to/ - Your #1 software login and authentication system, providing you with the most secure, flexible, and easy-to-use solutions.

Functions
-------------

```cpp
bool initRequest();
```
```cpp
bool loginRequest(std::string username, std::string password, std::string key);
```
```cpp
bool registerRequest(std::string username, std::string password, std::string key);
```
```cpp
bool downloadRequest(std::string fileid, const std::string& filename, const std::string& path);
```
```cpp
std::string webhookRequest(std::string webhookName, std::string parameters, std::string body, std::string contentType);
```
```cpp
void banUser();
```
```cpp
bool authMonitor();
```

Configuration
-------------

Navigate to `eauth/eauth.cpp`, and fill these lines of code:

```cpp
// Required configuration
std::string APPLICATION_TOKEN = _XOR_("application_token_here"); // Your application token goes here
std::string APPLICATION_SECRET = _XOR_("application_secret_here"); // Your application secret goes here;
std::string APPLICATION_VERSION = _XOR_("application_version_here"); // Your application version goes here;
```