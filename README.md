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
void banUser();
```

Configuration
-------------

Navigate to `eauth/eauth.cpp`, and fill these lines of code:

```cpp
// Required configuration
std::string APPLICATION_TOKEN = ""; // Your application token goes here
std::string APPLICATION_SECRET = ""; // Your application secret goes here;
std::string APPLICATION_VERSION = "1.0"; // Your application version goes here;
```