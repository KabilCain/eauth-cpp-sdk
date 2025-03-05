#include <string>

bool initRequest();
extern std::string error_message;
extern std::string rank;
extern std::string register_date;
extern std::string expire_date;
extern std::string hwid;
bool downloadRequest(std::string fileid, const std::string& filename, const std::string& path);
bool loginRequest(std::string username, std::string password, std::string key);
bool registerRequest(std::string username, std::string password, std::string key);
void banUser();
