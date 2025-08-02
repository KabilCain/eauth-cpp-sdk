#include <string>

bool initRequest();
extern std::string error_message;
extern std::string rank;
extern std::string register_date;
extern std::string expire_date;
extern std::string hwid;
bool downloadRequest(std::string fileID, const std::string& fileName, const std::string& path);
bool loginRequest(std::string username, std::string password, std::string key);
bool registerRequest(std::string username, std::string password, std::string key);
std::string webhookRequest(std::string webhookName, std::string parameters, std::string body = "", std::string contentType = "");
void banUser();
bool authMonitor();