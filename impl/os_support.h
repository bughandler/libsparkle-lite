#ifndef _OS_SUPPORT_H_
#define _OS_SUPPORT_H_

#include <map>
#include <string>
#include <functional>

using HttpHeaders = std::map<std::string, std::string>;
using HttpContentHandler = std::function<bool(size_t, const void*, size_t)>;

//
// perform a simple HTTP GET operation and return status code
// 
int http_get(const std::string& url, const HttpHeaders& requestHeaders, HttpContentHandler&& handler);

//
// check if the given [osMinRequiredVersion] is accepted by the current running platform
// 
bool is_acceptable_os_version(const std::string& osMinRequiredVersion);

//
// check if the name of os is matched
// 
bool is_matched_os_name(const std::string& osName);

//
// execute an executable file (PE/ELF) with the given argument string
// 
bool execute(const std::string& package, const std::string& args);

//
// get the language (ISO-639 code) setting of the current OS user
// 
std::string get_iso639_user_lang();

#endif //_OS_SUPPORT_H_