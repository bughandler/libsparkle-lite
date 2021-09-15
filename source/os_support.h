#ifndef _OS_SUPPORT_H_
#define _OS_SUPPORT_H_

#include <string>

//
// check if the given os + min_required_version is accepted by the current running platform
// 
bool is_acceptable_os_version(const std::string& osMinRequiredVersion);

bool is_matched_os_name(const std::string& osName);

bool execute(const std::string& package, const std::string& args);

#endif //_OS_SUPPORT_H_