#ifndef _OS_SUPPORT_H_
#define _OS_SUPPORT_H_

#include <string>

namespace SparkleLite {
// check if the given [osMinRequiredVersion] is accepted by the current running platform
//
bool is_acceptable_os_version(const std::string &osMinRequiredVersion);

//
// check if the name of os is matched
//
bool is_matched_os_name(const std::string &osName);

//
// execute an executable file (PE/ELF) with the given argument string
//
bool execute(const std::string &package, const std::string &args);

//
// get the language (ISO-639 code) setting of the current OS user
//
std::string get_iso639_user_lang();
}; //namespace SparkleLite

#endif //_OS_SUPPORT_H_