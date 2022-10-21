#ifndef _APPCAST_RESOLVER_H_
#define _APPCAST_RESOLVER_H_

#include "sparkle_internal.h"
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace SparkleLite {
Appcast ParseAppcastXML(std::string &xml);
};

#endif //_APPCAST_RESOLVER_H_