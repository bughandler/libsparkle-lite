#ifndef _APPCAST_RESOLVER_H_
#define _APPCAST_RESOLVER_H_

#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include "sparkle_internal.h"

namespace SparkleLite 
{
	Appcast ParseAppcastXML(std::string& xml);
};

#endif //_APPCAST_RESOLVER_H_