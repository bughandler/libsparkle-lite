#ifndef _SPARKLE_INTERNAL_H_
#define _SPARKLE_INTERNAL_H_

#include <map>
#include <string>
#include <vector>

namespace SparkleLite {
enum class SignatureAlgo {
	kNone,
	kDSA,
	kEd25519
};

struct AppcastEnclosure {
	std::string url;
	SignatureAlgo signType = SignatureAlgo::kNone;
	std::string signature;
	uint64_t size = 0;
	std::string mime;
	std::string installArgs;
	std::string os;
};
using EnclosureList = std::vector<AppcastEnclosure>;

using MultiLangString = std::map<uint16_t, std::string>;
struct AppcastItem {
	std::string channel;
	std::string version;
	std::string shortVersion;
	std::string pubDate;
	std::string title;
	MultiLangString description;
	std::string link;
	MultiLangString releaseNoteLink;
	std::string minSystemVerRequire;
	EnclosureList enclosures;
	std::string criticalUpdateVerBarrier;
	std::vector<std::string> informationalUpdateVers;
	std::string minAutoUpdateVerRequire;
	uint64_t rollOutInterval = 0;
};

struct Appcast {
	std::string title;
	std::string link;
	std::string description;
	std::string lang;
	std::vector<AppcastItem> items;
};

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

#define DEFAULT_SPARKLE_UA	("sparkle-lite-agent")

}; //namespace SparkleLite

#endif //_SPARKLE_INTERNAL_H_