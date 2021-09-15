#ifndef _SPARKLE_INTERNAL_H_
#define _SPARKLE_INTERNAL_H_

#include <string>
#include <vector>
#include <map>

namespace SparkleLite
{
	enum class SignatureType
	{
		kNone,
		kDSA,
		kEdDSA
	};

	struct AppcastEnclosure
	{
		std::string		url;
		SignatureType	signType = SignatureType::kNone;
		std::string		signature;
		uint64_t		size = 0;
		std::string		mime;
		std::string		installArgs;
		std::string		os;
	};
	using EnclosureList = std::vector<AppcastEnclosure>;

	using MultiLangString = std::map<uint16_t, std::string>;
	struct AppcastItem
	{
		std::string					channel;
		std::string					version;
		std::string					shortVersion;
		std::string					pubDate;
		std::string					title;
		MultiLangString				description;
		std::string					link;
		MultiLangString				releaseNoteLink;
		std::string					minSystemVerRequire;
		EnclosureList				enclosures;
		std::string					criticalUpdateVerBarrier;
		std::vector<std::string>	informationalUpdateVers;
		std::string					minAutoUpdateVerRequire;
		uint64_t					rollOutInterval = 0;
	};

	struct Appcast
	{
		std::string					title;
		std::string					link;
		std::string					description;
		std::string					lang;
		std::vector<AppcastItem>	items;
	};
};

#endif //_SPARKLE_INTERNAL_H_