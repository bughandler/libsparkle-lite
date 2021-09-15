#include <tuple>
#include <algorithm>
#include <pugixml.hpp>
#include "appcast_parser.h"

namespace SparkleLite
{
	pugi::xml_attribute findAttributeByName(pugi::xml_node& node, const std::string& name)
	{
		return node.find_attribute([&](const pugi::xml_attribute& attr) -> bool
			{
				return _stricmp(attr.name(), name.c_str()) == 0;
			});
	}

	std::tuple<uint16_t, std::string> resolveLangString(pugi::xml_node& node)
	{
		auto attr =findAttributeByName(node, "xml:lang");
		if (attr.hash_value())
		{
			std::string lang = attr.value();
			if (lang.size() == 2)
			{
				char code[2] = { (char)std::tolower(lang[0]), (char)std::tolower(lang[1]) };
				return { *(uint16_t*)code, node.value() };
			}
		}
		return {};
	}

	bool resolveAppcastEnclosure(pugi::xml_node& enclosureItem, AppcastEnclosure& enclosure)
	{
		AppcastEnclosure result;
		for (auto& attr : enclosureItem.attributes())
		{
			if (_stricmp(attr.name(), "url") == 0)
			{
				result.url = attr.value();
			}
			else if (_stricmp(attr.name(), "sparkle:edSignature") == 0)
			{
				result.signType = SignatureType::kEdDSA;
				result.signature = attr.value();
			}
			else if (_stricmp(attr.name(), "sparkle:dsaSignature") == 0)
			{
				result.signType = SignatureType::kDSA;
				result.signature = attr.value();
			}
			else if (_stricmp(attr.name(), "length") == 0)
			{
				result.size = strtoul(attr.value(), nullptr, 0);
			}
			else if (_stricmp(attr.name(), "type") == 0)
			{
				result.mime = attr.value();
			}
			else if (_stricmp(attr.name(), "sparkle:os") == 0)
			{
				result.os = attr.value();
			}
			else if (_stricmp(attr.name(), "sparkle:installerArguments") == 0)
			{
				result.installArgs = attr.value();
			}
			else
			{
				return false;
			}
		}
		
		if (result.url.empty() ||
			!result.size ||
			result.os.empty())
		{
			return false;
		}

		// done
		enclosure = std::move(result);
		return true;
	}

	bool resolveAppcastItem(pugi::xml_node& itemNode, AppcastItem& item)
	{
		AppcastItem result;
		for (auto& node : itemNode.children())
		{
			if (_stricmp(node.name(), "title") == 0)
			{
				// title
				result.title = node.child_value();
			}
			else if (_stricmp(node.name(), "pubDate"))
			{
				// publish date
				result.pubDate = node.child_value();
			}
			else if (_stricmp(node.name(), "description"))
			{
				// description
				auto [lang, str] = resolveLangString(node);
				if (str.empty())
				{
					return false;
				}
				result.description[lang] = str;
			}
			else if (_stricmp(node.name(), "link"))
			{
				// external download website URL
				result.link = node.child_value();
			}
			else if (_stricmp(node.name(), "sparkle:version"))
			{
				// version
				result.version = node.child_value();
			}
			else if (_stricmp(node.name(), "sparkle:shortVersionString"))
			{
				// short version string
				result.shortVersion = node.child_value();
			}
			else if (_stricmp(node.name(), "sparkle:releaseNotesLink"))
			{
				// release note
				auto [lang, str] = resolveLangString(node);
				if (str.empty())
				{
					return false;
				}
				result.releaseNoteLink[lang] = str;
			}
			else if (_stricmp(node.name(), "sparkle:channel"))
			{
				// channel
				result.channel = node.child_value();
			}
			else if (_stricmp(node.name(), "sparkle:minimumSystemVersion"))
			{
				// minimum OS version requirement
				result.minSystemVerRequire = node.child_value();
			}
			else if (_stricmp(node.name(), "sparkle:minimumAutoupdateVersion"))
			{
				// minimum OS version requirement to perform auto-update
				result.minAutoUpdateVerRequire = node.child_value();
			}
			else if (_stricmp(node.name(), "sparkle:criticalUpdate"))
			{
				// critical update
				auto attr = findAttributeByName(node, "sparkle:version");
				if (attr.hash_value())
				{
					result.criticalUpdateVerBarrier = attr.value();
				}
			}
			else if (_stricmp(node.name(), "sparkle:informationalUpdate"))
			{
				// informational update versions
				std::vector<std::string> versions;
				for (auto& infoNode : node.children())
				{
					if (_stricmp(infoNode.name(), "sparkle:version") != 0)
					{
						// illegal node
						return false;
					}
					versions.emplace_back(infoNode.child_value());
				}
				result.informationalUpdateVers = std::move(versions);
			}
			else if (_stricmp(node.name(), "sparkle:phasedRolloutInterval"))
			{
				// roll out interval
				result.rollOutInterval = strtoul(node.child_value(), nullptr, 0);
			}
			else if (_stricmp(node.name(), "enclosure"))
			{
				AppcastEnclosure info;
				if (resolveAppcastEnclosure(node, info))
				{
					result.enclosures.emplace_back(std::move(info));
				}
			}
			else
			{
				// illegal node
				return false;
			}
		}
		if (result.version.empty() ||
			(result.link.empty() && result.enclosures.empty()))
		{
			return false;
		}

		// done
		item = std::move(result);
		return true;
	}

	Appcast ParseAppcastXML(std::string& xml)
	{
		pugi::xml_document doc;
		auto result = doc.load_buffer_inplace(&xml[0], xml.size());
		if (!result)
		{
			return {};
		}

		Appcast appcast;
		auto channel = doc.child("rss").child("channel");
		for (auto& node : channel.children())
		{
			if (_stricmp(node.name(), "item"))
			{
				// we have an item
				AppcastItem item;
				if (resolveAppcastItem(node, item))
				{
					appcast.items.emplace_back(std::move(item));
				}
			}
			else if (_stricmp(node.name(), "title"))
			{
				appcast.title = node.child_value();
			}
			else if (_stricmp(node.name(), "description"))
			{
				appcast.description = node.child_value();
			}
			else if (_stricmp(node.name(), "link"))
			{
				appcast.link = node.child_value();
			}
			else if (_stricmp(node.name(), "language"))
			{
				appcast.lang = node.child_value();
			}
		}

		return std::move(appcast);
	}
};