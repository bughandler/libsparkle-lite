#include "sparkle_manager.h"
#include "appcast_parser.h"
#include "os_support.h"
#include "signature_verifier.h"
#include "simple_http.h"
#include <openssl/x509.h>
#include <algorithm>
#include <cassert>
#include <cctype>

namespace SparkleLite {

static std::tuple<size_t, bool> FindVersionPart(const std::string &v, size_t off) {
	auto idx = off;
	auto isDigit = true;
	while (idx < v.size()) {
		if (v.at(idx) == '.') {
			return { idx, isDigit };
		}
		if (isDigit && !std::isdigit(v.at(idx))) {
			isDigit = false;
		}
		++idx;
	}
	return { idx, isDigit };
}

int SafeVersionCompare(const std::string &x, const std::string &y) {
	size_t xOff = 0, yOff = 0;
	while (true) {
		auto [xPos, xIsDigit] = FindVersionPart(x, xOff);
		auto [yPos, yIsDigit] = FindVersionPart(y, yOff);

		if (xPos == xOff && yPos == yOff) {
			// both reach tail
			return 0;
		} else if (xPos == yOff && yPos > yOff) {
			// y wins
			return -1;
		} else if (xPos > xOff && yPos == yOff) {
			// x wins
			return 1;
		}

		// compare this part
		auto xPart = x.substr(xOff, xPos - xOff);
		auto yPart = y.substr(yOff, yPos - yOff);
		if (xIsDigit && yIsDigit) {
			// compare as number
			auto vX = std::stoll(xPart);
			auto vY = std::stoll(yPart);
			if (vX != vY) {
				return vX > vY ? 1 : -1;
			}
		} else {
			// compare as string
			int ret = _stricmp(xPart.c_str(), yPart.c_str());
			if (ret != 0) {
				return ret;
			}
		}

		// update offsets
		xOff = xPos + 1;
		yOff = yPos + 1;
	}
	return 0;
}

void SparkleManager::SetCallbacks(const SparkleCallbacks &callbacks) {
	handlers_ = callbacks;
}

void SparkleManager::SetAppcastURL(const std::string &url) {
	appcastUrl_ = url;
}

void SparkleManager::SetAppCurrentVersion(const std::string &ver) {
	appVer_ = ver;
}

void SparkleManager::SetSignatureVerifyParams(SignatureAlgo algo, const std::string &pubkey) {
	assert(algo != SignatureAlgo::kNone);
	assert(!pubkey.empty());
	signAlgo_ = algo;
	signPubKey_ = pubkey;
}

void SparkleManager::SetHttpsCAPath(const std::string &caPath) {
	caPath_ = caPath;
}

void SparkleManager::SetHttpHeader(const std::string &key, const std::string &value) {
	headers_.insert({ key, value });
}

bool SparkleManager::IsReady() {
	return (handlers_.sparkle_download_progress != nullptr &&
			handlers_.sparkle_new_version_found != nullptr &&
			handlers_.sparkle_request_shutdown != nullptr &&
			!appcastUrl_.empty() &&
			!appVer_.empty());
}

void SparkleManager::Clean() {
	cacheAppcast_ = {};
	downloadedPackage_.clear();
}

SparkleError SparkleManager::CheckUpdate(const std::string &preferLang, const std::vector<std::string> &channels, void *userdata) {
	// prepare
	HttpHeaders respHeaders;
	std::string respBody;
	auto status = simple_http_get(appcastUrl_, headers_, respHeaders, respBody);
	if (status != 200 ||
			respBody.empty()) {
		return SparkleError::kNetworkFail;
	}

#if 0
		auto it = respHeaders.find("Content-Type");
		if (_strnicmp(it->second.c_str(), XML_MIME, sizeof(XML_MIME) - 1) != 0)
		{
			return SparkleError::kNetworkFail;
		}
#endif

	// assume the body is appcast formatted xml, so we should parse it
	auto appcast = ParseAppcastXML(respBody);
	if (appcast.items.empty()) {
		return SparkleError::kInvalidAppcast;
	}

	FilteredAppcast selectedAppcast;

	std::sort(appcast.items.begin(), appcast.items.end(), [&](const AppcastItem &a, const AppcastItem &b) -> bool {
		return SafeVersionCompare(a.version, b.version) > 0;
	});
	if (!FilterSortedAppcast(appcast, preferLang, channels, selectedAppcast)) {
		return SparkleError::kNoUpdateFound;
	}

	if (selectedAppcast.enclosure.signType != signAlgo_) {
		return SparkleError::kUnsupportedSignAlgo;
	}
	cacheAppcast_ = selectedAppcast;

	// we have an update, notify it
#define PURE_C_STR_FIELD(_s_) ((_s_).empty() ? nullptr : (_s_).c_str())
	SparkleNewVersionInfo notify = { 0 };
	notify.isInformaional = selectedAppcast.isInformationalUpdate;
	notify.isCritical = selectedAppcast.isCriticalUpdate;
	notify.channel = PURE_C_STR_FIELD(selectedAppcast.channel);
	notify.version = PURE_C_STR_FIELD(selectedAppcast.version);
	notify.title = PURE_C_STR_FIELD(selectedAppcast.title);
	notify.pubData = PURE_C_STR_FIELD(selectedAppcast.pubDate);
	notify.description = PURE_C_STR_FIELD(selectedAppcast.description);
	notify.releaseNoteURL = PURE_C_STR_FIELD(selectedAppcast.releaseNoteLink);
	notify.downloadSize = selectedAppcast.enclosure.size;
	notify.downloadLink = PURE_C_STR_FIELD(selectedAppcast.enclosure.url);
	notify.downloadWebsite = PURE_C_STR_FIELD(selectedAppcast.downloadWebsite);
	notify.installArgs = PURE_C_STR_FIELD(selectedAppcast.enclosure.installArgs);
	handlers_.sparkle_new_version_found(&notify, userdata);

	// now we have a valid update
	return SparkleError::kNoError;
}

SparkleError SparkleManager::Dowload(void *buf, size_t bufsize, size_t *resultLen, void *userdata) {
	auto &enclousure = cacheAppcast_.enclosure;

	if (enclousure.url.empty()) {
		return SparkleError::kFail;
	}

	// download
	size_t offset = 0;
	bool overSize = false;
	HttpHeaders respHeaders;
	auto status = simple_http_get(enclousure.url, headers_, respHeaders,
			// content handler
			[&](size_t total, const void *data, size_t data_length) -> bool {
				if (offset + data_length > bufsize) {
					overSize = true;
					return false;
				}
				memcpy((char *)buf + offset, data, data_length);
				offset += data_length;

				// notify progress
				return handlers_.sparkle_download_progress(total, data_length, userdata) != 0;
			});
	if (overSize) {
		return SparkleError::kFileIOFail;
	}
	if (status != 200) {
		return SparkleError::kNetworkFail;
	}

	// verify data buffer
	if (!VerifyDataBuffer(buf, offset, enclousure.signType, enclousure.signature, signPubKey_)) {
		return SparkleError::kBadSignature;
	}

	if (resultLen) {
		*resultLen = offset;
	}
	return SparkleError::kNoError;
}

SparkleError SparkleManager::Dowload(const std::string &dstFile, void *userdata) {
	auto &enclosure = cacheAppcast_.enclosure;

	// try to use the cache
	if (!downloadedPackage_.empty()) {
		// already downloaded
		if (enclosure.signType == SignatureAlgo::kNone || VerifyFile(dstFile, enclosure.signType, enclosure.signature, signPubKey_)) {
			return SparkleError::kNoError;
		}
		downloadedPackage_.clear();
	}

	if (enclosure.url.empty()) {
		return SparkleError::kFail;
	}

	// prepare
	FILE *fd = nullptr;
	auto e = fopen_s(&fd, dstFile.c_str(), "wb");
	if (e != 0) {
		return SparkleError::kFileIOFail;
	}

	// download with progress callback
	bool hasIoError = false;
	HttpHeaders respHeaders;
	auto status = simple_http_get(enclosure.url, headers_, respHeaders,
			// content handler
			[&](size_t total, const void *data, size_t data_length) -> bool {
				auto size = fwrite(data, sizeof(char), data_length, fd);
				if (!size) {
					hasIoError = true;
					return false;
				}

				// notify progress
				return handlers_.sparkle_download_progress(total, data_length, userdata) != 0;
			});
	fclose(fd);
	if (hasIoError) {
		return SparkleError::kFileIOFail;
	}
	if (status != 200) {
		return SparkleError::kNetworkFail;
	}

	// validate it signature
	if (enclosure.signType != SignatureAlgo::kNone &&
			!VerifyFile(dstFile, enclosure.signType, enclosure.signature, signPubKey_)) {
		return SparkleError::kBadSignature;
	}

	// we done, save this downloaded file
	downloadedPackage_ = dstFile;
	return SparkleError::kNoError;
}

SparkleError SparkleManager::Install(const char *overideArgs, void *userdata) {
	if (downloadedPackage_.empty()) {
		return SparkleError::kNotReady;
	}
	auto &enclosure = cacheAppcast_.enclosure;

	// execute update package
	if (!execute(downloadedPackage_, overideArgs ? overideArgs : enclosure.installArgs)) {
		return SparkleError::kFail;
	}

	// request shutdown and go on
	handlers_.sparkle_request_shutdown(userdata);

	return SparkleError::kNoError;
}

bool SparkleManager::FilterSortedAppcast(const Appcast &appcast, const std::string &preferLang, const std::vector<std::string> &channels, FilteredAppcast &filterOut) {
	// sort by version
	for (auto &item : appcast.items) {
		if (SafeVersionCompare(appcast.items[0].version, appVer_) <= 0) {
			// no more match, cause they all must less than current app version
			break;
		}

		// match enclosure
		int enclosureIndex = -1;
		for (auto idx = 0; idx < item.enclosures.size(); idx++) {
			if (is_matched_os_name(item.enclosures[idx].os)) {
				enclosureIndex = idx;
				break;
			}
		}
		if (enclosureIndex == -1) {
			// no matched enclosure
			continue;
		}

		// match system version
		if (!item.minSystemVerRequire.empty() &&
				!is_acceptable_os_version(item.minSystemVerRequire)) {
			// not acceptable
			continue;
		}

		// match channel
		if (!item.channel.empty()) {
			if (channels.empty()) {
				// we don't have any explicitly specified channel
				continue;
			}

			auto it = std::find_if(channels.begin(), channels.end(), [&](const std::string &v) -> bool {
				return _stricmp(v.c_str(), item.channel.c_str()) == 0;
			});
			if (it == channels.end()) {
				// this channel is not acceptable
				continue;
			}
		}

		//
		// #NOTE
		// this version is good to go
		//
		for (auto &ver : item.informationalUpdateVers) {
			if (_stricmp(ver.c_str(), appVer_.c_str()) == 0) {
				filterOut.isInformationalUpdate = true;
			}
		}

		if (!item.criticalUpdateVerBarrier.empty() &&
				_stricmp(item.criticalUpdateVerBarrier.c_str(), appVer_.c_str()) > 0) {
			filterOut.isCriticalUpdate = true;
		}

		if (!item.minAutoUpdateVerRequire.empty() &&
				_stricmp(item.minAutoUpdateVerRequire.c_str(), appVer_.c_str()) <= 0) {
			filterOut.canAutoUpdateSupported = true;
		}

		// get other fields
		filterOut.enclosure = std::move(item.enclosures[enclosureIndex]);
		filterOut.channel = item.channel;
		filterOut.version = item.version;
		filterOut.shortVersion = item.shortVersion;
		filterOut.title = item.title;
		filterOut.pubDate = item.pubDate;
		filterOut.releaseNoteLink = FilterGetLangString(item.releaseNoteLink, preferLang);
		filterOut.description = FilterGetLangString(item.description, preferLang);
		filterOut.downloadWebsite = item.link;

		// we done
		return true;
	}
	return false;
}

std::string SparkleManager::FilterGetLangString(const MultiLangString &multiLangs, const std::string &lang) {
	if (multiLangs.empty() || lang.size() != 2) {
		return {};
	}
	char codeBuf[2] = { (char)std::tolower(lang[0]), (char)std::tolower(lang[1]) };
	auto code = *(uint16_t *)codeBuf;

	// match with lang-code
	auto matchIt = multiLangs.find(code);
	if (matchIt != multiLangs.end()) {
		return matchIt->second;
	}

	// find out the default one
	matchIt = multiLangs.find(0);
	if (matchIt != multiLangs.end()) {
		return matchIt->second;
	}

	// nothing
	return {};
}
}; //namespace SparkleLite