#ifndef _SPARKLE_MANAGER_H_
#define _SPARKLE_MANAGER_H_

#include "../sparkle_api.h"
#include "sparkle_internal.h"
#include <memory>
#include <tuple>

namespace httplib {
class Client;
};

namespace SparkleLite {
class SparkleManager {
	using HttpHeaders = std::map<std::string, std::string>;

	struct FilteredAppcast {
		bool valid = false;
		bool isInformationalUpdate = false;
		bool isCriticalUpdate = false;
		bool canAutoUpdateSupported = false;
		std::string channel;
		std::string version;
		std::string shortVersion;
		std::string pubDate;
		std::string title;
		std::string description;
		std::string releaseNoteLink;
		std::string downloadWebsite;
		AppcastEnclosure enclosure;
	};

public:
	void SetCallbacks(const SparkleCallbacks &callbacks);

	void SetAppcastURL(const std::string &url);

	void SetAppCurrentVersion(const std::string &ver);

	void SetSignatureVerifyParams(SignatureAlgo algo, const std::string &pubkey);

	void SetHttpsCAPath(const std::string &caPath);

	void SetHttpHeader(const std::string &key, const std::string &value);

	bool IsReady();

public:
	void Clean();

	SparkleError CheckUpdate(const std::string &preferLang, const std::vector<std::string> &channels, void *userdata);

	SparkleError Dowload(void *buf, size_t bufsize, size_t *resultLen, void *userdata);

	SparkleError Dowload(const std::string &dstFile, void *userdata);

	SparkleError Install(const char *overideArgs, void *userdata);

private:
	bool FilterSortedAppcast(const Appcast &appcast, const std::string &preferLang, const std::vector<std::string> &channels, FilteredAppcast &filterOut);

	std::string FilterGetLangString(const MultiLangString &multiLangs, const std::string &lang);

private:
	SignatureAlgo signAlgo_ = SignatureAlgo::kNone;
	std::string signPubKey_;
	std::string appcastUrl_;
	std::string ua_;
	std::string appVer_;
	std::string caPath_;
	SparkleCallbacks handlers_ = { nullptr };
	std::string downloadedPackage_;
	HttpHeaders headers_;
	FilteredAppcast cacheAppcast_;
};
}; //namespace SparkleLite

#endif //_SPARKLE_MANAGER_H_
