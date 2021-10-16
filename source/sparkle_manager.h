#ifndef _SPARKLE_MANAGER_H_
#define _SPARKLE_MANAGER_H_

#include <memory>
#include <tuple>
#include "sparkle_internal.h"
#include "sparkle_api.h"

namespace httplib { class Client; };

namespace SparkleLite
{
	class SparkleManager
	{
		using HttpHeaders = std::map<std::string, std::string>;

		struct FilteredAppcast
		{
			bool				valid = false;
			bool				isInformationalUpdate = false;
			bool				isCriticalUpdate = false;
			bool				canAutoUpdateSupported = false;
			std::string			channel;
			std::string			version;
			std::string			shortVersion;
			std::string			pubDate;
			std::string			title;
			std::string			description;
			std::string			releaseNoteLink;
			std::string			downloadWebsite;
			AppcastEnclosure	enclosure;
		};
	public:
		void SetCallbacks(const SparkleCallbacks& callbacks, void* userdata);

		void SetAppcastURL(const std::string& url);

		void SetAcceptChannels(const std::vector<std::string>& channels);

		void SetAppCurrentVersion(const std::string& ver);

		void SetAppLang(const std::string& lang);

		void SetSignatureVerifyParams(SignatureAlgo algo, const std::string& pubkey);

		void SetHttpsCAPath(const std::string& caPath);

		void SetHttpHeader(const std::string& key, const std::string& value);

		bool IsReady();

	public:
		void Clean();

		SparkleError CheckUpdate();

		SparkleError Dowload(void* buf, size_t bufsize, size_t* resultLen);

		SparkleError Dowload(const std::string& dstFile);

		SparkleError Install(const char* overideArgs);

	private:
		bool FilterAppcast(Appcast& appcast, FilteredAppcast& filterOut);

		std::string FilterGetLangString(const MultiLangString& multiLangs, const std::string& lang);
		
		std::tuple<std::shared_ptr<httplib::Client>, SparkleError> CreateHttpClient(const std::string& host);

		std::tuple<std::string, std::string> SimpleSplitUrl(const std::string& url);

	private:
		SignatureAlgo		signAlgo_ = SignatureAlgo::kNone;
		std::string			signPubKey_;
		std::string			appcastUrl_;
		std::string			ua_;
		std::string			appVer_;
		std::string			appLang_;
		std::vector<std::string>	appAcceptChannels_;
		std::string			caPath_;
		SparkleCallbacks	handlers_ = { nullptr };
		void*				userdata_ = nullptr;
		std::string			downloadedPackage_;
		HttpHeaders			headers_;
		FilteredAppcast		cacheAppcast_;
	};
};

#endif //_SPARKLE_MANAGER_H_
