#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <openssl/x509.h>
#include "sparkle_manager.h"
#include "sparkle_api.h"
#include "appcast_parser.h"
#include "signature_verifier.h"
#include "os_support.h"


#define HTTPS_SCHEME	("https://")
#define XML_MIME		("application/xml")

#ifdef _WIN32
#include <windows.h>
static X509_STORE* ReadWin32CertStore()
{
	HCERTSTORE SysRootStoreHandle = CertOpenSystemStoreA(0, "ROOT");
	if (SysRootStoreHandle == nullptr)
	{
		return nullptr;
	}

	X509_STORE* store = X509_STORE_new();
	PCCERT_CONTEXT certCtx = nullptr;
	while ((certCtx = CertEnumCertificatesInStore(SysRootStoreHandle, certCtx)) != nullptr)
	{
		// convert from DER to internal format
		X509* x509 = d2i_X509(nullptr,
			(const unsigned char**)&certCtx->pbCertEncoded,
			certCtx->cbCertEncoded);
		if (x509 != nullptr)
		{
			X509_STORE_add_cert(store, x509);
			X509_free(x509);
		}
	}
	CertFreeCertificateContext(certCtx);
	CertCloseStore(SysRootStoreHandle, 0);
	return store;
}
#endif

namespace SparkleLite
{

	void SparkleManager::SetCallbacks(const SparkleCallbacks& callbacks, void* userdata)
	{
		handlers_ = callbacks;
		userdata_ = userdata;
	}

	void SparkleManager::SetAppcastURL(const std::string& url)
	{
		appcastUrl_ = url;
	}

	void SparkleManager::SetAcceptChannels(const std::vector<std::string>& channels)
	{
		appAcceptChannels_ = channels;
	}

	void SparkleManager::SetAppCurrentVersion(const std::string& ver)
	{
		appVer_ = ver;
	}

	void SparkleManager::SetAppLang(const std::string& lang)
	{
		appLang_ = lang;
	}

	void SparkleManager::SetSignatureVerifyParams(SignatureAlgo algo, const std::string& pubkey)
	{
		assert(algo != SignatureAlgo::kNone);
		assert(!pubkey.empty());
		signAlgo_ = algo;
		signPubKey_ = pubkey;
	}

	void SparkleManager::SetHttpsCAPath(const std::string& caPath)
	{
		caPath_ = caPath;
	}

	void SparkleManager::SetHttpHeader(const std::string& key, const std::string& value)
	{
		headers_.insert({ key, value });
	}

	bool SparkleManager::IsReady()
	{
		return (handlers_.sparkle_download_progress != nullptr &&
			handlers_.sparkle_new_version_found != nullptr &&
			handlers_.sparkle_request_shutdown != nullptr &&
			!appcastUrl_.empty() &&
			!appVer_.empty() &&
			!appLang_.empty());
	}

	void SparkleManager::Clean()
	{
		cacheAppcast_ = {};
		downloadedPackage_.clear();
	}

	SparkleError SparkleManager::CheckUpdate()
	{
		// prepare
		auto [host, path] = SimpleSplitUrl(appcastUrl_);
		if (host.empty() || path.empty())
		{
			return SparkleError::kInvalidParameter;
		}

		auto [cli, err] = CreateHttpClient(host);
		if (!cli)
		{
			return err;
		}

		// DO HTTP GET
		auto res = cli->Get(path.c_str());
		if (res->status != 200 ||
			res->body.empty())
		{
			return SparkleError::kNetworkFail;
		}

#if 0
		auto it = res->headers.find("Content-Type");
		if (_strnicmp(it->second.c_str(), XML_MIME, sizeof(XML_MIME) - 1) != 0)
		{
			return SparkleError::kNetworkFail;
		}
#endif

		// assume the body is appcast formatted xml, so we should parse it
		auto appcast = ParseAppcastXML(res->body);
		if (appcast.items.empty())
		{
			return SparkleError::kInvalidAppcast;
		}

		FilteredAppcast selectedAppcast;
		if (!FilterAppcast(appcast, selectedAppcast))
		{
			return SparkleError::kNoUpdateFound;
		}

		if (selectedAppcast.enclosure.signType != signAlgo_)
		{
			return SparkleError::kUnsupportedSignAlgo;
		}

		// we have an update, notify it
#define PURE_C_STR_FIELD(_s_) ((_s_).empty()? nullptr : (_s_).c_str())
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
		handlers_.sparkle_new_version_found(&notify, userdata_);

		// now we have a valid update
		return SparkleError::kNoError;
	}

	SparkleError SparkleManager::Dowload(void* buf, size_t bufsize, size_t* resultLen)
	{
		auto& enclousure = cacheAppcast_.enclosure;

		if (enclousure.url.empty())
		{
			return SparkleError::kFail;
		}

		// prepare
		auto [host, path] = SimpleSplitUrl(enclousure.url);
		if (host.empty() || path.empty())
		{
			return SparkleError::kInvalidParameter;
		}

		auto [cli, err] = CreateHttpClient(host);
		if (!cli)
		{
			return err;
		}

		// download
		size_t offset = 0;
		bool   overSize = false;
		auto res = cli->Get(path.c_str(),
			// content handler
			[&](const char* data, size_t data_length) -> bool
			{
				if (offset + data_length > bufsize)
				{
					overSize = true;
					return false;
				}
				memcpy((char*)buf + offset, data, data_length);
				offset += data_length;
				return true;
			},
			// progress handler
				[this](uint64_t len, uint64_t total) -> bool
			{
				return handlers_.sparkle_download_progress(total, len, userdata_) != 0;
			});
		if (overSize)
		{
			return SparkleError::kFileIOFail;
		}
		if (res->status != 200 ||
			res->body.empty())
		{
			return SparkleError::kNetworkFail;
		}

		// verify data buffer
		if (!VerifyDataBuffer(buf, offset, enclousure.signType, enclousure.signature, signPubKey_))
		{
			return SparkleError::kBadSignature;
		}

		if (resultLen)
		{
			*resultLen = offset;
		}
		return SparkleError::kNoError;
	}

	SparkleError SparkleManager::Dowload(const std::string& dstFile)
	{
		auto& enclosure = cacheAppcast_.enclosure;

		// try to use the cache
		if (!downloadedPackage_.empty())
		{
			// already downloaded
			if (enclosure.signType == SignatureAlgo::kNone || VerifyFile(dstFile, enclosure.signType, enclosure.signature, signPubKey_))
			{
				return SparkleError::kNoError;
			}
			downloadedPackage_.clear();
		}

		if (enclosure.url.empty())
		{
			return SparkleError::kFail;
		}

		// prepare
		auto [host, path] = SimpleSplitUrl(enclosure.url);
		if (host.empty() || path.empty())
		{
			return SparkleError::kInvalidParameter;
		}

		auto [cli, err] = CreateHttpClient(host);
		if (!cli)
		{
			return err;
		}

		FILE* fd = nullptr;
		auto e = fopen_s(&fd, dstFile.c_str(), "wb");
		if (e != 0)
		{
			return SparkleError::kFileIOFail;
		}

		// download with progress callback
		bool hasIoError = false;
		auto res = cli->Get(path.c_str(),
			// content handler
			[&](const char* data, size_t data_length) -> bool
			{
				auto size = fwrite(data, sizeof(char), data_length, fd);
				if (!size)
				{
					hasIoError = true;
					return false;
				}
				return true;
			},
			// progress handler
				[this](uint64_t len, uint64_t total) -> bool
			{
				return handlers_.sparkle_download_progress(total, len, userdata_) != 0;
			});

		fclose(fd);
		if (hasIoError)
		{
			return SparkleError::kFileIOFail;
		}
		if (res->status != 200)
		{
			return SparkleError::kNetworkFail;
		}

		// validate it signature
		if (enclosure.signType != SignatureAlgo::kNone &&
			!VerifyFile(dstFile, enclosure.signType, enclosure.signature, signPubKey_))
		{
			return SparkleError::kBadSignature;
		}

		// we done, save this downloaded file
		downloadedPackage_ = dstFile;
		return SparkleError::kNoError;
	}

	SparkleError SparkleManager::Install(const char* overideArgs)
	{
		if (downloadedPackage_.empty())
		{
			return SparkleError::kNotReady;
		}
		auto& enclosure = cacheAppcast_.enclosure;

		// execute update package
		if (!execute(downloadedPackage_, overideArgs ? overideArgs : enclosure.installArgs))
		{
			return SparkleError::kFail;
		}

		// request shutdown and go on
		handlers_.sparkle_request_shutdown(userdata_);

		return SparkleError::kNoError;
	}

	bool SparkleManager::FilterAppcast(Appcast& appcast, FilteredAppcast& filterOut)
	{
		// sort by version
		std::sort(appcast.items.begin(), appcast.items.end(), [&](const AppcastItem& a, const AppcastItem& b) -> bool
			{
				return _stricmp(a.version.c_str(), b.version.c_str()) > 0;
			});

		for (auto& item : appcast.items)
		{
			if (_stricmp(appcast.items[0].version.c_str(), appVer_.c_str()) <= 0)
			{
				// no more match, cause they all must less than current app version
				break;
			}

			// match enclosure
			int	enclosureIndex = -1;
			for (auto idx = 0; idx < item.enclosures.size(); idx++)
			{
				if (is_matched_os_name(item.enclosures[idx].os))
				{
					enclosureIndex = idx;
					break;
				}
			}
			if (enclosureIndex == -1)
			{
				// no matched enclosure
				continue;
			}

			// match system version
			if (!item.minSystemVerRequire.empty() &&
				!is_acceptable_os_version(item.minSystemVerRequire))
			{
				// not acceptable
				continue;
			}

			// match channel
			if (!item.channel.empty())
			{
				if (appAcceptChannels_.empty())
				{
					// we don't have any explicitly specified channel
					continue;
				}

				auto it = std::find_if(appAcceptChannels_.begin(), appAcceptChannels_.end(), [&](const std::string& v) -> bool
					{
						return _stricmp(v.c_str(), item.channel.c_str()) == 0;
					});
				if (it == appAcceptChannels_.end())
				{
					// this channel is not acceptable
					continue;
				}
			}

			//
			// #NOTE
			// this version is good to go
			//
			for (auto& ver : item.informationalUpdateVers)
			{
				if (_stricmp(ver.c_str(), appVer_.c_str()) == 0)
				{
					filterOut.isInformationalUpdate = true;
				}
			}

			if (!item.criticalUpdateVerBarrier.empty() &&
				_stricmp(item.criticalUpdateVerBarrier.c_str(), appVer_.c_str()) > 0)
			{
				filterOut.isCriticalUpdate = true;
			}

			if (!item.minAutoUpdateVerRequire.empty() &&
				_stricmp(item.minAutoUpdateVerRequire.c_str(), appVer_.c_str()) <= 0)
			{
				filterOut.canAutoUpdateSupported = true;
			}

			// get other fields
			filterOut.enclosure = std::move(item.enclosures[enclosureIndex]);
			filterOut.channel = item.channel;
			filterOut.version = item.version;
			filterOut.shortVersion = item.shortVersion;
			filterOut.title = item.title;
			filterOut.pubDate = item.pubDate;
			filterOut.releaseNoteLink = FilterGetLangString(item.releaseNoteLink, appLang_);
			filterOut.description = FilterGetLangString(item.description, appLang_);
			filterOut.downloadWebsite = item.link;

			// we done
			return true;
		}
		return false;
	}

	std::string SparkleManager::FilterGetLangString(const MultiLangString& multiLangs, const std::string& lang)
	{
		if (multiLangs.empty() || lang.size() != 2)
		{
			return {};
		}
		char codeBuf[2] = { (char)std::tolower(lang[0]), (char)std::tolower(lang[1]) };
		auto code = *(uint16_t*)codeBuf;


		// match with lang-code
		auto matchIt = multiLangs.find(code);
		if (matchIt != multiLangs.end())
		{
			return matchIt->second;
		}

		// find out the default one
		matchIt = multiLangs.find(0);
		if (matchIt != multiLangs.end())
		{
			return matchIt->second;
		}

		// nothing
		return {};
	}

	std::tuple<std::shared_ptr<httplib::Client>, SparkleError> SparkleManager::CreateHttpClient(const std::string& host)
	{
		auto cli = std::make_shared<httplib::Client>(host);
		if (!cli->is_valid())
		{
			return { nullptr, SparkleError::kInvalidParameter };
		}

		// prepare SSL
		if (_strnicmp(host.c_str(), HTTPS_SCHEME, sizeof(HTTPS_SCHEME) - 1) == 0)
		{
			if (!caPath_.empty())
			{
				cli->set_ca_cert_path(caPath_.c_str());
			}
			else
			{
#ifdef _WIN32
				auto store = ReadWin32CertStore();
				if (!store)
				{
					return { nullptr, SparkleError::kSSLNotSupported };
				}
				cli->set_ca_cert_store(store);
#else
				return { nullptr, SparkleError::kSSLNotSupported };
#endif
			}
		}

		// prepare headers
		httplib::Headers headers;
		for (auto [k, v] : headers_)
		{
			headers.insert({ k, v });
		}
		if (headers_.find("User-Agent") == headers_.end())
		{
			headers.insert({ "User-Agent", "SparkleLite" });
		}
		cli->set_default_headers(headers);

		// done
		return { cli, SparkleError::kNoError };
	}

	std::tuple<std::string, std::string> SparkleManager::SimpleSplitUrl(const std::string& url)
	{
		auto pos = url.find("://");
		if (pos == std::string::npos)
		{
			return {};
		}
		pos += 3;

		pos = url.find_first_of('/', pos);
		if (pos == std::string::npos)
		{
			return {};
		}

		auto host = url.substr(0, pos);
		auto path = url.substr(pos);
		if (path.empty())
		{
			path = "/";
		}

		return { std::move(host), std::move(path) };
	}

};