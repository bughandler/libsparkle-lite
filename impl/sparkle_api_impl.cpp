#include "os_support.h"
#include "signature_verifier.h"
#include "simple_http.h"
#include "sparkle_manager.h"

#define IS_STRING_PARAM_VALID(_s_) ((_s_) != nullptr && strlen(_s_) != 0)

//
// The singleton sparkle update manager
//
SparkleLite::SparkleManager gMgr;

extern "C" {
SPARKLE_API_DELC(int)
sparkle_setup(
		const SparkleCallbacks *callbacks,
		const char *appCurrentVer,
		const char *appcastURL,
		SignAlgo signVerifyAlgo,
		const char *signVerifyPubKey,
		const char *sslCA) {
	if (!callbacks ||
			!callbacks->sparkle_new_version_found &&
					!callbacks->sparkle_download_progress &&
					!callbacks->sparkle_request_shutdown) {
		return SparkleError::kInvalidParameter;
	}

	if (!IS_STRING_PARAM_VALID(appCurrentVer) ||
			!IS_STRING_PARAM_VALID(appcastURL)) {
		return SparkleError::kInvalidParameter;
	}

	if (signVerifyAlgo != SignAlgo::kNoSign &&
			!IS_STRING_PARAM_VALID(signVerifyPubKey)) {
		return SparkleError::kInvalidParameter;
	} else if (signVerifyAlgo == SignAlgo::kDSA &&
			!SparkleLite::IsValidDSAPubKey(signVerifyPubKey)) {
		return SparkleError::kInvalidParameter;
	} else if (signVerifyAlgo == SignAlgo::kEd25519 &&
			!SparkleLite::IsValidEd25519Key(signVerifyPubKey)) {
		return SparkleError::kInvalidParameter;
	}

	if (gMgr.IsReady()) {
		return SparkleError::kAlreadyInitialized;
	}

	gMgr.SetCallbacks(*callbacks);
	gMgr.SetAppCurrentVersion(appCurrentVer);
	gMgr.SetAppcastURL(appcastURL);

	if (signVerifyAlgo == SignAlgo::kDSA) {
		gMgr.SetSignatureVerifyParams(SparkleLite::SignatureAlgo::kDSA, signVerifyPubKey);
	} else if (signVerifyAlgo == SignAlgo::kEd25519) {
		gMgr.SetSignatureVerifyParams(SparkleLite::SignatureAlgo::kEd25519, signVerifyPubKey);
	}
	if (IS_STRING_PARAM_VALID(sslCA)) {
		gMgr.SetHttpsCAPath(sslCA);
	}

	return gMgr.IsReady() ? SparkleError::kNoError : SparkleError::kFail;
}

SPARKLE_API_DELC(void)
sparkle_customize_http_header(const char *key, const char *value) {
	if (IS_STRING_PARAM_VALID(key) && IS_STRING_PARAM_VALID(value)) {
		gMgr.SetHttpHeader(key, value);
	}
}

SPARKLE_API_DELC(void)
sparkle_clean() {
	gMgr.Clean();
}

SPARKLE_API_DELC(int)
sparkle_check_update(
		const char *preferLang,
		const char **acceptChannels,
		int acceptChannelCount,
		void *userdata) {
	if (!gMgr.IsReady()) {
		return SparkleError::kNotReady;
	}

	// use system default lang is preferLang is not valid
	std::string lang;
	if (IS_STRING_PARAM_VALID(preferLang)) {
		lang = preferLang;
	} else {
		lang = SparkleLite::get_iso639_user_lang();
	}

	// check out channels
	std::vector<std::string> channels;
	if (acceptChannels && acceptChannelCount) {
		for (auto idx = 0; idx < acceptChannelCount; idx++) {
			if (!IS_STRING_PARAM_VALID(acceptChannels[idx])) {
				return SparkleError::kInvalidParameter;
			}
			channels.emplace_back(acceptChannels[idx]);
		}
	}

	return gMgr.CheckUpdate(lang, channels, userdata);
}

SPARKLE_API_DELC(int)
sparkle_download_to_file(const char *destinationFile, void *userdata) {
	if (!IS_STRING_PARAM_VALID(destinationFile)) {
		return SparkleError::kInvalidParameter;
	}
	if (!gMgr.IsReady()) {
		return SparkleError::kNotReady;
	}
	return gMgr.Dowload(destinationFile, userdata);
}

SPARKLE_API_DELC(int)
sparkle_download_to_buffer(void *buffer, size_t *bufferSize, void *userdata) {
	if (!buffer || !bufferSize || !(*bufferSize)) {
		return SparkleError::kInvalidParameter;
	}
	if (!gMgr.IsReady()) {
		return SparkleError::kNotReady;
	}
	return gMgr.Dowload(buffer, *bufferSize, bufferSize, userdata);
}

SPARKLE_API_DELC(int)
sparkle_install(const char *overrideArgs, void *userdata) {
	if (!gMgr.IsReady()) {
		return SparkleError::kNotReady;
	}
	return gMgr.Install(overrideArgs, userdata);
}
};

SPARKLE_API_DELC(int)
sparkle_set_http_proxy(const char *proxy) {
	return SparkleLite::simple_http_proxy_config(proxy) == 0 ? SparkleError::kNoError : SparkleError::kInvalidParameter;
}
