#ifndef _SPARKLE_API_H_
#define _SPARKLE_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32))
#define __WINDOWS__
#endif

#ifdef __WINDOWS__
// Windows
#define SPARKLE_API_CC	__stdcall
#ifndef SPARKLE_STATIC_LINK
#define SPARKLE_API_DELC(ret) __declspec(dllexport) ret SPARKLE_API_CC
#else
#define SPARKLE_API_DELC(ret) ret SPARKLE_API_CC
#endif
#else
#ifdef defined(__GNUC__) || defined(__SUNPRO_CC) || defined (__SUNPRO_C)
// GCC
#define SPARKLE_API_DELC(ret)   __attribute__((visibility("default"))) ret
#else
// Others
#define SPARKLE_API_DELC(ret) ret
#endif
#endif

	enum SparkleError
	{
		kAlreadyInitialized = 2,
		kNoUpdateFound = 1,
		kNoError = 0,
		kFail = -1,
		kCancel = -2,
		kInvalidParameter = -3,
		kNotReady = -4,
		kSSLNotSupported = -5,
		kNetworkFail = -6,
		kInvalidAppcast = -7,
		kFileIOFail = -8,
		kUnsupportedSignAlgo = -9,
		kBadSignature = -10
	};

	struct SparkleNewVersionInfo
	{
		unsigned char	isInformaional;
		unsigned char	isCritical;
		const char*		channel;
		const char*		version;
		const char*		title;
		const char*		pubData;
		const char*		description;
		const char*		releaseNoteURL;
		const char*		downloadWebsite;
		const char*		downloadLink;
		long long		downloadSize;
		const char*		installArgs;
	};

	struct SparkleCallbacks
	{
		void(SPARKLE_API_CC * sparkle_new_version_found)(const SparkleNewVersionInfo* appcast, void* userdata);
		int(SPARKLE_API_CC * sparkle_download_progress)(long long total, long long have, void* userdata);
		int(SPARKLE_API_CC * sparkle_request_shutdown)(void* userdata);
	};

	enum SignAlgo
	{
		kNoSign,
		kDSA,
		kEd25519
	};

	//
	// Setup sparkle updater with user defined information:
	// 
	// @param callbacks: A set of handlers used to interactive with sparkle module
	// @param curentBundleVer: Current internal version number, will match against <sparkle:version>
	// @param signVerifyAlgo: Signature algorithm
	// @param signVerifyPubKey: Encoded public key
	//						kNoneSign: it's empty
	//						kDSA: it's a PEM format string
	//						kEd25519 (EdDSA): it's base64 encoded key string
	// @param appcastURL: URL reference to the appcast xml file
	// @param sslCA: CA cert bundle file path, must be explicitly specified when using on non-windows platform and the Appcast URL has "https" scheme
	// @return SparkleError code
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_setup(
		const SparkleCallbacks* callbacks, 
		const char* appCurrentVer, 
		const char* appcastURL, 
		SignAlgo signVerifyAlgo,
		const char* signVerifyPubKey, 
		const char* sslCA);

	//
	// Customize HTTP headers that sparkle will use to perform HTTP(s) requests
	// 
	// @param key: HTTP header field name
	// @param value: HTTP header field value
	// 
	SPARKLE_API_DELC(void) sparkle_customize_http_header(const char* key, const char* value);

	//
	// Clean current update information cache if exists
	// 
	SPARKLE_API_DELC(void) sparkle_clean();

	//
	// Check new update
	// 
	// @param prepferLang: Two-letter lang code (ISO-639) for localization purpose, will follow the system settings by default
	// @param acceptChannels: An array of strings that indicate all the non-default update channels user would accepted (such as, ["insider", "beta"])
	// @param acceptChannelCount: Count of [acceptChannels]
	// @param userdata: custom userdata used in callbacks
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_check_update(
		const char* preferLang,
		const char** acceptChannels,
		int acceptChannelCount,
		void* userdata);

	//
	// Download current update package to the destination file
	// 
	// @param dstFile: An absolute file path that received data will write to
	// @param userdata: custom userdata used in callbacks
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_download_to_file(const char* dstFile, void* userdata);

	//
	// Download current update package to a user-defined buffer (and verify it signature)
	// @param buffer: Pointer to the data buffer
	// @param bufferSize: [in,out] Size of [buffer], in byte
	// @param userdata: custom userdata used in callbacks
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_download_to_buffer(void* buffer, size_t* bufferSize, void* userdata);

	//
	// Install current update package
	// @param overrideArgs: An optional parameter that explicitly specify the update package startup argument string, 
	//						it will override the corresponding string in appcast we fetched before
	// @param userdata: custom userdata used in callbacks
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_install(const char* overrideArgs, void* userdata);

#ifdef __cplusplus
};
#endif

#endif //_SPARKLE_API_H_