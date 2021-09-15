#ifndef _SPARKLE_API_H_
#define _SPARKLE_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#define SPARKLE_API_CC	__cdecl
#ifndef SPARKLE_STATIC_LINK
#define SPARKLE_API_DELC(ret) __declspec(dllexport) ret SPARKLE_API_CC
#else
#define SPARKLE_API_DELC(ret) ret SPARKLE_API_CC
#endif

	enum SparkleError
	{
		kAlreadyInitialized = 2,
		kNoUpdateFound = 1,
		kNoError = 0,
		kFail = -1,
		kCancel = -2,
		kInvalidParameter = 3,
		kNotReady = -4,
		kSSLNotSupported = -5,
		kNetworkFail = -6,
		kInvalidAppcast = -7,
		kFileIOFail = -8,
		kBadSignature = -9
	};

	struct NewVersionInfo
	{
		unsigned char	isInformaional;
		unsigned char	isCritical;
		const char*		channel;
		const char*		version;
		const char*		title;
		const char*		description;
		const char*		releaseNoteURL;
		const char*		downloadWebsite;
		const char*		downloadLink;
		__int64			downloadSize;
		const char*		installArgs;
	};

	struct Callbacks
	{
		void(SPARKLE_API_CC * sparkle_new_version_found)(const NewVersionInfo* appcast);
		int(SPARKLE_API_CC * sparkle_download_progress)(__int64 total, __int64 have);
		int(SPARKLE_API_CC * sparkle_request_shutdown)();
	};

	//
	// Setup sparkle updater with user defined information:
	// 
	// @param callbacks: A set of handlers used to interactive with sparkle module
	// @param curentBundleVer: Current internal version number, will match against <sparkle:version>
	// @param pemPubKey: A DSA public key used to verify the signature of downloaded file
	// @param appcastURL: URL reference to the appcast xml file
	// @param sslCA: CA cert bundle file path, must be explicitly specified when using on non-windows platform and the Appcast URL has "https" scheme
	// @param prepferLang: Two-letter country code for localization purpose, will follow the system settings by default
	// @param acceptChannels: An array of strings that indicate all the non-default update channels user would accepted (such as, ["insider", "beta"])
	// @param acceptChannelCount: Count of [acceptChannels]
	// @return SparkleError code
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_setup(const Callbacks* callbacks, const char* appCurrentVer, const char* appcastURL, const char* pemPubKey, const char* sslCA, const char* preferLang, const char** acceptChannels, int acceptChannelCount);

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
	SPARKLE_API_DELC(SparkleError) sparkle_check_update();

	//
	// Download current update package to the destination file
	// 
	// @param dstFile: An absolute file path that received data will write to
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_download_to_file(const char* dstFile);

	//
	// Download current update package to a user-defined buffer (and verify it signature)
	// @param buffer: Pointer to the data buffer
	// @param bufferSize: [in,out] Size of [buffer], in byte
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_download_to_buffer(void* buffer, size_t* bufferSize);

	//
	// Install current update package
	// @param overrideArgs: An optional parameter that explicitly specify the update package startup argument string, 
	//						it will override the corresponding string in appcast we fetched before
	// 
	SPARKLE_API_DELC(SparkleError) sparkle_install(const char* overrideArgs);

#ifdef __cplusplus
};
#endif

#endif //_SPARKLE_API_H_