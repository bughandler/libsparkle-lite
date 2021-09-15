#include "sparkle_manager.h"

#define IS_STRING_PARAM_VALID(_s_)	( (_s_) != nullptr && strlen(_s_) != 0 )

//
// The singleton sparkle update manager
// 
SparkleLite::SparkleManager gMgr;

extern "C"
{
	SPARKLE_API_DELC(SparkleError) sparkle_setup(
		const Callbacks* callbacks,
		const char* appCurrentVer,
		const char* appcastURL,
		const char* pemPubKey,
		const char* sslCA,
		const char* preferLang,
		const char** acceptChannels,
		int acceptChannelCount)
	{
		if (!callbacks ||
			!callbacks->sparkle_new_version_found &&
			!callbacks->sparkle_download_progress &&
			!callbacks->sparkle_request_shutdown)
		{
			return SparkleError::kInvalidParameter;
		}

		if (!IS_STRING_PARAM_VALID(appCurrentVer) ||
			!IS_STRING_PARAM_VALID(appcastURL))
		{
			return SparkleError::kInvalidParameter;
		}

		std::vector<std::string> channels;
		if (acceptChannels && acceptChannelCount)
		{
			for (auto idx = 0; idx < acceptChannelCount; idx++)
			{
				if (!IS_STRING_PARAM_VALID(acceptChannels[idx]))
				{
					return SparkleError::kInvalidParameter;
				}
				channels.emplace_back(acceptChannels[idx]);
			}
		}

		if (gMgr.IsReady())
		{
			return SparkleError::kAlreadyInitialized;
		}

		gMgr.SetCallbacks(*callbacks);
		gMgr.SetAppCurrentVersion(appCurrentVer);
		gMgr.SetAppcastURL(appcastURL);
		
		if (IS_STRING_PARAM_VALID(pemPubKey))
		{
			gMgr.SetSignaturePEM(pemPubKey);
		}
		if (IS_STRING_PARAM_VALID(sslCA))
		{
			gMgr.SetHttpsCAPath(sslCA);
		}
		if (IS_STRING_PARAM_VALID(preferLang))
		{
			gMgr.SetAppLang(preferLang);
		}
		if (!channels.empty())
		{
			gMgr.SetAcceptChannels(channels);
		}

		return gMgr.IsReady() ? SparkleError::kNoError : SparkleError::kFail;
	}

	SPARKLE_API_DELC(void) sparkle_customize_http_header(const char* key, const char* value)
	{
		if (IS_STRING_PARAM_VALID(key) && IS_STRING_PARAM_VALID(value))
		{
			gMgr.SetHttpHeader(key, value);
		}
	}

	SPARKLE_API_DELC(void) sparkle_clean()
	{
		gMgr.Clean();
	}

	SPARKLE_API_DELC(SparkleError) sparkle_check_update()
	{
		if (!gMgr.IsReady())
		{
			return SparkleError::kNotReady;
		}
		return gMgr.CheckUpdate();
	}

	SPARKLE_API_DELC(SparkleError) sparkle_download_to_file(const char* destinationFile)
	{
		if (!IS_STRING_PARAM_VALID(destinationFile))
		{
			return SparkleError::kInvalidParameter;
		}
		if (!gMgr.IsReady())
		{
			return SparkleError::kNotReady;
		}
		return gMgr.Dowload(destinationFile);
	}

	SPARKLE_API_DELC(SparkleError) sparkle_download_to_buffer(void* buffer, size_t* bufferSize)
	{
		if (!buffer || !bufferSize || !(*bufferSize))
		{
			return SparkleError::kInvalidParameter;
		}
		if (!gMgr.IsReady())
		{
			return SparkleError::kNotReady;
		}
		return gMgr.Dowload(buffer, *bufferSize, bufferSize);
	}

	SPARKLE_API_DELC(SparkleError) sparkle_install(const char* overrideArgs)
	{
		if (!gMgr.IsReady())
		{
			return SparkleError::kNotReady;
		}
		return gMgr.Install(overrideArgs);
	}
};
