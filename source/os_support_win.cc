
#include "os_support.h"
#if defined(_WIN32)
#include <cassert>
#include <functional>
#include <memory>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "WinHttp.lib")

std::wstring a2u(const std::string& s)
{
	if (s.empty())
	{
		return {};
	}
	int len = MultiByteToWideChar(CP_ACP, 0, s.data(), s.size(), nullptr, 0);
	if (!len)
	{
		return {};
	}
	std::wstring r;
	r.resize(len);
	MultiByteToWideChar(CP_ACP, 0, s.data(), s.size(), (LPWSTR)r.data(), r.size());
	return std::move(r);
}

std::string u2a(const std::wstring& s)
{
	if (s.empty())
	{
		return {};
	}
	int len = WideCharToMultiByte(CP_ACP, 0, s.data(), s.size(), nullptr, 0, nullptr, nullptr);
	if (len)
	{
		std::string r;
		r.resize(len);
		if (WideCharToMultiByte(CP_ACP, 0, s.data(), s.size(), (char*)r.data(), r.size(), nullptr, nullptr))
		{
			return std::move(r);
		}
	}
	return std::string();
}

template<typename T>
std::vector<T> splitString(const T& str, const T& delim)
{
	if (str.empty())
	{
		return {};
	}
	std::vector<T> result;
	size_t last = 0;
	size_t index = str.find_first_of(delim, last);
	while (index != T::npos)
	{
		T tt = str.substr(last, index - last);
		result.push_back(tt);
		last = index + delim.size();
		index = str.find_first_of(delim, last);
	}
	if (index - last > 0)
	{
		result.push_back(str.substr(last, index - last));
	}
	return std::move(result);
}

struct UrlComponents
{
	uint16_t port;
	std::wstring scheme, host, user, pwd, path, extra;
};

bool ParseUrl(const std::wstring& url, UrlComponents& components, bool escape)
{
	wchar_t scheme[16] = { 0 };
	wchar_t host[256] = { 0 };
	wchar_t path[256] = { 0 };
	wchar_t user[64] = { 0 };
	wchar_t pwd[64] = { 0 };
	wchar_t extra[512] = { 0 };
	URL_COMPONENTSW comps = { 0 };
	comps.dwStructSize = sizeof(comps);
	comps.dwExtraInfoLength = sizeof(extra) / sizeof(wchar_t);
	comps.lpszExtraInfo = extra;
	comps.dwHostNameLength = sizeof(host) / sizeof(wchar_t);
	comps.lpszHostName = host;
	comps.dwUrlPathLength = sizeof(path) / sizeof(wchar_t);
	comps.lpszUrlPath = path;
	comps.dwSchemeLength = sizeof(scheme) / sizeof(wchar_t);
	comps.lpszScheme = scheme;
	comps.dwUserNameLength = sizeof(user) / sizeof(wchar_t);
	comps.lpszUserName = user;
	comps.dwPasswordLength = sizeof(pwd) / sizeof(wchar_t);
	comps.lpszPassword = pwd;
	if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), escape ? ICU_ESCAPE : 0, &comps))
	{
		return false;
	}
	components.port = comps.nPort;
	components.scheme = std::wstring(scheme, comps.dwSchemeLength);
	components.host = std::wstring(host, comps.dwHostNameLength);
	components.path = std::wstring(path, comps.dwUrlPathLength);
	components.user = std::wstring(user, comps.dwUserNameLength);
	components.pwd = std::wstring(pwd, comps.dwPasswordLength);
	components.extra = std::wstring(extra, comps.dwExtraInfoLength);
	return true;
}

int PerformHttp(const std::string& method, 
	const std::string& url,
	bool autoProxy,
	const HttpHeaders& headers, 
	const std::string& body,
	HttpHeaders& responseHeaders, 
	HttpContentHandler&& contentHandler)
{
	auto unicodeUrl = a2u(url);
	if (unicodeUrl.empty())
	{
		return -1;
	}

	UrlComponents comps;
	if (!ParseUrl(unicodeUrl, comps, true))
	{
		return -1;
	}
	auto secure = _wcsicmp(comps.scheme.c_str(), L"https") == 0;

	// Use WinHttpOpen to obtain a session handle.
	auto uaIt = headers.find("User-Agent");
	auto hSession = WinHttpOpen(
		(uaIt == headers.end()? L"WinHttp" : a2u(uaIt->second).c_str()),
		WINHTTP_ACCESS_TYPE_NO_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 
		0);
	if (!hSession)
	{
		return -1;
	}

	// Prepare proxy
	if (autoProxy)
	{
		WINHTTP_CURRENT_USER_IE_PROXY_CONFIG IEProxyConfig = { 0 };
		if (WinHttpGetIEProxyConfigForCurrentUser(&IEProxyConfig))
		{
			DWORD						dwProxyAuthScheme = 0;
			WINHTTP_AUTOPROXY_OPTIONS	AutoProxyOptions = { 0 };
			WINHTTP_PROXY_INFO			ProxyInfo = { 0 };
			DWORD						cbProxyInfoSize = sizeof(ProxyInfo);

			if (IEProxyConfig.fAutoDetect)
			{
				AutoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;

				//
				// Use both DHCP and DNS-based auto detection
				//
				AutoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP |
					WINHTTP_AUTO_DETECT_TYPE_DNS_A;
			}

			//
			// If there's an auto config URL stored in the IE proxy settings, save it
			//
			if (IEProxyConfig.lpszAutoConfigUrl)
			{
				AutoProxyOptions.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
				AutoProxyOptions.lpszAutoConfigUrl = IEProxyConfig.lpszAutoConfigUrl;
			}

			//
			// If there's a static proxy
			//
			if (IEProxyConfig.lpszProxy)
			{
				AutoProxyOptions.dwFlags |= WINHTTP_AUTOPROXY_ALLOW_STATIC;
			}

			// If obtaining the PAC script requires NTLM/Negotiate
			// authentication, then automatically supply the client
			// domain credentials.
			AutoProxyOptions.fAutoLogonIfChallenged = TRUE;

			//
			// Call WinHttpGetProxyForUrl with our target URL. If 
			// auto-proxy succeeds, then set the proxy info on the 
			// request handle. If auto-proxy fails, ignore the error 
			// and attempt to send the HTTP request directly to the 
			// target server (using the default WINHTTP_ACCESS_TYPE_NO_PROXY 
			// configuration, which the request handle will inherit 
			// from the session).
			//
			if (WinHttpGetProxyForUrl(hSession,
				unicodeUrl.c_str(),
				&AutoProxyOptions,
				&ProxyInfo))
			{
				// A proxy configuration was found, set it on the
				// request handle.
				if (!WinHttpSetOption(hSession,
					WINHTTP_OPTION_PROXY,
					&ProxyInfo,
					cbProxyInfoSize))
				{
					// Exit if setting the proxy info failed.
					WinHttpCloseHandle(hSession);
					return -1;
				}
			}
		}
	}

	// Connect
	auto hConnect = WinHttpConnect(hSession, comps.host.c_str(), comps.port, 0);
	if (!hConnect)
	{
		WinHttpCloseHandle(hSession);
		return -1;
	}

	// Prepare request
	DWORD flag = secure ? WINHTTP_FLAG_SECURE : 0;
	auto hRequest = WinHttpOpenRequest(
		hConnect, 
		a2u(method).c_str(), 
		(comps.path + comps.extra).c_str(),
		nullptr, 
		WINHTTP_NO_REFERER,
		WINHTTP_DEFAULT_ACCEPT_TYPES,
		WINHTTP_FLAG_REFRESH | flag);
	if (!hRequest)
	{
		WinHttpCloseHandle(hConnect);
		WinHttpCloseHandle(hSession);
		return -1;
	}

	// Concatenate headers
	std::wstring plainRequestHeaders;
	if (!headers.empty())
	{
		for (auto [k, v] : headers)
		{
			if (_stricmp(k.c_str(), "User-Agent") == 0)
			{
				continue;
			}
			plainRequestHeaders += a2u(k);
			plainRequestHeaders += L": ";
			plainRequestHeaders += a2u(v);
			plainRequestHeaders += L"\r\n";
		}
	}

#define FULL_CLOSE()	WinHttpCloseHandle(hRequest); \
						WinHttpCloseHandle(hConnect); \
						WinHttpCloseHandle(hSession)

	// Send requests
	bool done = false;
	do 
	{
		if (plainRequestHeaders.empty())
		{
			done = !!WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				(LPVOID)body.data(), body.size(),
				body.size(), 0);
		}
		else
		{
			done = WinHttpSendRequest(hRequest,
				plainRequestHeaders.c_str(), plainRequestHeaders.size(),
				(LPVOID)body.data(), body.size(),
				body.size(), 0);
		}
	} while (!done && GetLastError() == ERROR_WINHTTP_RESEND_REQUEST);
	if (!done)
	{
		FULL_CLOSE();
		return -1;
	}

	// Receive response
	if (!WinHttpReceiveResponse(hRequest, nullptr))
	{
		FULL_CLOSE();
		return -1;
	}

	// Context
	int statusCode = 0;
	size_t contentLength = 0;
	HttpHeaders localRespHeaders;

	// Read status code
	auto dwSize = (DWORD)sizeof(statusCode);
	done = WinHttpQueryHeaders(
		hRequest,
		WINHTTP_QUERY_STATUS_CODE |
		WINHTTP_QUERY_FLAG_NUMBER,
		WINHTTP_HEADER_NAME_BY_INDEX,
		&statusCode,
		&dwSize,
		WINHTTP_NO_HEADER_INDEX);
	if (!done)
	{
		FULL_CLOSE();
		return -1;
	}

	// Read & parse headers
	dwSize = 0;
	WinHttpQueryHeaders(
		hRequest,
		WINHTTP_QUERY_RAW_HEADERS_CRLF,
		WINHTTP_HEADER_NAME_BY_INDEX,
		nullptr,
		&dwSize,
		WINHTTP_NO_HEADER_INDEX);
	if (!dwSize || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		FULL_CLOSE();
		return -1;
	}

	std::wstring plainRespHeaders;
	plainRespHeaders.resize(dwSize / sizeof(wchar_t));
	if (plainRespHeaders.empty())
	{
		FULL_CLOSE();
		return -1;
	}

	done = WinHttpQueryHeaders(
		hRequest,
		WINHTTP_QUERY_RAW_HEADERS_CRLF,
		WINHTTP_HEADER_NAME_BY_INDEX,
		(LPVOID)&plainRespHeaders[0], &dwSize,
		WINHTTP_NO_HEADER_INDEX);
	if (!done)
	{
		FULL_CLOSE();
		return -1;
	}

	auto lines = splitString<std::wstring>(plainRespHeaders, L"\r\n");
	for (const auto& line : lines)
	{
		if (line.empty())
		{
			continue;
		}
		auto pos = line.find_first_of(L':');
		if (pos > 0 && pos < line.size() - 1)
		{
			auto key = u2a(line.substr(0, pos));
			auto value = u2a(line.substr(pos + 1));
			if (!key.empty() && !value.empty())
			{
				localRespHeaders[key] = value;
			}
		}
	}

	// Check body length
	auto contentLenIt = localRespHeaders.find("Content-Length");
	if (contentLenIt != localRespHeaders.end())
	{
		contentLength = std::stol(contentLenIt->second);
	}
	if (!contentLength)
	{
		// no content
		responseHeaders = std::move(responseHeaders);
		return statusCode;
	}

	// Read in loop
	std::string buf;
	buf.resize(2 * 1024);
	if (buf.empty())
	{
		FULL_CLOSE();
		return -1;
	}

	size_t read = 0;
	while (read < contentLength)
	{
		DWORD avail = 0;
		if (!WinHttpQueryDataAvailable(hRequest, &avail))
		{
			FULL_CLOSE();
			return -1;
		}

		DWORD out = 0;
		if (!WinHttpReadData(hRequest, (void*)&buf[0], min(avail, buf.size()), &out))
		{
			FULL_CLOSE();
			return -1;
		}

		if (!contentHandler(contentLength, (void*)&buf[0], out))
		{
			// user cancel
			FULL_CLOSE();
			return -1;
		}
		read += out;
	}
	
	// done
	responseHeaders = std::move(localRespHeaders);
	return statusCode;
}

int http_get(const std::string& url, const HttpHeaders& requestHeaders, HttpContentHandler&& handler)
{
	HttpHeaders respHeaders;
	return PerformHttp("GET", url, true, requestHeaders, "", respHeaders, std::forward<HttpContentHandler>(handler));
}

bool is_acceptable_os_version(const std::string& osMinRequiredVersion)
{
	if (osMinRequiredVersion.empty())
	{
		return true;
	}

	OSVERSIONINFOEXW osvi = { sizeof(osvi), 0, 0, 0, 0, { 0 }, 0, 0 };
	DWORDLONG const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(
			VerSetConditionMask(
				0, VER_MAJORVERSION, VER_GREATER_EQUAL),
			VER_MINORVERSION, VER_GREATER_EQUAL),
		VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	sscanf_s(osMinRequiredVersion.c_str(), "%lu.%lu.%hu", &osvi.dwMajorVersion, &osvi.dwMinorVersion, &osvi.wServicePackMajor);
	return !VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask);
}

bool is_matched_os_name(const std::string& osName)
{
	if (_stricmp(osName.c_str(), "windows") == 0) return true;
#ifdef _WIN64
	if (_stricmp(osName.c_str(), "windows-x64") != 0) return true;
#else
	if (_stricmp(osName.c_str(), "windows-x86") != 0) return true;
#endif
	return false;
}

bool execute(const std::string& package, const std::string& args)
{
	SHELLEXECUTEINFOA sei = { 0 };
	sei.cbSize = sizeof(sei);
	sei.lpFile = package.c_str();
	sei.nShow = SW_SHOWDEFAULT;
	sei.fMask = SEE_MASK_FLAG_NO_UI;	// We display our own dialog box on error

	if (!args.empty())
	{
		sei.lpParameters = args.c_str();
	}

	return !!ShellExecuteExA(&sei);
}

std::string get_iso639_user_lang()
{
	std::string lang;
	lang.resize(2);
	auto langid = GetUserDefaultLangID();
	GetLocaleInfoA(langid, LOCALE_SISO639LANGNAME, &lang[0], lang.size());
	return std::move(lang);
}

#ifdef _USRDLL
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // handle to DLL module
	DWORD fdwReason,     // reason for calling function
	LPVOID lpReserved)  // reserved
{
	// Perform actions based on the reason for calling.
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		// Initialize once for each new process.
		// Return FALSE to fail DLL load.
		break;

	case DLL_THREAD_ATTACH:
		// Do thread-specific initialization.
		break;

	case DLL_THREAD_DETACH:
		// Do thread-specific cleanup.
		break;

	case DLL_PROCESS_DETACH:
		// Perform any necessary cleanup.
		break;
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
#endif //_USRDLL

#endif
