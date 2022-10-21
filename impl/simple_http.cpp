#include "simple_http.h"
#include "sparkle_internal.h"
#include <curl/curl.h>
#include <mutex>
#include <vector>

namespace SparkleLite {

static std::once_flag curlInitFlag;
static std::string curlProxyInfo;
static std::mutex curlProxyLock;

enum class HttpMethod {
	kGET,
	kPOST,
	kPUT,
	kHEAD,
	kDELETE
};

template <typename T>
std::vector<T> split_string(const T &str, const T &delim) {
	if (str.empty()) {
		return {};
	}
	std::vector<T> result;
	size_t last = 0;
	size_t index = str.find_first_of(delim, last);
	while (index != T::npos) {
		T tt = str.substr(last, index - last);
		result.push_back(tt);
		last = index + delim.size();
		index = str.find_first_of(delim, last);
	}
	if (index - last > 0) {
		result.push_back(str.substr(last, index - last));
	}
	return result;
}

struct HttpResponseContext {
	HttpHeaders respHeaders;
	HttpContentHandler handler;
	size_t contentLength = 0;
};

static size_t header_callback(
		char *buffer,
		size_t size,
		size_t nitems,
		void *userdata) {
	auto ctx = (HttpResponseContext *)userdata;
	std::string_view text(buffer, nitems * size);
	auto lines = split_string<std::string_view>(text, "\r\n");
	for (const auto &line : lines) {
		if (line.empty()) {
			continue;
		}
		auto pos = line.find_first_of(L':');
		if (pos > 0 && pos < line.size() - 2) {
			auto key = line.substr(0, pos);
			auto value = line.substr(pos + 2);
			if (!key.empty() && !value.empty()) {
				ctx->respHeaders.emplace(std::make_pair(key, value));
				if (!ctx->contentLength) {
					auto it = ctx->respHeaders.find("Content-Length");
					if (it != ctx->respHeaders.end()) {
						ctx->contentLength = std::strtoul(it->second.c_str(), nullptr, 10);
					}
				}
			}
		}
	}
	return nitems * size;
}

static size_t body_callback(void *data, size_t size, size_t nmemb, void *userp) {
	size_t realsize = size * nmemb;
	auto ctx = (HttpResponseContext *)userp;
	if (!ctx->handler(ctx->contentLength, data, realsize)) {
		// error occurred
		return 0;
	}
	return realsize;
}

std::string get_proxy_info() {
	std::unique_lock<std::mutex> lck(curlProxyLock);
	return curlProxyInfo;
}

int simple_http_perform(
		HttpMethod method,
		const std::string &url,
		const HttpHeaders &requestHeaders,
		const std::string &requestBody,
		HttpHeaders &responseHeaders,
		HttpContentHandler &&handler) {
	if (url.empty()) {
		return -1;
	}

	std::call_once(curlInitFlag, []() {
		curl_global_init(CURL_GLOBAL_ALL);
	});

	CURL *inst = curl_easy_init();
	if (!inst) {
		return -1;
	}

	int statusCode = -1;
	struct curl_slist *list = nullptr;
	do {
		bool err = false;

		// configure HTTP method
		switch (method) {
			case HttpMethod::kGET:
				break;
			case HttpMethod::kPOST:
				curl_easy_setopt(inst, CURLOPT_POST, 1);
				break;
			case HttpMethod::kPUT:
				curl_easy_setopt(inst, CURLOPT_PUT, 1);
				break;
			case HttpMethod::kHEAD:
				curl_easy_setopt(inst, CURLOPT_NOBODY, 1);
				break;
			case HttpMethod::kDELETE:
				curl_easy_setopt(inst, CURLOPT_CUSTOMREQUEST, "DELETE");
				break;
			default:
				err = true;
				break;
		}
		if (err)
			break;

		// add headers
		std::vector<std::string> fields;
		for (const auto &row : requestHeaders) {
			if (row.first.empty() || row.second.empty()) {
				err = true;
				break;
			}

			fields.emplace_back(row.first + ": " + row.second);
		}

		for (const auto &field : fields) {
			list = curl_slist_append(list, field.c_str());
			if (!list) {
				err = true;
				break;
			}
		}

		if (list) {
			curl_easy_setopt(inst, CURLOPT_HTTPHEADER, list);
		}

		// add User-Agent
		if (requestHeaders.find("User-Agent") == requestHeaders.end()) {
			curl_easy_setopt(inst, CURLOPT_USERAGENT, DEFAULT_SPARKLE_UA);
		}

		// set Accept-Encoding (all builtin encoding algorithms)
		curl_easy_setopt(inst, CURLOPT_ACCEPT_ENCODING, "");

		// add body
		if (!requestBody.empty()) {
			curl_easy_setopt(inst, CURLOPT_POSTFIELDS, requestBody.data());
			curl_easy_setopt(inst, CURLOPT_POSTFIELDSIZE, requestBody.size());
		}

		// set proxy
		auto proxyInfo = get_proxy_info();
		if (!proxyInfo.empty()) {
			curl_easy_setopt(inst, CURLOPT_PROXY, curlProxyInfo.c_str());
		}

		// set URL
		curl_easy_setopt(inst, CURLOPT_URL, url.c_str());

		if (strncasecmp(url.c_str(), "https://", 8) == 0) {
#ifdef _WIN32
			curl_easy_setopt(inst, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
#else
			// #TODO
			// Handle *unix system SSL properly
#endif
		}

		// prepare context
		HttpResponseContext ctx;
		ctx.handler = handler;

		// set response header reader
		curl_easy_setopt(inst, CURLOPT_HEADERFUNCTION, header_callback);
		curl_easy_setopt(inst, CURLOPT_HEADERDATA, (void *)&ctx);

		// set response body reader
		curl_easy_setopt(inst, CURLOPT_WRITEFUNCTION, body_callback);
		curl_easy_setopt(inst, CURLOPT_WRITEDATA, (void *)&ctx);

		// perform
		auto errCode = curl_easy_perform(inst);
		if (errCode != CURLE_OK) {
			err = true;
			break;
		}

		// get status code
		curl_easy_getinfo(inst, CURLINFO_RESPONSE_CODE, &statusCode);

		// save headers
		responseHeaders = std::move(ctx.respHeaders);

	} while (false);

	if (list) {
		curl_slist_free_all(list);
	}
	curl_easy_cleanup(inst);

	// done
	return statusCode;
}

int simple_http_get(
		const std::string &url,
		const HttpHeaders &requestHeaders,
		HttpHeaders &responseHeaders,
		std::string &responseBody) {
	return simple_http_perform(
			HttpMethod::kGET,
			url,
			requestHeaders,
			{},
			responseHeaders,
			[&](size_t, const void *data, size_t size) -> bool {
				responseBody.resize(responseBody.size() + size);
				if (responseBody.empty()) {
					// out of memory
					return false;
				}
				memcpy(&responseBody[0] + responseBody.size() - size, data, size);
				return true;
			});
}

int simple_http_get(
		const std::string &url,
		const HttpHeaders &requestHeaders,
		HttpHeaders &responseHeaders,
		HttpContentHandler &&cb) {
	return simple_http_perform(
			HttpMethod::kGET,
			url,
			requestHeaders,
			{},
			responseHeaders,
			std::forward<HttpContentHandler>(cb));
}

int simple_http_proxy_config(const std::string &cfg) {
	if (strncasecmp(cfg.c_str(), "http://", 7) == 0 ||
			strncasecmp(cfg.c_str(), "https://", 8) == 0 ||
			strncasecmp(cfg.c_str(), "socks4://", 9) == 0 ||
			strncasecmp(cfg.c_str(), "socks5://", 9) == 0 ||
			strncasecmp(cfg.c_str(), "socks4a://", 10) == 0 ||
			strncasecmp(cfg.c_str(), "socks5h://", 10) == 0) {
		std::unique_lock<std::mutex> lck(curlProxyLock);
		curlProxyInfo = cfg;
	}
	return -1;
}

} //namespace SparkleLite