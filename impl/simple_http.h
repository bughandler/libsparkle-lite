#ifndef _SIMPLE_HTTP_H_
#define _SIMPLE_HTTP_H_

#include <functional>
#include <map>
#include <string>

namespace SparkleLite {

using HttpContentHandler = std::function<bool(size_t, const void *, size_t)>;
using HttpHeaders = std::map<std::string, std::string>;

int simple_http_get(
		const std::string &url,
		const HttpHeaders &requestHeaders,
		HttpHeaders &responseHeaders,
		std::string &responseBody);

int simple_http_get(
		const std::string &url,
		const HttpHeaders &requestHeaders,
		HttpHeaders &responseHeaders,
		HttpContentHandler &&cb);

int simple_http_proxy_config(const std::string &cfg);

} //namespace SparkleLite

#endif //_SIMPLE_HTTP_H_
