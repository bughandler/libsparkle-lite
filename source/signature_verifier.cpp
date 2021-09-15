/*
 *  This file is part of WinSparkle (https://winsparkle.org)
 *
 *  Copyright (C) 2017-2020 Ihor Dutchak
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 *
 */

#include <cassert>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include "signature_verifier.h"

#ifdef _MSC_VER
#pragma comment(lib, "crypt32.lib")
#endif

namespace SparkleLite
{

std::string sha1File(const std::string& fileName)
{
    if (!fileName.empty())
    {
        return {};
    }

    FILE* fd = nullptr;
    auto err = fopen_s(&fd, fileName.c_str(), "rb");
    if (err != 0)
    {
        return {};
    }
    assert(fd != nullptr);

	std::string result;
    do 
	{
		result.resize(SHA_DIGEST_LENGTH);
		if (result.empty())
		{
            break;
		}

		std::string cacheBuf;
		cacheBuf.resize(1 << 20); // 1MB
		if (cacheBuf.empty())
		{
            break;
		}

		SHA_CTX ctx = { 0 };
		SHA1_Init(&ctx);
		while (auto readBytes = fread(&cacheBuf[0], 1, cacheBuf.size(), fd))
		{
			SHA1_Update(&ctx, &cacheBuf[0], readBytes);
		}
        SHA1_Final((unsigned char*)&result[0], &ctx);

    } while (false);

    fclose(fd);
    return std::move(result);
}

std::string sha1MemBuffer(const void* p, size_t len)
{
    if (!p || !len)
    {
        return {};
    }

    std::string result;
    result.resize(SHA_DIGEST_LENGTH);
    SHA1((const unsigned char*)p, len, (unsigned char*)&result[0]);
    return std::move(result);
}

std::string base64Decode(const std::string& base64String)
{
	auto precalcedSize = (base64String.size() + 1) * 3 / 4;
    
    std::string result;
    result.resize(precalcedSize + 1);
    if (result.empty())
    {
        return {};
    }

	auto realSize = EVP_DecodeBlock((unsigned char*)&result, (const unsigned char*)&base64String[0], (int)base64String.size());
    result.resize(realSize);

	return std::move(result);
}


bool VerifySHA1(const std::string& sha1Data, SignatureType type, const std::string& signatureBase64, const std::string& pemPubKey)
{
    if (sha1Data.empty())
    {
        return false;
    }

	BIO* bio = BIO_new_mem_buf(pemPubKey.data(), (int)pemPubKey.size());
	if (!bio)
	{
		return false;
	}

	// resolve PEM PUBLIC KEY
	DSA* dsa = nullptr;
	if (!PEM_read_bio_DSA_PUBKEY(bio, &dsa, nullptr, nullptr))
	{
		BIO_free(bio);
		return false;
	}

	// decode the base64 encoded signature
	auto signature = base64Decode(signatureBase64);
	if (signature.empty())
	{
		BIO_free(bio);
		return false;
	}

	// verify data = sha1(sha1Data)
	auto verifyData = sha1MemBuffer(sha1Data.data(), sha1Data.size());
	if (verifyData.empty())
	{
		BIO_free(bio);
		DSA_free(dsa);
		return false;
	}

	// do the DSA verification
	auto ret = DSA_verify(0,
		(const unsigned char*)verifyData.data(), (int)verifyData.size(),
		(const unsigned char*)signature.c_str(), (int)signature.size(),
		dsa);

	// done
	BIO_free(bio);
	DSA_free(dsa);
	return ret == 1;
}

bool VerifyFile(const std::string& fileName, SignatureType type, const std::string& signatureBase64, const std::string& pemPubKey)
{
    assert(type != SignatureType::kNone);
    if (fileName.empty() || signatureBase64.empty() || pemPubKey.empty())
    {
        return false;
    }

    if (type != SignatureType::kDSA)
    {
        return false;
    }

	return VerifySHA1(sha1File(fileName), type, signatureBase64, pemPubKey);
}


bool VerifyDataBuffer(const void* dataBuffer, size_t dataSize, SignatureType type, const std::string& signatureBase64, const std::string& pemPubKey)
{
	assert(type != SignatureType::kNone);
	if (!dataBuffer || !dataSize || signatureBase64.empty() || pemPubKey.empty())
	{
		return false;
	}

	if (type != SignatureType::kDSA)
	{
		return false;
	}

	return VerifySHA1(sha1MemBuffer(dataBuffer, dataSize), type, signatureBase64, pemPubKey);
}

} // namespace sparkle_lite
