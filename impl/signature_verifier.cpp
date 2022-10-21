#include "signature_verifier.h"
#include "third_party/mio.hpp"
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <cassert>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "crypt32.lib")
#endif

namespace SparkleLite {

enum class PType {
	kFileName,
	kDataBuffer
};

std::string sha1File(const std::string &fileName) {
	if (fileName.empty()) {
		return {};
	}

	FILE *fd = nullptr;
	auto err = fopen_s(&fd, fileName.c_str(), "rb");
	if (err != 0) {
		return {};
	}
	assert(fd != nullptr);

	std::string result;
	do {
		result.resize(SHA_DIGEST_LENGTH);
		if (result.empty()) {
			break;
		}

		std::string cacheBuf;
		cacheBuf.resize(1 << 20); // 1MB
		if (cacheBuf.empty()) {
			break;
		}

		SHA_CTX ctx = { 0 };
		SHA1_Init(&ctx);
		while (auto readBytes = fread(&cacheBuf[0], 1, cacheBuf.size(), fd)) {
			SHA1_Update(&ctx, &cacheBuf[0], readBytes);
		}
		SHA1_Final((unsigned char *)&result[0], &ctx);

	} while (false);

	fclose(fd);
	return std::move(result);
}

std::string sha1MemBuffer(const void *p, size_t len) {
	if (!p || !len) {
		return {};
	}

	std::string result;
	result.resize(SHA_DIGEST_LENGTH);
	SHA1((const unsigned char *)p, len, (unsigned char *)&result[0]);
	return std::move(result);
}

std::string base64Decode(const std::string &base64String) {
	if (base64String.empty()) {
		return {};
	}

	auto padCount = 0;
	if (base64String.back() == '=') {
		++padCount;
	}
	if (base64String.size() > 1 && base64String[base64String.size() - 2] == '=') {
		++padCount;
	}

	auto precalcedSize = (base64String.size() + 1) * 3 / 4;
	std::string result;
	result.resize(precalcedSize + 1);
	if (result.empty()) {
		return {};
	}

	auto realSize = EVP_DecodeBlock((unsigned char *)&result[0], (const unsigned char *)&base64String[0], (int)base64String.size());
	if (realSize <= padCount) {
		return {};
	}
	result.resize(realSize - padCount);

	return std::move(result);
}

bool DSAVerifySHA1(const std::string &sha1Data, SignatureAlgo type, const std::string &signatureBase64, const std::string &pemPubKey) {
	if (sha1Data.empty()) {
		return false;
	}

	BIO *bio = BIO_new_mem_buf(pemPubKey.data(), (int)pemPubKey.size());
	if (!bio) {
		return false;
	}

	// resolve PEM PUBLIC KEY
	DSA *dsa = nullptr;
	if (!PEM_read_bio_DSA_PUBKEY(bio, &dsa, nullptr, nullptr)) {
		BIO_free(bio);
		return false;
	}

	// decode the base64 encoded signature
	auto signature = base64Decode(signatureBase64);
	if (signature.empty()) {
		BIO_free(bio);
		return false;
	}

	// verify data = sha1(sha1Data)
	auto verifyData = sha1MemBuffer(sha1Data.data(), sha1Data.size());
	if (verifyData.empty()) {
		BIO_free(bio);
		DSA_free(dsa);
		return false;
	}

	// do the DSA verification
	auto ret = DSA_verify(0,
			(const unsigned char *)verifyData.data(), (int)verifyData.size(),
			(const unsigned char *)signature.c_str(), (int)signature.size(),
			dsa);

	// done
	BIO_free(bio);
	DSA_free(dsa);
	return ret == 1;
}

template <PType pt>
bool Ed25519Verify(const std::string_view p, SignatureAlgo type, const std::string &signatureBase64, const std::string &base64RawPubKey) {
	// decode the base64 encoded signature
	auto signature = base64Decode(signatureBase64);
	if (signature.empty()) {
		return false;
	}

	// decode the base64 encoded ed25519 public key
	auto rawPubKey = base64Decode(base64RawPubKey);
	if (rawPubKey.empty()) {
		return false;
	}

	// resolve the public key
	auto pubKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, (const unsigned char *)rawPubKey.data(), rawPubKey.size());
	if (!pubKey) {
		return false;
	}

	int ret = -1;
	EVP_MD_CTX *md_ctx = nullptr;
	FILE *fd = nullptr;
	do {
		md_ctx = EVP_MD_CTX_new();
		if (!md_ctx) {
			break;
		}

		if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pubKey) != 1) {
			break;
		}

		if constexpr (pt == PType::kDataBuffer) {
			ret = EVP_DigestVerify(md_ctx, (const unsigned char *)signature.data(), signature.size(), (const unsigned char *)p.data(), p.size());
		} else if constexpr (pt == PType::kFileName) {
			std::error_code error;
			mio::mmap_source mmap = mio::make_mmap_source(std::string(p), error);
			if (error) {
				break;
			}
			ret = EVP_DigestVerify(md_ctx, (const unsigned char *)signature.data(), signature.size(), (const unsigned char *)mmap.data(), mmap.size());
		} else {
			static_assert(false);
		}

		if (ret == -1) {
			auto x = ERR_error_string(ERR_get_error(), nullptr);
			printf(x);
		}

	} while (false);

	if (md_ctx) {
		EVP_MD_CTX_free(md_ctx);
	}
	if (fd) {
		fclose(fd);
	}
	EVP_PKEY_free(pubKey);
	return ret == 1;
}

bool VerifyFile(const std::string &fileName, SignatureAlgo type, const std::string &signatureBase64, const std::string &pemPubKey) {
	assert(type != SignatureAlgo::kNone);
	if (fileName.empty() || signatureBase64.empty() || pemPubKey.empty()) {
		return false;
	}

	switch (type) {
		case SignatureAlgo::kDSA:
			return DSAVerifySHA1(sha1File(fileName), type, signatureBase64, pemPubKey);
		case SignatureAlgo::kEd25519:
			return Ed25519Verify<PType::kFileName>(fileName, type, signatureBase64, pemPubKey);
		default:
			return false;
	}
}

bool VerifyDataBuffer(const void *dataBuffer, size_t dataSize, SignatureAlgo type, const std::string &signatureBase64, const std::string &pemPubKey) {
	assert(type != SignatureAlgo::kNone);
	if (!dataBuffer || !dataSize || signatureBase64.empty() || pemPubKey.empty()) {
		return false;
	}

	switch (type) {
		case SignatureAlgo::kDSA:
			return DSAVerifySHA1(sha1MemBuffer(dataBuffer, dataSize), type, signatureBase64, pemPubKey);
		case SignatureAlgo::kEd25519:
			return Ed25519Verify<PType::kDataBuffer>(std::string_view((const char *)dataBuffer, dataSize), type, signatureBase64, pemPubKey);
		default:
			return false;
	}
}

bool IsValidDSAPubKey(const std::string &pem) {
	if (pem.empty()) {
		return false;
	}

	BIO *bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
	if (!bio) {
		return false;
	}

	// resolve PEM PUBLIC KEY
	DSA *dsa = nullptr;
	if (!PEM_read_bio_DSA_PUBKEY(bio, &dsa, nullptr, nullptr)) {
		BIO_free(bio);
		return false;
	}

	DSA_free(dsa);
	BIO_free(bio);
	return true;
}

bool IsValidEd25519Key(const std::string &key) {
	if (key.empty()) {
		return false;
	}

	// decode the base64 encoded ed25519 public key
	auto rawPubKey = base64Decode(key);
	if (rawPubKey.empty()) {
		return false;
	}

	// resolve the public key
	auto pubKey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, (const unsigned char *)rawPubKey.data(), rawPubKey.size());
	if (!pubKey) {
		return false;
	}
	EVP_PKEY_free(pubKey);
	return true;
}

} //namespace SparkleLite
