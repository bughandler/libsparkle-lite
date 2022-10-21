#ifndef _signatureverifier_h_
#define _signatureverifier_h_

#include "sparkle_internal.h"
#include <cstdint>
#include <string>

namespace SparkleLite {
bool IsValidDSAPubKey(const std::string &pem);

bool IsValidEd25519Key(const std::string &key);

bool VerifyFile(const std::string &fileName, SignatureAlgo type, const std::string &signatureBase64, const std::string &pemPubKey);

bool VerifyDataBuffer(const void *dataBuffer, size_t dataSize, SignatureAlgo type, const std::string &signatureBase64, const std::string &pemPubKey);

} //namespace SparkleLite

#endif // _signatureverifier_h_
