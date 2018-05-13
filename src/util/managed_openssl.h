#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <memory>

using BIGNUM_ptr = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
using EC_KEY_ptr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using EC_POINT_ptr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using ECDSA_SIG_ptr = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
