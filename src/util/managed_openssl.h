#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <memory>

/** deleter functor for OpenSSL specific types */
struct openssl_deleter
{
 void operator()(BIGNUM* p) const { if(p) BN_clear_free(p); }
 void operator()(BN_CTX* p) const { if(p) BN_CTX_free(p); }
 void operator()(EC_KEY* p) const { if(p) EC_KEY_free(p); }
 void operator()(EC_POINT* p) const { if(p) EC_POINT_free(p); }
 void operator()(ECDSA_SIG* p) const { if(p) ECDSA_SIG_free(p); }
 void operator()(EVP_CIPHER_CTX* p) const { if(p) EVP_CIPHER_CTX_free(p); }
};

/** std::unique_ptr type aliases for OpenSSL specific types */
using BIGNUM_ptr = std::unique_ptr<BIGNUM, openssl_deleter>;
using BN_CTX_ptr = std::unique_ptr<BN_CTX, openssl_deleter>;
using EC_KEY_ptr = std::unique_ptr<EC_KEY, openssl_deleter>;
using EC_POINT_ptr = std::unique_ptr<EC_POINT, openssl_deleter>;
using ECDSA_SIG_ptr = std::unique_ptr<ECDSA_SIG, openssl_deleter>;
using EVP_CIPHER_CTX_ptr = std::unique_ptr<EVP_CIPHER_CTX, openssl_deleter>;
