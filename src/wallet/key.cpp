/*******************************************************************************************

            Hash(BEGIN(Satoshi[2010]), END(Sunny[2012])) == Videlicet[2014] ++

[Learn and Create] Viz. http://www.opensource.org/licenses/mit-license.php

*******************************************************************************************/

#include <map>

#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include "key.h"
#include "../util/util.h"

namespace Wallet
{

    // Generate a private key from just the secret parameter
    int EC_KEY_regenerate_key(EC_KEY_ptr& eckey, const BIGNUM_ptr& priv_key)
    {
        if ((nullptr == eckey) || (nullptr == priv_key))
            return 0;

        const EC_GROUP *group = EC_KEY_get0_group(eckey.get());

        EC_POINT_ptr pub_key(EC_POINT_new(group));
        if (nullptr == pub_key)
            return 0;
        
        BN_CTX_ptr ctx(BN_CTX_new());
        if (nullptr == ctx)
            return 0;

        if (!EC_POINT_mul(group, pub_key.get(), priv_key.get(), nullptr, nullptr, ctx.get()))
            return 0;

        EC_KEY_set_private_key(eckey.get(), priv_key.get());
        EC_KEY_set_public_key(eckey.get(), pub_key.get());

        return 1;
    }

    // Perform ECDSA key recovery (see SEC1 4.1.6) for curves over (mod p)-fields
    // recid selects which key is recovered
    // if check is nonzero, additional checks are performed
    int ECDSA_SIG_recover_key_GFp(EC_KEY_ptr& eckey, const ECDSA_SIG_ptr& ecsig, const unsigned char *msg, int msglen, int recid, int check)
    {
        if (!eckey) return 0;

        int ret = 0;

        BIGNUM *x = NULL;
        BIGNUM *e = NULL;
        BIGNUM *order = NULL;
        BIGNUM *sor = NULL;
        BIGNUM *eor = NULL;
        BIGNUM *field = NULL;
        BIGNUM *rr = NULL;
        BIGNUM *zero = NULL;
        int n = 0;
        int i = recid / 2;

        const BIGNUM* sig_r = nullptr;
        const BIGNUM* sig_s = nullptr;;
        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
            ECDSA_SIG_get0(ecsig.get(), &sig_r, &sig_s);
        #else
            sig_r = ecsig->r;
            sig_s = ecsig->s;
        #endif

        const EC_GROUP *group = EC_KEY_get0_group(eckey.get());
        BN_CTX_ptr ctx(BN_CTX_new());
        if (nullptr == ctx) { ret = -1; goto err; }
        BN_CTX_start(ctx.get());
        order = BN_CTX_get(ctx.get());
        if (!EC_GROUP_get_order(group, order, ctx.get())) { ret = -2; goto err; }
        x = BN_CTX_get(ctx.get());
        if (!BN_copy(x, order)) { ret=-1; goto err; }
        if (!BN_mul_word(x, i)) { ret=-1; goto err; }
        if (!BN_add(x, x, sig_r)) { ret=-1; goto err; }
        field = BN_CTX_get(ctx.get());
        if (!EC_GROUP_get_curve_GFp(group, field, NULL, NULL, ctx.get())) { ret=-2; goto err; }
        if (BN_cmp(x, field) >= 0) { ret=0; goto err; }
        EC_POINT_ptr R(EC_POINT_new(group));
        if (nullptr == R) { ret = -2; goto err; }
        if (!EC_POINT_set_compressed_coordinates_GFp(group, R.get(), x, recid % 2, ctx.get())) { ret=0; goto err; }
        if (check)
        {
            EC_POINT_ptr O(EC_POINT_new(group));
            if (nullptr == O) { ret = -2; goto err; }
            if (!EC_POINT_mul(group, O.get(), NULL, R.get(), order, ctx.get())) { ret=-2; goto err; }
            if (!EC_POINT_is_at_infinity(group, O.get())) { ret = 0; goto err; }
        }
        EC_POINT_ptr Q(EC_POINT_new(group));
        if (nullptr == Q) { ret = -2; goto err; }
        n = EC_GROUP_get_degree(group);
        e = BN_CTX_get(ctx.get());
        if (!BN_bin2bn(msg, msglen, e)) { ret=-1; goto err; }
        if (8*msglen > n) BN_rshift(e, e, 8-(n & 7));
        zero = BN_CTX_get(ctx.get());
        if (!BN_zero(zero)) { ret=-1; goto err; }
        if (!BN_mod_sub(e, zero, e, order, ctx.get())) { ret=-1; goto err; }
        rr = BN_CTX_get(ctx.get());
        if (!BN_mod_inverse(rr, sig_r, order, ctx.get())) { ret=-1; goto err; }
        sor = BN_CTX_get(ctx.get());
        if (!BN_mod_mul(sor, sig_s, rr, order, ctx.get())) { ret=-1; goto err; }
        eor = BN_CTX_get(ctx.get());
        if (!BN_mod_mul(eor, e, rr, order, ctx.get())) { ret=-1; goto err; }
        if (!EC_POINT_mul(group, Q.get(), eor, R.get(), sor, ctx.get())) { ret=-2; goto err; }
        if (!EC_KEY_set_public_key(eckey.get(), Q.get())) { ret=-2; goto err; }

        ret = 1;

    err:
        if (nullptr != ctx) {
            BN_CTX_end(ctx.get());
        }
        return ret;
    }

    void CKey::SetCompressedPubKey()
    {
        EC_KEY_set_conv_form(pkey.get(), POINT_CONVERSION_COMPRESSED);
        fCompressedPubKey = true;
    }

    void CKey::Reset()
    {
        fCompressedPubKey = false;
        pkey.reset(EC_KEY_new_by_curve_name(NID_sect571r1));
        if (nullptr == pkey)
            throw key_error("CKey::CKey() : EC_KEY_new_by_curve_name failed");
        fSet = false;
    }

    CKey::CKey() : pkey(nullptr)
    {
        Reset();
    }

    CKey::CKey(const CKey& b) : pkey(EC_KEY_dup(b.pkey.get()))
    {
        if (nullptr == pkey)
            throw key_error("CKey::CKey(const CKey&) : EC_KEY_dup failed");
        fSet = b.fSet;
    }

    CKey& CKey::operator=(const CKey& b)
    {
        if (nullptr == EC_KEY_copy(pkey.get(), b.pkey.get()))
            throw key_error("CKey::operator=(const CKey&) : EC_KEY_copy failed");
        fSet = b.fSet;
        return (*this);
    }

    CKey::~CKey()
    {
    }

    bool CKey::IsNull() const
    {
        return !fSet;
    }

    bool CKey::IsCompressed() const
    {
        return fCompressedPubKey;
    }

    void CKey::MakeNewKey(bool fCompressed)
    {
        if (!EC_KEY_generate_key(pkey.get()))
            throw key_error("CKey::MakeNewKey() : EC_KEY_generate_key failed");
        if (fCompressed)
            SetCompressedPubKey();
        fSet = true;
    }

    bool CKey::SetPrivKey(const CPrivKey& vchPrivKey)
    {
        const unsigned char* pbegin = &vchPrivKey[0];
        EC_KEY* pkey_temp = pkey.release(); // TODO, managed_openssl: better way to handle this?
        if (nullptr == d2i_ECPrivateKey(&pkey_temp, &pbegin, vchPrivKey.size()))
            return false;
        pkey.reset(pkey_temp);
        fSet = true;
        return true;
    }

    bool CKey::SetSecret(const CSecret& vchSecret, bool fCompressed)
    {
        pkey.reset(EC_KEY_new_by_curve_name(NID_sect571r1));
        if (nullptr == pkey)
            throw key_error("CKey::SetSecret() : EC_KEY_new_by_curve_name failed");
        if (vchSecret.size() != 72)
            throw key_error("CKey::SetSecret() : secret must be 32 bytes");
        BIGNUM_ptr bn(BN_bin2bn(&vchSecret[0], 72, BN_new()));
        if (nullptr == bn)
            throw key_error("CKey::SetSecret() : BN_bin2bn failed");
        if (!EC_KEY_regenerate_key(pkey, bn))
        {
            throw key_error("CKey::SetSecret() : EC_KEY_regenerate_key failed");
        }
        fSet = true;
        if (fCompressed || fCompressedPubKey)
            SetCompressedPubKey();
        return true;
    }

    CSecret CKey::GetSecret(bool &fCompressed) const
    {
        CSecret vchRet;
        vchRet.resize(72);
        const BIGNUM *bn = EC_KEY_get0_private_key(pkey.get());
        int nBytes = BN_num_bytes(bn);
        if (nullptr == bn)
            throw key_error("CKey::GetSecret() : EC_KEY_get0_private_key failed");
        int n = BN_bn2bin(bn, &vchRet[72 - nBytes]);
        if (n != nBytes)
            throw key_error("CKey::GetSecret(): BN_bn2bin failed");
        fCompressed = fCompressedPubKey;
        return vchRet;
    }

    CPrivKey CKey::GetPrivKey() const
    {
        int nSize = i2d_ECPrivateKey(pkey.get(), NULL);
        if (0 > nSize)
            throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey failed");
        CPrivKey vchPrivKey(nSize, 0);
        unsigned char* pbegin = &vchPrivKey[0];
        if (i2d_ECPrivateKey(pkey.get(), &pbegin) != nSize)
            throw key_error("CKey::GetPrivKey() : i2d_ECPrivateKey returned unexpected size");
        return vchPrivKey;
    }

    bool CKey::SetPubKey(const std::vector<unsigned char>& vchPubKey)
    {
        const unsigned char* pbegin = &vchPubKey[0];
        EC_KEY* pkey_temp = pkey.release(); // TODO, managed_openssl: better way to handle this?
        if (!o2i_ECPublicKey(&pkey_temp, &pbegin, vchPubKey.size()))
            return false;
        pkey.reset(pkey_temp);
        fSet = true;
        if (vchPubKey.size() >= 33)
            SetCompressedPubKey();
        return true;
    }

    std::vector<unsigned char> CKey::GetPubKey() const
    {
        int nSize = i2o_ECPublicKey(pkey.get(), NULL);
        if (0 > nSize)
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey failed");
        std::vector<unsigned char> vchPubKey(nSize, 0);
        unsigned char* pbegin = &vchPubKey[0];
        if (i2o_ECPublicKey(pkey.get(), &pbegin) != nSize)
            throw key_error("CKey::GetPubKey() : i2o_ECPublicKey returned unexpected size");
        return vchPubKey;
    }

    bool CKey::Sign(uint1024 hash, std::vector<unsigned char>& vchSig, int nBits)
    {
        unsigned int nSize = ECDSA_size(pkey.get());
        vchSig.resize(nSize); // Make sure it is big enough
        
        bool fSuccess = false;
        if(nBits == 256)
        {
            uint256 hash256 = hash.getuint256();
            fSuccess = (ECDSA_sign(0, (unsigned char*)&hash256, sizeof(hash256), &vchSig[0], &nSize, pkey.get()) == 1);
        }
        else if(nBits == 512)
        {
            uint512 hash512 = hash.getuint512();
            fSuccess = (ECDSA_sign(0, (unsigned char*)&hash512, sizeof(hash512), &vchSig[0], &nSize, pkey.get()) == 1);
        }
        else
            fSuccess = (ECDSA_sign(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], &nSize, pkey.get()) == 1);
        
        if(!fSuccess)
        {
            vchSig.clear();
            return false;
        }
        
        vchSig.resize(nSize); // Shrink to fit actual size
        return true;
    }

    // create a compact signature (65 bytes), which allows reconstructing the used public key
    // The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
    // The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
    //                  0x1D = second key with even y, 0x1E = second key with odd y
    bool CKey::SignCompact(uint256 hash, std::vector<unsigned char>& vchSig)
    {
        bool fOk = false;
        ECDSA_SIG_ptr sig(ECDSA_do_sign((unsigned char*)&hash, sizeof(hash), pkey.get()));
        if (nullptr == sig)
            return false;
        vchSig.clear();
        vchSig.resize(145, 0);

        const BIGNUM* sig_r = nullptr;
        const BIGNUM* sig_s = nullptr;;
        #if OPENSSL_VERSION_NUMBER >= 0x10100000L
            ECDSA_SIG_get0(sig.get(), &sig_r, &sig_s);
        #else
            sig_r = sig->r;
            sig_s = sig->s;
        #endif

        int nBitsR = BN_num_bits(sig_r);
        int nBitsS = BN_num_bits(sig_s);
        if (nBitsR <= 571 && nBitsS <= 571)
        {
            int nRecId = -1;
            for (int i=0; i < 9; i++)
            {
                CKey keyRec;
                keyRec.fSet = true;
                if (fCompressedPubKey)
                    keyRec.SetCompressedPubKey();
                if (ECDSA_SIG_recover_key_GFp(keyRec.pkey, sig, (unsigned char*)&hash, sizeof(hash), i, 1) == 1)
                    if (keyRec.GetPubKey() == this->GetPubKey())
                    {
                        nRecId = i;
                        break;
                    }
            }

            if (nRecId == -1)
                throw key_error("CKey::SignCompact() : unable to construct recoverable key");

            vchSig[0] = nRecId+27+(fCompressedPubKey ? 4 : 0);
            BN_bn2bin(sig_r, &vchSig[73-(nBitsR+7)/8]);
            BN_bn2bin(sig_s, &vchSig[145-(nBitsS+7)/8]);
            fOk = true;
        }
        return fOk;
    }

    // reconstruct public key from a compact signature
    // This is only slightly more CPU intensive than just verifying it.
    // If this function succeeds, the recovered public key is guaranteed to be valid
    // (the signature is a valid signature of the given data for that key)
    bool CKey::SetCompactSignature(uint256 hash, const std::vector<unsigned char>& vchSig)
    {
        if (vchSig.size() != 145)
            return false;
        int nV = vchSig[0];
        if (nV<27 || nV>=35)
            return false;
        ECDSA_SIG_ptr sig(ECDSA_SIG_new());
        if (nullptr == sig)
            return false;

        #if OPENSSL_VERSION_NUMBER > 0x10100000L
            BIGNUM_ptr sig_r(BN_bin2bn(&vchSig[1], 72, BN_new()));
            BIGNUM_ptr sig_s(BN_bin2bn(&vchSig[73], 72, BN_new()));
            if ((nullptr == sig_r) || (nullptr == sig_s))
                return false;
            // set r and s values, this transfers ownership to the ECDSA_SIG object
            ECDSA_SIG_set0(sig.get(), sig_r.release(), sig_s.release());
        #else
            BN_bin2bn(&vchSig[1], 72, sig->r);
            BN_bin2bn(&vchSig[73], 72, sig->s);
        #endif

        pkey.reset(EC_KEY_new_by_curve_name(NID_sect571r1));
        if (nV >= 31)
        {
            SetCompressedPubKey();
            nV -= 4;
        }
        if (ECDSA_SIG_recover_key_GFp(pkey, sig, (unsigned char*)&hash, sizeof(hash), nV - 27, 0) == 1)
        {
            fSet = true;
            return true;
        }
        return false;
    }

    bool CKey::Verify(uint1024 hash, const std::vector<unsigned char>& vchSig, int nBits)
    {
        bool fSuccess = false;
        if(nBits == 256)
        {
            uint256 hash256 = hash.getuint256();
            fSuccess = (ECDSA_verify(0, (unsigned char*)&hash256, sizeof(hash256), &vchSig[0], vchSig.size(), pkey.get()) == 1);
        }
        else if(nBits == 512)
        {
            uint512 hash512 = hash.getuint512();
            fSuccess = (ECDSA_verify(0, (unsigned char*)&hash512, sizeof(hash512), &vchSig[0], vchSig.size(), pkey.get()) == 1);
        }
        else
            fSuccess = (ECDSA_verify(0, (unsigned char*)&hash, sizeof(hash), &vchSig[0], vchSig.size(), pkey.get()) == 1);
            
        return fSuccess;
    }

    bool CKey::IsValid()
    {
        if (!fSet)
            return false;

        bool fCompr;
        CSecret secret = GetSecret(fCompr);
        CKey key2;
        key2.SetSecret(secret, fCompr);
        return GetPubKey() == key2.GetPubKey();
    }
}
