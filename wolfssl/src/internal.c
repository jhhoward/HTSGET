/* internal.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

/*
 * WOLFSSL_SMALL_CERT_VERIFY:
 *     Verify the certificate signature without using DecodedCert. Doubles up
 *     on some code but allows smaller peak heap memory usage.
 *     Cannot be used with WOLFSSL_NONBLOCK_OCSP.
 * WOLFSSL_ALT_CERT_CHAINS:
 *     Allows CA's to be presented by peer, but not part of a valid chain.
 *     Default wolfSSL behavior is to require validation of all presented peer
 *     certificates. This also allows loading intermediate CA's as trusted
 *     and ignoring no signer failures for CA's up the chain to root.
 * WOLFSSL_DTLS_RESEND_ONLY_TIMEOUT:
 *     Enable resending the previous DTLS handshake flight only on a network
 *     read timeout. By default we resend in two more cases, when we receive:
 *     - an out of order last msg of the peer's flight
 *     - a duplicate of the first msg from the peer's flight
 * WOLFSSL_NO_DEF_TICKET_ENC_CB:
 *     No default ticket encryption callback.
 *     Server only.
 *     Application must set its own callback to use session tickets.
 * WOLFSSL_TICKET_ENC_CHACHA20_POLY1305
 *     Use ChaCha20-Poly1305 to encrypt/decrypt session tickets in default
 *     callback. Default algorithm if none defined and algorithms compiled in.
 *     Server only.
 * WOLFSSL_TICKET_ENC_AES128_GCM
 *     Use AES128-GCM to encrypt/decrypt session tickets in default callback.
 *     Server only. Default algorithm if ChaCha20/Poly1305 not compiled in.
 * WOLFSSL_TICKET_ENC_AES256_GCM
 *     Use AES256-GCM to encrypt/decrypt session tickets in default callback.
 *     Server only.
 * WOLFSSL_TICKET_DECRYPT_NO_CREATE
 *     Default callback will not request creation of new ticket on successful
 *     decryption.
 *     Server only.
 * WOLFSSL_TLS13_NO_PEEK_HANDSHAKE_DONE
 *     Once a normal TLS 1.3 handshake is complete, a session ticket message
 *     may be received by a client. To support detecting this, peek will
 *     return WOLFSSL_ERROR_WANT_READ.
 *     This define turns off this behaviour.
 * WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY
 *     Verify hostname/ip address using alternate name (SAN) only and do not
 *     use the common name. Forces use of the alternate name, so certificates
 *     missing SAN will be rejected during the handshake
 * WOLFSSL_CHECK_SIG_FAULTS
 *     Verifies the ECC signature after signing in case of faults in the
 *     calculation of the signature. Useful when signature fault injection is a
 *     possible attack.
 * WOLFSSL_TLS13_IGNORE_AEAD_LIMITS
 *     Ignore the AEAD limits for messages specified in the RFC. After
 *     reaching the limit, we initiate a key update. We enforce the AEAD limits
 *     by default.
 *     https://www.rfc-editor.org/rfc/rfc8446#section-5.5
 *     https://www.rfc-editor.org/rfc/rfc9147.html#name-aead-limits
 */


#ifdef EXTERNAL_OPTS_OPENVPN
#error EXTERNAL_OPTS_OPENVPN should not be defined\
    when building wolfSSL
#endif

#ifndef WOLFCRYPT_ONLY

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dh.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#if defined(OPENSSL_EXTRA) && defined(WOLFCRYPT_HAVE_SRP) && !defined(NO_SHA)
    #include <wolfssl/wolfcrypt/srp.h>
#endif

#if defined(OPENSSL_EXTRA) && defined(HAVE_SECRET_CALLBACK)
    #include <wolfssl/wolfcrypt/coding.h>
#endif
#ifdef HAVE_LIBZ
    #include "zlib.h"
#endif

#ifdef WOLFSSL_QNX_CAAM
    /* included to get CAAM devId value */
    #include <wolfssl/wolfcrypt/port/caam/wolfcaam.h>
#endif

#if defined(DEBUG_WOLFSSL) || defined(SHOW_SECRETS) || \
    defined(CHACHA_AEAD_TEST) || defined(WOLFSSL_SESSION_EXPORT_DEBUG)
    #ifndef NO_STDIO_FILESYSTEM
        #ifdef FUSION_RTOS
            #include <fclstdio.h>
        #else
            #include <stdio.h>
        #endif
    #endif
#endif

#ifdef __sun
    #include <sys/filio.h>
#endif


#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }

#ifdef _MSC_VER
    /* disable for while(0) cases at the .c level for now */
    #pragma warning(disable:4127)
#endif

#if defined(WOLFSSL_CALLBACKS) && !defined(LARGE_STATIC_BUFFERS)
    #error \
WOLFSSL_CALLBACKS needs LARGE_STATIC_BUFFERS, please add LARGE_STATIC_BUFFERS
#endif

#if defined(HAVE_SECURE_RENEGOTIATION) && defined(HAVE_RENEGOTIATION_INDICATION)
    #error Cannot use both secure-renegotiation and renegotiation-indication
#endif

#ifndef WOLFSSL_NO_TLS12

#ifndef NO_WOLFSSL_CLIENT
    static int DoServerKeyExchange(WOLFSSL* ssl, const byte* input,
                                   word32* inOutIdx, word32 size);
    #ifndef NO_CERTS
        static int DoCertificateRequest(WOLFSSL* ssl, const byte* input,
                                        word32* inOutIdx, word32 size);
    #endif
    #ifdef HAVE_SESSION_TICKET
        static int DoSessionTicket(WOLFSSL* ssl, const byte* input,
                                   word32* inOutIdx, word32 size);
    #endif
#endif


#ifndef NO_WOLFSSL_SERVER
    static int DoClientKeyExchange(WOLFSSL* ssl, byte* input,
                                   word32* inOutIdx, word32 size);
    #if (!defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
                        defined(HAVE_ED448)) && !defined(WOLFSSL_NO_CLIENT_AUTH)
        static int DoCertificateVerify(WOLFSSL* ssl, byte* input,
                                       word32* inOutIdx, word32 size);
    #endif
#endif /* !NO_WOLFSSL_SERVER */

#endif /* !WOLFSSL_NO_TLS12 */

#ifndef NO_WOLFSSL_SERVER
    #if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)
        static int TicketEncCbCtx_Init(WOLFSSL_CTX* ctx,
                                       TicketEncCbCtx* keyCtx);
        static void TicketEncCbCtx_Free(TicketEncCbCtx* keyCtx);
        static int DefTicketEncCb(WOLFSSL* ssl,
                                  byte key_name[WOLFSSL_TICKET_NAME_SZ],
                                  byte iv[WOLFSSL_TICKET_IV_SZ],
                                  byte mac[WOLFSSL_TICKET_MAC_SZ],
                                  int enc, byte* ticket, int inLen, int* outLen,
                                  void* userCtx);
    #endif
#endif


#ifdef WOLFSSL_DTLS
    static int _DtlsCheckWindow(WOLFSSL* ssl);
    static int _DtlsUpdateWindow(WOLFSSL* ssl);
#endif

#ifdef WOLFSSL_DTLS13
#ifndef WOLFSSL_DTLS13_SEND_MOREACK_DEFAULT
#define WOLFSSL_DTLS13_SEND_MOREACK_DEFAULT 0
#endif
#endif /* WOLFSSL_DTLS13 */

enum processReply {
    doProcessInit = 0,
#ifndef NO_WOLFSSL_SERVER
    runProcessOldClientHello,
#endif
    getRecordLayerHeader,
    getData,
    verifyEncryptedMessage,
    decryptMessage,
    verifyMessage,
    runProcessingOneRecord,
    runProcessingOneMessage
};


#ifndef WOLFSSL_NO_TLS12

////// TLS13_DOWNGRADE_SZ and tls13Downgrade moved to internal.h

#if !defined(NO_OLD_TLS) && !defined(WOLFSSL_AEAD_ONLY)
static int SSL_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz,
                    int padLen, int content, int verify, int epochOrder);

#endif

#endif /* !WOLFSSL_NO_TLS12 */


#if defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_TSIP_TLS)
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#endif

#if defined(OPENSSL_EXTRA) && defined(HAVE_SECRET_CALLBACK)

    static int  SessionSecret_callback(WOLFSSL* ssl, void* secret,
                                                  int* secretSz, void* ctx);
#ifdef WOLFSSL_TLS13
    static int  SessionSecret_callback_Tls13(WOLFSSL* ssl, int id,
                       const unsigned char* secret, int secretSz, void* ctx);
#endif

    /* Label string for client random. */
    #define SSC_CR      "CLIENT_RANDOM"

    /*
     * This function builds up string for key-logging then call user's
     * key-log-callback to pass the string for TLS1.2 and older.
     * The user's key-logging callback has been set via
     * wolfSSL_CTX_set_keylog_callback function. The logging string format is:
     * "CLIENT_RANDOM <hex-encoded client random> <hex-encoded master-secret>"
     * parameter
     *  - ssl: WOLFSSL object
     *  - secret: pointer to the buffer holding master-secret
     *  - secretSz: size of secret
     *  - ctx: not used
     * returns 0 on success, negative value on failure.
     */
    static int SessionSecret_callback(WOLFSSL* ssl, void* secret,
                    int* secretSz, void* ctx)
    {
        wolfSSL_CTX_keylog_cb_func logCb = NULL;
        int msSz;
        int hasVal;
        int i;
        const char* label = SSC_CR;
        int labelSz = sizeof(SSC_CR);
        int buffSz;
        byte* log = NULL;
        word32 outSz;
        int idx;
        int ret;
        (void)ctx;

        if (ssl == NULL || secret == NULL || *secretSz == 0)
            return BAD_FUNC_ARG;
        if (ssl->arrays == NULL)
            return BAD_FUNC_ARG;

        /* get the user-callback func from CTX*/
        logCb = ssl->ctx->keyLogCb;
        if (logCb == NULL)
            return 0;

        /* need to make sure the given master-secret has a meaningful value */
        msSz   = *secretSz;
        hasVal = 0;
        for (i = 0; i < msSz; i++) {
            if (*((byte*)secret) != 0) {
                hasVal = 1;
                break;
            }
        }
        if (hasVal == 0)
            return 0; /* master-secret looks invalid */

        /* build up a hex-decoded keylog string
           "CLIENT_RANDOM <hex-encoded client random> <hex-encoded master-secret>"
           note that each keylog string does not have CR/LF.
        */
        buffSz  = labelSz + (RAN_LEN * 2) + 1 + ((*secretSz) * 2) + 1;
        log     = XMALLOC(buffSz, ssl->heap, DYNAMIC_TYPE_SECRET);
        if (log == NULL)
            return MEMORY_E;
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("SessionSecret log", log, buffSz);
#endif

        XMEMSET(log, 0, buffSz);
        XMEMCPY(log, label, labelSz -1);     /* put label w/o terminator */
        log[labelSz - 1] = ' ';              /* '\0' -> ' ' */
        idx = labelSz;
        outSz = buffSz - idx;
        if ((ret = Base16_Encode(ssl->arrays->clientRandom, RAN_LEN,
                                            log + idx, &outSz)) == 0) {
            idx += (outSz - 1); /* reduce terminator byte */
            outSz = buffSz - idx;

            if (outSz > 1) {
                log[idx++] = ' ';  /* add space*/
                outSz = buffSz - idx;

                if ((ret = Base16_Encode((byte*)secret, *secretSz,
                                             log + idx, &outSz)) == 0) {
                    /* pass the log to the client callback*/
                    logCb(ssl, (char*)log);
                    ret = 0;
                }
            }
            else
                ret = MEMORY_E;
        }
        /* Zero out Base16 encoded secret and other data. */
        ForceZero(log, buffSz);
        XFREE(log, ssl->heap, DYNAMIC_TYPE_SECRET);
        return ret;
    }

#if defined(WOLFSSL_TLS13)

     /* Label string for client early traffic secret. */
     #define SSC_TLS13_CETS     "CLIENT_EARLY_TRAFFIC_SECRET"
     /* Label string for client handshake traffic secret. */
     #define SSC_TLS13_CHTS     "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
     /* Label string for server handshake traffic secret. */
     #define SSC_TLS13_SHTS     "SERVER_HANDSHAKE_TRAFFIC_SECRET"
     /* Label string for client traffic secret. */
     #define SSC_TLS13_CTS      "CLIENT_TRAFFIC_SECRET_0"
     /* Label string for server traffic secret. */
     #define SSC_TLS13_STS      "SERVER_TRAFFIC_SECRET_0"
     /* Label string for early exporter secret. */
     #define SSC_TLS13_EES      "EARLY_EXPORTER_SECRET"
     /* Label string for exporter secret. */
     #define SSC_TLS13_ES       "EXPORTER_SECRET"

    /*
     * This function builds up string for key-logging then call user's
     * key-log-callback to pass the string for TLS1.3.
     * The user's key-logging callback has been set via
     * wolfSSL_CTX_set_keylog_callback function. The logging string format is:
     * "<Label> <hex-encoded client random> <hex-encoded secret>"
     *
     * parameter
     *  - ssl: WOLFSSL object
     *  - id: type of secret for logging
     *  - secret: pointer to the buffer holding secret
     *  - secretSz: size of secret
     *  - ctx: not used
     * returns 0 on success, negative value on failure.
     */
    static int SessionSecret_callback_Tls13(WOLFSSL* ssl, int id,
        const unsigned char* secret, int secretSz, void* ctx)
    {
        wolfSSL_CTX_keylog_cb_func logCb = NULL;
        const char* label;
        int         labelSz = 0;
        int         buffSz  = 0;
        byte*       log     = NULL;
        word32 outSz;
        int idx;
        int ret;

        (void)ctx;

        if (ssl == NULL || secret == NULL || secretSz == 0)
            return BAD_FUNC_ARG;
        if (ssl->arrays == NULL)
            return BAD_FUNC_ARG;

        /* get the user-callback func from CTX*/
        logCb = ssl->ctx->keyLogCb;
        if (logCb == NULL)
            return 0;

        switch (id) {
            case CLIENT_EARLY_TRAFFIC_SECRET:
                labelSz = sizeof(SSC_TLS13_CETS);
                label = SSC_TLS13_CETS;
                break;

            case CLIENT_HANDSHAKE_TRAFFIC_SECRET:
                labelSz = sizeof(SSC_TLS13_CHTS);
                label = SSC_TLS13_CHTS;
                break;

            case SERVER_HANDSHAKE_TRAFFIC_SECRET:
                labelSz = sizeof(SSC_TLS13_SHTS);
                label = SSC_TLS13_SHTS;
                break;

            case CLIENT_TRAFFIC_SECRET:
                labelSz = sizeof(SSC_TLS13_CTS);
                label = SSC_TLS13_CTS;
                break;

            case SERVER_TRAFFIC_SECRET:
                labelSz = sizeof(SSC_TLS13_STS);
                label = SSC_TLS13_STS;
                break;

            case EARLY_EXPORTER_SECRET:
                labelSz = sizeof(SSC_TLS13_EES);
                label = SSC_TLS13_EES;
                break;

            case EXPORTER_SECRET:
                labelSz = sizeof(SSC_TLS13_ES);
                label = SSC_TLS13_ES;
                break;

            default:
                return BAD_FUNC_ARG;
        }
        /* prepare a log string for passing user callback
         * "<Label> <hex-encoded client random> <hex-encoded secret>" */
        buffSz = labelSz + (RAN_LEN * 2) + 1 + secretSz * 2 + 1;
        log    = XMALLOC(buffSz, ssl->heap, DYNAMIC_TYPE_SECRET);
        if (log == NULL)
            return MEMORY_E;
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("SessionSecret log", log, buffSz);
#endif

        XMEMSET(log, 0, buffSz);
        XMEMCPY(log, label, labelSz - 1);     /* put label w/o terminator */
        log[labelSz - 1] = ' ';               /* '\0' -> ' ' */

        idx = labelSz;
        outSz = buffSz - idx;
        if ((ret = Base16_Encode(ssl->arrays->clientRandom, RAN_LEN,
                                            log + idx, &outSz)) == 0) {
            idx  += (outSz - 1); /* reduce terminator byte */
            outSz = buffSz - idx;

            if (outSz >1) {
                log[idx++] = ' ';        /* add space*/
                outSz = buffSz - idx;

                if ((ret = Base16_Encode((byte*)secret, secretSz,
                                log + idx, &outSz)) == 0) {
                    logCb(ssl, (char*)log);
                    ret = 0;
                }
            }
            else
                ret = MEMORY_E;
        }
        /* Zero out Base16 encoded secret and other data. */
        ForceZero(log, buffSz);
        XFREE(log, ssl->heap, DYNAMIC_TYPE_SECRET);
        return ret;
    }
#endif /* WOLFSSL_TLS13*/
#endif /* OPENSSL_EXTRA && HAVE_SECRET_CALLBACK*/

int IsTLS(const WOLFSSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_MINOR)
        return 1;

    return 0;
}


int IsAtLeastTLSv1_2(const WOLFSSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_2_MINOR)
        return 1;
#ifdef WOLFSSL_DTLS
    if (ssl->version.major == DTLS_MAJOR && ssl->version.minor <= DTLSv1_2_MINOR)
        return 1;
#endif

    return 0;
}

int IsAtLeastTLSv1_3(const ProtocolVersion pv)
{
    int ret;
    ret = (pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_3_MINOR);

#ifdef WOLFSSL_DTLS13
    if (ret == 0 && pv.major == DTLS_MAJOR && pv.minor <= DTLSv1_3_MINOR)
        return 1;
#endif

    return ret;
}

int IsEncryptionOn(WOLFSSL* ssl, int isSend)
{
    #ifdef WOLFSSL_DTLS
    /* For DTLS, epoch 0 is always not encrypted. */
    if (ssl->options.dtls && !isSend) {
        if (!IsAtLeastTLSv1_3(ssl->version) && ssl->keys.curEpoch == 0)
            return 0;
#ifdef WOLFSSL_DTLS13
        else if (IsAtLeastTLSv1_3(ssl->version)
                     && w64IsZero(ssl->keys.curEpoch64))
            return 0;
#endif /* WOLFSSL_DTLS13 */

    }
    #endif /* WOLFSSL_DTLS */
    #ifdef WOLFSSL_QUIC
        if (WOLFSSL_IS_QUIC(ssl) && IsAtLeastTLSv1_3(ssl->version)) {
            return 0;
        }
    #endif
    return ssl->keys.encryptionOn &&
        (isSend ? ssl->encrypt.setup : ssl->decrypt.setup);
}


#ifdef WOLFSSL_DTLS
/* Stream Control Transmission Protocol */
/* If SCTP is not enabled returns the state of the dtls option.
 * If SCTP is enabled returns dtls && !sctp. */
int IsDtlsNotSctpMode(WOLFSSL* ssl)
{
#ifdef WOLFSSL_SCTP
    return ssl->options.dtls && !ssl->options.dtlsSctp;
#else
    return ssl->options.dtls;
#endif
}

#if !defined(WOLFSSL_NO_TLS12) && !defined(NO_WOLFSSL_SERVER)
/* Secure Real-time Transport Protocol */
/* If SRTP is not enabled returns the state of the dtls option.
 * If SRTP is enabled returns dtls && !dtlsSrtpProfiles. */
static WC_INLINE int IsDtlsNotSrtpMode(WOLFSSL* ssl)
{
#ifdef WOLFSSL_SRTP
    return ssl->options.dtls && !ssl->dtlsSrtpProfiles;
#else
    return ssl->options.dtls;
#endif
}
#endif /* !WOLFSSL_NO_TLS12 && !NO_WOLFSSL_SERVER */
#endif /* WOLFSSL_DTLS */


#ifdef HAVE_LIBZ

    /* alloc user allocs to work with zlib */
    static void* myAlloc(void* opaque, unsigned int item, unsigned int size)
    {
        (void)opaque;
        return (void *)XMALLOC(item * size, opaque, DYNAMIC_TYPE_LIBZ);
    }


    static void myFree(void* opaque, void* memory)
    {
        (void)opaque;
        XFREE(memory, opaque, DYNAMIC_TYPE_LIBZ);
    }


    /* init zlib comp/decomp streams, 0 on success */
    static int InitStreams(WOLFSSL* ssl)
    {
        ssl->c_stream.zalloc = (alloc_func)myAlloc;
        ssl->c_stream.zfree  = (free_func)myFree;
        ssl->c_stream.opaque = (voidpf)ssl->heap;

        if (deflateInit(&ssl->c_stream, Z_DEFAULT_COMPRESSION) != Z_OK)
            return ZLIB_INIT_ERROR;

        ssl->didStreamInit = 1;

        ssl->d_stream.zalloc = (alloc_func)myAlloc;
        ssl->d_stream.zfree  = (free_func)myFree;
        ssl->d_stream.opaque = (voidpf)ssl->heap;

        if (inflateInit(&ssl->d_stream) != Z_OK) return ZLIB_INIT_ERROR;

        return 0;
    }


    static void FreeStreams(WOLFSSL* ssl)
    {
        if (ssl->didStreamInit) {
            deflateEnd(&ssl->c_stream);
            inflateEnd(&ssl->d_stream);
        }
    }


    /* compress in to out, return out size or error */
    static int myCompress(WOLFSSL* ssl, byte* in, int inSz, byte* out, int outSz)
    {
        int    err;
        int    currTotal = (int)ssl->c_stream.total_out;

        ssl->c_stream.next_in   = in;
        ssl->c_stream.avail_in  = inSz;
        ssl->c_stream.next_out  = out;
        ssl->c_stream.avail_out = outSz;

        err = deflate(&ssl->c_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) return ZLIB_COMPRESS_ERROR;

        return (int)ssl->c_stream.total_out - currTotal;
    }


    /* decompress in to out, return out size or error */
    static int myDeCompress(WOLFSSL* ssl, byte* in,int inSz, byte* out,int outSz)
    {
        int    err;
        int    currTotal = (int)ssl->d_stream.total_out;

        ssl->d_stream.next_in   = in;
        ssl->d_stream.avail_in  = inSz;
        ssl->d_stream.next_out  = out;
        ssl->d_stream.avail_out = outSz;

        err = inflate(&ssl->d_stream, Z_SYNC_FLUSH);
        if (err != Z_OK && err != Z_STREAM_END) return ZLIB_DECOMPRESS_ERROR;

        return (int)ssl->d_stream.total_out - currTotal;
    }

#endif /* HAVE_LIBZ */


#ifdef WOLFSSL_SESSION_EXPORT
/**
 * serializes the cipher specs struct for exporting
 * @return the amount written to 'exp' buffer
 */
static int ExportCipherSpecState(WOLFSSL* ssl, byte* exp, word32 len, byte ver,
        int type)
{
    word32 idx = 0;
    CipherSpecs* specs;

    WOLFSSL_ENTER("ExportCipherSpecState");

    if (exp == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    specs = &ssl->specs;
    if (WOLFSSL_EXPORT_SPC_SZ > len) {
        return BUFFER_E;
    }

    XMEMSET(exp, 0, WOLFSSL_EXPORT_SPC_SZ);

    c16toa(specs->key_size, exp + idx);      idx += OPAQUE16_LEN;
    c16toa(specs->iv_size, exp + idx);       idx += OPAQUE16_LEN;
    c16toa(specs->block_size, exp + idx);    idx += OPAQUE16_LEN;
    c16toa(specs->aead_mac_size, exp + idx); idx += OPAQUE16_LEN;
    exp[idx++] = specs->bulk_cipher_algorithm;
    exp[idx++] = specs->cipher_type;
    exp[idx++] = specs->mac_algorithm;
    exp[idx++] = specs->kea;
    exp[idx++] = specs->sig_algo;
    exp[idx++] = specs->hash_size;
    exp[idx++] = specs->pad_size;
    exp[idx++] = specs->static_ecdh;

    if (idx != WOLFSSL_EXPORT_SPC_SZ) {
        WOLFSSL_MSG("WOLFSSL_EXPORT_SPC_SZ needs updated and export version");
        return DTLS_EXPORT_VER_E;
    }

    /* send over state of AES too */
    if (type == WOLFSSL_EXPORT_TLS &&
            ssl->specs.bulk_cipher_algorithm == wolfssl_aes) {
        byte *pt = (byte*)ssl->encrypt.aes->reg;

        if ((idx + 2*AES_BLOCK_SIZE) > len) {
            WOLFSSL_MSG("Can not fit AES state into buffer");
            return BUFFER_E;
        }
        XMEMCPY(exp + idx, pt, AES_BLOCK_SIZE);
        idx += AES_BLOCK_SIZE;

        pt = (byte*)ssl->decrypt.aes->reg;
        XMEMCPY(exp + idx, pt, AES_BLOCK_SIZE);
        idx += AES_BLOCK_SIZE;
    }

    WOLFSSL_LEAVE("ExportCipherSpecState", idx);
    (void)ver;
    return idx;
}


/* serializes the key struct for exporting */
static int ExportKeyState(WOLFSSL* ssl, byte* exp, word32 len, byte ver,
        byte small, int type)
{
    word32 idx = 0;
    byte   sz;
    Keys* keys;

    WOLFSSL_ENTER("ExportKeyState");

    if (exp == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    keys = &(ssl->keys);

    if (DTLS_EXPORT_MIN_KEY_SZ > len) {
        WOLFSSL_MSG("Buffer not large enough for minimum key struct size");
        return BUFFER_E;
    }

    XMEMSET(exp, 0, DTLS_EXPORT_MIN_KEY_SZ);

    c32toa(keys->peer_sequence_number_hi, exp + idx); idx += OPAQUE32_LEN;
    c32toa(keys->peer_sequence_number_lo, exp + idx); idx += OPAQUE32_LEN;
    c32toa(keys->sequence_number_hi, exp + idx);      idx += OPAQUE32_LEN;
    c32toa(keys->sequence_number_lo, exp + idx);      idx += OPAQUE32_LEN;

    #if defined(WOLFSSL_DTLS)
    if (type == WOLFSSL_EXPORT_DTLS) {
        c16toa(keys->peerSeq[0].nextEpoch, exp + idx);  idx += OPAQUE16_LEN;
        c16toa(keys->peerSeq[0].nextSeq_hi, exp + idx); idx += OPAQUE16_LEN;
        c32toa(keys->peerSeq[0].nextSeq_lo, exp + idx); idx += OPAQUE32_LEN;
        c16toa(keys->curEpoch, exp + idx);   idx += OPAQUE16_LEN;
        c16toa(keys->curSeq_hi, exp + idx);  idx += OPAQUE16_LEN;
        c32toa(keys->curSeq_lo, exp + idx);  idx += OPAQUE32_LEN;
        c16toa(keys->peerSeq[0].prevSeq_hi, exp + idx); idx += OPAQUE16_LEN;
        c32toa(keys->peerSeq[0].prevSeq_lo, exp + idx); idx += OPAQUE32_LEN;

        c16toa(keys->dtls_peer_handshake_number, exp + idx);
        idx += OPAQUE16_LEN;
        c16toa(keys->dtls_expected_peer_handshake_number, exp + idx);
        idx += OPAQUE16_LEN;

        c16toa(keys->dtls_sequence_number_hi, exp + idx); idx += OPAQUE16_LEN;
        c32toa(keys->dtls_sequence_number_lo, exp + idx); idx += OPAQUE32_LEN;
        c16toa(keys->dtls_prev_sequence_number_hi, exp + idx);
        idx += OPAQUE16_LEN;
        c32toa(keys->dtls_prev_sequence_number_lo, exp + idx);
        idx += OPAQUE32_LEN;
        c16toa(keys->dtls_epoch, exp + idx);              idx += OPAQUE16_LEN;
        c16toa(keys->dtls_handshake_number, exp + idx);   idx += OPAQUE16_LEN;
    }
    #endif
    c32toa(keys->encryptSz, exp + idx);                   idx += OPAQUE32_LEN;
    c32toa(keys->padSz, exp + idx);                       idx += OPAQUE32_LEN;
    exp[idx++] = keys->encryptionOn;
    exp[idx++] = keys->decryptedCur;

    /* from here on the buffer needs checked because is variable length that
     * can be larger than DTLS_EXPORT_MIN_KEY_SZ */
#ifdef WOLFSSL_DTLS
    if (type == WOLFSSL_EXPORT_DTLS) {
        word32 i;
        if ((OPAQUE16_LEN * 2) + idx +
                (2 * (WOLFSSL_DTLS_WINDOW_WORDS * OPAQUE32_LEN)) > len) {
            WOLFSSL_MSG("Buffer not large enough for WOLFSSL_DTLS_WINDOW_WORDS");
            return BUFFER_E;
        }

        c16toa(WOLFSSL_DTLS_WINDOW_WORDS, exp + idx); idx += OPAQUE16_LEN;
        for (i = 0; i < WOLFSSL_DTLS_WINDOW_WORDS; i++) {
            c32toa(keys->peerSeq[0].window[i], exp + idx);
            idx += OPAQUE32_LEN;
        }
        c16toa(WOLFSSL_DTLS_WINDOW_WORDS, exp + idx); idx += OPAQUE16_LEN;
        for (i = 0; i < WOLFSSL_DTLS_WINDOW_WORDS; i++) {
            c32toa(keys->peerSeq[0].prevWindow[i], exp + idx);
            idx += OPAQUE32_LEN;
        }
    }
#endif

    if (idx >= len) {
        WOLFSSL_MSG("Buffer not large enough for truncated hmac flag");
        return BUFFER_E;
    }

#ifdef HAVE_TRUNCATED_HMAC
    sz         = ssl->truncated_hmac ? TRUNCATED_HMAC_SZ: ssl->specs.hash_size;
    exp[idx++] = ssl->truncated_hmac;
#else
    sz         = ssl->specs.hash_size;
    exp[idx++] = 0; /* no truncated hmac */
#endif

    sz = (small)? 0: sz;
    if (idx + (sz * 2) + OPAQUE8_LEN > len) {
        WOLFSSL_MSG("Buffer not large enough for MAC secret");
        return BUFFER_E;
    }

    exp[idx++] = sz;
    if (sz > 0) {
    #ifndef WOLFSSL_AEAD_ONLY
        XMEMCPY(exp + idx, keys->client_write_MAC_secret, sz); idx += sz;
        XMEMCPY(exp + idx, keys->server_write_MAC_secret, sz); idx += sz;
    #else
        XMEMSET(exp + idx, 0, sz); idx += sz;
        XMEMSET(exp + idx, 0, sz); idx += sz;
    #endif
    }

    sz = (small)? 0: ssl->specs.key_size;
    if (idx + (sz * 2) + OPAQUE8_LEN > len) {
        WOLFSSL_MSG("Buffer not large enough for write key");
        return BUFFER_E;
    }

    exp[idx++] = sz;
    if (sz > 0) {
        XMEMCPY(exp + idx, keys->client_write_key, sz); idx += sz;
        XMEMCPY(exp + idx, keys->server_write_key, sz); idx += sz;
    }

    sz = (small)? 0: ssl->specs.iv_size;
    if (idx + (sz * 2) + OPAQUE8_LEN + AEAD_MAX_EXP_SZ > len) {
        WOLFSSL_MSG("Buffer not large enough for IVs");
        return BUFFER_E;
    }

    exp[idx++] = sz;
    if (sz > 0) {
        XMEMCPY(exp + idx, keys->client_write_IV, sz); idx += sz;
        XMEMCPY(exp + idx, keys->server_write_IV, sz); idx += sz;
    }
    XMEMCPY(exp + idx, keys->aead_exp_IV, AEAD_MAX_EXP_SZ);
    idx += AEAD_MAX_EXP_SZ;

    sz = (small)? 0: AEAD_MAX_IMP_SZ;
    if (idx + (sz * 2) + OPAQUE8_LEN > len) {
        WOLFSSL_MSG("Buffer not large enough for imp IVs");
        return BUFFER_E;
    }
    exp[idx++] = sz;
    if (sz > 0) {
        XMEMCPY(exp + idx, keys->aead_enc_imp_IV, sz); idx += sz;
        XMEMCPY(exp + idx, keys->aead_dec_imp_IV, sz); idx += sz;
    }

    /* DTLS_EXPORT_KEY_SZ is max value. idx size can vary */
    if (idx > DTLS_EXPORT_KEY_SZ) {
        WOLFSSL_MSG("DTLS_EXPORT_KEY_SZ needs updated and export version");
        return DTLS_EXPORT_VER_E;
    }

    WOLFSSL_LEAVE("ExportKeyState", idx);
    (void)ver;
    (void)type;
    return idx;
}


/**
 * Imports the buffer 'exp' into the 'ssl' CipherSpec structure.
 * @param ssl WOLFSSL structure to import into
 * @param exp input buffer to read from
 * @param len length of exp buffer
 * @param ver version of import buffer found
 * @param type flag for importing a TLS session or DTLS
 *
 * @return size of exp buffer consumed on success and negative value on fail
 */
static int ImportCipherSpecState(WOLFSSL* ssl, const byte* exp, word32 len,
        byte ver, int type)
{
    word32 idx = 0;
    CipherSpecs* specs;
    word32 tmp_seq_peer_lo;
    word32 tmp_seq_peer_hi;
    word32 tmp_seq_lo;
    word32 tmp_seq_hi;

    WOLFSSL_ENTER("ImportCipherSpecState");

    if (exp == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    specs= &(ssl->specs);

    if (WOLFSSL_EXPORT_SPC_SZ > len) {
        WOLFSSL_MSG("Buffer not large enough for max spec struct size");
        return BUFFER_E;
    }

    ato16(exp + idx, &specs->key_size);      idx += OPAQUE16_LEN;
    ato16(exp + idx, &specs->iv_size);       idx += OPAQUE16_LEN;
    ato16(exp + idx, &specs->block_size);    idx += OPAQUE16_LEN;
    ato16(exp + idx, &specs->aead_mac_size); idx += OPAQUE16_LEN;
    specs->bulk_cipher_algorithm = exp[idx++];
    specs->cipher_type           = exp[idx++];
    specs->mac_algorithm         = exp[idx++];
    specs->kea                   = exp[idx++];
    specs->sig_algo              = exp[idx++];
    specs->hash_size             = exp[idx++];
    specs->pad_size              = exp[idx++];
    specs->static_ecdh           = exp[idx++];

    if (specs->pad_size != PAD_MD5 && specs->pad_size != PAD_SHA) {
        WOLFSSL_MSG("Importing bad or unknown pad size");
        return BAD_STATE_E;
    }

    /* temporarily save the sequence numbers */
    tmp_seq_peer_lo = ssl->keys.peer_sequence_number_lo;
    tmp_seq_peer_hi = ssl->keys.peer_sequence_number_hi;
    tmp_seq_lo = ssl->keys.sequence_number_lo;
    tmp_seq_hi = ssl->keys.sequence_number_hi;

    SetKeysSide(ssl, ENCRYPT_AND_DECRYPT_SIDE);

    /* reset sequence numbers after setting keys */
    ssl->keys.peer_sequence_number_lo = tmp_seq_peer_lo;
    ssl->keys.peer_sequence_number_hi = tmp_seq_peer_hi;
    ssl->keys.sequence_number_lo = tmp_seq_lo;
    ssl->keys.sequence_number_hi = tmp_seq_hi;

    if (type == WOLFSSL_EXPORT_TLS &&
            ssl->specs.bulk_cipher_algorithm == wolfssl_aes) {
        byte *pt = (byte*)ssl->encrypt.aes->reg;
        XMEMCPY(pt, exp + idx, AES_BLOCK_SIZE);
        idx += AES_BLOCK_SIZE;

        pt = (byte*)ssl->decrypt.aes->reg;
        XMEMCPY(pt, exp + idx, AES_BLOCK_SIZE);
        idx += AES_BLOCK_SIZE;
    }

    WOLFSSL_LEAVE("ImportCipherSpecState", idx);
    (void)ver;
    return idx;
}


/**
 * Import the Key structure
 *
 * @param ssl WOLFSSL structure to import into
 * @param exp buffer to read Key values from
 * @param len max length of buffer 'exp'
 * @param ver version of import buffer found
 * @param type flag for TLS vs DTLS
 *
 * @return amount of data read from exp on success or negative on fail
 */
static int ImportKeyState(WOLFSSL* ssl, const byte* exp, word32 len, byte ver,
        int type)
{
    word32 idx = 0;
    byte   sz;
    Keys  *keys;

    WOLFSSL_ENTER("ImportKeyState");

    if (exp == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    keys = &(ssl->keys);

    /* check minimum length -- includes byte used for size indicators */
    if (len < DTLS_EXPORT_MIN_KEY_SZ) {
        WOLFSSL_MSG("Buffer not large enough for minimum expected size");
        return BUFFER_E;
    }
    ato32(exp + idx, &keys->peer_sequence_number_hi); idx += OPAQUE32_LEN;
    ato32(exp + idx, &keys->peer_sequence_number_lo); idx += OPAQUE32_LEN;
    ato32(exp + idx, &keys->sequence_number_hi);      idx += OPAQUE32_LEN;
    ato32(exp + idx, &keys->sequence_number_lo);      idx += OPAQUE32_LEN;

    #if defined(WOLFSSL_DTLS)
    if (type == WOLFSSL_EXPORT_DTLS) {
        ato16(exp + idx, &keys->peerSeq[0].nextEpoch);  idx += OPAQUE16_LEN;
        ato16(exp + idx, &keys->peerSeq[0].nextSeq_hi); idx += OPAQUE16_LEN;
        ato32(exp + idx, &keys->peerSeq[0].nextSeq_lo); idx += OPAQUE32_LEN;
        ato16(exp + idx, &keys->curEpoch);   idx += OPAQUE16_LEN;
        ato16(exp + idx, &keys->curSeq_hi);  idx += OPAQUE16_LEN;
        ato32(exp + idx, &keys->curSeq_lo);  idx += OPAQUE32_LEN;
        ato16(exp + idx, &keys->peerSeq[0].prevSeq_hi); idx += OPAQUE16_LEN;
        ato32(exp + idx, &keys->peerSeq[0].prevSeq_lo); idx += OPAQUE32_LEN;

        ato16(exp + idx, &keys->dtls_peer_handshake_number);
        idx += OPAQUE16_LEN;
        ato16(exp + idx, &keys->dtls_expected_peer_handshake_number);
        idx += OPAQUE16_LEN;

        ato16(exp + idx, &keys->dtls_sequence_number_hi); idx += OPAQUE16_LEN;
        ato32(exp + idx, &keys->dtls_sequence_number_lo); idx += OPAQUE32_LEN;
        ato16(exp + idx, &keys->dtls_prev_sequence_number_hi);
        idx += OPAQUE16_LEN;
        ato32(exp + idx, &keys->dtls_prev_sequence_number_lo);
        idx += OPAQUE32_LEN;
        ato16(exp + idx, &keys->dtls_epoch);              idx += OPAQUE16_LEN;
        ato16(exp + idx, &keys->dtls_handshake_number);   idx += OPAQUE16_LEN;
    }
    #endif
    ato32(exp + idx, &keys->encryptSz);                   idx += OPAQUE32_LEN;
    ato32(exp + idx, &keys->padSz);                       idx += OPAQUE32_LEN;
    keys->encryptionOn = exp[idx++];
    keys->decryptedCur = exp[idx++];

    #if defined(WOLFSSL_DTLS)
    if (type == WOLFSSL_EXPORT_DTLS) {
        word16 i, wordCount, wordAdj = 0;

        /* do window */
        ato16(exp + idx, &wordCount);
        idx += OPAQUE16_LEN;

        if (wordCount > WOLFSSL_DTLS_WINDOW_WORDS) {
            wordCount = WOLFSSL_DTLS_WINDOW_WORDS;
            wordAdj = (WOLFSSL_DTLS_WINDOW_WORDS - wordCount) * sizeof(word32);
        }

        XMEMSET(keys->peerSeq[0].window, 0xFF, DTLS_SEQ_SZ);
        for (i = 0; i < wordCount; i++) {
            ato32(exp + idx, &keys->peerSeq[0].window[i]);
            idx += OPAQUE32_LEN;
        }
        idx += wordAdj;

        /* do prevWindow */
        ato16(exp + idx, &wordCount);
        idx += OPAQUE16_LEN;

        if (wordCount > WOLFSSL_DTLS_WINDOW_WORDS) {
            wordCount = WOLFSSL_DTLS_WINDOW_WORDS;
            wordAdj = (WOLFSSL_DTLS_WINDOW_WORDS - wordCount) * sizeof(word32);
        }

        XMEMSET(keys->peerSeq[0].prevWindow, 0xFF, DTLS_SEQ_SZ);
        for (i = 0; i < wordCount; i++) {
            ato32(exp + idx, &keys->peerSeq[0].prevWindow[i]);
            idx += OPAQUE32_LEN;
        }
        idx += wordAdj;

    }
    #endif

#ifdef HAVE_TRUNCATED_HMAC
    ssl->truncated_hmac = exp[idx++];
#else
    idx++; /* no truncated hmac */
#endif
    sz = exp[idx++];
#ifndef WOLFSSL_AEAD_ONLY
    if (sz > sizeof(keys->client_write_MAC_secret) || (sz * 2) + idx > len) {
        WOLFSSL_MSG("Buffer not large enough for MAC import");
        return BUFFER_E;
    }
    if (sz > 0) {
        XMEMCPY(keys->client_write_MAC_secret, exp + idx, sz); idx += sz;
        XMEMCPY(keys->server_write_MAC_secret, exp + idx, sz); idx += sz;
    }
#else
    if (sz + idx > len) {
        return BUFFER_E;
    }
    idx += sz; idx += sz;
#endif

    sz = exp[idx++];
    if (sz > sizeof(keys->client_write_key) || (sz * 2) + idx > len) {
        WOLFSSL_MSG("Buffer not large enough for key import");
        return BUFFER_E;
    }
    if (sz > 0) {
        XMEMCPY(keys->client_write_key, exp + idx, sz); idx += sz;
        XMEMCPY(keys->server_write_key, exp + idx, sz); idx += sz;
    }

    sz = exp[idx++];
    if (sz > sizeof(keys->client_write_IV) || (sz * 2) + idx > len) {
        WOLFSSL_MSG("Buffer not large enough for write IV import");
        return BUFFER_E;
    }
    if (sz > 0) {
        XMEMCPY(keys->client_write_IV, exp + idx, sz); idx += sz;
        XMEMCPY(keys->server_write_IV, exp + idx, sz); idx += sz;
    }
    XMEMCPY(keys->aead_exp_IV, exp + idx, AEAD_MAX_EXP_SZ);
    idx += AEAD_MAX_EXP_SZ;

    sz = exp[idx++];
    if (sz > sizeof(keys->aead_enc_imp_IV) || (sz * 2) + idx > len) {
        WOLFSSL_MSG("Buffer not large enough for imp IV import");
        return BUFFER_E;
    }
    if (sz > 0) {
        XMEMCPY(keys->aead_enc_imp_IV, exp + idx, sz); idx += sz;
        XMEMCPY(keys->aead_dec_imp_IV, exp + idx, sz); idx += sz;
    }

    WOLFSSL_LEAVE("ImportKeyState", idx);
    (void)ver;
    (void)type;
    return idx;
}


/* copy over necessary information from Options struct to buffer
 * On success returns size of buffer used on failure returns a negative value */
static int ExportOptions(WOLFSSL* ssl, byte* exp, word32 len, byte ver,
        int type)
{
    int      idx  = 0;
    word16   zero = 0;
    Options *options;

    WOLFSSL_ENTER("ExportOptions");

    if (ssl == NULL || exp == NULL || len < DTLS_EXPORT_OPT_SZ) {
        return BAD_FUNC_ARG;
    }

    options = &ssl->options;
    if (options == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(exp, 0, DTLS_EXPORT_OPT_SZ);

    /* these options are kept and sent to indicate verify status and strength
     * of handshake */
    exp[idx++] = options->sendVerify;
    exp[idx++] = options->verifyPeer;
    exp[idx++] = options->verifyNone;
    exp[idx++] = options->downgrade;
#ifndef NO_DH
    c16toa(options->minDhKeySz, exp + idx); idx += OPAQUE16_LEN;
    c16toa(options->maxDhKeySz, exp + idx); idx += OPAQUE16_LEN;
    c16toa(options->dhKeySz, exp + idx);    idx += OPAQUE16_LEN;
#else
    c16toa(zero, exp + idx); idx += OPAQUE16_LEN;
    c16toa(zero, exp + idx); idx += OPAQUE16_LEN;
    c16toa(zero, exp + idx); idx += OPAQUE16_LEN;
#endif
#ifndef NO_RSA
    c16toa((word16)(options->minRsaKeySz), exp + idx); idx += OPAQUE16_LEN;
#else
    c16toa(zero, exp + idx); idx += OPAQUE16_LEN;
#endif
#ifdef HAVE_ECC
    c16toa((word16)(options->minEccKeySz), exp + idx); idx += OPAQUE16_LEN;
#else
    c16toa(zero, exp + idx); idx += OPAQUE16_LEN;
#endif

    /* these options are kept to indicate state and behavior */
#ifndef NO_PSK
    exp[idx++] = options->havePSK;
#else
    exp[idx++] = 0;
#endif
    exp[idx++] = options->sessionCacheOff;
    exp[idx++] = options->sessionCacheFlushOff;
    exp[idx++] = options->side;
    exp[idx++] = options->resuming;
    exp[idx++] = options->haveSessionId;
    exp[idx++] = options->tls;
    exp[idx++] = options->tls1_1;
    exp[idx++] = options->dtls;
    exp[idx++] = options->connReset;
    exp[idx++] = options->isClosed;
    exp[idx++] = options->closeNotify;
    exp[idx++] = options->sentNotify;
    exp[idx++] = options->usingCompression;
    exp[idx++] = options->haveRSA;
    exp[idx++] = options->haveECC;
    exp[idx++] = options->haveDH;
    exp[idx++] = 0; /* Historical: haveNTRU */
    exp[idx++] = 0; /* Historical: haveQSH */
    exp[idx++] = options->haveECDSAsig;
    exp[idx++] = options->haveStaticECC;
    exp[idx++] = options->havePeerVerify;
    exp[idx++] = options->usingPSK_cipher;
    exp[idx++] = options->usingAnon_cipher;
    exp[idx++] = 0; /* Historical: options->sendAlertState */
    exp[idx++] = options->partialWrite;
    exp[idx++] = options->quietShutdown;
    exp[idx++] = options->groupMessages;
#ifdef HAVE_POLY1305
    exp[idx++] = options->oldPoly;
#else
    exp[idx++] = 0;
#endif
#ifdef HAVE_ANON
    exp[idx++] = options->haveAnon;
#else
    exp[idx++] = 0;
#endif
#ifdef HAVE_SESSION_TICKET
    exp[idx++] = options->createTicket;
    exp[idx++] = options->useTicket;
    exp[idx++] = options->noTicketTls12;
#ifdef WOLFSSL_TLS13
    if (ver > WOLFSSL_EXPORT_VERSION_3) {
        exp[idx++] = options->noTicketTls13;
    }
#else
    if (ver > WOLFSSL_EXPORT_VERSION_3) {
        exp[idx++] = 0;
    }
#endif
#else
    exp[idx++] = 0;
    exp[idx++] = 0;
    exp[idx++] = 0;
    if (ver > WOLFSSL_EXPORT_VERSION_3) {
        exp[idx++] = 0;
    }
#endif
    exp[idx++] = options->processReply;
    exp[idx++] = options->cipherSuite0;
    exp[idx++] = options->cipherSuite;
    exp[idx++] = options->serverState;
    exp[idx++] = options->clientState;
    exp[idx++] = options->handShakeState;
    exp[idx++] = options->handShakeDone;
    exp[idx++] = options->minDowngrade;
    exp[idx++] = options->connectState;
    exp[idx++] = options->acceptState;
    exp[idx++] = options->asyncState;

    if (type == WOLFSSL_EXPORT_TLS) {
#ifdef HAVE_ENCRYPT_THEN_MAC
        exp[idx++] = options->disallowEncThenMac;
        exp[idx++] = options->encThenMac;
        exp[idx++] = options->startedETMRead;
        exp[idx++] = options->startedETMWrite;
#else
        exp[idx++] = 0;
        exp[idx++] = 0;
        exp[idx++] = 0;
        exp[idx++] = 0;
#endif
    }

    /* version of connection */
    exp[idx++] = ssl->version.major;
    exp[idx++] = ssl->version.minor;

    (void)zero;

    /* check if changes were made and notify of need to update export version */
    switch (ver) {
        case WOLFSSL_EXPORT_VERSION_3:
            if (idx != DTLS_EXPORT_OPT_SZ_3) {
                WOLFSSL_MSG("Update DTLS_EXPORT_OPT_SZ and version of export");
                return DTLS_EXPORT_VER_E;
            }
            break;

        case WOLFSSL_EXPORT_VERSION:
            if (idx != DTLS_EXPORT_OPT_SZ && type == WOLFSSL_EXPORT_DTLS) {
                WOLFSSL_MSG("Update DTLS_EXPORT_OPT_SZ and version of export");
                return DTLS_EXPORT_VER_E;
            }
            break;

       default:
            WOLFSSL_MSG("New version case needs added to wolfSSL export");
            return DTLS_EXPORT_VER_E;
    }

    WOLFSSL_LEAVE("ExportOptions", idx);

    (void)type;
    return idx;
}


/* copy items from Export struct to Options struct
 * On success returns size of buffer used on failure returns a negative value */
static int ImportOptions(WOLFSSL* ssl, const byte* exp, word32 len, byte ver,
        int type)
{
    int idx = 0;
    Options* options = &ssl->options;

    switch (ver) {
        case WOLFSSL_EXPORT_VERSION:
            if (len < DTLS_EXPORT_OPT_SZ) {
                WOLFSSL_MSG("Sanity check on buffer size failed");
                return BAD_FUNC_ARG;
            }
            break;

        case WOLFSSL_EXPORT_VERSION_3:
            if (len < DTLS_EXPORT_OPT_SZ_3) {
                WOLFSSL_MSG("Sanity check on buffer size failed");
                return BAD_FUNC_ARG;
            }
            break;

        default:
            WOLFSSL_MSG("Export version not supported");
            return BAD_FUNC_ARG;
    }

    if (exp == NULL || options == NULL) {
        return BAD_FUNC_ARG;
    }


    /* these options are kept and sent to indicate verify status and strength
     * of handshake */
    options->sendVerify = exp[idx++];
    options->verifyPeer = exp[idx++];
    options->verifyNone = exp[idx++];
    options->downgrade  = exp[idx++];
#ifndef NO_DH
    ato16(exp + idx, &(options->minDhKeySz)); idx += OPAQUE16_LEN;
    ato16(exp + idx, &(options->maxDhKeySz)); idx += OPAQUE16_LEN;
    ato16(exp + idx, &(options->dhKeySz));    idx += OPAQUE16_LEN;
#else
    idx += OPAQUE16_LEN;
    idx += OPAQUE16_LEN;
    idx += OPAQUE16_LEN;
#endif
#ifndef NO_RSA
    ato16(exp + idx, (word16*)&(options->minRsaKeySz)); idx += OPAQUE16_LEN;
#else
    idx += OPAQUE16_LEN;
#endif
#ifdef HAVE_ECC
    ato16(exp + idx, (word16*)&(options->minEccKeySz)); idx += OPAQUE16_LEN;
#else
    idx += OPAQUE16_LEN;
#endif

    /* these options are kept to indicate state and behavior */
#ifndef NO_PSK
    options->havePSK = exp[idx++];
#else
    idx++;
#endif
    options->sessionCacheOff      = exp[idx++];
    options->sessionCacheFlushOff = exp[idx++];
    options->side                 = exp[idx++];
    options->resuming             = exp[idx++];
    options->haveSessionId    = exp[idx++];
    options->tls              = exp[idx++];
    options->tls1_1           = exp[idx++];
    options->dtls             = exp[idx++];
    options->connReset        = exp[idx++];
    options->isClosed         = exp[idx++];
    options->closeNotify      = exp[idx++];
    options->sentNotify       = exp[idx++];
    options->usingCompression = exp[idx++];
    options->haveRSA          = exp[idx++];
    options->haveECC          = exp[idx++];
    options->haveDH           = exp[idx++];
    idx++; /* Historical: haveNTRU */
    idx++; /* Historical: haveQSH */
    options->haveECDSAsig     = exp[idx++];
    options->haveStaticECC    = exp[idx++];
    options->havePeerVerify   = exp[idx++];
    options->usingPSK_cipher  = exp[idx++];
    options->usingAnon_cipher = exp[idx++];
    idx++; /* Historical: options->sendAlertState */
    options->partialWrite     = exp[idx++];
    options->quietShutdown    = exp[idx++];
    options->groupMessages    = exp[idx++];
#ifdef HAVE_POLY1305
    options->oldPoly = exp[idx++];      /* set when to use old rfc way of poly*/
#else
    idx++;
#endif
#ifdef HAVE_ANON
    options->haveAnon = exp[idx++];     /* User wants to allow Anon suites */
#else
    idx++;
#endif
#ifdef HAVE_SESSION_TICKET
    options->createTicket  = exp[idx++]; /* Server to create new Ticket */
    options->useTicket     = exp[idx++]; /* Use Ticket not session cache */
    options->noTicketTls12 = exp[idx++]; /* Server won't create new Ticket */
#ifdef WOLFSSL_TLS13
    if (ver > WOLFSSL_EXPORT_VERSION_3) {
        options->noTicketTls13 = exp[idx++];/* Server won't create new Ticket */
    }
#else
    if (ver > WOLFSSL_EXPORT_VERSION_3) {
        idx++;
    }
#endif
#else
    idx++;
    idx++;
    idx++;
    if (ver > WOLFSSL_EXPORT_VERSION_3) {
        idx++;
    }
#endif
    options->processReply   = exp[idx++];
    options->cipherSuite0   = exp[idx++];
    options->cipherSuite    = exp[idx++];
    options->serverState    = exp[idx++];
    options->clientState    = exp[idx++];
    options->handShakeState = exp[idx++];
    options->handShakeDone  = exp[idx++];
    options->minDowngrade   = exp[idx++];
    options->connectState   = exp[idx++];
    options->acceptState    = exp[idx++];
    options->asyncState     = exp[idx++];

    if (type == WOLFSSL_EXPORT_TLS) {
#ifdef HAVE_ENCRYPT_THEN_MAC
        options->disallowEncThenMac = exp[idx++];
        options->encThenMac         = exp[idx++];
        options->startedETMRead     = exp[idx++];
        options->startedETMWrite    = exp[idx++];
#else
        idx++;
        idx++;
        idx++;
        idx++;
#endif
    }

    /* version of connection */
    if (ssl->version.major != exp[idx++] || ssl->version.minor != exp[idx++]) {
        WOLFSSL_MSG("Version mismatch ie DTLS v1 vs v1.2");
        return VERSION_ERROR;
    }

    /* set TLS 1.3 flag in options if this was a TLS 1.3 connection */
    if (ssl->version.major == SSLv3_MAJOR &&
            ssl->version.minor == TLSv1_3_MINOR) {
        options->tls1_3 = 1;
    }

    return idx;
}


#ifndef WOLFSSL_SESSION_EXPORT_NOPEER
static int ExportPeerInfo(WOLFSSL* ssl, byte* exp, word32 len, byte ver)
{
    int    idx  = 0;
    int    ipSz = MAX_EXPORT_IP; /* start as max size */
    int    fam  = 0;
    word16 port = 0;
    char   ip[MAX_EXPORT_IP];

    if (ver != WOLFSSL_EXPORT_VERSION) {
        WOLFSSL_MSG("Export version not supported");
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL || exp == NULL ||
            len < (sizeof(ip) + 3 * WOLFSSL_EXPORT_LEN)) {
        return BAD_FUNC_ARG;
    }

    if (ssl->ctx->CBGetPeer == NULL) {
        WOLFSSL_MSG("No get peer call back set");
        return BAD_FUNC_ARG;
    }
    if (ssl->ctx->CBGetPeer(ssl, ip, &ipSz, &port, &fam) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Get peer callback error");
        return SOCKET_ERROR_E;
    }

    /* check that ipSz/fam is not negative or too large since user can set cb */
    if (ipSz < 0 || ipSz > MAX_EXPORT_IP || fam < 0) {
        WOLFSSL_MSG("Bad ipSz or fam returned from get peer callback");
        return SOCKET_ERROR_E;
    }

    c16toa((word16)fam, exp + idx);  idx += WOLFSSL_EXPORT_LEN;
    c16toa((word16)ipSz, exp + idx); idx += WOLFSSL_EXPORT_LEN;
    XMEMCPY(exp + idx, ip, ipSz);    idx += ipSz;
    c16toa(port, exp + idx);         idx += WOLFSSL_EXPORT_LEN;

    return idx;
}
#endif /* !WOLFSSL_SESSION_EXPORT_NOPEER */


static int ImportPeerInfo(WOLFSSL* ssl, const byte* buf, word32 len, byte ver)
{
    word16 idx = 0;
    word16 ipSz;
    word16 fam;
    word16 port;
    char   ip[MAX_EXPORT_IP];

    if (ver != WOLFSSL_EXPORT_VERSION && ver != WOLFSSL_EXPORT_VERSION_3) {
        WOLFSSL_MSG("Export version not supported");
        return BAD_FUNC_ARG;
    }

    if (len == 0) {
        WOLFSSL_MSG("No peer info sent");
        return 0;
    }

    if (ssl == NULL || buf == NULL || len < 3 * WOLFSSL_EXPORT_LEN) {
        return BAD_FUNC_ARG;
    }

    /* import sin family */
    ato16(buf + idx, &fam); idx += WOLFSSL_EXPORT_LEN;

    /* import ip address idx, and ipSz are unsigned but cast for enum */
    ato16(buf + idx, &ipSz); idx += WOLFSSL_EXPORT_LEN;
    if (ipSz >= sizeof(ip) || (word16)(idx + ipSz + WOLFSSL_EXPORT_LEN) > len) {
        return BUFFER_E;
    }
    XMEMSET(ip, 0, sizeof(ip));
    XMEMCPY(ip, buf + idx, ipSz); idx += ipSz;
    ip[ipSz] = '\0'; /* with check that ipSz less than ip this is valid */
    ato16(buf + idx, &port); idx += WOLFSSL_EXPORT_LEN;

    /* sanity check for a function to call, then use it to import peer info */
    if (ssl->ctx->CBSetPeer == NULL) {
        WOLFSSL_MSG("No set peer function");
        return BAD_FUNC_ARG;
    }
    if (ssl->ctx->CBSetPeer(ssl, ip, ipSz, port, fam) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("Error setting peer info");
        return SOCKET_ERROR_E;
    }

    return idx;
}


#ifdef WOLFSSL_DTLS
/* WOLFSSL_LOCAL function that serializes the current WOLFSSL session state only
 * buf is used to hold the serialized WOLFSSL struct and sz is the size of buf
 * passed in.
 * On success returns the size of serialized session state.*/
int wolfSSL_dtls_export_state_internal(WOLFSSL* ssl, byte* buf, word32 sz)
{
    int ret;
    word32 idx      = 0;
    word32 totalLen = 0;

    WOLFSSL_ENTER("wolfSSL_dtls_export_state_internal");

    if (buf == NULL || ssl == NULL) {
        WOLFSSL_LEAVE("wolfSSL_dtls_export_state_internal", BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }

    totalLen += WOLFSSL_EXPORT_LEN * 2; /* 2 protocol bytes and 2 length bytes */
    /* each of the following have a 2 byte length before data */
    totalLen += WOLFSSL_EXPORT_LEN + DTLS_EXPORT_MIN_KEY_SZ;
    if (totalLen > sz) {
        WOLFSSL_LEAVE("wolfSSL_dtls_export_state_internal", BUFFER_E);
        return BUFFER_E;
    }

    buf[idx++] =  (byte)DTLS_EXPORT_STATE_PRO;
    buf[idx++] = ((byte)DTLS_EXPORT_STATE_PRO & 0xF0) |
                 ((byte)WOLFSSL_EXPORT_VERSION & 0X0F);
    idx += WOLFSSL_EXPORT_LEN; /* leave room for total length */

    /* export keys struct and dtls state -- variable length stored in ret */
    idx += WOLFSSL_EXPORT_LEN; /* leave room for length */
    if ((ret = ExportKeyState(ssl, buf + idx, sz - idx,
                    WOLFSSL_EXPORT_VERSION, 1, WOLFSSL_EXPORT_DTLS)) < 0) {
        WOLFSSL_LEAVE("wolfSSL_dtls_export_state_internal", ret);
        return ret;
    }
    c16toa((word16)ret, buf + idx - WOLFSSL_EXPORT_LEN); idx += ret;

    /* place total length of exported buffer minus 2 bytes protocol/version */
    c16toa((word16)(idx - WOLFSSL_EXPORT_LEN), buf + WOLFSSL_EXPORT_LEN);

#ifdef WOLFSSL_SESSION_EXPORT_DEBUG
    /* if compiled with debug options then print the version, protocol, size */
    {
        char debug[256];
        XSNPRINTF(debug, sizeof(debug), "Exporting DTLS session state\n"
                   "\tVersion  : %d\n\tProtocol : %02X%01X\n\tLength of: %d\n\n"
               , (int)WOLFSSL_EXPORT_VERSION, buf[0], (buf[1] >> 4), idx - 2);
        WOLFSSL_MSG(debug);
    }
#endif /* WOLFSSL_SESSION_EXPORT_DEBUG */

    WOLFSSL_LEAVE("wolfSSL_dtls_export_state_internal", idx);
    return idx;
}


/* On success return amount of buffer consumed */
int wolfSSL_dtls_import_state_internal(WOLFSSL* ssl, const byte* buf, word32 sz)
{
    word32 idx    = 0;
    word16 length = 0;
    int version;
    int ret;

    WOLFSSL_ENTER("wolfSSL_dtls_import_state_internal");
    /* check at least enough room for protocol and length */
    if (sz < WOLFSSL_EXPORT_LEN * 2 || ssl == NULL) {
        WOLFSSL_LEAVE("wolfSSL_dtls_import_state_internal", BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }

    if (buf[idx++] !=  (byte)DTLS_EXPORT_STATE_PRO ||
            (buf[idx] & 0xF0) != ((byte)DTLS_EXPORT_PRO & 0xF0)) {
        WOLFSSL_MSG("Incorrect protocol");
        return BAD_FUNC_ARG;
    }
    version = buf[idx++] & 0x0F;

    ato16(buf + idx, &length); idx += WOLFSSL_EXPORT_LEN;
    if (length > sz - WOLFSSL_EXPORT_LEN) { /* subtract 2 for protocol */
        WOLFSSL_MSG("Buffer size sanity check failed");
        return BUFFER_E;
    }

#ifdef WOLFSSL_SESSION_EXPORT_DEBUG
    /* if compiled with debug options then print the version, protocol, size */
    {
        char debug[256];
        XSNPRINTF(debug, sizeof(debug), "Importing DTLS session state\n"
                   "\tVersion  : %d\n\tProtocol : %02X%01X\n\tLength of: %d\n\n"
               , (int)version, buf[0], (buf[1] >> 4), length);
        WOLFSSL_MSG(debug);
    }
#endif /* WOLFSSL_SESSION_EXPORT_DEBUG */

    /* perform sanity checks and extract Options information used */
    switch (version) {
        case WOLFSSL_EXPORT_VERSION:
            break;

        default:
            WOLFSSL_MSG("Bad export state version");
            return BAD_FUNC_ARG;

    }

    /* perform sanity checks and extract Keys struct */
    if (WOLFSSL_EXPORT_LEN + idx > sz) {
        WOLFSSL_MSG("Import Key struct error");
        return BUFFER_E;
    }
    ato16(buf + idx, &length); idx += WOLFSSL_EXPORT_LEN;
    if (length > DTLS_EXPORT_KEY_SZ || length + idx > sz) {
        WOLFSSL_MSG("Import Key struct error");
        return BUFFER_E;
    }
    if ((ret = ImportKeyState(ssl, buf + idx, length, version,
                    WOLFSSL_EXPORT_DTLS)) < 0) {
        WOLFSSL_MSG("Import Key struct error");
        WOLFSSL_LEAVE("wolfSSL_dtls_import_state_internal", ret);
        return ret;
    }
    idx += ret;

    WOLFSSL_LEAVE("wolfSSL_dtls_import_state_internal", ret);
    return idx;
}
#endif /* WOLFSSL_DTLS */


/**
 * Imports a serialized buffer (both TLS and DTLS)
 *
 * @param ssl WOLFSSL structure to import into
 * @param buf buffer containing serialized session
 * @param sz  size of buffer 'buf'
 * @param type flag for TLS or DTLS
 *
 * @return the size of serialized buffer on success
 */
int wolfSSL_session_import_internal(WOLFSSL* ssl, const unsigned char* buf,
        unsigned int sz, int type)
{
    word32 idx    = 0;
    word16 length = 0;
    int version   = 0;
    int ret = 0;
    int optSz = 0;
    int rc;
    byte validProto = 0; /* did we find a valid protocol */

    WOLFSSL_ENTER("wolfSSL_session_import_internal");
    /* check at least enough room for protocol and length */
    if (sz < WOLFSSL_EXPORT_LEN * 2 || ssl == NULL) {
        ret = BAD_FUNC_ARG;
    }

    /* Check if is TLS export protocol */
    if (ret == 0) {
        if (buf[idx]             ==  (byte)TLS_EXPORT_PRO &&
           (buf[idx + 1] & 0xF0) == ((byte)TLS_EXPORT_PRO & 0xF0)) {
            validProto = 1;
        }

        /* Check if is DTLS export protocol */
        if (buf[idx]             ==  (byte)DTLS_EXPORT_PRO &&
           (buf[idx + 1] & 0xF0) == ((byte)DTLS_EXPORT_PRO & 0xF0)) {
            validProto = 1;
        }

        if (validProto == 0) {
        #ifdef WOLFSSL_DTLS
            /* check if importing state only */
            return wolfSSL_dtls_import_state_internal(ssl, buf, sz);
        #else
            WOLFSSL_MSG("Invalid serialized session protocol value");
            ret = BAD_FUNC_ARG;
        #endif
        }
        idx += 1;
    }

    if (ret == 0) {
        version = buf[idx++] & 0x0F;
        ato16(buf + idx, &length); idx += WOLFSSL_EXPORT_LEN;
        if (length > sz - WOLFSSL_EXPORT_LEN) { /* subtract 2 for protocol */
            ret = BUFFER_E;
        }
    }

    /* if compiled with debug options then print the version, protocol, size */
#ifdef WOLFSSL_SESSION_EXPORT_DEBUG
    {
        char debug[256];
        XSNPRINTF(debug, sizeof(debug), "Importing DTLS session\n"
                   "\tVersion  : %d\n\tProtocol : %02X%01X\n\tLength of: %d\n\n"
               , (int)version, buf[0], (buf[1] >> 4), length);
        WOLFSSL_MSG(debug);
    }
#endif /* WOLFSSL_SESSION_EXPORT_DEBUG */

    /* perform sanity checks and extract Options information used */
    if (ret == 0) {
        switch (version) {
            case WOLFSSL_EXPORT_VERSION:
                if (type == WOLFSSL_EXPORT_DTLS) {
                    optSz = DTLS_EXPORT_OPT_SZ;
                }
                else {
                    optSz = TLS_EXPORT_OPT_SZ;
                }
                break;

            case WOLFSSL_EXPORT_VERSION_3:
                WOLFSSL_MSG("Importing older version 3");
                optSz = DTLS_EXPORT_OPT_SZ_3;
                break;

            default:
                WOLFSSL_MSG("Bad export version");
                ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0 && (WOLFSSL_EXPORT_LEN + optSz + idx > sz)) {
        WOLFSSL_MSG("Import Options struct error");
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ato16(buf + idx, &length); idx += WOLFSSL_EXPORT_LEN;
        if (length != optSz) {
            WOLFSSL_MSG("Import Options struct error");
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        rc = ImportOptions(ssl, buf + idx, length, version, type);
        if (rc < 0) {
            WOLFSSL_MSG("Import Options struct error");
            ret = rc;
        }
        else {
            idx += length;
        }
    }

    /* perform sanity checks and extract Keys struct */
    if (ret == 0 && (WOLFSSL_EXPORT_LEN + idx > sz)) {
        WOLFSSL_MSG("Import Key struct error");
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ato16(buf + idx, &length); idx += WOLFSSL_EXPORT_LEN;
        if (length > DTLS_EXPORT_KEY_SZ || length + idx > sz) {
            WOLFSSL_MSG("Import Key struct error");
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        rc = ImportKeyState(ssl, buf + idx, length, version, type);
        if (rc < 0) {
            WOLFSSL_MSG("Import Key struct error");
            ret = rc;
        }
        else {
            idx += rc;
        }
    }

    /* perform sanity checks and extract CipherSpecs struct */
    if (ret == 0 && (WOLFSSL_EXPORT_LEN + WOLFSSL_EXPORT_SPC_SZ + idx > sz)) {
        WOLFSSL_MSG("Import CipherSpecs struct error");
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ato16(buf + idx, &length); idx += WOLFSSL_EXPORT_LEN;
        if (length != WOLFSSL_EXPORT_SPC_SZ) {
            WOLFSSL_MSG("Import CipherSpecs struct error");
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        rc = ImportCipherSpecState(ssl, buf + idx, length, version, type);
        if (rc < 0) {
            WOLFSSL_MSG("Import CipherSpecs struct error");
            ret = rc;
        }
        else {
            idx += rc;
        }
    }

    /* perform sanity checks and extract DTLS peer info */
    if (ret == 0 && (WOLFSSL_EXPORT_LEN + idx > sz)) {
        WOLFSSL_MSG("Import DTLS peer info error");
        ret = BUFFER_E;
    }

    if (ret == 0) {
        ato16(buf + idx, &length); idx += WOLFSSL_EXPORT_LEN;
        if (idx + length > sz) {
            WOLFSSL_MSG("Import DTLS peer info error");
            ret = BUFFER_E;
        }
    }

    if (ret == 0) {
        rc = ImportPeerInfo(ssl, buf + idx, length, version);
        if (rc < 0) {
            WOLFSSL_MSG("Import Peer Addr error");
            ret = rc;
        }
        else {
            idx += rc;
        }
    }

    /* make sure is a valid suite used */
    if (ret == 0 && wolfSSL_get_cipher(ssl) == NULL) {
        WOLFSSL_MSG("Can not match cipher suite imported");
        ret = MATCH_SUITE_ERROR;
    }

#ifndef WOLFSSL_AEAD_ONLY
    /* set hmac function to use when verifying */
    if (ret == 0 && (ssl->options.tls == 1 || ssl->options.tls1_1 == 1 ||
                     ssl->options.dtls == 1)) {
    #if !defined(WOLFSSL_RENESAS_SCEPROTECT) && \
        !defined(WOLFSSL_RENESAS_TSIP_TLS)
        ssl->hmac = TLS_hmac;
    #else
        ssl->hmac = Renesas_cmn_TLS_hmac;
    #endif
    }

    /* do not allow stream ciphers with DTLS, except for NULL cipher */
    if (ret == 0 && ssl->specs.cipher_type == stream &&
        ssl->specs.bulk_cipher_algorithm != wolfssl_cipher_null) {
        WOLFSSL_MSG("Can not import stream ciphers for DTLS");
        ret = SANITY_CIPHER_E;
    }
#endif /* !WOLFSSL_AEAD_ONLY */

    if (ret != 0) {
        idx = ret;
    }
    WOLFSSL_LEAVE("wolfSSL_session_import_internal", idx);
    return idx;
}


/**
 * Handles serializing the session information.
 *
 * @param ssl WOLFSSL structure to serialize session from
 * @param buf output buffer to hold serialized session
 * @param sz  the size of buffer 'buf', if too small then gets updated
 * @param type if the input WOLFSSL structure is expected to be TLS or DTLS
 *              1 for yes is TLS and 0 for no is DTLS
 *
 * @return the size of serialized buffer on success and negative values on fail
 */
int wolfSSL_session_export_internal(WOLFSSL* ssl, byte* buf, word32* sz,
        int type)
{
    int ret = 0;
    word32 idx      = 0;
    word32 totalLen = 0;

    WOLFSSL_ENTER("wolfSSL_session_export_internal");

    if (ssl == NULL) {
        WOLFSSL_MSG("unexpected null argument");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        totalLen += WOLFSSL_EXPORT_LEN * 2; /* 2 protocol bytes and 2 length bytes */
        /* each of the following have a 2 byte length before data */
        totalLen += WOLFSSL_EXPORT_LEN + DTLS_EXPORT_OPT_SZ;
        totalLen += WOLFSSL_EXPORT_LEN + DTLS_EXPORT_KEY_SZ;
        totalLen += WOLFSSL_EXPORT_LEN + WOLFSSL_EXPORT_SPC_SZ;
        #ifdef WOLFSSL_DTLS
        if (type == WOLFSSL_EXPORT_DTLS) {
            totalLen += WOLFSSL_EXPORT_LEN + ssl->buffers.dtlsCtx.peer.sz;
        }
        #endif
    }

    /* check is at least the minimum size needed, TLS cipher states add more */
    if (ret == 0 && (totalLen > *sz || buf == NULL)) {
        WOLFSSL_MSG("export buffer was too small or null");
        *sz = totalLen;

        /* possible AES state needed */
        if (type == WOLFSSL_EXPORT_TLS) {
            *sz += AES_BLOCK_SIZE*2;
        }
        ret = LENGTH_ONLY_E;
    }

    if (ret == 0) {
        buf[idx++] =  (byte)(type == WOLFSSL_EXPORT_TLS)? TLS_EXPORT_PRO :
                    DTLS_EXPORT_PRO;
        buf[idx++] = ((byte)((type == WOLFSSL_EXPORT_TLS)? TLS_EXPORT_PRO :
                    DTLS_EXPORT_PRO) & 0xF0)
                    | ((byte)WOLFSSL_EXPORT_VERSION & 0X0F);

        idx += WOLFSSL_EXPORT_LEN; /* leave spot for length of total buffer  */

        idx += WOLFSSL_EXPORT_LEN;
        ret = ExportOptions(ssl, buf + idx, *sz - idx, WOLFSSL_EXPORT_VERSION,
                type);
        if (ret >= 0) {
            c16toa((word16)ret, buf + idx - WOLFSSL_EXPORT_LEN);
            idx += ret;
            ret  = 0;
        }
    }

    /* export keys struct and dtls state -- variable length stored in ret */
    if (ret == 0) {
        idx += WOLFSSL_EXPORT_LEN; /* leave room for length */
        ret = ExportKeyState(ssl, buf + idx, *sz - idx, WOLFSSL_EXPORT_VERSION,
                0, type);
        if (ret >= 0) {
            c16toa((word16)ret, buf + idx - WOLFSSL_EXPORT_LEN); idx += ret;
            ret = 0;
        }
    }

    /* export of cipher specs struct */
    if (ret == 0) {
        c16toa((word16)WOLFSSL_EXPORT_SPC_SZ, buf + idx);
        idx += WOLFSSL_EXPORT_LEN;
        ret = ExportCipherSpecState(ssl, buf + idx, *sz - idx,
                                                 WOLFSSL_EXPORT_VERSION, type);
        if (ret >= 0) {
            idx += ret;
            ret  = 0;
        }
    }

    /* export of peer information */
    if (ret == 0) {
        idx += WOLFSSL_EXPORT_LEN;
    #ifdef WOLFSSL_SESSION_EXPORT_NOPEER
        ret = 0; /* not saving peer port/ip information */
    #else
        ret = ExportPeerInfo(ssl, buf + idx, *sz - idx, WOLFSSL_EXPORT_VERSION);
    #endif
        if (ret >= 0) {
            c16toa(ret, buf + idx - WOLFSSL_EXPORT_LEN);
            idx += ret;
            ret  = 0;
        }
    }

    if (ret != 0 && buf != NULL) {
        /*in a fail case clear the buffer which could contain partial key info*/
        XMEMSET(buf, 0, *sz);
    }

    /* place total length of exported buffer minus 2 bytes protocol/version */
    if (ret == 0) {
        c16toa((word16)(idx - WOLFSSL_EXPORT_LEN), buf + WOLFSSL_EXPORT_LEN);
        ret = idx;

    #ifdef WOLFSSL_SESSION_EXPORT_DEBUG
        {
            char debug[256];
            XSNPRINTF(debug, sizeof(debug), "Exporting TLS session\n"
                   "\tVersion  : %d\n\tProtocol : %02X%01X\n\tLength of: %d\n\n"
                  ,(int)WOLFSSL_EXPORT_VERSION, buf[0], (buf[1] >> 4), idx - 2);
            WOLFSSL_MSG(debug);
        }
    #endif /* WOLFSSL_SESSION_EXPORT_DEBUG */
    }

    if (ret >= 0) {
        *sz = ret;
    }

    WOLFSSL_LEAVE("wolfSSL_session_export_internal", ret);
    return ret;
}
#endif /* WOLFSSL_SESSION_EXPORT */


void InitSSL_Method(WOLFSSL_METHOD* method, ProtocolVersion pv)
{
    method->version    = pv;
    method->side       = WOLFSSL_CLIENT_END;
    method->downgrade  = 0;
}

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EITHER_SIDE) || \
    defined(WOLFSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
int InitSSL_Side(WOLFSSL* ssl, word16 side)
{
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    /* set side */
    ssl->options.side = side;

    /* reset options that are side specific */
#ifdef HAVE_ECC
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ssl->options.haveECDSAsig  = 1; /* always on client side */
        ssl->options.haveECC = 1;       /* server turns on with ECC key cert */
        ssl->options.haveStaticECC = 1; /* server can turn on by loading key */
    }
#elif defined(HAVE_ED25519) || defined(HAVE_ED448)
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ssl->options.haveECDSAsig  = 1; /* always on client side */
        ssl->options.haveECC  = 1;      /* server turns on with ECC key cert */
    }
#endif
#ifdef HAVE_PQC
#ifdef HAVE_FALCON
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ssl->options.haveFalconSig  = 1; /* always on client side */
    }
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ssl->options.haveDilithiumSig  = 1; /* always on client side */
    }
#endif /* HAVE_DILITHIUM */
#endif /* HAVE_PQC */

#if defined(HAVE_EXTENDED_MASTER) && !defined(NO_WOLFSSL_CLIENT)
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        if ((ssl->ctx->method->version.major == SSLv3_MAJOR) &&
             (ssl->ctx->method->version.minor >= TLSv1_MINOR)) {
            ssl->options.haveEMS = 1;
        }
    #ifdef WOLFSSL_DTLS
        if (ssl->ctx->method->version.major == DTLS_MAJOR)
            ssl->options.haveEMS = 1;
    #endif /* WOLFSSL_DTLS */
    }
#endif /* HAVE_EXTENDED_MASTER && !NO_WOLFSSL_CLIENT */

#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
    if (ssl->options.dtls && ssl->options.side == WOLFSSL_SERVER_END) {
        int ret;
        ret = wolfSSL_DTLS_SetCookieSecret(ssl, NULL, 0);
        if (ret != 0) {
            WOLFSSL_MSG("DTLS Cookie Secret error");
            return ret;
        }
    }
#endif /* WOLFSSL_DTLS && !NO_WOLFSSL_SERVER */

    return InitSSL_Suites(ssl);
}
#endif /* OPENSSL_EXTRA || WOLFSSL_EITHER_SIDE */

/* Initialize SSL context, return 0 on success */
int InitSSL_Ctx(WOLFSSL_CTX* ctx, WOLFSSL_METHOD* method, void* heap)
{
    int ret = 0;

    XMEMSET(ctx, 0, sizeof(WOLFSSL_CTX));

    ctx->method   = method;
    ctx->refCount = 1;          /* so either CTX_free or SSL_free can release */
    ctx->heap     = ctx;        /* defaults to self */
    ctx->timeout  = WOLFSSL_SESSION_TIMEOUT;

#ifdef WOLFSSL_DTLS
    if (method->version.major == DTLS_MAJOR) {
        ctx->minDowngrade = WOLFSSL_MIN_DTLS_DOWNGRADE;
    }
    else
#endif /* WOLFSSL_DTLS */
    {
        /* current default: TLSv1_MINOR */
        ctx->minDowngrade = WOLFSSL_MIN_DOWNGRADE;
    }

    if (wc_InitMutex(&ctx->countMutex) < 0) {
        WOLFSSL_MSG("Mutex error on CTX init");
        ctx->err = CTX_INIT_MUTEX_E;
        WOLFSSL_ERROR_VERBOSE(BAD_MUTEX_E);
        return BAD_MUTEX_E;
    }

#ifndef NO_CERTS
    ctx->privateKeyDevId = INVALID_DEVID;
#endif

#ifndef NO_DH
    ctx->minDhKeySz  = MIN_DHKEY_SZ;
    ctx->maxDhKeySz  = MAX_DHKEY_SZ;
#endif
#ifndef NO_RSA
    ctx->minRsaKeySz = MIN_RSAKEY_SZ;
#endif
#ifdef HAVE_ECC
    ctx->minEccKeySz  = MIN_ECCKEY_SZ;
    ctx->eccTempKeySz = ECDHE_SIZE;
#endif
#ifdef HAVE_PQC
#ifdef HAVE_FALCON
    ctx->minFalconKeySz = MIN_FALCONKEY_SZ;
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    ctx->minDilithiumKeySz = MIN_DILITHIUMKEY_SZ;
#endif /* HAVE_DILITHIUM */
#endif /* HAVE_PQC */
    ctx->verifyDepth = MAX_CHAIN_DEPTH;
#ifdef OPENSSL_EXTRA
    ctx->cbioFlag = WOLFSSL_CBIO_NONE;
#endif

#ifdef HAVE_NETX
    ctx->CBIORecv = NetX_Receive;
    ctx->CBIOSend = NetX_Send;
#elif defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP)
    ctx->CBIORecv = Mynewt_Receive;
    ctx->CBIOSend = Mynewt_Send;
#elif defined WOLFSSL_LWIP_NATIVE
    ctx->CBIORecv = LwIPNativeReceive;
    ctx->CBIOSend = LwIPNativeSend;
#elif defined(WOLFSSL_GNRC)
    ctx->CBIORecv = GNRC_ReceiveFrom;
    ctx->CBIOSend = GNRC_SendTo;
#elif defined WOLFSSL_ISOTP
    ctx->CBIORecv = ISOTP_Receive;
    ctx->CBIOSend = ISOTP_Send;
#elif !defined(WOLFSSL_USER_IO)
    #ifdef MICRIUM
        ctx->CBIORecv = MicriumReceive;
        ctx->CBIOSend = MicriumSend;
        #ifdef WOLFSSL_DTLS
            if (method->version.major == DTLS_MAJOR) {
                ctx->CBIORecv   = MicriumReceiveFrom;
                ctx->CBIOSend   = MicriumSendTo;
            }
            #ifdef WOLFSSL_SESSION_EXPORT
                #error Micrium port does not support DTLS session export yet
            #endif
        #endif
    #elif defined WOLFSSL_UIP
        ctx->CBIORecv = uIPReceive;
        ctx->CBIOSend = uIPSend;
        #ifdef WOLFSSL_DTLS
        if (method->version.major == DTLS_MAJOR) {
            ctx->CBIOSendTo = uIPSendTo;
            ctx->CBIORecvFrom = uIPRecvFrom;
        }
        #endif
    #else
        ctx->CBIORecv = EmbedReceive;
        ctx->CBIOSend = EmbedSend;
        #ifdef WOLFSSL_SESSION_EXPORT
            ctx->CBGetPeer = EmbedGetPeer;
            ctx->CBSetPeer = EmbedSetPeer;
        #endif
        #ifdef WOLFSSL_DTLS
            if (method->version.major == DTLS_MAJOR) {
                ctx->CBIORecv   = EmbedReceiveFrom;
                ctx->CBIOSend   = EmbedSendTo;
            }
        #endif
    #endif /* MICRIUM */
#endif /* WOLFSSL_USER_IO */

#ifdef HAVE_PQC
#ifdef HAVE_FALCON
    if (method->side == WOLFSSL_CLIENT_END)
        ctx->haveFalconSig = 1;        /* always on client side */
                                       /* server can turn on by loading key */
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    if (method->side == WOLFSSL_CLIENT_END)
        ctx->haveDilithiumSig = 1;     /* always on client side */
                                       /* server can turn on by loading key */
#endif /* HAVE_DILITHIUM */
#endif /* HAVE_PQC */
#ifdef HAVE_ECC
    if (method->side == WOLFSSL_CLIENT_END) {
        ctx->haveECDSAsig  = 1;        /* always on client side */
        ctx->haveECC  = 1;             /* server turns on with ECC key cert */
        ctx->haveStaticECC = 1;        /* server can turn on by loading key */
    }
#elif defined(HAVE_ED25519) || defined(HAVE_ED448)
    if (method->side == WOLFSSL_CLIENT_END) {
        ctx->haveECDSAsig  = 1;        /* always on client side */
        ctx->haveECC  = 1;             /* server turns on with ECC key cert */
    }
#endif

#ifdef WOLFSSL_QNX_CAAM
    /* default to try using CAAM when built */
    ctx->devId = WOLFSSL_CAAM_DEVID;
#else
    ctx->devId = INVALID_DEVID;
#endif

#if defined(WOLFSSL_DTLS)
    #ifdef WOLFSSL_SCTP
        ctx->dtlsMtuSz = MAX_RECORD_SIZE;
    #elif defined(WOLFSSL_DTLS_MTU)
        ctx->dtlsMtuSz = MAX_MTU;
    #endif
#endif

#ifndef NO_CERTS
    ctx->cm = wolfSSL_CertManagerNew_ex(heap);
    if (ctx->cm == NULL) {
        WOLFSSL_MSG("Bad Cert Manager New");
        WOLFSSL_ERROR_VERBOSE(BAD_CERT_MANAGER_ERROR);
        return BAD_CERT_MANAGER_ERROR;
    }
    #ifdef OPENSSL_EXTRA
    /* setup WOLFSSL_X509_STORE */
    ctx->x509_store.cm = ctx->cm;
    /* set pointer back to x509 store */
    ctx->cm->x509_store_p = &ctx->x509_store;

    /* WOLFSSL_X509_VERIFY_PARAM */
    if ((ctx->param = (WOLFSSL_X509_VERIFY_PARAM*)XMALLOC(
                           sizeof(WOLFSSL_X509_VERIFY_PARAM),
                           heap, DYNAMIC_TYPE_OPENSSL)) == NULL) {
        WOLFSSL_MSG("ctx->param memory error");
        return MEMORY_E;
    }
    XMEMSET(ctx->param, 0, sizeof(WOLFSSL_X509_VERIFY_PARAM));
    /* WOLFSSL_X509_LOOKUP */
    if ((ctx->x509_store.lookup.dirs =
                            (WOLFSSL_BY_DIR*)XMALLOC(sizeof(WOLFSSL_BY_DIR),
                            heap, DYNAMIC_TYPE_OPENSSL)) == NULL) {
        WOLFSSL_MSG("ctx-x509_store.lookup.dir memory allocation error");
        XFREE(ctx->param, heap, DYNAMIC_TYPE_OPENSSL);
        ctx->param = NULL;
        return MEMORY_E;
    }
    XMEMSET(ctx->x509_store.lookup.dirs, 0, sizeof(WOLFSSL_BY_DIR));
    if (wc_InitMutex(&ctx->x509_store.lookup.dirs->lock) != 0) {
        WOLFSSL_MSG("Bad mutex init");
        XFREE(ctx->param, heap, DYNAMIC_TYPE_OPENSSL);
        ctx->param = NULL;
        XFREE(ctx->x509_store.lookup.dirs, heap, DYNAMIC_TYPE_OPENSSL);
        ctx->x509_store.lookup.dirs = NULL;
        WOLFSSL_ERROR_VERBOSE(BAD_MUTEX_E);
        return BAD_MUTEX_E;
    }
    #endif
#endif

#if defined(HAVE_EXTENDED_MASTER) && !defined(NO_WOLFSSL_CLIENT)
    if (method->side == WOLFSSL_CLIENT_END) {
        if ((method->version.major == SSLv3_MAJOR) &&
             (method->version.minor >= TLSv1_MINOR)) {

            ctx->haveEMS = 1;
        }
#ifdef WOLFSSL_DTLS
        if (method->version.major == DTLS_MAJOR)
            ctx->haveEMS = 1;
#endif /* WOLFSSL_DTLS */
    }
#endif /* HAVE_EXTENDED_MASTER && !NO_WOLFSSL_CLIENT */

#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER)
#ifndef WOLFSSL_NO_DEF_TICKET_ENC_CB
    ret = TicketEncCbCtx_Init(ctx, &ctx->ticketKeyCtx);
    if (ret != 0) return ret;
    ctx->ticketEncCb = DefTicketEncCb;
    ctx->ticketEncCtx = (void*)&ctx->ticketKeyCtx;
#endif
    ctx->ticketHint = SESSION_TICKET_HINT_DEFAULT;
#if defined(WOLFSSL_TLS13)
    ctx->maxTicketTls13 = 1; /* default to sending a session ticket if compiled
                                in */
#endif
#endif

#ifdef WOLFSSL_EARLY_DATA
    ctx->maxEarlyDataSz = MAX_EARLY_DATA_SZ;
#endif

#if defined(WOLFSSL_TLS13) && !defined(HAVE_SUPPORTED_CURVES)
    ctx->noPskDheKe = 1;
#endif

#if defined(WOLFSSL_QT) && !defined(NO_PSK)
    /* Qt retrieves supported cipher list at initialization
     * from get_cipher_compat().
     * Qt doesn't allow to use a cipher if it is not in the supported list.
     * Therefore, we need to enable PSK cipher at the beginning.
     */
    ctx->havePSK = 1;
#endif
    ctx->heap = heap; /* wolfSSL_CTX_load_static_memory sets */

#ifdef HAVE_WOLF_EVENT
    ret = wolfEventQueue_Init(&ctx->event_queue);
#endif /* HAVE_WOLF_EVENT */

#ifdef WOLFSSL_MAXQ10XX_TLS
    /* Let maxq10xx know what TLS version we are using. */
    ctx->devId = MAXQ_DEVICE_ID;
    maxq10xx_SetupPkCallbacks(ctx, &method->version);
#endif /* WOLFSSL_MAXQ10XX_TLS */

    return ret;
}


#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
void wolfSSL_CRYPTO_cleanup_ex_data(WOLFSSL_CRYPTO_EX_DATA* ex_data)
{
    int n_ex_data = (int)(sizeof ex_data->ex_data / sizeof ex_data->ex_data[0]);
    for (--n_ex_data; n_ex_data >= 0; --n_ex_data) {
        if (ex_data->ex_data[n_ex_data] != NULL)
            (void)wolfSSL_CRYPTO_set_ex_data_with_cleanup(ex_data, n_ex_data,
                                                          NULL, NULL);
    }
}
#endif /* HAVE_EX_DATA_CLEANUP_HOOKS */

/* In case contexts are held in array and don't want to free actual ctx. */

/* The allocations done in InitSSL_Ctx must be free'd with ctx->onHeapHint
 * logic. A WOLFSSL_CTX can be assigned a static memory heap hint using
 * wolfSSL_CTX_load_static_memory after CTX creation, which means variables
 * allocated in InitSSL_Ctx were allocated from heap and should be free'd with
 * a NULL heap hint. */
void SSL_CtxResourceFree(WOLFSSL_CTX* ctx)
{
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && \
                     defined(HAVE_TLS_EXTENSIONS) && !defined(NO_WOLFSSL_SERVER)
    int i;
#endif
    void* heapAtCTXInit = ctx->heap;
#ifdef WOLFSSL_STATIC_MEMORY
    if (ctx->onHeapHint == 0) {
        heapAtCTXInit = NULL;
    }
#endif

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
    wolfSSL_CRYPTO_cleanup_ex_data(&ctx->ex_data);
#endif

#ifdef HAVE_WOLF_EVENT
    wolfEventQueue_Free(&ctx->event_queue);
#endif /* HAVE_WOLF_EVENT */

    XFREE(ctx->method, heapAtCTXInit, DYNAMIC_TYPE_METHOD);
    ctx->method = NULL;

    if (ctx->suites) {
        XFREE(ctx->suites, ctx->heap, DYNAMIC_TYPE_SUITES);
        ctx->suites = NULL;
    }

#ifndef NO_DH
    XFREE(ctx->serverDH_G.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    ctx->serverDH_G.buffer = NULL;
    XFREE(ctx->serverDH_P.buffer, ctx->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    ctx->serverDH_P.buffer = NULL;
#endif /* !NO_DH */

#ifdef SINGLE_THREADED
    if (ctx->rng) {
        wc_FreeRng(ctx->rng);
        XFREE(ctx->rng, ctx->heap, DYNAMIC_TYPE_RNG);
        ctx->rng = NULL;
    }
#endif /* SINGLE_THREADED */

#ifndef NO_CERTS
    if (ctx->privateKey != NULL && ctx->privateKey->buffer != NULL) {
        ForceZero(ctx->privateKey->buffer, ctx->privateKey->length);
    }
    FreeDer(&ctx->privateKey);
#ifdef OPENSSL_ALL
    wolfSSL_EVP_PKEY_free(ctx->privateKeyPKey);
#endif
    FreeDer(&ctx->certificate);
    #ifdef KEEP_OUR_CERT
        if (ctx->ourCert && ctx->ownOurCert) {
            wolfSSL_X509_free(ctx->ourCert);
            ctx->ourCert = NULL;
        }
    #endif /* KEEP_OUR_CERT */
    FreeDer(&ctx->certChain);
    wolfSSL_CertManagerFree(ctx->cm);
    ctx->cm = NULL;
    #ifdef OPENSSL_ALL
        if (ctx->x509_store.objs != NULL) {
            wolfSSL_sk_X509_OBJECT_pop_free(ctx->x509_store.objs, NULL);
            ctx->x509_store.objs = NULL;
        }
    #endif
    #if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || \
        defined(WOLFSSL_WPAS_SMALL)
        wolfSSL_X509_STORE_free(ctx->x509_store_pt);
    #endif
    #if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EXTRA) || defined(HAVE_LIGHTY)
        wolfSSL_sk_X509_NAME_pop_free(ctx->ca_names, NULL);
        ctx->ca_names = NULL;
    #endif
    #ifdef OPENSSL_EXTRA
        if (ctx->x509Chain) {
            wolfSSL_sk_X509_pop_free(ctx->x509Chain, NULL);
            ctx->x509Chain = NULL;
        }
    #endif
#endif /* !NO_CERTS */

#ifdef HAVE_TLS_EXTENSIONS
#if !defined(NO_TLS)
    TLSX_FreeAll(ctx->extensions, ctx->heap);
#endif /* !NO_TLS */
#ifndef NO_WOLFSSL_SERVER
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
    if (ctx->certOcspRequest) {
        FreeOcspRequest(ctx->certOcspRequest);
        XFREE(ctx->certOcspRequest, ctx->heap, DYNAMIC_TYPE_OCSP_REQUEST);
    }
#endif

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
    for (i = 0; i < MAX_CHAIN_DEPTH; i++) {
        if (ctx->chainOcspRequest[i]) {
            FreeOcspRequest(ctx->chainOcspRequest[i]);
            XFREE(ctx->chainOcspRequest[i], ctx->heap, DYNAMIC_TYPE_OCSP_REQUEST);
            ctx->chainOcspRequest[i] = NULL;
        }
    }
#endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */
#endif /* !NO_WOLFSSL_SERVER */

#endif /* HAVE_TLS_EXTENSIONS */
#ifdef OPENSSL_EXTRA
    if (ctx->alpn_cli_protos) {
        XFREE((void*)ctx->alpn_cli_protos, ctx->heap, DYNAMIC_TYPE_OPENSSL);
        ctx->alpn_cli_protos = NULL;
    }
    if (ctx->param) {
        XFREE(ctx->param, heapAtCTXInit, DYNAMIC_TYPE_OPENSSL);
        ctx->param = NULL;
    }

    if (ctx->x509_store.lookup.dirs) {
#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
        if (ctx->x509_store.lookup.dirs->dir_entry) {
            wolfSSL_sk_BY_DIR_entry_free(ctx->x509_store.lookup.dirs->dir_entry);
        }

#endif
        wc_FreeMutex(&ctx->x509_store.lookup.dirs->lock);
        XFREE(ctx->x509_store.lookup.dirs, heapAtCTXInit, DYNAMIC_TYPE_OPENSSL);
    }
#endif
#ifdef WOLFSSL_STATIC_EPHEMERAL
    #ifndef NO_DH
    FreeDer(&ctx->staticKE.dhKey);
    #endif
    #ifdef HAVE_ECC
    FreeDer(&ctx->staticKE.ecKey);
    #endif
    #ifdef HAVE_CURVE25519
    FreeDer(&ctx->staticKE.x25519Key);
    #endif
    #ifdef HAVE_CURVE448
    FreeDer(&ctx->staticKE.x448Key);
    #endif
    #ifndef SINGLE_THREADED
    if (ctx->staticKELockInit) {
        wc_FreeMutex(&ctx->staticKELock);
        ctx->staticKELockInit = 0;
    }
    #endif
#endif
    (void)heapAtCTXInit;
}

#ifdef WOLFSSL_STATIC_MEMORY
static void SSL_CtxResourceFreeStaticMem(void* heap)
{
    if (heap != NULL
    #ifdef WOLFSSL_HEAP_TEST
        /* avoid dereferencing a test value */
         && heap != (void*)WOLFSSL_HEAP_TEST
    #endif
    ) {
        WOLFSSL_HEAP_HINT* hint = (WOLFSSL_HEAP_HINT*)heap;
        WOLFSSL_HEAP*      mem  = hint->memory;
        wc_FreeMutex(&mem->memory_mutex);
    }
}
#endif /* WOLFSSL_STATIC_MEMORY */

void FreeSSL_Ctx(WOLFSSL_CTX* ctx)
{
    int refCount;
    void* heap = ctx->heap;
#ifdef WOLFSSL_STATIC_MEMORY
    if (ctx->onHeapHint == 0) {
        heap = NULL;
    }
#endif

    /* decrement CTX reference count */
    if ((refCount = SSL_CTX_RefCount(ctx, -1)) < 0) {
        /* check error state, if mutex error code then mutex init failed but
         * CTX was still malloc'd */
        if (ctx->err == CTX_INIT_MUTEX_E) {
            SSL_CtxResourceFree(ctx);
            XFREE(ctx, heap, DYNAMIC_TYPE_CTX);
        #ifdef WOLFSSL_STATIC_MEMORY
            SSL_CtxResourceFreeStaticMem(heap);
        #endif
        }
        return;
    }

    if (refCount == 0) {
        WOLFSSL_MSG("CTX ref count down to 0, doing full free");

        SSL_CtxResourceFree(ctx);
#if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER) && \
    !defined(WOLFSSL_NO_DEF_TICKET_ENC_CB)
        TicketEncCbCtx_Free(&ctx->ticketKeyCtx);
#endif
        wc_FreeMutex(&ctx->countMutex);
        XFREE(ctx, heap, DYNAMIC_TYPE_CTX);
    #ifdef WOLFSSL_STATIC_MEMORY
        SSL_CtxResourceFreeStaticMem(heap);
    #endif
    }
    else {
        WOLFSSL_MSG("CTX ref count not 0 yet, no free");
    }
    (void)heap; /* not used in some builds */
}


/* Set cipher pointers to null */
void InitCiphers(WOLFSSL* ssl)
{
#ifdef BUILD_ARC4
    ssl->encrypt.arc4 = NULL;
    ssl->decrypt.arc4 = NULL;
#endif
#ifdef BUILD_DES3
    ssl->encrypt.des3 = NULL;
    ssl->decrypt.des3 = NULL;
#endif
#ifdef BUILD_AES
    ssl->encrypt.aes = NULL;
    ssl->decrypt.aes = NULL;
#endif
#ifdef HAVE_CAMELLIA
    ssl->encrypt.cam = NULL;
    ssl->decrypt.cam = NULL;
#endif
#ifdef HAVE_CHACHA
    ssl->encrypt.chacha = NULL;
    ssl->decrypt.chacha = NULL;
#endif
#if defined(HAVE_POLY1305) && defined(HAVE_ONE_TIME_AUTH)
    ssl->auth.poly1305 = NULL;
#endif
    ssl->encrypt.setup = 0;
    ssl->decrypt.setup = 0;
#ifdef HAVE_ONE_TIME_AUTH
    ssl->auth.setup    = 0;
#endif

#ifdef WOLFSSL_DTLS13
    XMEMSET(&ssl->dtlsRecordNumberEncrypt, 0,
        sizeof(ssl->dtlsRecordNumberEncrypt));
    XMEMSET(&ssl->dtlsRecordNumberDecrypt, 0,
         sizeof(ssl->dtlsRecordNumberEncrypt));
#endif /* WOLFSSL_DTLS13 */

}


/* Free ciphers */
void FreeCiphers(WOLFSSL* ssl)
{
    (void)ssl;
#ifdef BUILD_ARC4
    wc_Arc4Free(ssl->encrypt.arc4);
    wc_Arc4Free(ssl->decrypt.arc4);
    XFREE(ssl->encrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.arc4, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef BUILD_DES3
    wc_Des3Free(ssl->encrypt.des3);
    wc_Des3Free(ssl->decrypt.des3);
    XFREE(ssl->encrypt.des3, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.des3, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#if defined(BUILD_AES) || defined(BUILD_AESGCM) /* See: InitKeys() in keys.c
                                                 * on addition of BUILD_AESGCM
                                                 * check (enc->aes, dec->aes) */
    wc_AesFree(ssl->encrypt.aes);
    wc_AesFree(ssl->decrypt.aes);
    #if (defined(BUILD_AESGCM) || defined(HAVE_AESCCM)) && \
                                                      !defined(WOLFSSL_NO_TLS12)
        XFREE(ssl->decrypt.additional, ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
        XFREE(ssl->encrypt.additional, ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
    #endif
    XFREE(ssl->encrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef CIPHER_NONCE
    XFREE(ssl->decrypt.nonce, ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
    XFREE(ssl->encrypt.nonce, ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
#endif
#ifdef HAVE_CAMELLIA
    XFREE(ssl->encrypt.cam, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.cam, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#ifdef HAVE_CHACHA
    if (ssl->encrypt.chacha)
        ForceZero(ssl->encrypt.chacha, sizeof(ChaCha));
    if (ssl->decrypt.chacha)
        ForceZero(ssl->decrypt.chacha, sizeof(ChaCha));
    XFREE(ssl->encrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.chacha, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#if defined(HAVE_POLY1305) && defined(HAVE_ONE_TIME_AUTH)
    if (ssl->auth.poly1305)
        ForceZero(ssl->auth.poly1305, sizeof(Poly1305));
    XFREE(ssl->auth.poly1305, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif
#if defined(WOLFSSL_TLS13) && defined(HAVE_NULL_CIPHER)
    wc_HmacFree(ssl->encrypt.hmac);
    wc_HmacFree(ssl->decrypt.hmac);
    XFREE(ssl->encrypt.hmac, ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->decrypt.hmac, ssl->heap, DYNAMIC_TYPE_CIPHER);
#endif

#ifdef WOLFSSL_DTLS13
#ifdef BUILD_AES
    if (ssl->dtlsRecordNumberEncrypt.aes != NULL) {
        wc_AesFree(ssl->dtlsRecordNumberEncrypt.aes);
        XFREE(ssl->dtlsRecordNumberEncrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
        ssl->dtlsRecordNumberEncrypt.aes = NULL;
    }
    if (ssl->dtlsRecordNumberDecrypt.aes != NULL) {
        wc_AesFree(ssl->dtlsRecordNumberDecrypt.aes);
        XFREE(ssl->dtlsRecordNumberDecrypt.aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
        ssl->dtlsRecordNumberDecrypt.aes = NULL;
    }
#endif /* BUILD_AES */
#ifdef HAVE_CHACHA
    XFREE(ssl->dtlsRecordNumberEncrypt.chacha,
          ssl->heap, DYNAMIC_TYPE_CIPHER);
    XFREE(ssl->dtlsRecordNumberDecrypt.chacha,
          ssl->heap, DYNAMIC_TYPE_CIPHER);
    ssl->dtlsRecordNumberEncrypt.chacha = NULL;
    ssl->dtlsRecordNumberDecrypt.chacha = NULL;
#endif /* HAVE_CHACHA */
#endif /* WOLFSSL_DTLS13 */
}


void InitCipherSpecs(CipherSpecs* cs)
{
    XMEMSET(cs, 0, sizeof(CipherSpecs));

    cs->bulk_cipher_algorithm = INVALID_BYTE;
    cs->cipher_type           = INVALID_BYTE;
    cs->mac_algorithm         = INVALID_BYTE;
    cs->kea                   = INVALID_BYTE;
    cs->sig_algo              = INVALID_BYTE;
}

#if defined(USE_ECDSA_KEYSZ_HASH_ALGO) || (defined(WOLFSSL_TLS13) && \
                                                              defined(HAVE_ECC))
static int GetMacDigestSize(byte macAlgo)
{
    switch (macAlgo) {
    #ifndef NO_SHA
        case sha_mac:
            return WC_SHA_DIGEST_SIZE;
    #endif
    #ifndef NO_SHA256
        case sha256_mac:
            return WC_SHA256_DIGEST_SIZE;
    #endif
    #ifdef WOLFSSL_SHA384
        case sha384_mac:
            return WC_SHA384_DIGEST_SIZE;
    #endif
    #ifdef WOLFSSL_SHA512
        case sha512_mac:
            return WC_SHA512_DIGEST_SIZE;
    #endif
        default:
            break;
    }
    return NOT_COMPILED_IN;
}
#endif /* USE_ECDSA_KEYSZ_HASH_ALGO */

static WC_INLINE void AddSuiteHashSigAlgo(Suites* suites, byte macAlgo,
    byte sigAlgo, int keySz, word16* inOutIdx)
{
    int addSigAlgo = 1;

#ifdef USE_ECDSA_KEYSZ_HASH_ALGO
    if (sigAlgo == ecc_dsa_sa_algo) {
        int digestSz = GetMacDigestSize(macAlgo);
        /* do not add sig/algos with digest size larger than key size */
        if (digestSz <= 0 || (keySz > 0 && digestSz > keySz)) {
            addSigAlgo = 0;
        }
    }
#else
    (void)keySz;
#endif /* USE_ECDSA_KEYSZ_HASH_ALGO */

    if (addSigAlgo) {
    #ifdef HAVE_ED25519
        if (sigAlgo == ed25519_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = ED25519_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = ED25519_SA_MINOR;
            *inOutIdx += 1;
        }
        else
    #endif
    #ifdef HAVE_ED448
        if (sigAlgo == ed448_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = ED448_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = ED448_SA_MINOR;
            *inOutIdx += 1;
        }
        else
    #endif
    #ifdef HAVE_PQC
    #ifdef HAVE_FALCON
        if (sigAlgo == falcon_level1_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = FALCON_LEVEL1_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = FALCON_LEVEL1_SA_MINOR;
            *inOutIdx += 1;
        }
        else
        if (sigAlgo == falcon_level5_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = FALCON_LEVEL5_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = FALCON_LEVEL5_SA_MINOR;
            *inOutIdx += 1;
        }
        else
    #endif /* HAVE_FALCON */
    #ifdef HAVE_DILITHIUM
        if (sigAlgo == dilithium_level2_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_LEVEL2_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_LEVEL2_SA_MINOR;
            *inOutIdx += 1;
        }
        else
        if (sigAlgo == dilithium_level3_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_LEVEL3_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_LEVEL3_SA_MINOR;
            *inOutIdx += 1;
        }
        else
        if (sigAlgo == dilithium_level5_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_LEVEL5_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_LEVEL5_SA_MINOR;
            *inOutIdx += 1;
        }
        else
        if (sigAlgo == dilithium_aes_level2_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_AES_LEVEL2_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_AES_LEVEL2_SA_MINOR;
            *inOutIdx += 1;
        }
        else
        if (sigAlgo == dilithium_aes_level3_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_AES_LEVEL3_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_AES_LEVEL3_SA_MINOR;
            *inOutIdx += 1;
        }
        else
        if (sigAlgo == dilithium_aes_level5_sa_algo) {
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_AES_LEVEL5_SA_MAJOR;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = DILITHIUM_AES_LEVEL5_SA_MINOR;
            *inOutIdx += 1;
        }
        else
    #endif /* HAVE_DILITHIUM */
    #endif /* HAVE_PQC */
#ifdef WC_RSA_PSS
        if (sigAlgo == rsa_pss_sa_algo) {
            /* RSA PSS is sig then mac */
            suites->hashSigAlgo[*inOutIdx] = sigAlgo;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = macAlgo;
            *inOutIdx += 1;
    #ifdef WOLFSSL_TLS13
            /* Add the certificate algorithm as well */
            suites->hashSigAlgo[*inOutIdx] = sigAlgo;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = PSS_RSAE_TO_PSS_PSS(macAlgo);
            *inOutIdx += 1;
    #endif
        }
        else
#endif
        {
            suites->hashSigAlgo[*inOutIdx] = macAlgo;
            *inOutIdx += 1;
            suites->hashSigAlgo[*inOutIdx] = sigAlgo;
            *inOutIdx += 1;
        }
    }
}

void InitSuitesHashSigAlgo(Suites* suites, int haveECDSAsig, int haveRSAsig,
                           int haveFalconSig, int haveDilithiumSig,
                           int haveAnon, int tls1_2, int keySz)
{
    word16 idx = 0;

    (void)tls1_2;
    (void)keySz;

#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
    if (haveECDSAsig) {
#ifdef HAVE_ECC
    #ifdef WOLFSSL_SHA512
        AddSuiteHashSigAlgo(suites, sha512_mac, ecc_dsa_sa_algo, keySz, &idx);
    #endif
    #ifdef WOLFSSL_SHA384
        AddSuiteHashSigAlgo(suites, sha384_mac, ecc_dsa_sa_algo, keySz, &idx);
    #endif
    #ifndef NO_SHA256
        AddSuiteHashSigAlgo(suites, sha256_mac, ecc_dsa_sa_algo, keySz, &idx);
    #endif
    #if !defined(NO_SHA) && (!defined(NO_OLD_TLS) || \
                                            defined(WOLFSSL_ALLOW_TLS_SHA1))
        AddSuiteHashSigAlgo(suites, sha_mac, ecc_dsa_sa_algo, keySz, &idx);
    #endif
#endif
    #ifdef HAVE_ED25519
        AddSuiteHashSigAlgo(suites, no_mac, ed25519_sa_algo, keySz, &idx);
    #endif
    #ifdef HAVE_ED448
        AddSuiteHashSigAlgo(suites, no_mac, ed448_sa_algo, keySz, &idx);
    #endif
    }
#endif /* HAVE_ECC || HAVE_ED25519 || HAVE_ED448 */
    if (haveFalconSig) {
#if defined(HAVE_PQC)
#ifdef HAVE_FALCON
        AddSuiteHashSigAlgo(suites, no_mac, falcon_level1_sa_algo, keySz, &idx);
        AddSuiteHashSigAlgo(suites, no_mac, falcon_level5_sa_algo, keySz, &idx);
#endif /* HAVE_FALCON */
#endif /* HAVE_PQC */
    }
    if (haveDilithiumSig) {
#if defined(HAVE_PQC)
#ifdef HAVE_DILITHIUM
        AddSuiteHashSigAlgo(suites, no_mac, dilithium_level2_sa_algo, keySz,
                            &idx);
        AddSuiteHashSigAlgo(suites, no_mac, dilithium_level3_sa_algo, keySz,
                            &idx);
        AddSuiteHashSigAlgo(suites, no_mac, dilithium_level5_sa_algo, keySz,
                            &idx);
        AddSuiteHashSigAlgo(suites, no_mac, dilithium_aes_level2_sa_algo, keySz,
                            &idx);
        AddSuiteHashSigAlgo(suites, no_mac, dilithium_aes_level3_sa_algo, keySz,
                            &idx);
        AddSuiteHashSigAlgo(suites, no_mac, dilithium_aes_level5_sa_algo, keySz,
                            &idx);
#endif /* HAVE_DILITHIUM */
#endif /* HAVE_PQC */
    }
    if (haveRSAsig) {
    #ifdef WC_RSA_PSS
        if (tls1_2) {
        #ifdef WOLFSSL_SHA512
            AddSuiteHashSigAlgo(suites, sha512_mac, rsa_pss_sa_algo, keySz,
                                                                          &idx);
        #endif
        #ifdef WOLFSSL_SHA384
            AddSuiteHashSigAlgo(suites, sha384_mac, rsa_pss_sa_algo, keySz,
                                                                          &idx);
        #endif
        #ifndef NO_SHA256
            AddSuiteHashSigAlgo(suites, sha256_mac, rsa_pss_sa_algo, keySz,
                                                                          &idx);
        #endif
        }
    #endif
    #ifdef WOLFSSL_SHA512
        AddSuiteHashSigAlgo(suites, sha512_mac, rsa_sa_algo, keySz, &idx);
    #endif
    #ifdef WOLFSSL_SHA384
        AddSuiteHashSigAlgo(suites, sha384_mac, rsa_sa_algo, keySz, &idx);
    #endif
    #ifndef NO_SHA256
        AddSuiteHashSigAlgo(suites, sha256_mac, rsa_sa_algo, keySz, &idx);
    #endif
    #ifdef WOLFSSL_SHA224
        AddSuiteHashSigAlgo(suites, sha224_mac, rsa_sa_algo, keySz, &idx);
    #endif
    #if !defined(NO_SHA) && (!defined(NO_OLD_TLS) || \
                                            defined(WOLFSSL_ALLOW_TLS_SHA1))
        AddSuiteHashSigAlgo(suites, sha_mac, rsa_sa_algo, keySz, &idx);
    #endif
    }

#ifdef HAVE_ANON
    if (haveAnon) {
        AddSuiteHashSigAlgo(suites, sha_mac, anonymous_sa_algo, keySz, &idx);
    }
#endif

    (void)haveAnon;
    (void)haveECDSAsig;
    suites->hashSigAlgoSz = idx;
}

void InitSuites(Suites* suites, ProtocolVersion pv, int keySz, word16 haveRSA,
                word16 havePSK, word16 haveDH, word16 haveECDSAsig,
                word16 haveECC, word16 haveStaticRSA, word16 haveStaticECC,
                word16 haveFalconSig, word16 haveDilithiumSig, word16 haveAnon,
                word16 haveNull, int side)
{
    word16 idx = 0;
    int    tls    = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_MINOR;
    int    tls1_2 = pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_2_MINOR;
#ifdef WOLFSSL_TLS13
    int    tls1_3 = IsAtLeastTLSv1_3(pv);
#endif
    int    dtls   = 0;
    int    haveRSAsig = 1;

#ifdef WOLFSSL_DTLS
    /* If DTLS v1.2 or later than set tls1_2 flag */
    if (pv.major == DTLS_MAJOR && pv.minor <= DTLSv1_2_MINOR) {
        tls1_2 = 1;
    }
#endif

    (void)tls;  /* shut up compiler */
    (void)tls1_2;
    (void)dtls;
    (void)haveDH;
    (void)havePSK;
    (void)haveStaticRSA;
    (void)haveStaticECC;
    (void)haveECC;
    (void)side;
    (void)haveRSA;    /* some builds won't read */
    (void)haveRSAsig; /* non ecc builds won't read */
    (void)haveAnon;   /* anon ciphers optional */
    (void)haveNull;
    (void)haveFalconSig;
    (void)haveDilithiumSig;

    if (suites == NULL) {
        WOLFSSL_MSG("InitSuites pointer error");
        return;
    }

    if (suites->setSuites)
        return;      /* trust user settings, don't override */

#ifdef WOLFSSL_TLS13
#ifdef BUILD_TLS_AES_128_GCM_SHA256
    if (tls1_3) {
        suites->suites[idx++] = TLS13_BYTE;
        suites->suites[idx++] = TLS_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_AES_256_GCM_SHA384
    if (tls1_3) {
        suites->suites[idx++] = TLS13_BYTE;
        suites->suites[idx++] = TLS_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_CHACHA20_POLY1305_SHA256
    if (tls1_3) {
        suites->suites[idx++] = TLS13_BYTE;
        suites->suites[idx++] = TLS_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_AES_128_CCM_SHA256
    if (tls1_3) {
        suites->suites[idx++] = TLS13_BYTE;
        suites->suites[idx++] = TLS_AES_128_CCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_AES_128_CCM_8_SHA256
    if (tls1_3) {
        suites->suites[idx++] = TLS13_BYTE;
        suites->suites[idx++] = TLS_AES_128_CCM_8_SHA256;
    }
#endif

#ifdef HAVE_NULL_CIPHER
    #ifdef BUILD_TLS_SHA256_SHA256
        if (tls1_3 && haveNull) {
            suites->suites[idx++] = ECC_BYTE;
            suites->suites[idx++] = TLS_SHA256_SHA256;
        }
    #endif

    #ifdef BUILD_TLS_SHA384_SHA384
        if (tls1_3 && haveNull) {
            suites->suites[idx++] = ECC_BYTE;
            suites->suites[idx++] = TLS_SHA384_SHA384;
        }
    #endif
#endif
#endif /* WOLFSSL_TLS13 */

#ifndef WOLFSSL_NO_TLS12

#if !defined(NO_WOLFSSL_SERVER) && !defined(NO_RSA)
    if (side == WOLFSSL_SERVER_END && haveStaticECC) {
        haveRSA = 0;   /* can't do RSA with ECDSA key */
    }

    if (side == WOLFSSL_SERVER_END && haveECDSAsig) {
        haveRSAsig = 0;     /* can't have RSA sig if signed by ECDSA */
    }
#endif /* !NO_WOLFSSL_SERVER */

#ifdef WOLFSSL_DTLS
    if (pv.major == DTLS_MAJOR) {
        dtls   = 1;
        tls    = 1;
        /* May be dead assignments dependent upon configuration */
        (void) dtls;
        (void) tls;
        tls1_2 = pv.minor <= DTLSv1_2_MINOR;
    }
#endif

#ifdef HAVE_RENEGOTIATION_INDICATION
    if (side == WOLFSSL_CLIENT_END) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_EMPTY_RENEGOTIATION_INFO_SCSV;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveDH && haveRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveECC && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveECC && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveDH && havePSK) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    if (tls1_2 && haveDH && haveAnon) {
      suites->suites[idx++] = CIPHER_BYTE;
      suites->suites[idx++] = TLS_DH_anon_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DH_anon_WITH_AES_256_GCM_SHA384
    if (tls1_2 && haveDH && haveAnon) {
      suites->suites[idx++] = CIPHER_BYTE;
      suites->suites[idx++] = TLS_DH_anon_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    if (tls1_2 && haveDH && havePSK) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    if (tls1_2 && havePSK) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_GCM_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256
    if (tls1_2 && havePSK) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

/* Place as higher priority for MYSQL */
#if defined(WOLFSSL_MYSQL_COMPATIBLE)
#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
    }
#endif
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    if (tls1_2 && haveECC && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    if (tls1_2 && haveECC && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    if (tls && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    if (tls && haveECC && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    if (tls && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    if (tls && haveECC && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    if (!dtls && tls && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    if (!dtls && tls && haveECC && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveECC && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
    if (!dtls && tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    if (!dtls && tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveRSAsig && haveStaticECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CCM;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    if (tls1_2 && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CCM_8
    if (tls1_2 && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveDH && haveRSA)
#else
    if (tls && haveDH && haveRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveDH && haveRSA)
#else
    if (tls && haveDH && haveRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

/* Place as higher priority for MYSQL testing */
#if !defined(WOLFSSL_MYSQL_COMPATIBLE)
#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_256_CBC_SHA;
    }
#endif
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    if (tls && haveDH && haveRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveRSA && haveStaticRSA)
#else
    if (tls && haveRSA && haveStaticRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveRSA && haveStaticRSA)
#else
    if (tls && haveRSA && haveStaticRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    if (tls && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    if (tls && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    if (tls1_2 && haveECC) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] =
                              TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    if (tls1_2 && haveRSA) {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_NULL_SHA
    if (tls && haveECC && haveNull) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_ECDSA_WITH_NULL_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_MD5
    if (tls && haveRSA && haveNull && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_NULL_MD5;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    if (tls && haveRSA && haveNull && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_NULL_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveRSA && haveNull && haveStaticRSA)
#else
    if (tls && haveRSA && haveNull && haveStaticRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveDH && havePSK)
#else
    if (tls && haveDH && havePSK)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA384
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK)
#else
    if (tls && havePSK)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CBC_SHA384;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveDH && havePSK)
#else
    if (tls && haveDH && havePSK)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK)
#else
    if (tls1 && havePSK)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    if (tls && havePSK) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CCM
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_128_CCM;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CCM
    if (tls && haveDH && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_AES_256_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK)
#else
    if (tls && havePSK)
#endif
    {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK)
#else
    if (tls && havePSK)
#endif
    {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK)
#else
    if (tls && havePSK)
#endif
    {
        suites->suites[idx++] = CHACHA_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK)
#else
    if (tls && havePSK)
#endif
    {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK)
#else
    if (tls && havePSK)
#endif
    {
        suites->suites[idx++] = ECDHE_PSK_BYTE;
        suites->suites[idx++] = TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CCM;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM_8
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_128_CCM_8;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM_8
    if (tls && havePSK) {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_AES_256_CCM_8;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA384
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveDH && havePSK)
#else
    if (tls && haveDH && havePSK && haveNull)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_NULL_SHA384;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA384
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK && haveNull)
#else
    if (tls && havePSK && haveNull)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA384;
    }
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_NULL_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK && haveNull)
#else
    if (tls && havePSK && haveNull)
#endif
    {
        suites->suites[idx++] = ECC_BYTE;
        suites->suites[idx++] = TLS_ECDHE_PSK_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveDH && havePSK && haveNull)
#else
    if (tls && haveDH && havePSK && haveNull)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_PSK_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && havePSK && haveNull)
#else
    if (tls && havePSK && haveNull)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA256;
    }
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA
    if (tls && havePSK && haveNull) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_PSK_WITH_NULL_SHA;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    if (!dtls && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_128_SHA;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    if (!dtls && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = SSL_RSA_WITH_RC4_128_MD5;
    }
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    if (haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = SSL_RSA_WITH_3DES_EDE_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    if (tls && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    if (tls && haveDH && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    if (tls && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    if (tls && haveDH && haveRSA && haveStaticRSA) {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveRSA && haveStaticRSA)
#else
    if (tls && haveRSA && haveStaticRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveDH && haveRSA && haveStaticRSA)
#else
    if (tls && haveDH && haveRSA && haveStaticRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveRSA && haveStaticRSA)
#else
    if (tls && haveRSA && haveStaticRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
#ifndef WOLFSSL_OLDTLS_SHA2_CIPHERSUITES
    if (tls1_2 && haveDH && haveRSA && haveStaticRSA)
#else
    if (tls && haveDH && haveRSA && haveStaticRSA)
#endif
    {
        suites->suites[idx++] = CIPHER_BYTE;
        suites->suites[idx++] = TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256;
    }
#endif

#endif /* !WOLFSSL_NO_TLS12 */

    suites->suiteSz = idx;

    if (suites->hashSigAlgoSz == 0) {
        InitSuitesHashSigAlgo(suites, haveECDSAsig | haveECC,
                              haveRSAsig | haveRSA, haveFalconSig,
                              haveDilithiumSig, 0, tls1_2, keySz);
    }
}

#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_CERTS) || \
    (!defined(NO_WOLFSSL_CLIENT) && (!defined(NO_DH) || defined(HAVE_ECC)))

/* Decode the signature algorithm.
 *
 * input     The encoded signature algorithm.
 * hashalgo  The hash algorithm.
 * hsType    The signature type.
 */
static WC_INLINE void DecodeSigAlg(const byte* input, byte* hashAlgo, byte* hsType)
{
    *hsType = invalid_sa_algo;
    switch (input[0]) {
        case NEW_SA_MAJOR:
    #ifdef HAVE_ED25519
            /* ED25519: 0x0807 */
            if (input[1] == ED25519_SA_MINOR) {
                *hsType = ed25519_sa_algo;
                /* Hash performed as part of sign/verify operation. */
                *hashAlgo = sha512_mac;
            }
            else
    #endif
    #ifdef HAVE_ED448
            /* ED448: 0x0808 */
            if (input[1] == ED448_SA_MINOR) {
                *hsType = ed448_sa_algo;
                /* Hash performed as part of sign/verify operation. */
                *hashAlgo = sha512_mac;
            }
            else
    #endif
    #ifdef WC_RSA_PSS
            /* PSS PSS signatures: 0x080[9-b] */
            if (input[1] >= pss_sha256 && input[1] <= pss_sha512) {
                *hsType   = rsa_pss_pss_algo;
                *hashAlgo = PSS_PSS_HASH_TO_MAC(input[1]);
            }
            else
    #endif
            {
                *hsType   = input[0];
                *hashAlgo = input[1];
            }
            break;
#ifdef HAVE_PQC
        case PQC_SA_MAJOR:
            /* Hash performed as part of sign/verify operation. */
    #ifdef HAVE_FALCON
            if (input[1] == FALCON_LEVEL1_SA_MINOR) {
                *hsType = falcon_level1_sa_algo;
                *hashAlgo = sha512_mac;
            }
            else if (input[1] == FALCON_LEVEL5_SA_MINOR) {
                *hsType = falcon_level5_sa_algo;
                *hashAlgo = sha512_mac;
            }
    #endif /* HAVE_FALCON */
    #ifdef HAVE_DILITHIUM
            if (input[1] == DILITHIUM_LEVEL2_SA_MINOR) {
                *hsType = dilithium_level2_sa_algo;
                *hashAlgo = sha512_mac;
            }
            else if (input[1] == DILITHIUM_LEVEL3_SA_MINOR) {
                *hsType = dilithium_level3_sa_algo;
                *hashAlgo = sha512_mac;
            }
            else if (input[1] == DILITHIUM_LEVEL5_SA_MINOR) {
                *hsType = dilithium_level5_sa_algo;
                *hashAlgo = sha512_mac;
            }
            else if (input[1] == DILITHIUM_AES_LEVEL2_SA_MINOR) {
                *hsType = dilithium_aes_level2_sa_algo;
                *hashAlgo = sha512_mac;
            }
            else if (input[1] == DILITHIUM_AES_LEVEL3_SA_MINOR) {
                *hsType = dilithium_aes_level3_sa_algo;
                *hashAlgo = sha512_mac;
            }
            else if (input[1] == DILITHIUM_AES_LEVEL5_SA_MINOR) {
                *hsType = dilithium_aes_level5_sa_algo;
                *hashAlgo = sha512_mac;
            }
    #endif /* HAVE_DILITHIUM */
            break;
#endif
        default:
            *hashAlgo = input[0];
            *hsType   = input[1];
            break;
    }
}
#endif /* !NO_WOLFSSL_SERVER || !NO_CERTS */

#ifndef WOLFSSL_NO_TLS12
#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT)
#if !defined(NO_DH) || defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
             defined(HAVE_CURVE448) || (!defined(NO_RSA) && defined(WC_RSA_PSS))

static enum wc_HashType HashAlgoToType(int hashAlgo)
{
    switch (hashAlgo) {
    #ifdef WOLFSSL_SHA512
        case sha512_mac:
            return WC_HASH_TYPE_SHA512;
    #endif
    #ifdef WOLFSSL_SHA384
        case sha384_mac:
            return WC_HASH_TYPE_SHA384;
    #endif
    #ifndef NO_SHA256
        case sha256_mac:
            return WC_HASH_TYPE_SHA256;
    #endif
    #ifdef WOLFSSL_SHA224
        case sha224_mac:
            return WC_HASH_TYPE_SHA224;
    #endif
    #if !defined(NO_SHA) && (!defined(NO_OLD_TLS) || \
                             defined(WOLFSSL_ALLOW_TLS_SHA1))
        case sha_mac:
            return WC_HASH_TYPE_SHA;
    #endif
        default:
            WOLFSSL_MSG("Bad hash sig algo");
            break;
    }

    return WC_HASH_TYPE_NONE;
}
#endif /* !NO_DH || HAVE_ECC || (!NO_RSA && WC_RSA_PSS) */
#endif /* !NO_WOLFSSL_SERVER || !NO_WOLFSSL_CLIENT */
#endif /* !WOLFSSL_NO_TLS12 */

////////////////////////

////////////////////////

#ifndef NO_RSA
#if !defined(WOLFSSL_NO_TLS12) || \
    (defined(WC_RSA_PSS) && defined(HAVE_PK_CALLBACKS))
#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT)
static int TypeHash(int hashAlgo)
{
    switch (hashAlgo) {
    #ifdef WOLFSSL_SHA512
        case sha512_mac:
            return SHA512h;
    #endif
    #ifdef WOLFSSL_SHA384
        case sha384_mac:
            return SHA384h;
    #endif
    #ifndef NO_SHA256
        case sha256_mac:
            return SHA256h;
    #endif
    #ifdef WOLFSSL_SHA224
        case sha224_mac:
            return SHA224h;
    #endif
    #ifndef NO_SHA
        case sha_mac:
            return SHAh;
    #endif
        default:
            break;
    }

    return 0;
}
#endif /* !NO_WOLFSSL_SERVER && !NO_WOLFSSL_CLIENT */
#endif /* !WOLFSSL_NO_TLS12 */

#if defined(WC_RSA_PSS)
int ConvertHashPss(int hashAlgo, enum wc_HashType* hashType, int* mgf)
{
    switch (hashAlgo) {
        #ifdef WOLFSSL_SHA512
        case sha512_mac:
            *hashType = WC_HASH_TYPE_SHA512;
            if (mgf != NULL)
                *mgf = WC_MGF1SHA512;
            break;
        #endif
        #ifdef WOLFSSL_SHA384
        case sha384_mac:
            *hashType = WC_HASH_TYPE_SHA384;
            if (mgf != NULL)
                *mgf = WC_MGF1SHA384;
            break;
        #endif
        #ifndef NO_SHA256
        case sha256_mac:
            *hashType = WC_HASH_TYPE_SHA256;
            if (mgf != NULL)
                *mgf = WC_MGF1SHA256;
            break;
        #endif
        default:
            return BAD_FUNC_ARG;
    }

    return 0;
}
#endif

#if !defined(NO_WOLFSSL_SERVER) || !defined(WOLFSSL_NO_CLIENT_AUTH)
int RsaSign(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out,
            word32* outSz, int sigAlgo, int hashAlgo, RsaKey* key,
            DerBuffer* keyBufInfo)
{
    int ret;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;
    (void)sigAlgo;
    (void)hashAlgo;

    WOLFSSL_ENTER("RsaSign");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    if (key) {
        ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        if (ret != 0)
            return ret;
    }
#endif

#if defined(WC_RSA_PSS)
    if (sigAlgo == rsa_pss_sa_algo) {
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int mgf = 0;

        ret = ConvertHashPss(hashAlgo, &hashType, &mgf);
        if (ret != 0)
            return ret;

    #if defined(HAVE_PK_CALLBACKS)
        if (ssl->ctx->RsaPssSignCb) {
            void* ctx = wolfSSL_GetRsaPssSignCtx(ssl);
            ret = ssl->ctx->RsaPssSignCb(ssl, in, inSz, out, outSz,
                                         TypeHash(hashAlgo), mgf,
                                         keyBuf, keySz, ctx);
        }
        else
    #endif
        {
            ret = wc_RsaPSS_Sign(in, inSz, out, *outSz, hashType, mgf, key,
                                                                      ssl->rng);
        }
    }
    else
#endif
#if defined(HAVE_PK_CALLBACKS)
    if (ssl->ctx->RsaSignCb) {
        void* ctx = wolfSSL_GetRsaSignCtx(ssl);
        ret = ssl->ctx->RsaSignCb(ssl, in, inSz, out, outSz, keyBuf, keySz,
                                                                          ctx);
    }
    else
#endif /*HAVE_PK_CALLBACKS */
        ret = wc_RsaSSL_Sign(in, inSz, out, *outSz, key, ssl->rng);

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (key && ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    /* For positive response return in outSz */
    if (ret > 0) {
        *outSz = ret;
        ret = 0;
    }

    WOLFSSL_LEAVE("RsaSign", ret);

    return ret;
}
#endif

int RsaVerify(WOLFSSL* ssl, byte* in, word32 inSz, byte** out, int sigAlgo,
              int hashAlgo, RsaKey* key, buffer* keyBufInfo)
{
    int ret = SIG_VERIFY_E;

#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;
    (void)sigAlgo;
    (void)hashAlgo;

    WOLFSSL_ENTER("RsaVerify");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#if defined(WC_RSA_PSS)
    if (sigAlgo == rsa_pss_sa_algo) {
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int mgf = 0;

        ret = ConvertHashPss(hashAlgo, &hashType, &mgf);
        if (ret != 0)
            return ret;
#ifdef HAVE_PK_CALLBACKS
        if (ssl->ctx->RsaPssVerifyCb) {
            void* ctx = wolfSSL_GetRsaPssVerifyCtx(ssl);
            ret = ssl->ctx->RsaPssVerifyCb(ssl, in, inSz, out,
                                           TypeHash(hashAlgo), mgf,
                                           keyBuf, keySz, ctx);
        }
        else
#endif /*HAVE_PK_CALLBACKS */
            ret = wc_RsaPSS_VerifyInline(in, inSz, out, hashType, mgf, key);
    }
    else
#endif
#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->RsaVerifyCb) {
        void* ctx = wolfSSL_GetRsaVerifyCtx(ssl);
        ret = ssl->ctx->RsaVerifyCb(ssl, in, inSz, out, keyBuf, keySz, ctx);
    }
    #if !defined(WOLFSSL_RENESAS_SCEPROTECT) && \
        !defined(WOLFSSL_RENESAS_TSIP_TLS)
    else
    #else
    if (!ssl->ctx->RsaVerifyCb || ret == CRYPTOCB_UNAVAILABLE)
    #endif
#endif /*HAVE_PK_CALLBACKS */
    {
        ret = wc_RsaSSL_VerifyInline(in, inSz, out, key);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("RsaVerify", ret);

    return ret;
}

/* Verify RSA signature, 0 on success */
/* This function is used to check the sign result */
int VerifyRsaSign(WOLFSSL* ssl, byte* verifySig, word32 sigSz,
    const byte* plain, word32 plainSz, int sigAlgo, int hashAlgo, RsaKey* key,
    DerBuffer* keyBufInfo)
{
    byte* out = NULL;  /* inline result */
    int   ret;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;
    (void)sigAlgo;
    (void)hashAlgo;

    WOLFSSL_ENTER("VerifyRsaSign");

    if (verifySig == NULL || plain == NULL) {
        return BAD_FUNC_ARG;
    }

    if (sigSz > ENCRYPT_LEN) {
        WOLFSSL_MSG("Signature buffer too big");
        return BUFFER_E;
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    if (key) {
        ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        if (ret != 0)
            return ret;
    }
#endif

#if defined(WC_RSA_PSS)
    if (sigAlgo == rsa_pss_sa_algo) {
        enum wc_HashType hashType = WC_HASH_TYPE_NONE;
        int mgf = 0;

        ret = ConvertHashPss(hashAlgo, &hashType, &mgf);
        if (ret != 0)
            return ret;
    #ifdef HAVE_PK_CALLBACKS
        if (ssl->ctx->RsaPssSignCheckCb) {
            /* The key buffer includes private/public portion,
                but only public is used */
            /* If HSM hardware is checking the signature result you can
                optionally skip the sign check and return 0 */
            /* The ctx here is the RsaSignCtx set using wolfSSL_SetRsaSignCtx */
            void* ctx = wolfSSL_GetRsaPssSignCtx(ssl);
            ret = ssl->ctx->RsaPssSignCheckCb(ssl, verifySig, sigSz, &out,
                                           TypeHash(hashAlgo), mgf,
                                           keyBuf, keySz, ctx);
            if (ret > 0) {
                ret = wc_RsaPSS_CheckPadding(plain, plainSz, out, ret,
                                             hashType);
                if (ret != 0) {
                    ret = VERIFY_CERT_ERROR;
                    WOLFSSL_ERROR_VERBOSE(ret);
                }
            }
        }
        else
    #endif /* HAVE_PK_CALLBACKS */
        {
            ret = wc_RsaPSS_VerifyInline(verifySig, sigSz, &out, hashType, mgf,
                                         key);
            if (ret > 0) {
    #ifdef HAVE_SELFTEST
                ret = wc_RsaPSS_CheckPadding(plain, plainSz, out, ret,
                                             hashType);
    #else
                ret = wc_RsaPSS_CheckPadding_ex(plain, plainSz, out, ret,
                                                hashType, -1,
                                                mp_count_bits(&key->n));
    #endif
                if (ret != 0) {
                    ret = VERIFY_CERT_ERROR;
                    WOLFSSL_ERROR_VERBOSE(ret);
                }
            }
        }

    }
    else
#endif /* WC_RSA_PSS */
    {
    #ifdef HAVE_PK_CALLBACKS
        if (ssl->ctx->RsaSignCheckCb) {
            /* The key buffer includes private/public portion,
                but only public is used */
            /* If HSM hardware is checking the signature result you can
                optionally skip the sign check and return 0 */
            /* The ctx here is the RsaSignCtx set using wolfSSL_SetRsaSignCtx */
            void* ctx = wolfSSL_GetRsaSignCtx(ssl);
            ret = ssl->ctx->RsaSignCheckCb(ssl, verifySig, sigSz, &out,
                keyBuf, keySz, ctx);
        }
        else
    #endif /* HAVE_PK_CALLBACKS */
        {
            ret = wc_RsaSSL_VerifyInline(verifySig, sigSz, &out, key);
        }

        if (ret > 0) {
            if (ret != (int)plainSz || !out ||
                                            XMEMCMP(plain, out, plainSz) != 0) {
                WOLFSSL_MSG("RSA Signature verification failed");
                ret = RSA_SIGN_FAULT;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
            else {
                ret = 0;  /* RSA reset */
            }
        }
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (key && ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("VerifyRsaSign", ret);

    return ret;
}

#ifndef WOLFSSL_NO_TLS12

#if !defined(NO_WOLFSSL_SERVER) || !defined(WOLFSSL_NO_CLIENT_AUTH)
int RsaDec(WOLFSSL* ssl, byte* in, word32 inSz, byte** out, word32* outSz,
    RsaKey* key, DerBuffer* keyBufInfo)
{
    byte *outTmp;
    byte mask;
    int ret;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("RsaDec");

    outTmp = *out;
#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->RsaDecCb) {
        void* ctx = wolfSSL_GetRsaDecCtx(ssl);
        ret = ssl->ctx->RsaDecCb(ssl, in, inSz, &outTmp, keyBuf, keySz, ctx);
    }
    else
#endif /* HAVE_PK_CALLBACKS */
    {
        #ifdef WC_RSA_BLINDING
            ret = wc_RsaSetRNG(key, ssl->rng);
            if (ret != 0)
                return ret;
        #endif
        ret = wc_RsaPrivateDecryptInline(in, inSz, &outTmp, key);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    mask = ctMaskGT(ret, 0);
    *outSz = (word32)(ret & (int)(sword8)mask);
    ret &= (int)(sword8)(~mask);
    /* Copy pointer */
    ctMaskCopy(mask, (byte*)out, (byte*)&outTmp, sizeof(*out));

    WOLFSSL_LEAVE("RsaDec", ret);

    return ret;
}
#endif /* !NO_WOLFSSL_SERVER) || !WOLFSSL_NO_CLIENT_AUTH */

int RsaEnc(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out, word32* outSz,
    RsaKey* key, buffer* keyBufInfo)
{
    int ret = BAD_FUNC_ARG;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("RsaEnc");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->RsaEncCb) {
        void* ctx = wolfSSL_GetRsaEncCtx(ssl);
        ret = ssl->ctx->RsaEncCb(ssl, in, inSz, out, outSz, keyBuf, keySz, ctx);
    }
    #if !defined(WOLFSSL_RENESAS_SCEPROTECT) && \
        !defined(WOLFSSL_RENESAS_TSIP_TLS)
    else
    #else
    if (!ssl->ctx->RsaEncCb || ret == CRYPTOCB_UNAVAILABLE)
    #endif
#endif /* HAVE_PK_CALLBACKS */
    {
        ret = wc_RsaPublicEncrypt(in, inSz, out, *outSz, key, ssl->rng);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    /* For positive response return in outSz */
    if (ret > 0) {
        *outSz = ret;
        ret = 0;
    }

    WOLFSSL_LEAVE("RsaEnc", ret);

    return ret;
}

#endif /* !WOLFSSL_NO_TLS12 */

#endif /* NO_RSA */

#ifdef HAVE_ECC

int EccSign(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out,
    word32* outSz, ecc_key* key, DerBuffer* keyBufInfo)
{
    int ret;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("EccSign");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    if (key) {
        ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        if (ret != 0)
            return ret;
    }
#endif

#if defined(HAVE_PK_CALLBACKS)
    if (ssl->ctx->EccSignCb) {
        void* ctx = wolfSSL_GetEccSignCtx(ssl);
        if (ctx == NULL) {
            /* Try to get the WOLFSSL_CTX EccSignCtx*/
            ctx = wolfSSL_CTX_GetEccSignCtx(ssl->ctx);
        }
        ret = ssl->ctx->EccSignCb(ssl, in, inSz, out, outSz, keyBuf,
            keySz, ctx);
#if defined(WOLFSSL_RENESAS_TSIP_TLS)
        if (ret == CRYPTOCB_UNAVAILABLE) {
            ret = wc_ecc_sign_hash(in, inSz, out, outSz, ssl->rng, key);
        }
#endif /* WOLFSSL_RENESAS_TSIP_TLS */
    }
    else
#endif /* HAVE_PK_CALLBACKS */
    {
        ret = wc_ecc_sign_hash(in, inSz, out, outSz, ssl->rng, key);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (key && ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("EccSign", ret);

    return ret;
}

int EccVerify(WOLFSSL* ssl, const byte* in, word32 inSz, const byte* out,
    word32 outSz, ecc_key* key, buffer* keyBufInfo)
{
    int ret = SIG_VERIFY_E;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("EccVerify");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->EccVerifyCb) {
        void* ctx = wolfSSL_GetEccVerifyCtx(ssl);
        ret = ssl->ctx->EccVerifyCb(ssl, in, inSz, out, outSz, keyBuf, keySz,
            &ssl->eccVerifyRes, ctx);
    }
    #if !defined(WOLFSSL_RENESAS_SCEPROTECT) && \
        !defined(WOLFSSL_RENESAS_TSIP_TLS) && \
        !defined(WOLFSSL_MAXQ108X)
    else
    #else
    if (!ssl->ctx->EccVerifyCb || ret == CRYPTOCB_UNAVAILABLE)
    #endif
#endif /* HAVE_PK_CALLBACKS  */
    {
        ret = wc_ecc_verify_hash(in, inSz, out, outSz, &ssl->eccVerifyRes, key);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
    else
#endif /* WOLFSSL_ASYNC_CRYPT */
    {
        if (ret != 0 || ssl->eccVerifyRes == 0) {
            if (ret == 0) {
                ret = VERIFY_SIGN_ERROR;
            }
            WOLFSSL_ERROR_VERBOSE(ret);
        }
        else {
            ret = 0;
        }
    }

    WOLFSSL_LEAVE("EccVerify", ret);

    return ret;
}

int EccSharedSecret(WOLFSSL* ssl, ecc_key* priv_key, ecc_key* pub_key,
        byte* pubKeyDer, word32* pubKeySz, byte* out, word32* outlen,
        int side)
{
    int ret;
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV* asyncDev = NULL;
#endif

    (void)ssl;
    (void)pubKeyDer;
    (void)pubKeySz;
    (void)side;

    WOLFSSL_ENTER("EccSharedSecret");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    if (priv_key != NULL) {
        asyncDev = &priv_key->asyncDev;
        ret = wolfSSL_AsyncInit(ssl, asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        if (ret != 0)
            return ret;
    }
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->EccSharedSecretCb) {
        void* ctx = wolfSSL_GetEccSharedSecretCtx(ssl);
        ecc_key* otherKey = (side == WOLFSSL_CLIENT_END) ? pub_key : priv_key;
        ret = ssl->ctx->EccSharedSecretCb(ssl, otherKey, pubKeyDer,
            pubKeySz, out, outlen, side, ctx);
    }
    else
#endif
    {
#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    !defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2)) && \
    !defined(HAVE_SELFTEST)
        ret = wc_ecc_set_rng(priv_key, ssl->rng);
        if (ret == 0)
#endif
        {
            PRIVATE_KEY_UNLOCK();
            ret = wc_ecc_shared_secret(priv_key, pub_key, out, outlen);
            PRIVATE_KEY_LOCK();
        }
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("EccSharedSecret", ret);

    return ret;
}

int EccMakeKey(WOLFSSL* ssl, ecc_key* key, ecc_key* peer)
{
    int ret = 0;
    int keySz = 0;
    int ecc_curve = ECC_CURVE_DEF;

    WOLFSSL_ENTER("EccMakeKey");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_NONE);
    if (ret != 0)
        return ret;
#endif

    /* get key size */
    if (peer == NULL || peer->dp == NULL) {
        keySz = ssl->eccTempKeySz;
        /* get curve type */
        if (ssl->ecdhCurveOID > 0) {
            ecc_curve = wc_ecc_get_oid(ssl->ecdhCurveOID, NULL, NULL);
        }
    }
    else {
        keySz = peer->dp->size;
        ecc_curve = peer->dp->id;
    }

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->EccKeyGenCb) {
        void* ctx = wolfSSL_GetEccKeyGenCtx(ssl);
        ret = ssl->ctx->EccKeyGenCb(ssl, key, keySz, ecc_curve, ctx);
    }
    else
#endif
    {
        ret = wc_ecc_make_key_ex(ssl->rng, keySz, key, ecc_curve);
    }
	
    /* make sure the curve is set for TLS */
    if (ret == 0 && key->dp) {
        ssl->ecdhCurveOID = key->dp->oidSum;
    #if defined(WOLFSSL_TLS13) || defined(HAVE_FFDHE)
        ssl->namedGroup = 0;
    #endif
    }


    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
    WOLFSSL_ENTER("z");
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
	WOLFSSL_LEAVE("z", ret);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

	
    WOLFSSL_LEAVE("EccMakeKey", ret);

    return ret;
}
#endif /* HAVE_ECC */

#ifdef HAVE_ED25519
/* Check whether the key contains a public key.
 * If not then pull it out of the leaf certificate.
 *
 * ssl  SSL/TLS object.
 * returns MEMORY_E when unable to allocate memory, a parsing error, otherwise
 * 0 on success.
 */
int Ed25519CheckPubKey(WOLFSSL* ssl)
{
#ifndef HAVE_ED25519_KEY_IMPORT
    (void)ssl;
    return NOT_COMPILED_IN;
#else /* HAVE_ED25519_KEY_IMPORT */
    ed25519_key* key = (ed25519_key*)ssl->hsKey;
    int ret = 0;

    /* Public key required for signing. */
    if (key != NULL && !key->pubKeySet) {
        DerBuffer* leaf = ssl->buffers.certificate;
        DecodedCert* cert = (DecodedCert*)XMALLOC(sizeof(*cert),
                                     ssl->heap, DYNAMIC_TYPE_DCERT);
        if (cert == NULL)
            ret = MEMORY_E;

        if (ret == 0) {
            InitDecodedCert(cert, leaf->buffer, leaf->length, ssl->heap);
            ret = DecodeToKey(cert, 0);
        }
        if (ret == 0) {
            ret = wc_ed25519_import_public(cert->publicKey, cert->pubKeySize,
                                                                           key);
        }
        if (cert != NULL) {
            FreeDecodedCert(cert);
            XFREE(cert, ssl->heap, DYNAMIC_TYPE_DCERT);
        }
    }

    return ret;
#endif /* HAVE_ED25519_KEY_IMPORT */
}

/* Sign the data using EdDSA and key using Ed25519.
 *
 * ssl    SSL object.
 * in     Data or message to sign.
 * inSz   Length of the data.
 * out    Buffer to hold signature.
 * outSz  On entry, size of the buffer. On exit, the size of the signature.
 * key    The private Ed25519 key data.
 * keySz  The length of the private key data in bytes.
 * ctx    The callback context.
 * returns 0 on success, otherwise the value is an error.
 */
int Ed25519Sign(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out,
                word32* outSz, ed25519_key* key, DerBuffer* keyBufInfo)
{
#ifndef HAVE_ED25519_SIGN
    (void)ssl;
    (void)in;
    (void)inSz;
    (void)out;
    (void)outSz;
    (void)key;
    (void)keyBufInfo;
    return NOT_COMPILED_IN;
#else /* HAVE_ED25519_SIGN */
    int ret;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("Ed25519Sign");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#if defined(HAVE_PK_CALLBACKS)
    if (ssl->ctx->Ed25519SignCb) {
        void* ctx = wolfSSL_GetEd25519SignCtx(ssl);
        ret = ssl->ctx->Ed25519SignCb(ssl, in, inSz, out, outSz, keyBuf,
            keySz, ctx);
    }
    else
#endif /* HAVE_PK_CALLBACKS */
    {
        ret = wc_ed25519_sign_msg(in, inSz, out, outSz, key);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("Ed25519Sign", ret);

    return ret;
#endif /* HAVE_ED25519_SIGN */
}

/* Verify the data using EdDSA and key using Ed25519.
 *
 * ssl    SSL object.
 * in     Signature data.
 * inSz   Length of the signature data in bytes.
 * msg    Message to verify.
 * outSz  Length of message in bytes.
 * key    The public Ed25519 key data.
 * keySz  The length of the private key data in bytes.
 * ctx    The callback context.
 * returns 0 on success, otherwise the value is an error.
 */
int Ed25519Verify(WOLFSSL* ssl, const byte* in, word32 inSz, const byte* msg,
                  word32 msgSz, ed25519_key* key, buffer* keyBufInfo)
{
#ifndef HAVE_ED25519_VERIFY
    (void)ssl;
    (void)in;
    (void)inSz;
    (void)msg;
    (void)msgSz;
    (void)key;
    (void)keyBufInfo;
    return NOT_COMPILED_IN;
#else /* HAVE_ED25519_VERIFY */
    int ret;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("Ed25519Verify");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->Ed25519VerifyCb) {
        void* ctx = wolfSSL_GetEd25519VerifyCtx(ssl);
        ret = ssl->ctx->Ed25519VerifyCb(ssl, in, inSz, msg, msgSz, keyBuf,
                                        keySz, &ssl->eccVerifyRes, ctx);
    }
    else
#endif /* HAVE_PK_CALLBACKS  */
    {
        ret = wc_ed25519_verify_msg(in, inSz, msg, msgSz,
                                    &ssl->eccVerifyRes, key);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
    else
#endif /* WOLFSSL_ASYNC_CRYPT */
    {
        ret = (ret != 0 || ssl->eccVerifyRes == 0) ? VERIFY_SIGN_ERROR : 0;
    }

    WOLFSSL_LEAVE("Ed25519Verify", ret);

    return ret;
#endif /* HAVE_ED25519_VERIFY */
}
#endif /* HAVE_ED25519 */

#ifndef WOLFSSL_NO_TLS12

#ifdef HAVE_CURVE25519
#ifdef HAVE_PK_CALLBACKS
    /* Gets X25519 key for shared secret callback testing
     * Client side: returns peer key
     * Server side: returns private key
     */
    static int X25519GetKey(WOLFSSL* ssl, curve25519_key** otherKey)
    {
        int ret = NO_PEER_KEY;
        struct curve25519_key* tmpKey = NULL;

        if (ssl == NULL || otherKey == NULL) {
            return BAD_FUNC_ARG;
        }

        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            if (!ssl->peerX25519Key || !ssl->peerX25519KeyPresent ||
                                       !ssl->peerX25519Key->dp) {
                return NO_PEER_KEY;
            }
            tmpKey = (struct curve25519_key*)ssl->peerX25519Key;
        }
        else if (ssl->options.side == WOLFSSL_SERVER_END) {
            if (!ssl->eccTempKeyPresent) {
                return NO_PRIVATE_KEY;
            }
            tmpKey = (struct curve25519_key*)ssl->eccTempKey;
        }

        if (tmpKey) {
            *otherKey = (curve25519_key *)tmpKey;
            ret = 0;
        }

        return ret;
    }
#endif /* HAVE_PK_CALLBACKS */

static int X25519SharedSecret(WOLFSSL* ssl, curve25519_key* priv_key,
        curve25519_key* pub_key, byte* pubKeyDer, word32* pubKeySz,
        byte* out, word32* outlen, int side)
{
    int ret;

    (void)ssl;
    (void)pubKeyDer;
    (void)pubKeySz;
    (void)side;

    WOLFSSL_ENTER("X25519SharedSecret");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &priv_key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->X25519SharedSecretCb) {
        curve25519_key* otherKey = NULL;

        ret = X25519GetKey(ssl, &otherKey);
        if (ret == 0) {
            void* ctx = wolfSSL_GetX25519SharedSecretCtx(ssl);
            ret = ssl->ctx->X25519SharedSecretCb(ssl, otherKey, pubKeyDer,
                pubKeySz, out, outlen, side, ctx);
        }
    }
    else
#endif
    {
        ret = wc_curve25519_shared_secret_ex(priv_key, pub_key, out, outlen,
                                             EC25519_LITTLE_ENDIAN);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &priv_key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("X25519SharedSecret", ret);

    return ret;
}

static int X25519MakeKey(WOLFSSL* ssl, curve25519_key* key,
        curve25519_key* peer)
{
    int ret = 0;

    (void)peer;

    WOLFSSL_ENTER("X25519MakeKey");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_NONE);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->X25519KeyGenCb) {
        void* ctx = wolfSSL_GetX25519KeyGenCtx(ssl);
        ret = ssl->ctx->X25519KeyGenCb(ssl, key, CURVE25519_KEYSIZE, ctx);
    }
    else
#endif
    {
        ret = wc_curve25519_make_key(ssl->rng, CURVE25519_KEYSIZE, key);
    }

    if (ret == 0) {
        ssl->ecdhCurveOID = ECC_X25519_OID;
    #if defined(WOLFSSL_TLS13) || defined(HAVE_FFDHE)
        ssl->namedGroup = 0;
    #endif
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("X25519MakeKey", ret);

    return ret;
}
#endif /* HAVE_CURVE25519 */

#endif /* !WOLFSSL_NO_TLS12 */

#ifdef HAVE_ED448
/* Check whether the key contains a public key.
 * If not then pull it out of the leaf certificate.
 *
 * ssl  SSL/TLS object.
 * returns MEMORY_E when unable to allocate memory, a parsing error, otherwise
 * 0 on success.
 */
int Ed448CheckPubKey(WOLFSSL* ssl)
{
#ifndef HAVE_ED448_KEY_IMPORT
    (void)ssl;
    return NOT_COMPILED_IN;
#else /* HAVE_ED448_KEY_IMPORT */
    ed448_key* key = (ed448_key*)ssl->hsKey;
    int ret = 0;

    /* Public key required for signing. */
    if (key != NULL && !key->pubKeySet) {
        DerBuffer* leaf = ssl->buffers.certificate;
        DecodedCert* cert = (DecodedCert*)XMALLOC(sizeof(*cert), ssl->heap,
            DYNAMIC_TYPE_DCERT);
        if (cert == NULL)
            ret = MEMORY_E;

        if (ret == 0) {
            InitDecodedCert(cert, leaf->buffer, leaf->length, ssl->heap);
            ret = DecodeToKey(cert, 0);
        }
        if (ret == 0) {
            ret = wc_ed448_import_public(cert->publicKey, cert->pubKeySize,
                key);
        }
        if (cert != NULL) {
            FreeDecodedCert(cert);
            XFREE(cert, ssl->heap, DYNAMIC_TYPE_DCERT);
        }
    }

    return ret;
#endif /* HAVE_ED448_KEY_IMPORT */
}

/* Sign the data using EdDSA and key using Ed448.
 *
 * ssl    SSL object.
 * in     Data or message to sign.
 * inSz   Length of the data.
 * out    Buffer to hold signature.
 * outSz  On entry, size of the buffer. On exit, the size of the signature.
 * key    The private Ed448 key data.
 * keySz  The length of the private key data in bytes.
 * ctx    The callback context.
 * returns 0 on success, otherwise the value is an error.
 */
int Ed448Sign(WOLFSSL* ssl, const byte* in, word32 inSz, byte* out,
              word32* outSz, ed448_key* key, DerBuffer* keyBufInfo)
{
#ifndef HAVE_ED448_SIGN
    (void)ssl;
    (void)in;
    (void)inSz;
    (void)out;
    (void)outSz;
    (void)key;
    (void)keyBufInfo;
    return NOT_COMPILED_IN;
#else /* HAVE_ED448_SIGN */
    int ret;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("Ed448Sign");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#if defined(HAVE_PK_CALLBACKS)
    if (ssl->ctx->Ed448SignCb) {
        void* ctx = wolfSSL_GetEd448SignCtx(ssl);
        ret = ssl->ctx->Ed448SignCb(ssl, in, inSz, out, outSz, keyBuf, keySz,
            ctx);
    }
    else
#endif /* HAVE_PK_CALLBACKS */
    {
        ret = wc_ed448_sign_msg(in, inSz, out, outSz, key, NULL, 0);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("Ed448Sign", ret);

    return ret;
#endif /* HAVE_ED448_SIGN */
}

/* Verify the data using EdDSA and key using Ed448.
 *
 * ssl    SSL object.
 * in     Signature data.
 * inSz   Length of the signature data in bytes.
 * msg    Message to verify.
 * outSz  Length of message in bytes.
 * key    The public Ed448 key data.
 * keySz  The length of the private key data in bytes.
 * ctx    The callback context.
 * returns 0 on success, otherwise the value is an error.
 */
int Ed448Verify(WOLFSSL* ssl, const byte* in, word32 inSz, const byte* msg,
                word32 msgSz, ed448_key* key, buffer* keyBufInfo)
{
#ifndef HAVE_ED448_VERIFY
    (void)ssl;
    (void)in;
    (void)inSz;
    (void)msg;
    (void)msgSz;
    (void)key;
    (void)keyBufInfo;
    return NOT_COMPILED_IN;
#else /* HAVE_ED448_VERIFY */
    int ret;
#ifdef HAVE_PK_CALLBACKS
    const byte* keyBuf = NULL;
    word32 keySz = 0;

    if (keyBufInfo) {
        keyBuf = keyBufInfo->buffer;
        keySz = keyBufInfo->length;
    }
#endif

    (void)ssl;
    (void)keyBufInfo;

    WOLFSSL_ENTER("Ed448Verify");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->Ed448VerifyCb) {
        void* ctx = wolfSSL_GetEd448VerifyCtx(ssl);
        ret = ssl->ctx->Ed448VerifyCb(ssl, in, inSz, msg, msgSz, keyBuf, keySz,
             &ssl->eccVerifyRes, ctx);
    }
    else
#endif /* HAVE_PK_CALLBACKS  */
    {
        ret = wc_ed448_verify_msg(in, inSz, msg, msgSz, &ssl->eccVerifyRes, key,
            NULL, 0);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
    else
#endif /* WOLFSSL_ASYNC_CRYPT */
    {
        ret = (ret != 0 || ssl->eccVerifyRes == 0) ? VERIFY_SIGN_ERROR : 0;
    }

    WOLFSSL_LEAVE("Ed448Verify", ret);

    return ret;
#endif /* HAVE_ED448_VERIFY */
}
#endif /* HAVE_ED448 */

#ifndef WOLFSSL_NO_TLS12

#ifdef HAVE_CURVE448
#ifdef HAVE_PK_CALLBACKS
    /* Gets X448 key for shared secret callback testing
     * Client side: returns peer key
     * Server side: returns private key
     */
    static int X448GetKey(WOLFSSL* ssl, curve448_key** otherKey)
    {
        int ret = NO_PEER_KEY;
        struct curve448_key* tmpKey = NULL;

        if (ssl == NULL || otherKey == NULL) {
            return BAD_FUNC_ARG;
        }

        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            if (!ssl->peerX448Key || !ssl->peerX448KeyPresent) {
                return NO_PEER_KEY;
            }
            tmpKey = (struct curve448_key*)ssl->peerX448Key;
        }
        else if (ssl->options.side == WOLFSSL_SERVER_END) {
            if (!ssl->eccTempKeyPresent) {
                return NO_PRIVATE_KEY;
            }
            tmpKey = (struct curve448_key*)ssl->eccTempKey;
        }

        if (tmpKey) {
            *otherKey = (curve448_key *)tmpKey;
            ret = 0;
        }

        return ret;
    }
#endif /* HAVE_PK_CALLBACKS */

static int X448SharedSecret(WOLFSSL* ssl, curve448_key* priv_key,
                            curve448_key* pub_key, byte* pubKeyDer,
                            word32* pubKeySz, byte* out, word32* outlen,
                            int side)
{
    int ret;

    (void)ssl;
    (void)pubKeyDer;
    (void)pubKeySz;
    (void)side;

    WOLFSSL_ENTER("X448SharedSecret");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &priv_key->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->X448SharedSecretCb) {
        curve448_key* otherKey = NULL;

        ret = X448GetKey(ssl, &otherKey);
        if (ret == 0) {
            void* ctx = wolfSSL_GetX448SharedSecretCtx(ssl);
            ret = ssl->ctx->X448SharedSecretCb(ssl, otherKey, pubKeyDer,
                pubKeySz, out, outlen, side, ctx);
        }
    }
    else
#endif
    {
        ret = wc_curve448_shared_secret_ex(priv_key, pub_key, out, outlen,
            EC448_LITTLE_ENDIAN);
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &priv_key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("X448SharedSecret", ret);

    return ret;
}

static int X448MakeKey(WOLFSSL* ssl, curve448_key* key, curve448_key* peer)
{
    int ret = 0;

    (void)peer;

    WOLFSSL_ENTER("X448MakeKey");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &key->asyncDev, WC_ASYNC_FLAG_NONE);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->X448KeyGenCb) {
        void* ctx = wolfSSL_GetX448KeyGenCtx(ssl);
        ret = ssl->ctx->X448KeyGenCb(ssl, key, CURVE448_KEY_SIZE, ctx);
    }
    else
#endif
    {
        ret = wc_curve448_make_key(ssl->rng, CURVE448_KEY_SIZE, key);
    }

    if (ret == 0) {
        ssl->ecdhCurveOID = ECC_X448_OID;
    #if defined(WOLFSSL_TLS13) || defined(HAVE_FFDHE)
        ssl->namedGroup = 0;
    #endif
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &key->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("X448MakeKey", ret);

    return ret;
}
#endif /* HAVE_CURVE448 */

#endif /* !WOLFSSL_NO_TLS12 */

#if !defined(NO_CERTS) || !defined(NO_PSK)
#if !defined(NO_DH)

int DhGenKeyPair(WOLFSSL* ssl, DhKey* dhKey,
    byte* priv, word32* privSz,
    byte* pub, word32* pubSz)
{
    int ret;

    WOLFSSL_ENTER("DhGenKeyPair");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &dhKey->asyncDev, WC_ASYNC_FLAG_NONE);
    if (ret != 0)
        return ret;
#endif

#if defined(HAVE_PK_CALLBACKS)
    ret = NOT_COMPILED_IN;
    if (ssl && ssl->ctx && ssl->ctx->DhGenerateKeyPairCb) {
        ret = ssl->ctx->DhGenerateKeyPairCb(dhKey, ssl->rng, priv, privSz,
                                            pub, pubSz);
    }
    if (ret == NOT_COMPILED_IN)
#endif
    {
        PRIVATE_KEY_UNLOCK();
        ret = wc_DhGenerateKeyPair(dhKey, ssl->rng, priv, privSz, pub, pubSz);
        PRIVATE_KEY_LOCK();
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &dhKey->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("DhGenKeyPair", ret);

    return ret;
}

int DhAgree(WOLFSSL* ssl, DhKey* dhKey,
    const byte* priv, word32 privSz,
    const byte* otherPub, word32 otherPubSz,
    byte* agree, word32* agreeSz,
    const byte* prime, word32 primeSz)
{
    int ret;

    (void)ssl;

    WOLFSSL_ENTER("DhAgree");

#ifdef WOLFSSL_ASYNC_CRYPT
    /* initialize event */
    ret = wolfSSL_AsyncInit(ssl, &dhKey->asyncDev, WC_ASYNC_FLAG_NONE);
    if (ret != 0)
        return ret;
#endif

#ifdef HAVE_PK_CALLBACKS
    if (ssl->ctx->DhAgreeCb) {
        void* ctx = wolfSSL_GetDhAgreeCtx(ssl);

        WOLFSSL_MSG("Calling DhAgree Callback Function");
        ret = ssl->ctx->DhAgreeCb(ssl, dhKey, priv, privSz,
                    otherPub, otherPubSz, agree, agreeSz, ctx);
    }
    else
#endif
    {
#if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
        /* check the public key has valid number */
        if (dhKey != NULL && (prime == NULL || primeSz == 0)) {
            /* wc_DhCheckPubKey does not do exponentiation */
            ret = wc_DhCheckPubKey(dhKey, otherPub, otherPubSz);
        }
        else {
            ret = wc_DhCheckPubValue(prime, primeSz, otherPub, otherPubSz);
        }
        if (ret != 0) {
            /* translate to valid error (wc_DhCheckPubValue returns MP_VAL -1) */
            ret = PEER_KEY_ERROR;
            WOLFSSL_ERROR_VERBOSE(ret);

    #ifdef OPENSSL_EXTRA
            SendAlert(ssl, alert_fatal, illegal_parameter);
    #endif
        }
        else
#endif
        {
            PRIVATE_KEY_UNLOCK();
            ret = wc_DhAgree(dhKey, agree, agreeSz, priv, privSz, otherPub,
                    otherPubSz);
            PRIVATE_KEY_LOCK();
        }
    }

    /* Handle async pending response */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl, &dhKey->asyncDev);
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    WOLFSSL_LEAVE("DhAgree", ret);

    (void)prime;
    (void)primeSz;

    return ret;
}
#endif /* !NO_DH */
#endif /* !NO_CERTS || !NO_PSK */


#ifdef HAVE_PK_CALLBACKS
int wolfSSL_IsPrivatePkSet(WOLFSSL* ssl)
{
    int pkcbset = 0;
    (void)ssl;

#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448) || \
                                                                !defined(NO_RSA)
    if (0
    #ifdef HAVE_ECC
        || (ssl->ctx->EccSignCb != NULL &&
                                        ssl->buffers.keyType == ecc_dsa_sa_algo)
    #endif
    #ifdef HAVE_ED25519
        || (ssl->ctx->Ed25519SignCb != NULL &&
                                        ssl->buffers.keyType == ed25519_sa_algo)
    #endif
    #ifdef HAVE_ED448
        || (ssl->ctx->Ed448SignCb != NULL &&
                                          ssl->buffers.keyType == ed448_sa_algo)
    #endif
    #ifndef NO_RSA
        || (ssl->ctx->RsaSignCb != NULL && ssl->buffers.keyType == rsa_sa_algo)
        || (ssl->ctx->RsaDecCb != NULL && ssl->buffers.keyType == rsa_kea)
        #ifdef WC_RSA_PSS
        || (ssl->ctx->RsaPssSignCb != NULL &&
                                        ssl->buffers.keyType == rsa_pss_sa_algo)
        #endif
    #endif
    ) {
        pkcbset = 1;
    }
#endif
    return pkcbset;
}

int wolfSSL_CTX_IsPrivatePkSet(WOLFSSL_CTX* ctx)
{
    int pkcbset = 0;
    (void)ctx;
#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448) || \
                                                                !defined(NO_RSA)
    if (0
    #ifdef HAVE_ECC
        || ctx->EccSignCb != NULL
    #endif
    #ifdef HAVE_ED25519
        || ctx->Ed25519SignCb != NULL
    #endif
    #ifdef HAVE_ED448
        || ctx->Ed448SignCb != NULL
    #endif
    #ifndef NO_RSA
        || ctx->RsaSignCb != NULL
        || ctx->RsaDecCb != NULL
        #ifdef WC_RSA_PSS
        || ctx->RsaPssSignCb != NULL
        #endif
    #endif
    ) {
        pkcbset = 1;
    }
#endif
    return pkcbset;
}
#endif /* HAVE_PK_CALLBACKS */


////////////////////////////////////////////////////////

/* free use of temporary arrays */
void FreeArrays(WOLFSSL* ssl, int keep)
{
    if (ssl->arrays) {
        if (keep && !IsAtLeastTLSv1_3(ssl->version)) {
            /* keeps session id for user retrieval */
            XMEMCPY(ssl->session->sessionID, ssl->arrays->sessionID, ID_LEN);
            ssl->session->sessionIDSz = ssl->arrays->sessionIDSz;
        }
        if (ssl->arrays->preMasterSecret) {
            ForceZero(ssl->arrays->preMasterSecret, ENCRYPT_LEN);
            XFREE(ssl->arrays->preMasterSecret, ssl->heap, DYNAMIC_TYPE_SECRET);
            ssl->arrays->preMasterSecret = NULL;
        }
        XFREE(ssl->arrays->pendingMsg, ssl->heap, DYNAMIC_TYPE_ARRAYS);
        ssl->arrays->pendingMsg = NULL;
        ForceZero(ssl->arrays, sizeof(Arrays)); /* clear arrays struct */
    }
    XFREE(ssl->arrays, ssl->heap, DYNAMIC_TYPE_ARRAYS);
    ssl->arrays = NULL;
}

void FreeKey(WOLFSSL* ssl, int type, void** pKey)
{
    if (ssl && pKey && *pKey) {
        switch (type) {
        #ifndef NO_RSA
            case DYNAMIC_TYPE_RSA:
                wc_FreeRsaKey((RsaKey*)*pKey);
                break;
        #endif /* ! NO_RSA */
        #ifdef HAVE_ECC
            case DYNAMIC_TYPE_ECC:
            #if defined(WC_ECC_NONBLOCK) && defined(WOLFSSL_ASYNC_CRYPT_SW) && \
                defined(WC_ASYNC_ENABLE_ECC)
                if (((ecc_key*)*pKey)->nb_ctx != NULL) {
                    XFREE(((ecc_key*)*pKey)->nb_ctx, ((ecc_key*)*pKey)->heap,
                          DYNAMIC_TYPE_TMP_BUFFER);
                }
            #endif /* WC_ECC_NONBLOCK && WOLFSSL_ASYNC_CRYPT_SW &&
                      WC_ASYNC_ENABLE_ECC */
                wc_ecc_free((ecc_key*)*pKey);
                break;
        #endif /* HAVE_ECC */
        #ifdef HAVE_ED25519
            case DYNAMIC_TYPE_ED25519:
                wc_ed25519_free((ed25519_key*)*pKey);
                break;
        #endif /* HAVE_ED25519 */
        #ifdef HAVE_CURVE25519
            case DYNAMIC_TYPE_CURVE25519:
                wc_curve25519_free((curve25519_key*)*pKey);
                break;
        #endif /* HAVE_CURVE25519 */
        #ifdef HAVE_ED448
            case DYNAMIC_TYPE_ED448:
                wc_ed448_free((ed448_key*)*pKey);
                break;
        #endif /* HAVE_ED448 */
        #ifdef HAVE_CURVE448
            case DYNAMIC_TYPE_CURVE448:
                wc_curve448_free((curve448_key*)*pKey);
                break;
        #endif /* HAVE_CURVE448 */
        #if defined(HAVE_PQC)
        #if defined(HAVE_FALCON)
            case DYNAMIC_TYPE_FALCON:
                wc_falcon_free((falcon_key*)*pKey);
                break;
        #endif /* HAVE_FALCON */
        #if defined(HAVE_DILITHIUM)
            case DYNAMIC_TYPE_DILITHIUM:
                wc_dilithium_free((dilithium_key*)*pKey);
                break;
        #endif /* HAVE_DILITHIUM */
        #endif /* HAVE_PQC */
        #ifndef NO_DH
            case DYNAMIC_TYPE_DH:
                wc_FreeDhKey((DhKey*)*pKey);
                break;
        #endif /* !NO_DH */
            default:
                break;
        }
        XFREE(*pKey, ssl->heap, type);

        /* Reset pointer */
        *pKey = NULL;
    }
}

int AllocKey(WOLFSSL* ssl, int type, void** pKey)
{
    int ret = BAD_FUNC_ARG;
    int sz = 0;
#ifdef HAVE_ECC
    ecc_key* eccKey;
#endif /* HAVE_ECC */
#if defined(WC_ECC_NONBLOCK) && defined(WOLFSSL_ASYNC_CRYPT_SW) && \
    defined(WC_ASYNC_ENABLE_ECC)
    ecc_nb_ctx_t* nbCtx;
#endif /* WC_ECC_NONBLOCK && WOLFSSL_ASYNC_CRYPT_SW && WC_ASYNC_ENABLE_ECC*/

    if (ssl == NULL || pKey == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Sanity check key destination */
    if (*pKey != NULL) {
        WOLFSSL_MSG("Key already present!");
        return BAD_STATE_E;
    }

    /* Determine size */
    switch (type) {
    #ifndef NO_RSA
        case DYNAMIC_TYPE_RSA:
            sz = sizeof(RsaKey);
            break;
    #endif /* ! NO_RSA */
    #ifdef HAVE_ECC
        case DYNAMIC_TYPE_ECC:
            sz = sizeof(ecc_key);
            break;
    #endif /* HAVE_ECC */
    #ifdef HAVE_ED25519
        case DYNAMIC_TYPE_ED25519:
            sz = sizeof(ed25519_key);
            break;
    #endif /* HAVE_ED25519 */
    #ifdef HAVE_CURVE25519
        case DYNAMIC_TYPE_CURVE25519:
            sz = sizeof(curve25519_key);
            break;
    #endif /* HAVE_CURVE25519 */
    #ifdef HAVE_ED448
        case DYNAMIC_TYPE_ED448:
            sz = sizeof(ed448_key);
            break;
    #endif /* HAVE_ED448 */
    #ifdef HAVE_CURVE448
        case DYNAMIC_TYPE_CURVE448:
            sz = sizeof(curve448_key);
            break;
    #endif /* HAVE_CURVE448 */
    #if defined(HAVE_PQC)
    #if defined(HAVE_FALCON)
        case DYNAMIC_TYPE_FALCON:
            sz = sizeof(falcon_key);
            break;
    #endif /* HAVE_FALCON */
    #if defined(HAVE_DILITHIUM)
        case DYNAMIC_TYPE_DILITHIUM:
            sz = sizeof(dilithium_key);
            break;
    #endif /* HAVE_DILITHIUM */
    #endif /* HAVE_PQC */
    #ifndef NO_DH
        case DYNAMIC_TYPE_DH:
            sz = sizeof(DhKey);
            break;
    #endif /* !NO_DH */
        default:
            return BAD_FUNC_ARG;
    }

    /* Allocate memory for key */
    *pKey = (void *)XMALLOC(sz, ssl->heap, type);
    if (*pKey == NULL) {
        return MEMORY_E;
    }

    /* Initialize key */
    switch (type) {
    #ifndef NO_RSA
        case DYNAMIC_TYPE_RSA:
            ret = wc_InitRsaKey_ex((RsaKey*)*pKey, ssl->heap, ssl->devId);
            break;
    #endif /* ! NO_RSA */
    #ifdef HAVE_ECC
        case DYNAMIC_TYPE_ECC:
            eccKey = (ecc_key*)*pKey;
            ret = wc_ecc_init_ex(eccKey, ssl->heap, ssl->devId);
            if (ret == 0) {
            #if defined(WC_ECC_NONBLOCK) && defined(WOLFSSL_ASYNC_CRYPT_SW) && \
                defined(WC_ASYNC_ENABLE_ECC)
                nbCtx = (ecc_nb_ctx_t*)XMALLOC(sizeof(ecc_nb_ctx_t),
                            eccKey->heap, DYNAMIC_TYPE_TMP_BUFFER);
                if (nbCtx == NULL) {
                    ret = MEMORY_E;
                }
                else {
                    ret = wc_ecc_set_nonblock(eccKey, nbCtx);
                    if (ret != 0) {
                        XFREE(nbCtx, eccKey->heap, DYNAMIC_TYPE_TMP_BUFFER);
                    }
                }
            #endif /* WC_ECC_NONBLOCK && WOLFSSL_ASYNC_CRYPT_SW &&
                      WC_ASYNC_ENABLE_ECC */
            }
            break;
    #endif /* HAVE_ECC */
    #ifdef HAVE_ED25519
        case DYNAMIC_TYPE_ED25519:
            wc_ed25519_init_ex((ed25519_key*)*pKey, ssl->heap, ssl->devId);
            ret = 0;
            break;
    #endif /* HAVE_CURVE25519 */
    #ifdef HAVE_CURVE25519
        case DYNAMIC_TYPE_CURVE25519:
            wc_curve25519_init_ex((curve25519_key*)*pKey, ssl->heap, ssl->devId);
            ret = 0;
            break;
    #endif /* HAVE_CURVE25519 */
    #ifdef HAVE_ED448
        case DYNAMIC_TYPE_ED448:
            wc_ed448_init_ex((ed448_key*)*pKey, ssl->heap, ssl->devId);
            ret = 0;
            break;
    #endif /* HAVE_CURVE448 */
    #if defined(HAVE_PQC)
    #if defined(HAVE_FALCON)
        case DYNAMIC_TYPE_FALCON:
            wc_falcon_init((falcon_key*)*pKey);
            ret = 0;
            break;
    #endif /* HAVE_FALCON */
    #if defined(HAVE_DILITHIUM)
        case DYNAMIC_TYPE_DILITHIUM:
            wc_dilithium_init((dilithium_key*)*pKey);
            ret = 0;
            break;
    #endif /* HAVE_DILITHIUM */
    #endif /* HAVE_PQC */
    #ifdef HAVE_CURVE448
        case DYNAMIC_TYPE_CURVE448:
            wc_curve448_init((curve448_key*)*pKey);
            ret = 0;
            break;
    #endif /* HAVE_CURVE448 */
    #ifndef NO_DH
        case DYNAMIC_TYPE_DH:
            ret = wc_InitDhKey_ex((DhKey*)*pKey, ssl->heap, ssl->devId);
            break;
    #endif /* !NO_DH */
        default:
            return BAD_FUNC_ARG;
    }

    /* On error free handshake key */
    if (ret != 0) {
        FreeKey(ssl, type, pKey);
    }

    return ret;
}

#if !defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
    defined(HAVE_CURVE25519) || defined(HAVE_ED448) || \
    defined(HAVE_CURVE448) || (defined(HAVE_PQC) && defined(HAVE_FALCON)) || \
    (defined(HAVE_PQC) && defined(HAVE_DILITHIUM))
static int ReuseKey(WOLFSSL* ssl, int type, void* pKey)
{
    int ret = 0;

    (void)ssl;

    switch (type) {
    #ifndef NO_RSA
        case DYNAMIC_TYPE_RSA:
            wc_FreeRsaKey((RsaKey*)pKey);
            ret = wc_InitRsaKey_ex((RsaKey*)pKey, ssl->heap, ssl->devId);
            break;
    #endif /* ! NO_RSA */
    #ifdef HAVE_ECC
        case DYNAMIC_TYPE_ECC:
            wc_ecc_free((ecc_key*)pKey);
            ret = wc_ecc_init_ex((ecc_key*)pKey, ssl->heap, ssl->devId);
            break;
    #endif /* HAVE_ECC */
    #ifdef HAVE_ED25519
        case DYNAMIC_TYPE_ED25519:
            wc_ed25519_free((ed25519_key*)pKey);
            ret = wc_ed25519_init_ex((ed25519_key*)pKey, ssl->heap,
                ssl->devId);
            break;
    #endif /* HAVE_CURVE25519 */
    #ifdef HAVE_CURVE25519
        case DYNAMIC_TYPE_CURVE25519:
            wc_curve25519_free((curve25519_key*)pKey);
            ret = wc_curve25519_init_ex((curve25519_key*)pKey, ssl->heap,
                ssl->devId);
            break;
    #endif /* HAVE_CURVE25519 */
    #ifdef HAVE_ED448
        case DYNAMIC_TYPE_ED448:
            wc_ed448_free((ed448_key*)pKey);
            ret = wc_ed448_init_ex((ed448_key*)pKey, ssl->heap, ssl->devId);
            break;
    #endif /* HAVE_CURVE448 */
    #ifdef HAVE_CURVE448
        case DYNAMIC_TYPE_CURVE448:
            wc_curve448_free((curve448_key*)pKey);
            ret = wc_curve448_init((curve448_key*)pKey);
            break;
    #endif /* HAVE_CURVE448 */
    #if defined(HAVE_PQC) && defined(HAVE_FALCON)
        case DYNAMIC_TYPE_FALCON:
            wc_falcon_free((falcon_key*)pKey);
            ret = wc_falcon_init((falcon_key*)pKey);
            break;
    #endif /* HAVE_PQC && HAVE_FALCON */
    #ifndef NO_DH
        case DYNAMIC_TYPE_DH:
            wc_FreeDhKey((DhKey*)pKey);
            ret = wc_InitDhKey_ex((DhKey*)pKey, ssl->heap, ssl->devId);
            break;
    #endif /* !NO_DH */
        default:
            return BAD_FUNC_ARG;
    }

    return ret;
}
#endif

#ifdef WOLFSSL_ASYNC_IO
void FreeAsyncCtx(WOLFSSL* ssl, byte freeAsync)
{
    if (ssl->async != NULL) {
        if (ssl->async->freeArgs != NULL) {
            ssl->async->freeArgs(ssl, ssl->async->args);
            ssl->async->freeArgs = NULL;
        }
#if defined(WOLFSSL_ASYNC_CRYPT) && !defined(WOLFSSL_NO_TLS12)
        if (ssl->options.buildArgsSet) {
            FreeBuildMsgArgs(ssl, &ssl->async->buildArgs);
            ssl->options.buildArgsSet = 0;
        }
#endif
        if (freeAsync) {
            XFREE(ssl->async, ssl->heap, DYNAMIC_TYPE_ASYNC);
            ssl->async = NULL;
        }
    }
}
#endif

void FreeKeyExchange(WOLFSSL* ssl)
{
    /* Cleanup signature buffer */
    if (ssl->buffers.sig.buffer) {
        XFREE(ssl->buffers.sig.buffer, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
        ssl->buffers.sig.buffer = NULL;
        ssl->buffers.sig.length = 0;
    }

    /* Cleanup digest buffer */
    if (ssl->buffers.digest.buffer) {
        XFREE(ssl->buffers.digest.buffer, ssl->heap, DYNAMIC_TYPE_DIGEST);
        ssl->buffers.digest.buffer = NULL;
        ssl->buffers.digest.length = 0;
    }

    /* Free handshake key */
    FreeKey(ssl, ssl->hsType, &ssl->hsKey);

#ifndef NO_DH
    /* Free temp DH key */
    FreeKey(ssl, DYNAMIC_TYPE_DH, (void**)&ssl->buffers.serverDH_Key);
#endif
}


/* Free up all memory used by Suites structure from WOLFSSL */
void FreeSuites(WOLFSSL* ssl)
{
#ifdef SINGLE_THREADED
    if (ssl->options.ownSuites)
#endif
    {
    #ifdef OPENSSL_ALL
        if (ssl->suites != NULL) {
            /* Enough to free stack structure since WOLFSSL_CIPHER
             * isn't allocated separately. */
            wolfSSL_sk_SSL_CIPHER_free(ssl->suites->stack);
        }
    #endif
        XFREE(ssl->suites, ssl->heap, DYNAMIC_TYPE_SUITES);
    }
    ssl->suites = NULL;
}


/* In case holding SSL object in array and don't want to free actual ssl */
void SSL_ResourceFree(WOLFSSL* ssl)
{
    /* Note: any resources used during the handshake should be released in the
     * function FreeHandshakeResources(). Be careful with the special cases
     * like the RNG which may optionally be kept for the whole session. (For
     * example with the RNG, it isn't used beyond the handshake except when
     * using stream ciphers where it is retained. */

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        WOLFSSL_MSG("Free'ing server ssl");
    }
    else {
        WOLFSSL_MSG("Free'ing client ssl");
    }

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
    wolfSSL_CRYPTO_cleanup_ex_data(&ssl->ex_data);
#endif

    FreeCiphers(ssl);
    FreeArrays(ssl, 0);
    FreeKeyExchange(ssl);
#ifdef WOLFSSL_ASYNC_IO
    /* Cleanup async */
    FreeAsyncCtx(ssl, 1);
#endif
    if (ssl->options.weOwnRng) {
        wc_FreeRng(ssl->rng);
        XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
    }
    FreeSuites(ssl);
    FreeHandshakeHashes(ssl);
    XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

    /* clear keys struct after session */
    ForceZero(&ssl->keys, sizeof(Keys));

#ifdef WOLFSSL_TLS13
    if (ssl->options.tls1_3) {
        ForceZero(&ssl->clientSecret, sizeof(ssl->clientSecret));
        ForceZero(&ssl->serverSecret, sizeof(ssl->serverSecret));
    }
#endif
#ifdef WOLFSSL_HAVE_TLS_UNIQUE
    ForceZero(&ssl->clientFinished, TLS_FINISHED_SZ_MAX);
    ForceZero(&ssl->serverFinished, TLS_FINISHED_SZ_MAX);
    ssl->serverFinished_len = 0;
    ssl->clientFinished_len = 0;
#endif
#ifndef NO_DH
    if (ssl->buffers.serverDH_Priv.buffer != NULL) {
        ForceZero(ssl->buffers.serverDH_Priv.buffer,
                                             ssl->buffers.serverDH_Priv.length);
    }
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
#endif /* !NO_DH */
#ifndef NO_CERTS
    ssl->keepCert = 0; /* make sure certificate is free'd */
    wolfSSL_UnloadCertsKeys(ssl);
#endif
#ifndef NO_RSA
    FreeKey(ssl, DYNAMIC_TYPE_RSA, (void**)&ssl->peerRsaKey);
    ssl->peerRsaKeyPresent = 0;
#endif
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_SCEPROTECT)
    XFREE(ssl->peerSceTsipEncRsaKeyIndex, ssl->heap, DYNAMIC_TYPE_RSA);
    Renesas_cmn_Cleanup(ssl);
#endif
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, FORCED_FREE);
    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);
#if defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_SERVER)
    if (ssl->buffers.tls13CookieSecret.buffer != NULL) {
        ForceZero(ssl->buffers.tls13CookieSecret.buffer,
            ssl->buffers.tls13CookieSecret.length);
    }
    XFREE(ssl->buffers.tls13CookieSecret.buffer, ssl->heap,
          DYNAMIC_TYPE_COOKIE_PWD);
#endif
#ifdef WOLFSSL_DTLS
    DtlsMsgPoolReset(ssl);
    if (ssl->dtls_rx_msg_list != NULL) {
        DtlsMsgListDelete(ssl->dtls_rx_msg_list, ssl->heap);
        ssl->dtls_rx_msg_list = NULL;
        ssl->dtls_rx_msg_list_sz = 0;
    }
    XFREE(ssl->buffers.dtlsCtx.peer.sa, ssl->heap, DYNAMIC_TYPE_SOCKADDR);
    ssl->buffers.dtlsCtx.peer.sa = NULL;
#ifndef NO_WOLFSSL_SERVER
    if (ssl->buffers.dtlsCookieSecret.buffer != NULL) {
        ForceZero(ssl->buffers.dtlsCookieSecret.buffer,
            ssl->buffers.dtlsCookieSecret.length);
    }
    XFREE(ssl->buffers.dtlsCookieSecret.buffer, ssl->heap,
          DYNAMIC_TYPE_COOKIE_PWD);
#endif

#ifdef WOLFSSL_DTLS13
    if (ssl->dtls13ClientHello != NULL) {
        XFREE(ssl->dtls13ClientHello, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
        ssl->dtls13ClientHello = NULL;
        ssl->dtls13ClientHelloSz = 0;
    }
#endif /* WOLFSSL_DTLS13 */

#endif /* WOLFSSL_DTLS */
#ifdef OPENSSL_EXTRA
#ifndef NO_BIO
    /* Don't free if there was/is a previous element in the chain.
     * This means that this BIO was part of a chain that will be
     * free'd separately. */
    if (ssl->biord != ssl->biowr)        /* only free write if different */
        if (ssl->biowr != NULL && ssl->biowr->prev == NULL)
            wolfSSL_BIO_free(ssl->biowr);
    if (ssl->biord != NULL && ssl->biord->prev == NULL)
        wolfSSL_BIO_free(ssl->biord);
    ssl->biowr = NULL;
    ssl->biord = NULL;
#endif
#endif
#ifdef HAVE_LIBZ
    FreeStreams(ssl);
#endif
#ifdef HAVE_ECC
    FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccKey);
    ssl->peerEccKeyPresent = 0;
    FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccDsaKey);
    ssl->peerEccDsaKeyPresent = 0;
#endif
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) ||defined(HAVE_CURVE448)
    {
        int dtype = 0;
    #ifdef HAVE_ECC
        dtype = DYNAMIC_TYPE_ECC;
    #endif
    #ifdef HAVE_CURVE25519
        if (ssl->peerX25519KeyPresent
    #ifdef HAVE_ECC
                           || ssl->eccTempKeyPresent == DYNAMIC_TYPE_CURVE25519
    #endif /* HAVE_ECC */
           )
        {
            dtype = DYNAMIC_TYPE_CURVE25519;
        }
    #endif /* HAVE_CURVE25519 */
    #ifdef HAVE_CURVE448
        if (ssl->peerX448KeyPresent
    #ifdef HAVE_ECC
                             || ssl->eccTempKeyPresent == DYNAMIC_TYPE_CURVE448
    #endif /* HAVE_ECC */
           )
        {
            dtype = DYNAMIC_TYPE_CURVE448;
        }
    #endif /* HAVE_CURVE448 */
        FreeKey(ssl, dtype, (void**)&ssl->eccTempKey);
        ssl->eccTempKeyPresent = 0;
    }
#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
#ifdef HAVE_CURVE25519
    FreeKey(ssl, DYNAMIC_TYPE_CURVE25519, (void**)&ssl->peerX25519Key);
    ssl->peerX25519KeyPresent = 0;
#endif
#ifdef HAVE_ED25519
    FreeKey(ssl, DYNAMIC_TYPE_ED25519, (void**)&ssl->peerEd25519Key);
    ssl->peerEd25519KeyPresent = 0;
    #ifdef HAVE_PK_CALLBACKS
        if (ssl->buffers.peerEd25519Key.buffer != NULL) {
            XFREE(ssl->buffers.peerEd25519Key.buffer, ssl->heap,
                                                          DYNAMIC_TYPE_ED25519);
            ssl->buffers.peerEd25519Key.buffer = NULL;
        }
    #endif
#endif
#ifdef HAVE_CURVE448
    FreeKey(ssl, DYNAMIC_TYPE_CURVE448, (void**)&ssl->peerX448Key);
    ssl->peerX448KeyPresent = 0;
#endif
#ifdef HAVE_ED448
    FreeKey(ssl, DYNAMIC_TYPE_ED448, (void**)&ssl->peerEd448Key);
    ssl->peerEd448KeyPresent = 0;
    #ifdef HAVE_PK_CALLBACKS
        if (ssl->buffers.peerEd448Key.buffer != NULL) {
            XFREE(ssl->buffers.peerEd448Key.buffer, ssl->heap,
                                                            DYNAMIC_TYPE_ED448);
            ssl->buffers.peerEd448Key.buffer = NULL;
        }
    #endif
#endif
#if defined(HAVE_PQC) && defined(HAVE_FALCON)
    FreeKey(ssl, DYNAMIC_TYPE_FALCON, (void**)&ssl->peerFalconKey);
    ssl->peerFalconKeyPresent = 0;
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        XFREE(ssl->buffers.peerEccDsaKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        XFREE(ssl->buffers.peerRsaKey.buffer, ssl->heap, DYNAMIC_TYPE_RSA);
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
#ifdef HAVE_TLS_EXTENSIONS
#if !defined(NO_TLS)
    TLSX_FreeAll(ssl->extensions, ssl->heap);
#endif /* !NO_TLS */
#ifdef HAVE_ALPN
    if (ssl->alpn_peer_requested != NULL) {
        XFREE(ssl->alpn_peer_requested, ssl->heap, DYNAMIC_TYPE_ALPN);
        ssl->alpn_peer_requested = NULL;
        ssl->alpn_peer_requested_length = 0;
    }
#endif
#endif /* HAVE_TLS_EXTENSIONS */
#if defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP)
    if (ssl->mnCtx) {
        mynewt_ctx_clear(ssl->mnCtx);
        ssl->mnCtx = NULL;
    }
#endif
#ifdef HAVE_NETX
    if (ssl->nxCtx.nxPacket)
        nx_packet_release(ssl->nxCtx.nxPacket);
#endif
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    if (ssl->x509_store_pt)
        wolfSSL_X509_STORE_free(ssl->x509_store_pt);
#endif
#ifdef KEEP_PEER_CERT
    FreeX509(&ssl->peerCert);
#endif

    if (ssl->session != NULL)
        wolfSSL_FreeSession(ssl->ctx, ssl->session);
#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite) {
        FreeWriteDup(ssl);
    }
#endif
#ifdef OPENSSL_EXTRA
    if (ssl->param) {
        XFREE(ssl->param, ssl->heap, DYNAMIC_TYPE_OPENSSL);
    }
#endif
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    while (ssl->certReqCtx != NULL) {
        CertReqCtx* curr = ssl->certReqCtx;
        ssl->certReqCtx = curr->next;
        XFREE(curr, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif
#ifdef WOLFSSL_STATIC_EPHEMERAL
    #ifndef NO_DH
    FreeDer(&ssl->staticKE.dhKey);
    #endif
    #ifdef HAVE_ECC
    FreeDer(&ssl->staticKE.ecKey);
    #endif
    #ifdef HAVE_CURVE25519
    FreeDer(&ssl->staticKE.x25519Key);
    #endif
    #ifdef HAVE_CURVE448
    FreeDer(&ssl->staticKE.x448Key);
    #endif
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    /* check if using fixed io buffers and free them */
    if (ssl->heap != NULL) {
    #ifdef WOLFSSL_HEAP_TEST
    /* avoid dereferencing a test value */
    if (ssl->heap != (void*)WOLFSSL_HEAP_TEST) {
    #endif
        WOLFSSL_HEAP_HINT* ssl_hint = (WOLFSSL_HEAP_HINT*)ssl->heap;
        WOLFSSL_HEAP*      ctx_heap;
        void* heap = ssl->ctx ? ssl->ctx->heap : ssl->heap;

        ctx_heap = ssl_hint->memory;
        if (wc_LockMutex(&(ctx_heap->memory_mutex)) != 0) {
            WOLFSSL_MSG("Bad memory_mutex lock");
        }
        ctx_heap->curIO--;
        if (FreeFixedIO(ctx_heap, &(ssl_hint->outBuf)) != 1) {
            WOLFSSL_MSG("Error freeing fixed output buffer");
        }
        if (FreeFixedIO(ctx_heap, &(ssl_hint->inBuf)) != 1) {
            WOLFSSL_MSG("Error freeing fixed output buffer");
        }
        if (ssl_hint->haFlag) { /* check if handshake count has been decreased*/
            ctx_heap->curHa--;
        }
        wc_UnLockMutex(&(ctx_heap->memory_mutex));

        /* check if tracking stats */
        if (ctx_heap->flag & WOLFMEM_TRACK_STATS) {
            XFREE(ssl_hint->stats, heap, DYNAMIC_TYPE_SSL);
        }
        XFREE(ssl->heap, heap, DYNAMIC_TYPE_SSL);
    #ifdef WOLFSSL_HEAP_TEST
    }
    #endif
    }
#endif /* WOLFSSL_STATIC_MEMORY */
#ifdef OPENSSL_EXTRA
    /* Enough to free stack structure since WOLFSSL_CIPHER
     * isn't allocated separately. */
    wolfSSL_sk_CIPHER_free(ssl->supportedCiphers);
    wolfSSL_sk_X509_pop_free(ssl->peerCertChain, NULL);
    #ifdef KEEP_OUR_CERT
    wolfSSL_sk_X509_pop_free(ssl->ourCertChain, NULL);
    #endif
#endif
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_EXTRA) || defined(HAVE_LIGHTY)
    wolfSSL_sk_X509_NAME_pop_free(ssl->ca_names, NULL);
    ssl->ca_names = NULL;
#endif
#ifdef WOLFSSL_DTLS13
    Dtls13FreeFsmResources(ssl);
#endif /* WOLFSSL_DTLS13 */
#ifdef WOLFSSL_QUIC
    wolfSSL_quic_free(ssl);
#endif
}

/* Free any handshake resources no longer needed */
void FreeHandshakeResources(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("FreeHandshakeResources");

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        /* DTLS_POOL (DTLSv1.3 flushes the queue autonomously) */
        if(!IsAtLeastTLSv1_3(ssl->version)) {
            DtlsMsgPoolReset(ssl);
            DtlsMsgListDelete(ssl->dtls_rx_msg_list, ssl->heap);
            ssl->dtls_rx_msg_list = NULL;
            ssl->dtls_rx_msg_list_sz = 0;
        }
#ifdef WOLFSSL_DTLS13
        if (ssl->dtls13ClientHello != NULL) {
            XFREE(ssl->dtls13ClientHello, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
            ssl->dtls13ClientHello = NULL;
            ssl->dtls13ClientHelloSz = 0;
        }
#endif /* WOLFSSL_DTLS13 */
    }
#endif

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled) {
        WOLFSSL_MSG("Secure Renegotiation needs to retain handshake resources");
        return;
    }
#endif

    /* input buffer */
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, NO_FORCED_FREE);

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    if (!ssl->options.tls1_3)
#endif
    {
    #ifndef OPENSSL_EXTRA
        /* free suites unless using compatibility layer */
        FreeSuites(ssl);
    #endif
        /* hsHashes */
        FreeHandshakeHashes(ssl);
    }

    /* RNG */
    if (ssl->options.tls1_1 == 0
#ifndef WOLFSSL_AEAD_ONLY
        || ssl->specs.cipher_type == stream
#endif
#if defined(WOLFSSL_TLS13)
    /* Post-handshake auth requires random on client side for TLS 1.3.
     * Session ticket requires random on server side.
     */
    #if !defined(WOLFSSL_POST_HANDSHAKE_AUTH) && !defined(HAVE_SESSION_TICKET)
        || ssl->options.tls1_3
    #elif !defined(WOLFSSL_POST_HANDSHAKE_AUTH) && defined(HAVE_SESSION_TICKET)
        || (ssl->options.tls1_3 && ssl->options.side == WOLFSSL_CLIENT_END)
    #elif !defined(HAVE_SESSION_TICKET)
        || (ssl->options.tls1_3 && ssl->options.side == WOLFSSL_SERVER_END)
    #endif
#endif
    ) {
        if (ssl->options.weOwnRng) {
            wc_FreeRng(ssl->rng);
            XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
            ssl->rng = NULL;
            ssl->options.weOwnRng = 0;
        }
    }

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH) && \
                                                    defined(HAVE_SESSION_TICKET)
    if (!ssl->options.tls1_3)
#endif
        /* arrays */
        if (ssl->options.saveArrays == 0)
            FreeArrays(ssl, 1);

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    if (!ssl->options.tls1_3 || ssl->options.side == WOLFSSL_CLIENT_END)
#endif
    {
#ifndef NO_RSA
        /* peerRsaKey */
        FreeKey(ssl, DYNAMIC_TYPE_RSA, (void**)&ssl->peerRsaKey);
        ssl->peerRsaKeyPresent = 0;
#endif
#ifdef HAVE_ECC
        FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccDsaKey);
        ssl->peerEccDsaKeyPresent = 0;
#endif /* HAVE_ECC */
#ifdef HAVE_ED25519
        FreeKey(ssl, DYNAMIC_TYPE_ED25519, (void**)&ssl->peerEd25519Key);
        ssl->peerEd25519KeyPresent = 0;
#endif /* HAVE_ED25519 */
#ifdef HAVE_ED448
        FreeKey(ssl, DYNAMIC_TYPE_ED448, (void**)&ssl->peerEd448Key);
        ssl->peerEd448KeyPresent = 0;
#endif /* HAVE_ED448 */
#if defined(HAVE_PQC) && defined(HAVE_FALCON)
        FreeKey(ssl, DYNAMIC_TYPE_FALCON, (void**)&ssl->peerFalconKey);
        ssl->peerFalconKeyPresent = 0;
#endif /* HAVE_PQC */
    }

#ifdef HAVE_ECC
    FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccKey);
    ssl->peerEccKeyPresent = 0;
#endif
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
    {
        int dtype;
    #ifdef HAVE_ECC
        dtype = DYNAMIC_TYPE_ECC;
    #elif defined(HAVE_CURVE25519)
        dtype = DYNAMIC_TYPE_CURVE25519;
    #else
        dtype = DYNAMIC_TYPE_CURVE448;
    #endif
    #if defined(HAVE_ECC) && defined(HAVE_CURVE25519)
        if (ssl->peerX25519KeyPresent ||
                              ssl->eccTempKeyPresent == DYNAMIC_TYPE_CURVE25519)
         {
            dtype = DYNAMIC_TYPE_CURVE25519;
         }
    #endif
    #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519)) && \
                                                          defined(HAVE_CURVE448)
        if (ssl->peerX448KeyPresent ||
                                ssl->eccTempKeyPresent == DYNAMIC_TYPE_CURVE448)
         {
            dtype = DYNAMIC_TYPE_CURVE448;
         }
    #endif
        FreeKey(ssl, dtype, (void**)&ssl->eccTempKey);
        ssl->eccTempKeyPresent = 0;
    }
#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
#ifdef HAVE_CURVE25519
    FreeKey(ssl, DYNAMIC_TYPE_CURVE25519, (void**)&ssl->peerX25519Key);
    ssl->peerX25519KeyPresent = 0;
#endif
#ifdef HAVE_CURVE448
    FreeKey(ssl, DYNAMIC_TYPE_CURVE448, (void**)&ssl->peerX448Key);
    ssl->peerX448KeyPresent = 0;
#endif

#ifndef NO_DH
    if (ssl->buffers.serverDH_Priv.buffer) {
        ForceZero(ssl->buffers.serverDH_Priv.buffer,
                                             ssl->buffers.serverDH_Priv.length);
    }
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
    ssl->buffers.serverDH_Priv.buffer = NULL;
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    ssl->buffers.serverDH_Pub.buffer = NULL;
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
    }
#endif /* !NO_DH */

#ifndef NO_CERTS
    wolfSSL_UnloadCertsKeys(ssl);
#endif
#ifdef HAVE_PK_CALLBACKS
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    if (!ssl->options.tls1_3 || ssl->options.side == WOLFSSL_CLIENT_END)
#endif
    {
    #ifdef HAVE_ECC
        XFREE(ssl->buffers.peerEccDsaKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
        ssl->buffers.peerEccDsaKey.buffer = NULL;
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        XFREE(ssl->buffers.peerRsaKey.buffer, ssl->heap, DYNAMIC_TYPE_RSA);
        ssl->buffers.peerRsaKey.buffer = NULL;
    #endif /* NO_RSA */
    #ifdef HAVE_ED25519
        XFREE(ssl->buffers.peerEd25519Key.buffer, ssl->heap,
                                                          DYNAMIC_TYPE_ED25519);
        ssl->buffers.peerEd25519Key.buffer = NULL;
    #endif
    #ifdef HAVE_ED448
        XFREE(ssl->buffers.peerEd448Key.buffer, ssl->heap, DYNAMIC_TYPE_ED448);
        ssl->buffers.peerEd448Key.buffer = NULL;
    #endif
    }
#endif /* HAVE_PK_CALLBACKS */

#if defined(HAVE_TLS_EXTENSIONS) && !defined(HAVE_SNI) && \
!defined(NO_TLS) && !defined(HAVE_ALPN) && !defined(WOLFSSL_POST_HANDSHAKE_AUTH) && \
    !defined(WOLFSSL_DTLS_CID)
    /* Some extensions need to be kept for post-handshake querying. */
    TLSX_FreeAll(ssl->extensions, ssl->heap);
    ssl->extensions = NULL;
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    /* when done with handshake decrement current handshake count */
    if (ssl->heap != NULL) {
    #ifdef WOLFSSL_HEAP_TEST
    /* avoid dereferencing a test value */
    if (ssl->heap != (void*)WOLFSSL_HEAP_TEST) {
    #endif
        WOLFSSL_HEAP_HINT* ssl_hint = (WOLFSSL_HEAP_HINT*)ssl->heap;
        WOLFSSL_HEAP*      ctx_heap;

        ctx_heap = ssl_hint->memory;
        if (wc_LockMutex(&(ctx_heap->memory_mutex)) != 0) {
            WOLFSSL_MSG("Bad memory_mutex lock");
        }
        ctx_heap->curHa--;
        ssl_hint->haFlag = 0; /* set to zero since handshake has been dec */
        wc_UnLockMutex(&(ctx_heap->memory_mutex));
    #ifdef WOLFSSL_HEAP_TEST
    }
    #endif
    }
#endif /* WOLFSSL_STATIC_MEMORY */
}


/* heap argument is the heap hint used when creating SSL */
void FreeSSL(WOLFSSL* ssl, void* heap)
{
    WOLFSSL_CTX* ctx = ssl->ctx;
    SSL_ResourceFree(ssl);
    XFREE(ssl, heap, DYNAMIC_TYPE_SSL);
    if (ctx)
        FreeSSL_Ctx(ctx); /* will decrement and free underlying CTX if 0 */
    (void)heap;
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(ssl, sizeof(*ssl));
#endif
}

#if !defined(NO_OLD_TLS) || defined(WOLFSSL_DTLS) || \
    !defined(WOLFSSL_NO_TLS12) || \
    ((defined(HAVE_CHACHA) || defined(HAVE_AESCCM) || defined(HAVE_AESGCM)) \
     && defined(HAVE_AEAD))

#if defined(WOLFSSL_DTLS) || !defined(WOLFSSL_NO_TLS12)
static WC_INLINE void GetSEQIncrement(WOLFSSL* ssl, int verify, word32 seq[2])
{
    if (verify) {
        seq[0] = ssl->keys.peer_sequence_number_hi;
        seq[1] = ssl->keys.peer_sequence_number_lo++;
        if (seq[1] > ssl->keys.peer_sequence_number_lo) {
            /* handle rollover */
            ssl->keys.peer_sequence_number_hi++;
        }
    }
    else {
        seq[0] = ssl->keys.sequence_number_hi;
        seq[1] = ssl->keys.sequence_number_lo++;
        if (seq[1] > ssl->keys.sequence_number_lo) {
            /* handle rollover */
            ssl->keys.sequence_number_hi++;
        }
    }
}
#endif /* WOLFSSL_DTLS || !WOLFSSL_NO_TLS12 */


#ifdef WOLFSSL_DTLS
static WC_INLINE void DtlsGetSEQ(WOLFSSL* ssl, int order, word32 seq[2])
{
#ifdef HAVE_SECURE_RENEGOTIATION
    order = DtlsCheckOrder(ssl, order);
#endif
    if (order == PREV_ORDER) {
        /* Previous epoch case */
        if (ssl->options.haveMcast) {
        #ifdef WOLFSSL_MULTICAST
            seq[0] = (((word32)ssl->keys.dtls_epoch - 1) << 16) |
                     (ssl->options.mcastID << 8) |
                     (ssl->keys.dtls_prev_sequence_number_hi & 0xFF);
        #endif
        }
        else
            seq[0] = (((word32)ssl->keys.dtls_epoch - 1) << 16) |
                     (ssl->keys.dtls_prev_sequence_number_hi & 0xFFFF);
        seq[1] = ssl->keys.dtls_prev_sequence_number_lo;
    }
    else if (order == PEER_ORDER) {
        if (ssl->options.haveMcast) {
        #ifdef WOLFSSL_MULTICAST
            seq[0] = ((word32)ssl->keys.curEpoch << 16) |
                     (ssl->keys.curPeerId << 8) |
                     (ssl->keys.curSeq_hi & 0xFF);
        #endif
        }
        else
            seq[0] = ((word32)ssl->keys.curEpoch << 16) |
                     (ssl->keys.curSeq_hi & 0xFFFF);
        seq[1] = ssl->keys.curSeq_lo; /* explicit from peer */
    }
    else {
        if (ssl->options.haveMcast) {
        #ifdef WOLFSSL_MULTICAST
            seq[0] = ((word32)ssl->keys.dtls_epoch << 16) |
                     (ssl->options.mcastID << 8) |
                     (ssl->keys.dtls_sequence_number_hi & 0xFF);
        #endif
        }
        else
            seq[0] = ((word32)ssl->keys.dtls_epoch << 16) |
                     (ssl->keys.dtls_sequence_number_hi & 0xFFFF);
        seq[1] = ssl->keys.dtls_sequence_number_lo;
    }
}

static WC_INLINE void DtlsSEQIncrement(WOLFSSL* ssl, int order)
{
    word32 seq;
#ifdef HAVE_SECURE_RENEGOTIATION
    order = DtlsCheckOrder(ssl, order);
#endif

    if (order == PREV_ORDER) {
        seq = ssl->keys.dtls_prev_sequence_number_lo++;
        if (seq > ssl->keys.dtls_prev_sequence_number_lo) {
            /* handle rollover */
            ssl->keys.dtls_prev_sequence_number_hi++;
        }
    }
    else if (order == PEER_ORDER) {
        seq = ssl->keys.peer_sequence_number_lo++;
        if (seq > ssl->keys.peer_sequence_number_lo) {
            /* handle rollover */
            ssl->keys.peer_sequence_number_hi++;
        }
    }
    else {
        seq = ssl->keys.dtls_sequence_number_lo++;
        if (seq > ssl->keys.dtls_sequence_number_lo) {
            /* handle rollover */
            ssl->keys.dtls_sequence_number_hi++;
        }
    }
}
#endif /* WOLFSSL_DTLS */

#if defined(WOLFSSL_DTLS) || !defined(WOLFSSL_NO_TLS12)
void WriteSEQ(WOLFSSL* ssl, int verifyOrder, byte* out)
{
    word32 seq[2] = {0, 0};

    if (!ssl->options.dtls) {
        GetSEQIncrement(ssl, verifyOrder, seq);
    }
    else {
#ifdef WOLFSSL_DTLS
        DtlsGetSEQ(ssl, verifyOrder, seq);
#endif
    }

    c32toa(seq[0], out);
    c32toa(seq[1], out + OPAQUE32_LEN);
}
#endif /* WOLFSSL_DTLS || !WOLFSSL_NO_TLS12 */
#endif /* !NO_OLD_TLS || WOLFSSL_DTLS || !WOLFSSL_NO_TLS12 ||
        *     ((HAVE_CHACHA || HAVE_AESCCM || HAVE_AESGCM) && HAVE_AEAD) */

#ifdef WOLFSSL_DTLS

/* functions for managing DTLS datagram reordering */

/* Need to allocate space for the handshake message header. The hashing
 * routines assume the message pointer is still within the buffer that
 * has the headers, and will include those headers in the hash. The store
 * routines need to take that into account as well. New will allocate
 * extra space for the headers. */
DtlsMsg* DtlsMsgNew(word32 sz, byte tx, void* heap)
{
    DtlsMsg* msg;
    WOLFSSL_ENTER("DtlsMsgNew()");

    (void)heap;
    msg = (DtlsMsg*)XMALLOC(sizeof(DtlsMsg), heap, DYNAMIC_TYPE_DTLS_MSG);

    if (msg != NULL) {
        XMEMSET(msg, 0, sizeof(DtlsMsg));
        msg->sz = sz;
        msg->type = no_shake;
        if (tx) {
            msg->raw = msg->fullMsg =
                    (byte*)XMALLOC(sz + DTLS_HANDSHAKE_HEADER_SZ, heap,
                            DYNAMIC_TYPE_DTLS_FRAG);
            msg->ready = 1;
            if (msg->raw == NULL) {
                DtlsMsgDelete(msg, heap);
                msg = NULL;
            }
        }
    }

    return msg;
}

void DtlsMsgDelete(DtlsMsg* item, void* heap)
{
    (void)heap;
    WOLFSSL_ENTER("DtlsMsgDelete()");

    if (item != NULL) {
        while (item->fragBucketList != NULL) {
            DtlsFragBucket* next = item->fragBucketList->m.m.next;
            DtlsMsgDestroyFragBucket(item->fragBucketList, heap);
            item->fragBucketList = next;
        }
        if (item->raw != NULL)
            XFREE(item->raw, heap, DYNAMIC_TYPE_DTLS_FRAG);
        XFREE(item, heap, DYNAMIC_TYPE_DTLS_MSG);
    }
}


void DtlsMsgListDelete(DtlsMsg* head, void* heap)
{
    DtlsMsg* next;
    WOLFSSL_ENTER("DtlsMsgListDelete()");
    while (head) {
        next = head->next;
        DtlsMsgDelete(head, heap);
        head = next;
    }
}

/**
 * Drop messages when they are no longer going to be retransmitted
 */
void DtlsTxMsgListClean(WOLFSSL* ssl)
{
    DtlsMsg* head = ssl->dtls_tx_msg_list;
    DtlsMsg* next;
    WOLFSSL_ENTER("DtlsTxMsgListClean()");
    while (head) {
        next = head->next;
        if (VerifyForTxDtlsMsgDelete(ssl, head))
            DtlsMsgDelete(head, ssl->heap);
        else
            /* Stored packets should be in order so break on first failed
             * verify */
            break;
        ssl->dtls_tx_msg_list_sz--;
        head = next;
    }
    ssl->dtls_tx_msg_list = head;
}

static DtlsFragBucket* DtlsMsgCreateFragBucket(word32 offset, const byte* data,
                                               word32 dataSz, void* heap)
{
    DtlsFragBucket* bucket =
            (DtlsFragBucket*)XMALLOC(sizeof(DtlsFragBucket) + dataSz, heap,
                                     DYNAMIC_TYPE_DTLS_FRAG);
    if (bucket != NULL) {
        XMEMSET(bucket, 0, sizeof(*bucket));
        bucket->m.m.next = NULL;
        bucket->m.m.offset = offset;
        bucket->m.m.sz = dataSz;
        if (data != NULL)
            XMEMCPY(bucket->buf, data, dataSz);
    }
    return bucket;
}

void DtlsMsgDestroyFragBucket(DtlsFragBucket* fragBucket, void* heap)
{
    (void)heap;
    XFREE(fragBucket, heap, DYNAMIC_TYPE_DTLS_FRAG);
}

/*
 * data overlaps with cur but is before next.
 * data + dataSz has to end before or inside next. next can be NULL.
 */
static DtlsFragBucket* DtlsMsgCombineFragBuckets(DtlsMsg* msg,
        DtlsFragBucket* cur, DtlsFragBucket* next, word32 offset,
        const byte* data, word32 dataSz, void* heap)
{
    word32 offsetEnd = offset + dataSz;
    word32 newOffset = min(cur->m.m.offset, offset);
    word32 newOffsetEnd;
    word32 newSz;
    word32 overlapSz = cur->m.m.sz;
    DtlsFragBucket** chosenBucket;
    DtlsFragBucket* newBucket;
    DtlsFragBucket* otherBucket;
    byte combineNext = FALSE;

    if (next != NULL && offsetEnd >= next->m.m.offset)
        combineNext = TRUE;

    if (combineNext)
        newOffsetEnd = next->m.m.offset + next->m.m.sz;
    else
        newOffsetEnd = max(cur->m.m.offset + cur->m.m.sz, offsetEnd);

    newSz = newOffsetEnd - newOffset;

    /* Expand the larger bucket if data bridges the gap between cur and next */
    if (!combineNext || cur->m.m.sz >= next->m.m.sz) {
        chosenBucket = &cur;
        otherBucket = next;
    }
    else {
        chosenBucket = &next;
        otherBucket = cur;
    }

    {
        DtlsFragBucket* tmp = (DtlsFragBucket*)XREALLOC(*chosenBucket,
                sizeof(DtlsFragBucket) + newSz, heap, DYNAMIC_TYPE_DTLS_FRAG);
        if (tmp == NULL)
            return NULL;
        if (chosenBucket == &next) {
            /* Update the link */
            DtlsFragBucket* beforeNext = cur;
            while (beforeNext->m.m.next != next)
                beforeNext = beforeNext->m.m.next;
            beforeNext->m.m.next = tmp;
        }
        newBucket = *chosenBucket = tmp;
    }

    if (combineNext) {
        /* Put next first since it will always be at the end. Use memmove since
         * newBucket may be next. */
        XMEMMOVE(newBucket->buf + (next->m.m.offset - newOffset), next->buf,
                next->m.m.sz);
        /* memory after newOffsetEnd is already copied. Don't do extra work. */
        newOffsetEnd = next->m.m.offset;
    }

    if (newOffset == offset) {
        /* data comes first */
        if (newOffsetEnd <= offsetEnd) {
            /* data encompasses cur. only copy data */
            XMEMCPY(newBucket->buf, data,
                    min(dataSz, newOffsetEnd - newOffset));
        }
        else {
            /* data -> cur. memcpy as much possible as its faster. */
            XMEMMOVE(newBucket->buf + dataSz, cur->buf,
                    cur->m.m.sz - (offsetEnd - cur->m.m.offset));
            XMEMCPY(newBucket->buf, data, dataSz);
        }
    }
    else {
        /* cur -> data */
        word32 curOffsetEnd = cur->m.m.offset + cur->m.m.sz;
        if (newBucket != cur)
            XMEMCPY(newBucket->buf, cur->buf, cur->m.m.sz);
        XMEMCPY(newBucket->buf + cur->m.m.sz,
                data + (curOffsetEnd - offset),
                newOffsetEnd - curOffsetEnd);
    }
    /* FINALLY the newBucket is populated correctly */

    /* All buckets up to and including next (if combining) have to be free'd */
    {
        DtlsFragBucket* toFree = cur->m.m.next;
        while (toFree != next) {
            DtlsFragBucket* n = toFree->m.m.next;
            overlapSz += toFree->m.m.sz;
            DtlsMsgDestroyFragBucket(toFree, heap);
            msg->fragBucketListCount--;
            toFree = n;
        }
        if (combineNext) {
            newBucket->m.m.next = next->m.m.next;
            overlapSz += next->m.m.sz;
            DtlsMsgDestroyFragBucket(otherBucket, heap);
            msg->fragBucketListCount--;
        }
        else {
            newBucket->m.m.next = next;
        }
    }
    /* Adjust size in msg */
    msg->bytesReceived += newSz - overlapSz;
    newBucket->m.m.offset = newOffset;
    newBucket->m.m.sz = newSz;
    return newBucket;
}

static void DtlsMsgAssembleCompleteMessage(DtlsMsg* msg)
{
    DtlsHandShakeHeader* dtls;

    /* We have received all necessary fragments. Reconstruct the header. */
    if (msg->fragBucketListCount != 1 || msg->fragBucketList->m.m.offset != 0 ||
            msg->fragBucketList->m.m.sz != msg->sz) {
        WOLFSSL_MSG("Major error in fragment assembly logic");
        return;
    }

    /* Re-cycle the DtlsFragBucket as the buffer that holds the complete
     * handshake message and the header. */
    msg->raw = (byte*)msg->fragBucketList;
    msg->fullMsg = msg->fragBucketList->buf;
    msg->ready = 1;

    /* frag->padding makes sure we can fit the entire DTLS handshake header
     * before frag->buf */

    /* note the dtls pointer needs to be computed from msg->fragBucketList, not
     * from msg->fragBucketList->buf, to avoid a pointerOutOfBounds access
     * detected by cppcheck.
     *
     * also note, the (void *) intermediate cast is necessary to avoid a
     * potential -Wcast-align around alignment of DtlsHandShakeHeader exceeding
     * alignment of char.
     */
    dtls = (DtlsHandShakeHeader*)(void *)((char *)msg->fragBucketList
                                          + OFFSETOF(DtlsFragBucket,buf)
                                          - DTLS_HANDSHAKE_HEADER_SZ);

    msg->fragBucketList = NULL;
    msg->fragBucketListCount = 0;

    dtls->type = msg->type;
    c32to24(msg->sz, dtls->length);
    c16toa((word16)msg->seq, dtls->message_seq);
    c32to24(0, dtls->fragment_offset);
    c32to24(msg->sz, dtls->fragment_length);
}

int DtlsMsgSet(DtlsMsg* msg, word32 seq, word16 epoch, const byte* data, byte type,
               word32 fragOffset, word32 fragSz, void* heap, word32 totalLen)
{
    word32 fragOffsetEnd = fragOffset + fragSz;

    WOLFSSL_ENTER("DtlsMsgSet()");

    if (msg == NULL || data == NULL || msg->sz != totalLen ||
            fragOffsetEnd > totalLen) {
        WOLFSSL_ERROR_VERBOSE(BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }

    if (msg->ready)
        return 0; /* msg is already complete */

    if (msg->type != no_shake) {
        /* msg is already populated with the correct seq, epoch, and type */
        if (msg->type != type || msg->epoch != epoch || msg->seq != seq) {
            WOLFSSL_ERROR_VERBOSE(SEQUENCE_ERROR);
            return SEQUENCE_ERROR;
        }
    }
    else {
        msg->type = type;
        msg->epoch = epoch;
        msg->seq = seq;
    }

    if (msg->fragBucketList == NULL) {
        /* Clean list. Create first fragment. */
        msg->fragBucketList = DtlsMsgCreateFragBucket(fragOffset, data, fragSz, heap);
        if (msg->fragBucketList != NULL) {
            msg->bytesReceived = fragSz;
            msg->fragBucketListCount++;
        }
        else {
            return MEMORY_ERROR;
        }
    }
    else {
        /* See if we can expand any existing bucket to fit this new data into */
        DtlsFragBucket* prev = NULL;
        DtlsFragBucket* cur = msg->fragBucketList;
        byte done = 0;
        for (; cur != NULL; prev = cur, cur = cur->m.m.next) {
            word32 curOffset = cur->m.m.offset;
            word32 curEnd    = cur->m.m.offset + cur->m.m.sz;

            if (fragOffset >= curOffset && fragOffsetEnd <= curEnd) {
                /* We already have this fragment */
                done = 1;
                break;
            }
            else if (fragOffset <= curEnd) {
                /* found place to store fragment */
                break;
            }
        }
        if (!done) {
            if (cur == NULL) {
                /* We reached the end of the list. data is after and disjointed
                 * from anything we have received so far. */
                if (msg->fragBucketListCount >= DTLS_FRAG_POOL_SZ) {
                    WOLFSSL_ERROR_VERBOSE(DTLS_TOO_MANY_FRAGMENTS_E);
                    return DTLS_TOO_MANY_FRAGMENTS_E;
                }
                prev->m.m.next =
                        DtlsMsgCreateFragBucket(fragOffset, data, fragSz, heap);
                if (prev->m.m.next != NULL) {
                    msg->bytesReceived += fragSz;
                    msg->fragBucketListCount++;
                }
            }
            else if (prev == NULL && fragOffsetEnd < cur->m.m.offset) {
                    /* This is the new first fragment we have received */
                    if (msg->fragBucketListCount >= DTLS_FRAG_POOL_SZ) {
                        WOLFSSL_ERROR_VERBOSE(DTLS_TOO_MANY_FRAGMENTS_E);
                        return DTLS_TOO_MANY_FRAGMENTS_E;
                    }
                    msg->fragBucketList = DtlsMsgCreateFragBucket(fragOffset, data,
                            fragSz, heap);
                    if (msg->fragBucketList != NULL) {
                        msg->fragBucketList->m.m.next = cur;
                        msg->bytesReceived += fragSz;
                        msg->fragBucketListCount++;
                    }
                    else {
                        /* reset on error */
                        msg->fragBucketList = cur;
                    }
            }
            else {
                /* Find if this fragment overlaps with any more */
                DtlsFragBucket* next = cur->m.m.next;
                DtlsFragBucket** prev_next = prev != NULL
                        ? &prev->m.m.next : &msg->fragBucketList;
                while (next != NULL &&
                        (next->m.m.offset + next->m.m.sz) <= fragOffsetEnd)
                    next = next->m.m.next;
                /* We can combine the buckets */
                *prev_next = DtlsMsgCombineFragBuckets(msg, cur, next,
                        fragOffset, data, fragSz, heap);
                if (*prev_next == NULL) /* reset on error */
                    *prev_next = cur;
            }
        }
    }

    if (msg->bytesReceived == msg->sz)
        DtlsMsgAssembleCompleteMessage(msg);

    return 0;
}


DtlsMsg* DtlsMsgFind(DtlsMsg* head, word16 epoch, word32 seq)
{
    WOLFSSL_ENTER("DtlsMsgFind()");
    while (head != NULL && !(head->epoch == epoch && head->seq == seq)) {
        head = head->next;
    }
    return head;
}


void DtlsMsgStore(WOLFSSL* ssl, word16 epoch, word32 seq, const byte* data,
        word32 dataSz, byte type, word32 fragOffset, word32 fragSz, void* heap)
{
    /* See if seq exists in the list. If it isn't in the list, make
     * a new item of size dataSz, copy fragSz bytes from data to msg->msg
     * starting at offset fragOffset, and add fragSz to msg->fragSz. If
     * the seq is in the list and it isn't full, copy fragSz bytes from
     * data to msg->msg starting at offset fragOffset, and add fragSz to
     * msg->fragSz. Insertions take into account data already in the list
     * in case there are overlaps in the handshake message due to retransmit
     * messages. The new item should be inserted into the list in its
     * proper position.
     *
     * 1. Find seq in list, or where seq should go in list. If seq not in
     *    list, create new item and insert into list. Either case, keep
     *    pointer to item.
     * 2. Copy the data from the message to the stored message where it
     *    belongs without overlaps.
     */

    DtlsMsg* head = ssl->dtls_rx_msg_list;
    WOLFSSL_ENTER("DtlsMsgStore()");

    if (head != NULL) {
        DtlsMsg* cur = DtlsMsgFind(head, epoch, seq);
        if (cur == NULL) {
            cur = DtlsMsgNew(dataSz, 0, heap);
            if (cur != NULL) {
                if (DtlsMsgSet(cur, seq, epoch, data, type,
                                       fragOffset, fragSz, heap, dataSz) < 0) {
                    DtlsMsgDelete(cur, heap);
                }
                else {
                    ssl->dtls_rx_msg_list_sz++;
                    head = DtlsMsgInsert(head, cur);
                }
            }
        }
        else {
            /* If this fails, the data is just dropped. */
            DtlsMsgSet(cur, seq, epoch, data, type, fragOffset,
                    fragSz, heap, dataSz);
        }
    }
    else {
        head = DtlsMsgNew(dataSz, 0, heap);
        if (DtlsMsgSet(head, seq, epoch, data, type, fragOffset,
                    fragSz, heap, dataSz) < 0) {
            DtlsMsgDelete(head, heap);
            head = NULL;
        }
        else {
            ssl->dtls_rx_msg_list_sz++;
        }
    }

    ssl->dtls_rx_msg_list = head;
}


/* DtlsMsgInsert() is an in-order insert. */
DtlsMsg* DtlsMsgInsert(DtlsMsg* head, DtlsMsg* item)
{
    WOLFSSL_ENTER("DtlsMsgInsert()");
    if (head == NULL || (item->epoch <= head->epoch &&
                         item->seq   <  head->seq)) {
        item->next = head;
        head = item;
    }
    else if (head->next == NULL) {
        head->next = item;
    }
    else {
        DtlsMsg* cur = head->next;
        DtlsMsg* prev = head;
        while (cur) {
            if (item->epoch <= cur->epoch &&
                item->seq   <  cur->seq) {
                item->next = cur;
                prev->next = item;
                break;
            }
            prev = cur;
            cur = cur->next;
        }
        if (cur == NULL) {
            prev->next = item;
        }
    }

    return head;
}


/**
 * DtlsMsgPoolSave() adds the message to the end of the stored transmit
 * list. Must be called BEFORE BuildMessage or DtlsSEQIncrement or
 * anything else that increments ssl->keys.dtls_handshake_number.
 */
int DtlsMsgPoolSave(WOLFSSL* ssl, const byte* data, word32 dataSz,
                    enum HandShakeType type)
{
    DtlsMsg* item;
    int ret = 0;

    WOLFSSL_ENTER("DtlsMsgPoolSave()");

    if (ssl->dtls_tx_msg_list_sz > DTLS_POOL_SZ) {
        WOLFSSL_ERROR(DTLS_POOL_SZ_E);
        return DTLS_POOL_SZ_E;
    }

    item = DtlsMsgNew(dataSz, 1, ssl->heap);

    if (item != NULL) {
        DtlsMsg* cur = ssl->dtls_tx_msg_list;

        XMEMCPY(item->raw, data, dataSz);
        item->epoch = ssl->keys.dtls_epoch;
        item->seq = ssl->keys.dtls_handshake_number;
        item->type = type;

        if (cur == NULL)
            ssl->dtls_tx_msg_list = item;
        else {
            while (cur->next)
                cur = cur->next;
            cur->next = item;
        }
        ssl->dtls_tx_msg_list_sz++;
    }
    else
        ret = MEMORY_E;

    WOLFSSL_LEAVE("DtlsMsgPoolSave()", ret);
    return ret;
}


/* DtlsMsgPoolTimeout() updates the timeout time. */
int DtlsMsgPoolTimeout(WOLFSSL* ssl)
{
    int result = -1;
    WOLFSSL_ENTER("DtlsMsgPoolTimeout()");
    if (ssl->dtls_timeout <  ssl->dtls_timeout_max) {
        ssl->dtls_timeout *= DTLS_TIMEOUT_MULTIPLIER;
        result = 0;
    }
    WOLFSSL_LEAVE("DtlsMsgPoolTimeout()", result);
    return result;
}


/* DtlsMsgPoolReset() deletes the stored transmit list. */
void DtlsMsgPoolReset(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("DtlsMsgPoolReset()");
    if (ssl->dtls_tx_msg_list) {
        DtlsMsgListDelete(ssl->dtls_tx_msg_list, ssl->heap);
        ssl->dtls_tx_msg_list = NULL;
        ssl->dtls_tx_msg = NULL;
        ssl->dtls_tx_msg_list_sz = 0;
    }
}


int VerifyForDtlsMsgPoolSend(WOLFSSL* ssl, byte type, word32 fragOffset)
{
    /**
     * only the first message from previous flight should be valid
     * to be used for triggering retransmission of whole DtlsMsgPool.
     * change cipher suite type is not verified here
     */
    return ((fragOffset == 0) &&
           (((ssl->options.side == WOLFSSL_SERVER_END) &&
             ((type == client_hello) ||
             ((ssl->options.verifyPeer) && (type == certificate)) ||
             ((!ssl->options.verifyPeer) && (type == client_key_exchange)))) ||
            ((ssl->options.side == WOLFSSL_CLIENT_END) &&
             (type == hello_request || type == server_hello))));
}


/**
 * Verify if message `item` from `ssl->dtls_tx_msg_list` should be deleted
 * depending on the current state of the handshake negotiation.
 */
int VerifyForTxDtlsMsgDelete(WOLFSSL* ssl, DtlsMsg* item)
{
    WOLFSSL_ENTER("VerifyForTxDtlsMsgDelete()");
    if (item->epoch < ssl->keys.dtls_epoch - 1)
        /* Messages not from current or previous epoch can be deleted */
        return 1;
    switch (ssl->options.side) {
    case WOLFSSL_CLIENT_END:
        if (item->type == client_hello &&
                ssl->options.serverState >= SERVER_HELLODONE_COMPLETE)
            return 1; /* client can forget first client_hello if received full
                       * flight of packets from server */
        else
            return 0;
    case WOLFSSL_SERVER_END:
        if (ssl->options.clientState >= CLIENT_HELLO_COMPLETE &&
                item->type == hello_request)
            return 1; /* Server can forget HelloRequest if client sent a valid
                       * ClientHello */
        if (ssl->options.clientState >= CLIENT_FINISHED_COMPLETE &&
                item->type <= server_hello_done)
            return 1; /* server can forget everything up to ServerHelloDone if
                       * a client finished message has been received and
                       * successfully processed */
        else
            return 0;
    default:
        return 0;
    }
}


/* DtlsMsgPoolSend() will send the stored transmit list. The stored list is
 * updated with new sequence numbers, and will be re-encrypted if needed. */
int DtlsMsgPoolSend(WOLFSSL* ssl, int sendOnlyFirstPacket)
{
    int ret = 0;
    DtlsMsg* pool;
    int epochOrder;

    WOLFSSL_ENTER("DtlsMsgPoolSend()");

    pool = ssl->dtls_tx_msg == NULL ? ssl->dtls_tx_msg_list : ssl->dtls_tx_msg;

    if (pool != NULL) {
        if ((ssl->options.side == WOLFSSL_SERVER_END &&
             !(ssl->options.acceptState == ACCEPT_BEGIN_RENEG ||
               ssl->options.acceptState == SERVER_HELLO_DONE ||
               ssl->options.acceptState == ACCEPT_FINISHED_DONE ||
               ssl->options.acceptState == ACCEPT_THIRD_REPLY_DONE)) ||
            (ssl->options.side == WOLFSSL_CLIENT_END &&
             !(ssl->options.connectState == CLIENT_HELLO_SENT ||
               ssl->options.connectState == HELLO_AGAIN_REPLY ||
               ssl->options.connectState == FINISHED_DONE ||
               ssl->options.connectState == SECOND_REPLY_DONE))) {

            WOLFSSL_ERROR(DTLS_RETX_OVER_TX);
            ssl->error = DTLS_RETX_OVER_TX;
            return WOLFSSL_FATAL_ERROR;
        }

        while (pool != NULL) {
            if (pool->epoch == 0) {
                DtlsRecordLayerHeader* dtls;

                dtls = (DtlsRecordLayerHeader*)pool->raw;
                /* If the stored record's epoch is 0, and the currently set
                 * epoch is 0, use the "current order" sequence number.
                 * If the stored record's epoch is 0 and the currently set
                 * epoch is not 0, the stored record is considered a "previous
                 * order" sequence number. */
                epochOrder = (ssl->keys.dtls_epoch == 0) ?
                             CUR_ORDER : PREV_ORDER;

                WriteSEQ(ssl, epochOrder, dtls->sequence_number);
                DtlsSEQIncrement(ssl, epochOrder);
                if ((ret = CheckAvailableSize(ssl, pool->sz)) != 0) {
                    WOLFSSL_ERROR(ret);
                    return ret;
                }

                XMEMCPY(ssl->buffers.outputBuffer.buffer +
                        ssl->buffers.outputBuffer.idx +
                        ssl->buffers.outputBuffer.length,
                        pool->raw, pool->sz);
                ssl->buffers.outputBuffer.length += pool->sz;
            }
            else {
                /* Handle sending packets from previous epoch */
                byte*  input;
                byte*  output;
                int    inputSz, sendSz;

                input = pool->raw;
                inputSz = pool->sz;
                sendSz = inputSz + cipherExtraData(ssl);

#ifdef HAVE_SECURE_RENEGOTIATION
                /*
                 * CUR_ORDER will use ssl->secure_renegotiation from epoch 2+.
                 * ssl->keys otherwise
                 * PREV_ORDER will always use ssl->keys
                 */
                if (DtlsSCRKeysSet(ssl)) {
                    if (pool->epoch == ssl->secure_renegotiation->tmp_keys.dtls_epoch)
                        epochOrder = CUR_ORDER;
                    else
                        epochOrder = PREV_ORDER;
                }
                else {
                    epochOrder = CUR_ORDER;
                }
#else
                epochOrder = CUR_ORDER;
#endif


                /* add back in header space from saved pool size */
                sendSz += DTLS_HANDSHAKE_EXTRA;
                sendSz += DTLS_RECORD_EXTRA;

                if ((ret = CheckAvailableSize(ssl, sendSz)) != 0) {
                    WOLFSSL_ERROR(ret);
                    return ret;
                }

                output = ssl->buffers.outputBuffer.buffer +
                         ssl->buffers.outputBuffer.length;
                if (inputSz != ENUM_LEN)
                    sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                          handshake, 0, 0, 0, epochOrder);
                else
                    /* inputSz == ENUM_LEN must mean that this is a change cipher
                     * spec message */
                    sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                          change_cipher_spec, 0, 0, 0, epochOrder);

                if (sendSz < 0) {
                    WOLFSSL_ERROR(BUILD_MSG_ERROR);
                    return BUILD_MSG_ERROR;
                }

                ssl->buffers.outputBuffer.length += sendSz;
            }


            if (!ssl->options.groupMessages)
                ret = SendBuffered(ssl);

            /**
             * on server side, retransmission is being triggered only by sending
             * first message of given flight, in order to trigger client
             * to retransmit its whole flight. Sending the whole previous flight
             * could lead to retransmission of previous client flight for each
             * server message from previous flight. Therefore one message should
             * be enough to do the trick.
             */
            if (sendOnlyFirstPacket &&
                ssl->options.side == WOLFSSL_SERVER_END)
                pool = NULL;
            else
                pool = pool->next;
            ssl->dtls_tx_msg = pool;
        }

        if (ret == 0 && ssl->options.groupMessages)
            ret = SendBuffered(ssl);
    }

    WOLFSSL_LEAVE("DtlsMsgPoolSend()", ret);
    return ret;
}

#endif /* WOLFSSL_DTLS */

#if defined(WOLFSSL_ALLOW_SSLV3) && !defined(NO_OLD_TLS)

ProtocolVersion MakeSSLv3(void)
{
    ProtocolVersion pv;
    pv.major = SSLv3_MAJOR;
    pv.minor = SSLv3_MINOR;

    return pv;
}

#endif /* WOLFSSL_ALLOW_SSLV3 && !NO_OLD_TLS */


#ifdef WOLFSSL_DTLS

ProtocolVersion MakeDTLSv1(void)
{
    ProtocolVersion pv;
    pv.major = DTLS_MAJOR;
    pv.minor = DTLS_MINOR;

    return pv;
}

#ifndef WOLFSSL_NO_TLS12

ProtocolVersion MakeDTLSv1_2(void)
{
    ProtocolVersion pv;
    pv.major = DTLS_MAJOR;
    pv.minor = DTLSv1_2_MINOR;

    return pv;
}

#endif /* !WOLFSSL_NO_TLS12 */

#ifdef WOLFSSL_DTLS13

ProtocolVersion MakeDTLSv1_3(void)
{
    ProtocolVersion pv;
    pv.major = DTLS_MAJOR;
    pv.minor = DTLSv1_3_MINOR;

    return pv;
}

#endif /* WOLFSSL_DTLS13 */
#endif /* WOLFSSL_DTLS */


#ifndef NO_ASN_TIME
#if defined(USER_TICKS)
#if 0
    word32 LowResTimer(void)
    {
        /*
        write your own clock tick function if don't want time(0)
        needs second accuracy but doesn't have to correlated to EPOCH
        */
    }
#endif

#elif defined(TIME_OVERRIDES)
#if !defined(NO_ASN) && !defined(NO_ASN_TIME)
    /* use same asn time overrides unless user wants tick override above */

    word32 LowResTimer(void)
    {
        return (word32) wc_Time(0);
    }
#else
    #ifndef HAVE_TIME_T_TYPE
        typedef long time_t;
    #endif
    extern time_t XTIME(time_t * timer);

    word32 LowResTimer(void)
    {
        return (word32) XTIME(0);
    }
#endif

#elif defined(USE_WINDOWS_API)

    word32 LowResTimer(void)
    {
        static int           init = 0;
        static LARGE_INTEGER freq;
        LARGE_INTEGER        count;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        return (word32)(count.QuadPart / freq.QuadPart);
    }

#elif defined(HAVE_RTP_SYS)

    #include "rtptime.h"

    word32 LowResTimer(void)
    {
        return (word32)rtp_get_system_sec();
    }

#elif defined(WOLFSSL_DEOS)

    word32 LowResTimer(void)
    {
        const word32 systemTickTimeInHz = 1000000 / systemTickInMicroseconds();
        const volatile word32 *systemTickPtr = systemTickPointer();

        return (word32) *systemTickPtr/systemTickTimeInHz;
    }

#elif defined(MICRIUM)

    word32 LowResTimer(void)
    {
        OS_TICK ticks = 0;
        OS_ERR  err;

        ticks = OSTimeGet(&err);

        return (word32) (ticks / OSCfg_TickRate_Hz);
    }


#elif defined(MICROCHIP_TCPIP_V5)

    word32 LowResTimer(void)
    {
        return (word32) (TickGet() / TICKS_PER_SECOND);
    }


#elif defined(MICROCHIP_TCPIP)

    #if defined(MICROCHIP_MPLAB_HARMONY)

        #include <system/tmr/sys_tmr.h>

        word32 LowResTimer(void)
        {
            return (word32) (SYS_TMR_TickCountGet() /
                             SYS_TMR_TickCounterFrequencyGet());
        }

    #else

        word32 LowResTimer(void)
        {
            return (word32) (SYS_TICK_Get() / SYS_TICK_TicksPerSecondGet());
        }

    #endif

#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)

    word32 LowResTimer(void)
    {
        TIME_STRUCT mqxTime;

        _time_get_elapsed(&mqxTime);

        return (word32) mqxTime.SECONDS;
    }
#elif defined(FREESCALE_FREE_RTOS) || defined(FREESCALE_KSDK_FREERTOS)

    #include "include/task.h"

    unsigned int LowResTimer(void)
    {
        return (unsigned int)(((float)xTaskGetTickCount())/configTICK_RATE_HZ);
    }

#elif defined(FREERTOS)

    #include "task.h"

    unsigned int LowResTimer(void)
    {
        return (unsigned int)(((float)xTaskGetTickCount())/configTICK_RATE_HZ);
    }

#elif defined(FREESCALE_KSDK_BM)

    #include "lwip/sys.h" /* lwIP */
    word32 LowResTimer(void)
    {
        return sys_now()/1000;
    }

#elif defined(WOLFSSL_TIRTOS)

    word32 LowResTimer(void)
    {
        return (word32) Seconds_get();
    }
#elif defined(WOLFSSL_XILINX)
    #include "xrtcpsu.h"

    word32 LowResTimer(void)
    {
        XRtcPsu_Config* con;
        XRtcPsu         rtc;

        con = XRtcPsu_LookupConfig(XPAR_XRTCPSU_0_DEVICE_ID);
        if (con != NULL) {
            if (XRtcPsu_CfgInitialize(&rtc, con, con->BaseAddr)
                    == XST_SUCCESS) {
                return (word32)XRtcPsu_GetCurrentTime(&rtc);
            }
            else {
                WOLFSSL_MSG("Unable to initialize RTC");
            }
        }

        return 0;
    }

#elif defined(WOLFSSL_UTASKER)

    word32 LowResTimer(void)
    {
        return (word32)(uTaskerSystemTick / TICK_RESOLUTION);
    }

#elif defined(WOLFSSL_NUCLEUS_1_2)

    #define NU_TICKS_PER_SECOND 100

    word32 LowResTimer(void)
    {
        /* returns number of 10ms ticks, so 100 ticks/sec */
        return NU_Retrieve_Clock() / NU_TICKS_PER_SECOND;
    }
#elif defined(WOLFSSL_APACHE_MYNEWT)

    #include "os/os_time.h"
    word32 LowResTimer(void)
    {
        word32 now;
        struct os_timeval tv;
        os_gettimeofday(&tv, NULL);
        now = (word32)tv.tv_sec;
        return now;
    }

#elif defined(WOLFSSL_ZEPHYR)

    word32 LowResTimer(void)
    {
        return k_uptime_get() / 1000;
    }

#elif defined(WOLFSSL_LINUXKM)
    word32 LowResTimer(void)
    {
        return (word32)time(NULL);
    }

#else
    /* Posix style time */
    #if !defined(USER_TIME) && !defined(USE_WOLF_TM)
    #include <time.h>
    #endif

    word32 LowResTimer(void)
    {
    #if !defined(NO_ASN) && !defined(NO_ASN_TIME)
        return (word32)wc_Time(0);
    #else
        return (word32)XTIME(0);
    #endif
    }
#endif
#else
    /* user must supply timer function to return elapsed seconds:
     *   word32 LowResTimer(void);
     */
#endif /* !NO_ASN_TIME */

#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
/* Store the message for use with CertificateVerify using EdDSA.
 *
 * ssl   SSL/TLS object.
 * data  Message to store.
 * sz    Size of message to store.
 * returns MEMORY_E if not able to reallocate, otherwise 0.
 */
static int EdDSA_Update(WOLFSSL* ssl, const byte* data, int sz)
{
    int   ret = 0;
    byte* msgs;

    if (ssl->options.cacheMessages) {
        msgs = (byte*)XMALLOC(ssl->hsHashes->length + sz, ssl->heap,
            DYNAMIC_TYPE_HASHES);
        if (msgs == NULL)
            ret = MEMORY_E;
        if ((ret == 0) && (ssl->hsHashes->messages != NULL)) {
            XMEMCPY(msgs, ssl->hsHashes->messages, ssl->hsHashes->length);
            ForceZero(ssl->hsHashes->messages, ssl->hsHashes->length);
            XFREE(ssl->hsHashes->messages, ssl->heap, DYNAMIC_TYPE_HASHES);
        }
        if (ret == 0) {
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Add("Handshake messages", msgs,
                ssl->hsHashes->length + sz);
        #endif
            ssl->hsHashes->messages = msgs;
            XMEMCPY(msgs + ssl->hsHashes->length, data, sz);
            ssl->hsHashes->prevLen = ssl->hsHashes->length;
            ssl->hsHashes->length += sz;
        }
    }

    return ret;
}
#endif /* (HAVE_ED25519 || HAVE_ED448) && !WOLFSSL_NO_CLIENT_AUTH */

int HashRaw(WOLFSSL* ssl, const byte* data, int sz)
{
    int ret = 0;
#ifdef WOLFSSL_DEBUG_TLS
    byte digest[WC_MAX_DIGEST_SIZE];

    WOLFSSL_MSG("HashRaw:");
    WOLFSSL_MSG("Data:");
    WOLFSSL_BUFFER(data, sz);
    WOLFSSL_MSG("Hashes:");
#endif

    (void)data;
    (void)sz;

    if (ssl->hsHashes == NULL) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_RENESAS_TSIP_TLS) && (WOLFSSL_RENESAS_TSIP_VER >= 115)
    ret = tsip_StoreMessage(ssl, data, sz);
    if (ret != 0 && ret != CRYPTOCB_UNAVAILABLE) {
        return ret;
    }
#endif /* WOLFSSL_RENESAS_TSIP_TLS && WOLFSSL_RENESAS_TSIP_VER >= 115 */

#ifndef NO_OLD_TLS
    #ifndef NO_SHA
        wc_ShaUpdate(&ssl->hsHashes->hashSha, data, sz);
    #endif
    #ifndef NO_MD5
        wc_Md5Update(&ssl->hsHashes->hashMd5, data, sz);
    #endif
#endif /* NO_OLD_TLS */

    if (IsAtLeastTLSv1_2(ssl)) {
    #ifndef NO_SHA256
        ret = wc_Sha256Update(&ssl->hsHashes->hashSha256, data, sz);
        if (ret != 0)
            return ret;
    #ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("Sha256");
        wc_Sha256GetHash(&ssl->hsHashes->hashSha256, digest);
        WOLFSSL_BUFFER(digest, WC_SHA256_DIGEST_SIZE);
    #endif
    #endif
    #ifdef WOLFSSL_SHA384
        ret = wc_Sha384Update(&ssl->hsHashes->hashSha384, data, sz);
        if (ret != 0)
            return ret;
    #ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("Sha384");
        wc_Sha384GetHash(&ssl->hsHashes->hashSha384, digest);
        WOLFSSL_BUFFER(digest, WC_SHA384_DIGEST_SIZE);
    #endif
    #endif
    #ifdef WOLFSSL_SHA512
        ret = wc_Sha512Update(&ssl->hsHashes->hashSha512, data, sz);
        if (ret != 0)
            return ret;
    #ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("Sha512");
        wc_Sha512GetHash(&ssl->hsHashes->hashSha512, digest);
        WOLFSSL_BUFFER(digest, WC_SHA512_DIGEST_SIZE);
    #endif
    #endif
    #if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
        ret = EdDSA_Update(ssl, data, sz);
        if (ret != 0)
            return ret;
    #endif
    }

    return ret;
}

/* add output to md5 and sha handshake hashes, exclude record header */
int HashOutput(WOLFSSL* ssl, const byte* output, int sz, int ivSz)
{
    const byte* adj;

    if (ssl->hsHashes == NULL)
        return BAD_FUNC_ARG;

    adj = output + RECORD_HEADER_SZ + ivSz;
    sz -= RECORD_HEADER_SZ;

#ifdef HAVE_FUZZER
    if (ssl->fuzzerCb)
        ssl->fuzzerCb(ssl, output, sz, FUZZ_HASH, ssl->fuzzerCtx);
#endif
#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        if (IsAtLeastTLSv1_3(ssl->version)) {
#ifdef WOLFSSL_DTLS13
            word16 dtls_record_extra;
            dtls_record_extra = Dtls13GetRlHeaderLength(ssl, (byte)IsEncryptionOn(ssl, 1));
            dtls_record_extra -= RECORD_HEADER_SZ;

            adj += dtls_record_extra;
            sz  -= dtls_record_extra;
#endif /* WOLFSSL_DTLS13 */
        } else {
            adj += DTLS_RECORD_EXTRA;
            sz  -= DTLS_RECORD_EXTRA;
        }
    }
#endif

    return HashRaw(ssl, adj, sz);
}


/* add input to md5 and sha handshake hashes, include handshake header */
int HashInput(WOLFSSL* ssl, const byte* input, int sz)
{
    const byte* adj;

    if (ssl->hsHashes == NULL) {
        return BAD_FUNC_ARG;
    }

    adj = input - HANDSHAKE_HEADER_SZ;
    sz += HANDSHAKE_HEADER_SZ;

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        adj -= DTLS_HANDSHAKE_EXTRA;
        sz  += DTLS_HANDSHAKE_EXTRA;

#ifdef WOLFSSL_DTLS13
        if (IsAtLeastTLSv1_3(ssl->version))
            return Dtls13HashHandshake(ssl, adj, (word16)sz);
#endif /* WOLFSSL_DTLS13 */

    }
#endif

    return HashRaw(ssl, adj, sz);
}


/* add record layer header for message */
static void AddRecordHeader(byte* output, word32 length, byte type, WOLFSSL* ssl, int epochOrder)
{
    RecordLayerHeader* rl;

    (void)epochOrder;

    /* record layer header */
    rl = (RecordLayerHeader*)output;
    if (rl == NULL) {
        return;
    }
    rl->type    = type;
    rl->pvMajor = ssl->version.major;       /* type and version same in each */
#ifdef WOLFSSL_TLS13
    if (IsAtLeastTLSv1_3(ssl->version)) {
        rl->pvMinor = TLSv1_2_MINOR;
#ifdef WOLFSSL_DTLS
        if (ssl->options.dtls)
            rl->pvMinor = DTLSv1_2_MINOR;
#endif /* WOLFSSL_DTLS */
    }
    else
#endif
        rl->pvMinor = ssl->version.minor;

#ifdef WOLFSSL_ALTERNATIVE_DOWNGRADE
    if (ssl->options.side == WOLFSSL_CLIENT_END
    &&  ssl->options.connectState == CONNECT_BEGIN
    && !ssl->options.resuming) {
        rl->pvMinor = ssl->options.downgrade ? ssl->options.minDowngrade
                                             : ssl->version.minor;
    }
#endif

    if (!ssl->options.dtls) {
        c16toa((word16)length, rl->length);
    }
    else {
#ifdef WOLFSSL_DTLS
        DtlsRecordLayerHeader* dtls;

        /* dtls record layer header extensions */
        dtls = (DtlsRecordLayerHeader*)output;
        WriteSEQ(ssl, epochOrder, dtls->sequence_number);
        c16toa((word16)length, dtls->length);
#endif
    }
}


#if !defined(WOLFSSL_NO_TLS12) || (defined(HAVE_SESSION_TICKET) && \
                                                    !defined(NO_WOLFSSL_SERVER))
/* add handshake header for message */
static void AddHandShakeHeader(byte* output, word32 length,
                               word32 fragOffset, word32 fragLength,
                               byte type, WOLFSSL* ssl)
{
    HandShakeHeader* hs;
    (void)fragOffset;
    (void)fragLength;
    (void)ssl;

    /* handshake header */
    hs = (HandShakeHeader*)output;
    if (hs == NULL)
        return;

    hs->type = type;
    c32to24(length, hs->length);         /* type and length same for each */
#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        DtlsHandShakeHeader* dtls;

        /* dtls handshake header extensions */
        dtls = (DtlsHandShakeHeader*)output;
        c16toa(ssl->keys.dtls_handshake_number++, dtls->message_seq);
        c32to24(fragOffset, dtls->fragment_offset);
        c32to24(fragLength, dtls->fragment_length);
    }
#endif
}

/* add both headers for handshake message */
/*static*/ void AddHeaders(byte* output, word32 length, byte type, WOLFSSL* ssl)
{
    word32 lengthAdj = HANDSHAKE_HEADER_SZ;
    word32 outputAdj = RECORD_HEADER_SZ;

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        lengthAdj += DTLS_HANDSHAKE_EXTRA;
        outputAdj += DTLS_RECORD_EXTRA;
    }
#endif

    AddRecordHeader(output, length + lengthAdj, handshake, ssl, CUR_ORDER);
    AddHandShakeHeader(output + outputAdj, length, 0, length, type, ssl);
}
#endif /* !WOLFSSL_NO_TLS12 || (HAVE_SESSION_TICKET && !NO_WOLFSSL_SERVER) */


#ifndef WOLFSSL_NO_TLS12
#if !defined(NO_CERTS) && (!defined(NO_WOLFSSL_SERVER) || \
                           !defined(WOLFSSL_NO_CLIENT_AUTH)) || \
                           defined(WOLFSSL_DTLS)
static void AddFragHeaders(byte* output, word32 fragSz, word32 fragOffset,
                           word32 length, byte type, WOLFSSL* ssl)
{
    word32 lengthAdj = HANDSHAKE_HEADER_SZ;
    word32 outputAdj = RECORD_HEADER_SZ;
    (void)fragSz;

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        lengthAdj += DTLS_HANDSHAKE_EXTRA;
        outputAdj += DTLS_RECORD_EXTRA;
    }
#endif

    AddRecordHeader(output, fragSz + lengthAdj, handshake, ssl, CUR_ORDER);
    AddHandShakeHeader(output + outputAdj, length, fragOffset, fragSz, type, ssl);
}
#endif /* NO_CERTS */

#if !defined(NO_WOLFSSL_SERVER) || \
    (!defined(NO_WOLFSSL_CLIENT) && !defined(NO_CERTS) && \
     !defined(WOLFSSL_NO_CLIENT_AUTH))
/**
 * Send the handshake message. This function handles fragmenting the message
 * so that it will fit into the desired MTU or the max fragment size.
 * @param ssl     Connection object
 * @param input   Input starting at the record layer header. This function
 *                assumes that the appropriate record and handshake headers
 *                are present. These headers must assume no fragmentation.
 *                That is handled here.
 * @param inputSz Length of message excluding headers (this is the total
 *                length of all fragments)
 * @param type    Type of message being sent
 * @return        0 on success and negative otherwise
 */
static int SendHandshakeMsg(WOLFSSL* ssl, byte* input, word32 inputSz,
        enum HandShakeType type, const char* packetName)
{
    int maxFrag;
    int ret = 0;
    int headerSz;

    WOLFSSL_ENTER("SendHandshakeMsg");
    (void)type;
    (void)packetName;

    if (ssl == NULL || input == NULL)
        return BAD_FUNC_ARG;
#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls)
        headerSz = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
    else
#endif
    {
        /* In TLS we send one handshake header in total, not one
         * per fragment like in DTLS. The handshake header should
         * already be in the input buffer. */
        inputSz += HANDSHAKE_HEADER_SZ;
        headerSz = RECORD_HEADER_SZ;
    }
    maxFrag = wolfSSL_GetMaxFragSize(ssl, (int)inputSz);

    /* Make sure input is not the ssl output buffer as this
     * function doesn't handle that */
    if (input >= ssl->buffers.outputBuffer.buffer &&
            input < ssl->buffers.outputBuffer.buffer +
                     ssl->buffers.outputBuffer.bufferSize) {
        WOLFSSL_MSG("Can't use output buffer for input in SendHandshakeMsg");
        return BAD_FUNC_ARG;
    }
    if (!ssl->options.buildingMsg) {
        /* Hash it before the loop as we modify the input with
         * encryption on */
        ret = HashOutput(ssl, input, headerSz + (int)inputSz, 0);
        if (ret != 0)
            return ret;
#ifdef WOLFSSL_DTLS
        /* Decrement msg number so that we continue to use the
         * same msg number for this msg */
        if (ssl->options.dtls)
            ssl->keys.dtls_handshake_number--;
#endif
    }
    while (ssl->fragOffset < inputSz) {
        byte* output;
        int outputSz;
        byte* data = input + ssl->fragOffset + headerSz;
        word32 fragSz = (word32)maxFrag;

        ssl->options.buildingMsg = 1;

        if (inputSz - ssl->fragOffset < fragSz)
            fragSz = inputSz - ssl->fragOffset;

        /* check for available size */
        outputSz = headerSz + fragSz;
        if (IsEncryptionOn(ssl, 1))
            outputSz += cipherExtraData(ssl);
        if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
            return ret;
        if (ssl->buffers.outputBuffer.buffer == NULL)
            return MEMORY_E;
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        if (IsEncryptionOn(ssl, 1)) {
            /* First we need to add the fragment header ourselves.
             * We do this in the input to minimize allocations */
            int dataSz = (int)fragSz;
#ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                data   -= DTLS_HANDSHAKE_HEADER_SZ;
                dataSz += DTLS_HANDSHAKE_HEADER_SZ;
                AddHandShakeHeader(data, inputSz, ssl->fragOffset, fragSz,
                                   type, ssl);
                ssl->keys.dtls_handshake_number--;
            }
            if (IsDtlsNotSctpMode(ssl) &&
                (ret = DtlsMsgPoolSave(ssl, data,
                        fragSz + DTLS_HANDSHAKE_HEADER_SZ, type))
                    != 0)
                return ret;
#endif
            ret = BuildMessage(ssl, output, outputSz,
                        data, dataSz, handshake, 0, 0, 0, CUR_ORDER);
            if (ret >= 0)
                outputSz = ret;
            else
                return ret;
            ret = 0;
        }
        else {
#ifdef WOLFSSL_DTLS
            if (ssl->options.dtls)
                AddFragHeaders(output, fragSz, ssl->fragOffset,
                        inputSz, type, ssl);
            else
#endif
                AddRecordHeader(output, fragSz, handshake, ssl, CUR_ORDER);

            XMEMCPY(output + headerSz, data, fragSz);
#ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                ssl->keys.dtls_handshake_number--;
                DtlsSEQIncrement(ssl, CUR_ORDER);
            }
            if (IsDtlsNotSctpMode(ssl)) {
                if ((ret = DtlsMsgPoolSave(ssl, output, headerSz + fragSz,
                        type)) != 0) {
                    return ret;
                }
            }
#endif
        }
        ssl->buffers.outputBuffer.length += outputSz;
#if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn) {
            AddPacketName(ssl, packetName);
        }
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, packetName, handshake,
                output, outputSz, WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
#endif
        ssl->fragOffset += fragSz;
        if (!ssl->options.groupMessages)
            ret = SendBuffered(ssl);
        if (ret != 0)
            return ret;
    }
#ifdef WOLFSSL_DTLS
    /* Increment msg number once we sent all fragments */
    if (ssl->options.dtls)
        ssl->keys.dtls_handshake_number++;
#endif
    ssl->fragOffset = 0;
    ssl->options.buildingMsg = 0;
    return ret;
}
#endif /* !NO_WOLFSSL_SERVER || (!NO_WOLFSSL_CLIENT && !NO_CERTS &&
        *  !WOLFSSL_NO_CLIENT_AUTH) */

#endif /* !WOLFSSL_NO_TLS12 */


/* return bytes received, -1 on error */
static int wolfSSLReceive(WOLFSSL* ssl, byte* buf, word32 sz)
{
    int recvd;
    int retryLimit = WOLFSSL_MODE_AUTO_RETRY_ATTEMPTS;

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        /* QUIC only "reads" from data provided by the application
         * via wolfSSL_provide_quic_data(). Transfer from there
         * into the inputBuffer. */
        return wolfSSL_quic_receive(ssl, buf, sz);
    }
#endif

    if (ssl->CBIORecv == NULL) {
        WOLFSSL_MSG("Your IO Recv callback is null, please set");
        return -1;
    }

retry:
    recvd = ssl->CBIORecv(ssl, (char *)buf, (int)sz, ssl->IOCB_ReadCtx);
    if (recvd < 0) {
        switch (recvd) {
            case WOLFSSL_CBIO_ERR_GENERAL:        /* general/unknown error */
                #ifdef WOLFSSL_APACHE_HTTPD
                #ifndef NO_BIO
                    if (ssl->biord) {
                        /* If retry and read flags are set, return WANT_READ */
                        if ((ssl->biord->flags & WOLFSSL_BIO_FLAG_READ) &&
                            (ssl->biord->flags & WOLFSSL_BIO_FLAG_RETRY)) {
                            return WANT_READ;
                        }
                    }
                #endif
                #endif
                return -1;

            case WOLFSSL_CBIO_ERR_WANT_READ:      /* want read, would block */
                if (retryLimit > 0 && ssl->ctx->autoRetry &&
                        !ssl->options.handShakeDone && !ssl->options.dtls) {
                    retryLimit--;
                    goto retry;
                }
                return WANT_READ;

            case WOLFSSL_CBIO_ERR_CONN_RST:       /* connection reset */
                #ifdef USE_WINDOWS_API
                if (ssl->options.dtls) {
                    goto retry;
                }
                #endif
                ssl->options.connReset = 1;
                return -1;

            case WOLFSSL_CBIO_ERR_ISR:            /* interrupt */
                /* see if we got our timeout */
                #ifdef WOLFSSL_CALLBACKS
                    if (ssl->toInfoOn) {
                        struct itimerval timeout;
                        getitimer(ITIMER_REAL, &timeout);
                        if (timeout.it_value.tv_sec == 0 &&
                                                timeout.it_value.tv_usec == 0) {
                            XSTRNCPY(ssl->timeoutInfo.timeoutName,
                                    "recv() timeout", MAX_TIMEOUT_NAME_SZ);
                            ssl->timeoutInfo.timeoutName[
                                MAX_TIMEOUT_NAME_SZ] = '\0';

                            WOLFSSL_MSG("Got our timeout");
                            return WANT_READ;
                        }
                    }
                #endif
                goto retry;

            case WOLFSSL_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
                ssl->options.isClosed = 1;
                return -1;

            case WOLFSSL_CBIO_ERR_TIMEOUT:
            #ifdef WOLFSSL_DTLS
#ifdef WOLFSSL_DTLS13
                if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)) {
                    /* TODO: support WANT_WRITE here */
                    if (Dtls13RtxTimeout(ssl) < 0) {
                        WOLFSSL_MSG(
                            "Error trying to retransmit DTLS buffered message");
                        return -1;
                    }
                    goto retry;
                }
#endif /* WOLFSSL_DTLS13 */

                if (IsDtlsNotSctpMode(ssl) &&
                    ssl->options.handShakeState != HANDSHAKE_DONE &&
                    DtlsMsgPoolTimeout(ssl) == 0 &&
                    DtlsMsgPoolSend(ssl, 0) == 0) {

                    /* retry read for DTLS during handshake only */
                    goto retry;
                }
            #endif
                return -1;

            default:
                WOLFSSL_MSG("Unexpected recv return code");
                return recvd;
        }
    }

    return recvd;
}


/* Switch dynamic output buffer back to static, buffer is assumed clear */
void ShrinkOutputBuffer(WOLFSSL* ssl)
{
    WOLFSSL_MSG("Shrinking output buffer");
    XFREE(ssl->buffers.outputBuffer.buffer - ssl->buffers.outputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.outputBuffer.dynamicFlag = 0;
    ssl->buffers.outputBuffer.offset      = 0;
}


/* Switch dynamic input buffer back to static, keep any remaining input */
/* forced free means cleaning up */
/* Be *CAREFUL* where this function is called. ProcessReply relies on
 * inputBuffer.idx *NOT* changing inside the ProcessReply function. ProcessReply
 * calls ShrinkInputBuffer itself when it is safe to do so. Don't overuse it. */
void ShrinkInputBuffer(WOLFSSL* ssl, int forcedFree)
{
    int usedLength = ssl->buffers.inputBuffer.length -
                     ssl->buffers.inputBuffer.idx;
    if (!forcedFree && (usedLength > STATIC_BUFFER_LEN ||
            ssl->buffers.clearOutputBuffer.length > 0))
        return;

    WOLFSSL_MSG("Shrinking input buffer");

    if (!forcedFree && usedLength > 0) {
        XMEMCPY(ssl->buffers.inputBuffer.staticBuffer,
               ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
               usedLength);
    }

    ForceZero(ssl->buffers.inputBuffer.buffer -
        ssl->buffers.inputBuffer.offset,
        ssl->buffers.inputBuffer.bufferSize);
    XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.inputBuffer.dynamicFlag = 0;
    ssl->buffers.inputBuffer.offset      = 0;
    ssl->buffers.inputBuffer.idx = 0;
    ssl->buffers.inputBuffer.length = usedLength;
}

int SendBuffered(WOLFSSL* ssl)
{
    if (ssl->CBIOSend == NULL && !WOLFSSL_IS_QUIC(ssl)) {
        WOLFSSL_MSG("Your IO Send callback is null, please set");
        return SOCKET_ERROR_E;
    }

#ifdef WOLFSSL_DEBUG_TLS
    if (ssl->buffers.outputBuffer.idx == 0) {
        WOLFSSL_MSG("Data to send");
        WOLFSSL_BUFFER(ssl->buffers.outputBuffer.buffer,
                       ssl->buffers.outputBuffer.length);
    }
#endif

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        return wolfSSL_quic_send(ssl);
    }
#endif

    while (ssl->buffers.outputBuffer.length > 0) {
        int sent = ssl->CBIOSend(ssl,
                                      (char*)ssl->buffers.outputBuffer.buffer +
                                      ssl->buffers.outputBuffer.idx,
                                      (int)ssl->buffers.outputBuffer.length,
                                      ssl->IOCB_WriteCtx);
        if (sent < 0) {
            switch (sent) {

                case WOLFSSL_CBIO_ERR_WANT_WRITE:        /* would block */
                    return WANT_WRITE;

                case WOLFSSL_CBIO_ERR_CONN_RST:          /* connection reset */
                    ssl->options.connReset = 1;
                    break;

                case WOLFSSL_CBIO_ERR_ISR:               /* interrupt */
                    /* see if we got our timeout */
                    #ifdef WOLFSSL_CALLBACKS
                        if (ssl->toInfoOn) {
                            struct itimerval timeout;
                            getitimer(ITIMER_REAL, &timeout);
                            if (timeout.it_value.tv_sec == 0 &&
                                                timeout.it_value.tv_usec == 0) {
                                XSTRNCPY(ssl->timeoutInfo.timeoutName,
                                        "send() timeout", MAX_TIMEOUT_NAME_SZ);
                                ssl->timeoutInfo.timeoutName[
                                    MAX_TIMEOUT_NAME_SZ] = '\0';

                                WOLFSSL_MSG("Got our timeout");
                                return WANT_WRITE;
                            }
                        }
                    #endif
                    continue;

                case WOLFSSL_CBIO_ERR_CONN_CLOSE: /* epipe / conn closed */
                    ssl->options.connReset = 1;  /* treat same as reset */
                    break;

                default:
                    return SOCKET_ERROR_E;
            }

            return SOCKET_ERROR_E;
        }

        if (sent > (int)ssl->buffers.outputBuffer.length) {
            WOLFSSL_MSG("SendBuffered() out of bounds read");
            return SEND_OOB_READ_E;
        }

        ssl->buffers.outputBuffer.idx += sent;
        ssl->buffers.outputBuffer.length -= sent;
    }

    ssl->buffers.outputBuffer.idx = 0;

    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);

    return 0;
}


/* Grow the output buffer */
static WC_INLINE int GrowOutputBuffer(WOLFSSL* ssl, int size)
{
    byte* tmp;
#if WOLFSSL_GENERAL_ALIGNMENT > 0
    byte  hdrSz = ssl->options.dtls ? DTLS_RECORD_HEADER_SZ :
                                      RECORD_HEADER_SZ;
    byte align = WOLFSSL_GENERAL_ALIGNMENT;
#else
    const byte align = WOLFSSL_GENERAL_ALIGNMENT;
#endif

#if WOLFSSL_GENERAL_ALIGNMENT > 0
    /* the encrypted data will be offset from the front of the buffer by
       the header, if the user wants encrypted alignment they need
       to define their alignment requirement */

    while (align < hdrSz)
        align *= 2;
#endif

    tmp = (byte*)XMALLOC(size + ssl->buffers.outputBuffer.length + align,
                             ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    WOLFSSL_MSG("growing output buffer");

    if (tmp == NULL)
        return MEMORY_E;

#if WOLFSSL_GENERAL_ALIGNMENT > 0
    if (align)
        tmp += align - hdrSz;
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    /* can be from IO memory pool which does not need copy if same buffer */
    if (ssl->buffers.outputBuffer.length &&
            tmp == ssl->buffers.outputBuffer.buffer) {
        ssl->buffers.outputBuffer.bufferSize =
            size + ssl->buffers.outputBuffer.length;
        return 0;
    }
#endif

    if (ssl->buffers.outputBuffer.length)
        XMEMCPY(tmp, ssl->buffers.outputBuffer.buffer,
               ssl->buffers.outputBuffer.length);

    if (ssl->buffers.outputBuffer.dynamicFlag) {
        XFREE(ssl->buffers.outputBuffer.buffer -
              ssl->buffers.outputBuffer.offset, ssl->heap,
              DYNAMIC_TYPE_OUT_BUFFER);
    }
    ssl->buffers.outputBuffer.dynamicFlag = 1;

#if WOLFSSL_GENERAL_ALIGNMENT > 0
    if (align)
        ssl->buffers.outputBuffer.offset = align - hdrSz;
    else
#endif
        ssl->buffers.outputBuffer.offset = 0;

    ssl->buffers.outputBuffer.buffer = tmp;
    ssl->buffers.outputBuffer.bufferSize = size +
                                           ssl->buffers.outputBuffer.length;
    return 0;
}


/* Grow the input buffer, should only be to read cert or big app data */
int GrowInputBuffer(WOLFSSL* ssl, int size, int usedLength)
{
    byte* tmp;
#if defined(WOLFSSL_DTLS) || WOLFSSL_GENERAL_ALIGNMENT > 0
    byte  align = ssl->options.dtls ? WOLFSSL_GENERAL_ALIGNMENT : 0;
    byte  hdrSz = DTLS_RECORD_HEADER_SZ;
#else
    const byte align = WOLFSSL_GENERAL_ALIGNMENT;
#endif

#if defined(WOLFSSL_DTLS) || WOLFSSL_GENERAL_ALIGNMENT > 0
    /* the encrypted data will be offset from the front of the buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (align < hdrSz)
           align *= 2;
    }
#endif

    if (usedLength < 0 || size < 0) {
        WOLFSSL_MSG("GrowInputBuffer() called with negative number");
        return BAD_FUNC_ARG;
    }

    tmp = (byte*)XMALLOC(size + usedLength + align,
                             ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    WOLFSSL_MSG("growing input buffer");

    if (tmp == NULL)
        return MEMORY_E;

#if defined(WOLFSSL_DTLS) || WOLFSSL_GENERAL_ALIGNMENT > 0
    if (align)
        tmp += align - hdrSz;
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    /* can be from IO memory pool which does not need copy if same buffer */
    if (usedLength && tmp == ssl->buffers.inputBuffer.buffer) {
        ssl->buffers.inputBuffer.bufferSize = size + usedLength;
        ssl->buffers.inputBuffer.idx    = 0;
        ssl->buffers.inputBuffer.length = usedLength;
        return 0;
    }
#endif

    if (usedLength)
        XMEMCPY(tmp, ssl->buffers.inputBuffer.buffer +
                    ssl->buffers.inputBuffer.idx, usedLength);

    if (ssl->buffers.inputBuffer.dynamicFlag) {
        if (IsEncryptionOn(ssl, 1)) {
            ForceZero(ssl->buffers.inputBuffer.buffer -
                ssl->buffers.inputBuffer.offset,
                ssl->buffers.inputBuffer.bufferSize);
        }
        XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
              ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    }

    ssl->buffers.inputBuffer.dynamicFlag = 1;
#if defined(WOLFSSL_DTLS) || WOLFSSL_GENERAL_ALIGNMENT > 0
    if (align)
        ssl->buffers.inputBuffer.offset = align - hdrSz;
    else
#endif
        ssl->buffers.inputBuffer.offset = 0;

    ssl->buffers.inputBuffer.buffer = tmp;
    ssl->buffers.inputBuffer.bufferSize = size + usedLength;
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = usedLength;

    return 0;
}


/* Check available size into output buffer, make room if needed.
 * This function needs to be called before anything gets put
 * into the output buffers since it flushes pending data if it
 * predicts that the msg will exceed MTU. */
int CheckAvailableSize(WOLFSSL *ssl, int size)
{
    if (size < 0) {
        WOLFSSL_MSG("CheckAvailableSize() called with negative number");
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        if (size + ssl->buffers.outputBuffer.length -
            ssl->buffers.outputBuffer.idx >
#if defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)
                ssl->dtlsMtuSz
#else
                ssl->dtls_expected_rx
#endif
                ) {
            int ret;
            WOLFSSL_MSG("CheckAvailableSize() flushing buffer "
                        "to make room for new message");
            if ((ret = SendBuffered(ssl)) != 0) {
                return ret;
            }
        }
        if (size > (int)
#if defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)
                ssl->dtlsMtuSz
#else
                ssl->dtls_expected_rx
#endif
#ifdef WOLFSSL_DTLS13
            /* DTLS1.3 uses the output buffer to store the full message and deal
               with fragmentation later in dtls13HandshakeSend() */
            && !IsAtLeastTLSv1_3(ssl->version)
#endif /* WOLFSSL_DTLS13 */
            ) {
            WOLFSSL_MSG("CheckAvailableSize() called with size greater than MTU.");
            return DTLS_SIZE_ERROR;
        }
    }
#endif

    if (ssl->buffers.outputBuffer.bufferSize - ssl->buffers.outputBuffer.length
                                             < (word32)size) {
        if (GrowOutputBuffer(ssl, size) < 0)
            return MEMORY_E;
    }

    return 0;
}

#ifdef WOLFSSL_DTLS13
static int GetInputData(WOLFSSL *ssl, word32 size);
static int GetDtls13RecordHeader(WOLFSSL* ssl, word32* inOutIdx,
    RecordLayerHeader* rh, word16* size)
{

    Dtls13UnifiedHdrInfo hdrInfo;
    w64wrapper epochNumber;
    byte epochBits;
    int readSize;
    int ret;

    readSize = ssl->buffers.inputBuffer.length - *inOutIdx;

    if (readSize < DTLS_UNIFIED_HEADER_MIN_SZ)
        return BUFFER_ERROR;

    epochBits = *(ssl->buffers.inputBuffer.buffer + *inOutIdx) & EE_MASK;
    ret = Dtls13ReconstructEpochNumber(ssl, epochBits, &epochNumber);
    if (ret != 0)
        return ret;

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG_EX("reconstructed epoch number: %ld",
                   epochNumber);
#endif /* WOLFSSL_DEBUG_TLS */

    /* protected records always use unified_headers in DTLSv1.3 */
    if (w64IsZero(epochNumber))
        return SEQUENCE_ERROR;

    if (ssl->dtls13DecryptEpoch == NULL)
        return BAD_STATE_E;

#ifdef WOLFSSL_EARLY_DATA
    if (w64Equal(epochNumber, w64From32(0x0, DTLS13_EPOCH_EARLYDATA)) &&
            ssl->options.handShakeDone) {
        WOLFSSL_MSG("discarding early data after handshake");
        return SEQUENCE_ERROR;
    }
#endif /* WOLFSSL_DTLS13 */

    if (!w64Equal(ssl->dtls13DecryptEpoch->epochNumber, epochNumber)) {
        ret = Dtls13SetEpochKeys(ssl, epochNumber, DECRYPT_SIDE_ONLY);
        if (ret != 0)
            return SEQUENCE_ERROR;
    }

    ret = Dtls13GetUnifiedHeaderSize(ssl,
        *(ssl->buffers.inputBuffer.buffer+*inOutIdx), &ssl->dtls13CurRlLength);
    if (ret != 0)
        return ret;

    if (readSize < ssl->dtls13CurRlLength + DTLS13_RN_MASK_SIZE) {
        /* when using DTLS over a medium that does not guarantee that a full
         * message is received in a single read, we may end up without the full
         * header and minimum ciphertext to decrypt record sequence numbers */
        ret = GetInputData(ssl, ssl->dtls13CurRlLength + DTLS13_RN_MASK_SIZE);
        if (ret != 0)
            return ret;

        readSize = ssl->buffers.inputBuffer.length - *inOutIdx;
    }

    ret = Dtls13ParseUnifiedRecordLayer(ssl,
        ssl->buffers.inputBuffer.buffer + *inOutIdx, (word16)readSize,
        &hdrInfo);

    if (ret != 0)
        return ret;

    *size = hdrInfo.recordLength;
    c16toa(*size, rh->length);

   /* type is implicit */
    rh->type = application_data;

    /* version is implicit */
    rh->pvMajor = ssl->version.major;
    rh->pvMinor = DTLSv1_2_MINOR;

    ssl->keys.curEpoch64 = epochNumber;

    ret = Dtls13ReconstructSeqNumber(ssl, &hdrInfo, &ssl->keys.curSeq);
    if (ret != 0)
        return ret;

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG_EX("reconstructed seq number: %ld",
                   ssl->keys.curSeq);
#endif /* WOLFSSL_DEBUG_TLS */

    XMEMCPY(ssl->dtls13CurRL, ssl->buffers.inputBuffer.buffer + *inOutIdx,
            ssl->dtls13CurRlLength);
    *inOutIdx += ssl->dtls13CurRlLength;

    return 0;
}

#endif /* WOLFSSL_DTLS13 */

#ifdef WOLFSSL_DTLS
static int GetDtlsRecordHeader(WOLFSSL* ssl, word32* inOutIdx,
    RecordLayerHeader* rh, word16* size)
{

#ifdef HAVE_FUZZER
    if (ssl->fuzzerCb)
        ssl->fuzzerCb(ssl, ssl->buffers.inputBuffer.buffer + *inOutIdx,
                      DTLS_RECORD_HEADER_SZ, FUZZ_HEAD, ssl->fuzzerCtx);
#endif

#ifdef WOLFSSL_DTLS13
    int ret;

    if (Dtls13IsUnifiedHeader(*(ssl->buffers.inputBuffer.buffer + *inOutIdx))) {

        /* version 1.3 already negotiated */
        if (ssl->options.tls1_3) {
            ret = GetDtls13RecordHeader(ssl, inOutIdx, rh, size);
            if (ret == 0 || ret != SEQUENCE_ERROR || ret != DTLS_CID_ERROR)
                return ret;
        }

#ifndef NO_WOLFSSL_CLIENT
        if (ssl->options.side == WOLFSSL_CLIENT_END
            && ssl->options.serverState < SERVER_HELLO_COMPLETE
            && IsAtLeastTLSv1_3(ssl->version)
            && !ssl->options.handShakeDone) {
            /* we may have lost ServerHello. Try to send a empty ACK to shortcut
               Server retransmission timer */
            ssl->dtls13Rtx.sendAcks = 1;
        }
#endif
        return SEQUENCE_ERROR;
    }

    /* not a unified header, check that we have at least
     * DTLS_RECORD_HEADER_SZ */
    if (ssl->buffers.inputBuffer.length - *inOutIdx < DTLS_RECORD_HEADER_SZ) {
        ret = GetInputData(ssl, DTLS_RECORD_HEADER_SZ);
        if (ret != 0)
            return LENGTH_ERROR;
    }
#endif /* WOLFSSL_DTLS13 */

    /* type and version in same spot */
    XMEMCPY(rh, ssl->buffers.inputBuffer.buffer + *inOutIdx,
            ENUM_LEN + VERSION_SZ);
    *inOutIdx += ENUM_LEN + VERSION_SZ;
    ato16(ssl->buffers.inputBuffer.buffer + *inOutIdx, &ssl->keys.curEpoch);
#ifdef WOLFSSL_DTLS13
    /* only non protected message can use the DTLSPlaintext record header */
    if (ssl->options.tls1_3 && ssl->keys.curEpoch != 0)
            return SEQUENCE_ERROR;

    w64Zero(&ssl->keys.curEpoch64);
    if (!w64IsZero(ssl->dtls13DecryptEpoch->epochNumber))
        Dtls13SetEpochKeys(ssl, ssl->keys.curEpoch64, DECRYPT_SIDE_ONLY);

#endif /* WOLFSSL_DTLS13 */
    *inOutIdx += OPAQUE16_LEN;
    if (ssl->options.haveMcast) {
    #ifdef WOLFSSL_MULTICAST
        ssl->keys.curPeerId = ssl->buffers.inputBuffer.buffer[*inOutIdx];
        ssl->keys.curSeq_hi = ssl->buffers.inputBuffer.buffer[*inOutIdx+1];
    #endif
    }
    else
        ato16(ssl->buffers.inputBuffer.buffer + *inOutIdx, &ssl->keys.curSeq_hi);
    *inOutIdx += OPAQUE16_LEN;
    ato32(ssl->buffers.inputBuffer.buffer + *inOutIdx, &ssl->keys.curSeq_lo);
    *inOutIdx += OPAQUE32_LEN;  /* advance past rest of seq */

#ifdef WOLFSSL_DTLS13
    /* DTLSv1.3 PlainText records use DTLSv1.2 sequence number encoding. Update
       the DTLv1.3 word64 version as well */
    ssl->keys.curSeq = w64From32(ssl->keys.curSeq_hi, ssl->keys.curSeq_lo);
#endif /* WOLFSSL_DTLS13 */

    ato16(ssl->buffers.inputBuffer.buffer + *inOutIdx, size);
    *inOutIdx += LENGTH_SZ;

    return 0;
}
#endif /* WOLFSSL_DTLS */

/* do all verify and sanity checks on record header */
static int GetRecordHeader(WOLFSSL* ssl, word32* inOutIdx,
                           RecordLayerHeader* rh, word16 *size)
{
    byte tls12minor;
#ifdef WOLFSSL_DTLS
    int ret;
#endif /* WOLFSSL_DTLS */

#ifdef OPENSSL_ALL
    word32 start = *inOutIdx;
#endif

    (void)tls12minor;

    if (!ssl->options.dtls) {
#ifdef HAVE_FUZZER
        if (ssl->fuzzerCb)
            ssl->fuzzerCb(ssl, ssl->buffers.inputBuffer.buffer + *inOutIdx,
                          RECORD_HEADER_SZ, FUZZ_HEAD, ssl->fuzzerCtx);
#endif
        XMEMCPY(rh, ssl->buffers.inputBuffer.buffer + *inOutIdx, RECORD_HEADER_SZ);
        *inOutIdx += RECORD_HEADER_SZ;
        ato16(rh->length, size);
    }
    else {
#ifdef WOLFSSL_DTLS
        ret = GetDtlsRecordHeader(ssl, inOutIdx, rh, size);
        if (ret != 0)
            return ret;
#endif
    }

#ifdef WOLFSSL_DTLS
    /* DTLSv1.3 MUST check window after deprotecting to avoid timing channel
       (RFC9147 Section 4.5.1) */
    if (IsDtlsNotSctpMode(ssl) && !IsAtLeastTLSv1_3(ssl->version)) {
        if (!_DtlsCheckWindow(ssl) ||
                (rh->type == application_data && ssl->keys.curEpoch == 0) ||
                (rh->type == alert && ssl->options.handShakeDone &&
                        ssl->keys.curEpoch == 0 && ssl->keys.dtls_epoch != 0)) {
            WOLFSSL_LEAVE("GetRecordHeader()", SEQUENCE_ERROR);
            return SEQUENCE_ERROR;
        }
    }
#endif

#if defined(WOLFSSL_DTLS13) || defined(WOLFSSL_TLS13)
    tls12minor = TLSv1_2_MINOR;
#endif
#ifdef WOLFSSL_DTLS13
    if (ssl->options.dtls)
        tls12minor = DTLSv1_2_MINOR;
#endif /* WOLFSSL_DTLS13 */
    /* catch version mismatch */
#ifndef WOLFSSL_TLS13
    if (rh->pvMajor != ssl->version.major || rh->pvMinor != ssl->version.minor)
#else
    if (rh->pvMajor != ssl->version.major ||
        (rh->pvMinor != ssl->version.minor &&
         (!IsAtLeastTLSv1_3(ssl->version) || rh->pvMinor != tls12minor)
        ))
#endif
    {
        if (ssl->options.side == WOLFSSL_SERVER_END &&
            ssl->options.acceptState < ACCEPT_FIRST_REPLY_DONE)

            WOLFSSL_MSG("Client attempting to connect with different version");
        else if (ssl->options.side == WOLFSSL_CLIENT_END &&
                                 ssl->options.downgrade &&
                                 ssl->options.connectState < FIRST_REPLY_DONE)
            WOLFSSL_MSG("Server attempting to accept with different version");
        else if (ssl->options.dtls && rh->type == handshake)
            /* Check the DTLS handshake message RH version later. */
            WOLFSSL_MSG("DTLS handshake, skip RH version number check");
#ifdef WOLFSSL_DTLS13
        else if (ssl->options.dtls && !ssl->options.handShakeDone) {
            /* we may have lost the ServerHello and this is a unified record
               before version been negotiated */
            if (Dtls13IsUnifiedHeader(*ssl->buffers.inputBuffer.buffer)) {
                return SEQUENCE_ERROR;
            }
        }
#endif /* WOLFSSL_DTLS13 */
        else {
            WOLFSSL_MSG("SSL version error");
            /* send alert per RFC5246 Appendix E. Backward Compatibility */
            if (ssl->options.side == WOLFSSL_CLIENT_END)
                SendAlert(ssl, alert_fatal, wolfssl_alert_protocol_version);
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;              /* only use requested version */
        }
    }

    /* record layer length check */
#ifdef HAVE_MAX_FRAGMENT
    if (*size > (ssl->max_fragment + MAX_COMP_EXTRA + MAX_MSG_EXTRA)) {
        SendAlert(ssl, alert_fatal, record_overflow);
        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
        return LENGTH_ERROR;
    }
#else
    if (*size > (MAX_RECORD_SIZE + MAX_COMP_EXTRA + MAX_MSG_EXTRA)) {
        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
        return LENGTH_ERROR;
    }
#endif

    if (*size == 0 && rh->type != application_data) {
        WOLFSSL_MSG("0 length, non-app data record.");
        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
        return LENGTH_ERROR;
    }

    /* verify record type here as well */
    switch (rh->type) {
        case handshake:
        case change_cipher_spec:
        case application_data:
        case alert:
#ifdef WOLFSSL_DTLS13
        case ack:
#endif /* WOLFSSL_DTLS13 */
            break;
        case no_type:
        default:
#ifdef OPENSSL_ALL
            if (!ssl->options.dtls) {
                char *method = (char*)ssl->buffers.inputBuffer.buffer + start;
                /* Attempt to identify if this is a plain HTTP request.
                 * No size checks because this function assumes at least
                 * RECORD_HEADER_SZ size of data has been read which is
                 * also the longest string comparison in this if. */
                if (XSTRNCMP(method, "GET ", XSTR_SIZEOF("GET ")) == 0 ||
                    XSTRNCMP(method, "POST ", XSTR_SIZEOF("POST ")) == 0 ||
                    XSTRNCMP(method, "HEAD ", XSTR_SIZEOF("HEAD ")) == 0 ||
                    XSTRNCMP(method, "PUT ", XSTR_SIZEOF("PUT ")) == 0) {
                    WOLFSSL_MSG("Plain HTTP request detected");
                    return SSL_R_HTTP_REQUEST;
                }
            }
#endif
            WOLFSSL_MSG("Unknown Record Type");
            WOLFSSL_ERROR_VERBOSE(UNKNOWN_RECORD_TYPE);
            return UNKNOWN_RECORD_TYPE;
    }

    /* haven't decrypted this record yet */
    ssl->keys.decryptedCur = 0;

    return 0;
}

#ifndef WOLFSSL_NO_TLS12
static int GetHandShakeHeader(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                              byte *type, word32 *size, word32 totalSz)
{
    const byte *ptr = input + *inOutIdx;
    (void)ssl;

    *inOutIdx += HANDSHAKE_HEADER_SZ;
    if (*inOutIdx > totalSz)
        return BUFFER_E;

    *type = ptr[0];
    c24to32(&ptr[1], size);

    return 0;
}
#endif

#ifdef WOLFSSL_DTLS
int GetDtlsHandShakeHeader(WOLFSSL* ssl, const byte* input,
                           word32* inOutIdx, byte *type, word32 *size,
                           word32 *fragOffset, word32 *fragSz,
                           word32 totalSz)
{
    word32 idx = *inOutIdx;

    *inOutIdx += HANDSHAKE_HEADER_SZ + DTLS_HANDSHAKE_EXTRA;
    if (*inOutIdx > totalSz) {
        WOLFSSL_ERROR(BUFFER_E);
        return BUFFER_E;
    }

    *type = input[idx++];
    c24to32(input + idx, size);
    idx += OPAQUE24_LEN;

    ato16(input + idx, &ssl->keys.dtls_peer_handshake_number);
    idx += DTLS_HANDSHAKE_SEQ_SZ;

    c24to32(input + idx, fragOffset);
    idx += DTLS_HANDSHAKE_FRAG_SZ;
    c24to32(input + idx, fragSz);

    if ((ssl->curRL.pvMajor != ssl->version.major) ||
        (!IsAtLeastTLSv1_3(ssl->version) && ssl->curRL.pvMinor != ssl->version.minor) ||
        (IsAtLeastTLSv1_3(ssl->version) && ssl->curRL.pvMinor != DTLSv1_2_MINOR)
        ) {
        if (*type != client_hello && *type != hello_verify_request && *type != server_hello) {
            WOLFSSL_ERROR(VERSION_ERROR);
            return VERSION_ERROR;
        }
        else {
            WOLFSSL_MSG("DTLS Handshake ignoring hello or verify version");
        }
    }
    return 0;
}
#endif


#if !defined(NO_OLD_TLS) || \
    (defined(NO_OLD_TLS) && defined(WOLFSSL_ALLOW_TLS_SHA1))
/* fill with MD5 pad size since biggest required */
static const byte PAD1[PAD_MD5] =
                              { 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
                                0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36
                              };
static const byte PAD2[PAD_MD5] =
                              { 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
                                0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c
                              };
#endif /* !NO_OLD_TLS || (NO_OLD_TLS && WOLFSSL_ALLOW_TLS_SHA1) */

#ifndef NO_OLD_TLS

/* calculate MD5 hash for finished */
#ifdef WOLFSSL_TI_HASH
#include <wolfssl/wolfcrypt/hash.h>
#endif

static int BuildMD5(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret;
    byte md5_result[WC_MD5_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Md5* md5 = (wc_Md5*)XMALLOC(sizeof(wc_Md5), ssl->heap, DYNAMIC_TYPE_HASHCTX);
    if (md5 == NULL)
        return MEMORY_E;
#else
    wc_Md5  md5[1];
#endif

    /* make md5 inner */
    ret = wc_Md5Copy(&ssl->hsHashes->hashMd5, md5);
    if (ret == 0)
        ret = wc_Md5Update(md5, sender, SIZEOF_SENDER);
    if (ret == 0)
        ret = wc_Md5Update(md5, ssl->arrays->masterSecret,SECRET_LEN);
    if (ret == 0)
        ret = wc_Md5Update(md5, PAD1, PAD_MD5);
    if (ret == 0)
        ret = wc_Md5Final(md5, md5_result);

    /* make md5 outer */
    if (ret == 0) {
        ret = wc_InitMd5_ex(md5, ssl->heap, ssl->devId);
        if (ret == 0) {
            ret = wc_Md5Update(md5, ssl->arrays->masterSecret,SECRET_LEN);
            if (ret == 0)
                ret = wc_Md5Update(md5, PAD2, PAD_MD5);
            if (ret == 0)
                ret = wc_Md5Update(md5, md5_result, WC_MD5_DIGEST_SIZE);
            if (ret == 0)
                ret = wc_Md5Final(md5, hashes->md5);
            wc_Md5Free(md5);
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(md5, ssl->heap, DYNAMIC_TYPE_HASHCTX);
#endif

    return ret;
}


/* calculate SHA hash for finished */
static int BuildSHA(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret;
    byte sha_result[WC_SHA_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha* sha = (wc_Sha*)XMALLOC(sizeof(wc_Sha), ssl->heap, DYNAMIC_TYPE_HASHCTX);
    if (sha == NULL)
        return MEMORY_E;
#else
    wc_Sha  sha[1];
#endif
    /* make sha inner */
    ret = wc_ShaCopy(&ssl->hsHashes->hashSha, sha); /* Save current position */
    if (ret == 0)
        ret = wc_ShaUpdate(sha, sender, SIZEOF_SENDER);
    if (ret == 0)
        ret = wc_ShaUpdate(sha, ssl->arrays->masterSecret,SECRET_LEN);
    if (ret == 0)
        ret = wc_ShaUpdate(sha, PAD1, PAD_SHA);
    if (ret == 0)
        ret = wc_ShaFinal(sha, sha_result);

    /* make sha outer */
    if (ret == 0) {
        ret = wc_InitSha_ex(sha, ssl->heap, ssl->devId);
        if (ret == 0) {
            ret = wc_ShaUpdate(sha, ssl->arrays->masterSecret,SECRET_LEN);
            if (ret == 0)
                ret = wc_ShaUpdate(sha, PAD2, PAD_SHA);
            if (ret == 0)
                ret = wc_ShaUpdate(sha, sha_result, WC_SHA_DIGEST_SIZE);
            if (ret == 0)
                ret = wc_ShaFinal(sha, hashes->sha);
            wc_ShaFree(sha);
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sha, ssl->heap, DYNAMIC_TYPE_HASHCTX);
#endif

    return ret;
}
#endif

#ifndef WOLFSSL_NO_TLS12

/* Finished doesn't support SHA512, not SHA512 cipher suites yet */
static int BuildFinished(WOLFSSL* ssl, Hashes* hashes, const byte* sender)
{
    int ret = 0;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

#ifndef NO_TLS
    if (ssl->options.tls) {
        ret = BuildTlsFinished(ssl, hashes, sender);
    }
#else
    (void)hashes;
    (void)sender;
#endif
#ifndef NO_OLD_TLS
    if (!ssl->options.tls) {
        ret = BuildMD5(ssl, hashes, sender);
        if (ret == 0) {
            ret = BuildSHA(ssl, hashes, sender);
        }
    }
#endif

    return ret;
}

#endif /* WOLFSSL_NO_TLS12 */


//////////////////////////////////////////


#ifndef NO_CERTS


/* Match names with wildcards, each wildcard can represent a single name
   component or fragment but not multiple names, i.e.,
   *.z.com matches y.z.com but not x.y.z.com

   return 1 on success */
int MatchDomainName(const char* pattern, int len, const char* str)
{
    int ret = 0;
    char p, s;

    if (pattern == NULL || str == NULL || len <= 0)
        return 0;

    while (len > 0) {

        p = (char)XTOLOWER((unsigned char)*pattern++);
        if (p == '\0')
            break;

        if (p == '*') {
            while (--len > 0 &&
                (p = (char)XTOLOWER((unsigned char)*pattern++)) == '*') {
            }

            if (len == 0)
                p = '\0';

            while ( (s = (char)XTOLOWER((unsigned char) *str)) != '\0') {
                if (s == p)
                    break;
                if (s == '.')
                    return 0;
                str++;
            }
        }
        else {
            if (p != (char)XTOLOWER((unsigned char) *str))
                return 0;
        }


        if (len > 0) {
            str++;
            len--;
        }
    }

    if (*str == '\0' && len == 0) {
        ret = 1; /* success */
    }

    return ret;
}


/* Check that alternative names, if they exists, match the domain.
 * Fail if there are wild patterns and they didn't match.
 * Check the common name if no alternative names matched.
 *
 * dCert    Decoded cert to get the alternative names from.
 * domain   Domain name to compare against.
 * checkCN  Whether to check the common name.
 * returns  1 : match was found.
 *          0 : no match found.
 *         -1 : No matches and wild pattern match failed.
 */
int CheckForAltNames(DecodedCert* dCert, const char* domain, int* checkCN)
{
    int match = 0;
    DNS_entry* altName = NULL;
    char *buf;
    word32 len;

    WOLFSSL_MSG("Checking AltNames");

    if (dCert)
        altName = dCert->altNames;

    if (checkCN != NULL) {
        *checkCN = (altName == NULL) ? 1 : 0;
    }

    while (altName) {
        WOLFSSL_MSG("\tindividual AltName check");

#if defined(OPENSSL_ALL) || defined(WOLFSSL_IP_ALT_NAME)
        if (altName->type == ASN_IP_TYPE) {
            buf = altName->ipString;
            len = (word32)XSTRLEN(buf);
        }
        else
#endif /* OPENSSL_ALL || WOLFSSL_IP_ALT_NAME */
        {
            buf = altName->name;
            len = altName->len;
        }

        if (MatchDomainName(buf, len, domain)) {
            match = 1;
            if (checkCN != NULL) {
                *checkCN = 0;
            }
            WOLFSSL_MSG("\tmatch found");
            break;
        }
        /* No matches and wild pattern match failed. */
        else if (buf && (len >=1) && (buf[0] == '*')) {
            match = -1;
            WOLFSSL_MSG("\twildcard match failed");
        }

        altName = altName->next;
    }

    return match;
}


/* Check the domain name matches the subject alternative name or the subject
 * name.
 *
 * dcert          Decoded certificate.
 * domainName     The domain name.
 * domainNameLen  The length of the domain name.
 * returns DOMAIN_NAME_MISMATCH when no match found and 0 on success.
 */
int CheckHostName(DecodedCert* dCert, const char *domainName, size_t domainNameLen)
{
    int checkCN;
    int ret = DOMAIN_NAME_MISMATCH;

    /* Assume name is NUL terminated. */
    (void)domainNameLen;

    if (CheckForAltNames(dCert, domainName, &checkCN) != 1) {
        WOLFSSL_MSG("DomainName match on alt names failed");
    }
    else {
        ret = 0;
    }

#ifndef WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY
    if (checkCN == 1) {
        if (MatchDomainName(dCert->subjectCN, dCert->subjectCNLen,
                            domainName) == 1) {
            ret = 0;
        }
        else {
            WOLFSSL_MSG("DomainName match on common name failed");
        }
    }
#endif /* !WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY */

    return ret;
}

int CheckIPAddr(DecodedCert* dCert, const char* ipasc)
{
    WOLFSSL_MSG("Checking IPAddr");

    return CheckHostName(dCert, ipasc, (size_t)XSTRLEN(ipasc));
}


#ifdef SESSION_CERTS
static void AddSessionCertToChain(WOLFSSL_X509_CHAIN* chain,
    byte* certBuf, word32 certSz)
{
   if (chain->count < MAX_CHAIN_DEPTH &&
                               certSz < MAX_X509_SIZE) {
        chain->certs[chain->count].length = certSz;
        XMEMCPY(chain->certs[chain->count].buffer, certBuf, certSz);
        chain->count++;
    }
    else {
        WOLFSSL_MSG("Couldn't store chain cert for session");
    }
}
#endif

#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS) || \
    defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
static void CopyDecodedName(WOLFSSL_X509_NAME* name, DecodedCert* dCert, int nameType)
{
    if (nameType == SUBJECT) {
        XSTRNCPY(name->name, dCert->subject, ASN_NAME_MAX);
        name->name[ASN_NAME_MAX - 1] = '\0';
        name->sz = (int)XSTRLEN(name->name) + 1;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
        name->rawLen = min(dCert->subjectRawLen, ASN_NAME_MAX);
        XMEMCPY(name->raw, dCert->subjectRaw, name->rawLen);
#endif
    }
    else {
        XSTRNCPY(name->name, dCert->issuer, ASN_NAME_MAX);
        name->name[ASN_NAME_MAX - 1] = '\0';
        name->sz = (int)XSTRLEN(name->name) + 1;
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)) \
    && (defined(HAVE_PKCS7) || defined(WOLFSSL_CERT_EXT))
        name->rawLen = min(dCert->issuerRawLen, ASN_NAME_MAX);
        if (name->rawLen) {
            XMEMCPY(name->raw, dCert->issuerRaw, name->rawLen);
        }
#endif
    }
}


#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(IGNORE_NAME_CONSTRAINTS)
/* copies over additional alt names such as dirName
 * returns 0 on success
 */
static int CopyAdditionalAltNames(DNS_entry** to, DNS_entry* from, int type,
        void* heap)
{
    DNS_entry* cur = from;

    if (to == NULL) {
        return BAD_FUNC_ARG;
    }

    while (cur != NULL) {
        if (cur->type == type) {
            DNS_entry* dnsEntry;
            int strLen = cur->len;

            dnsEntry = AltNameNew(heap);
            if (dnsEntry == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                return MEMORY_E;
            }

            dnsEntry->type = type;
            dnsEntry->name = (char*)XMALLOC(strLen + 1, heap,
                    DYNAMIC_TYPE_ALTNAME);
            if (dnsEntry->name == NULL) {
                WOLFSSL_MSG("\tOut of Memory");
                XFREE(dnsEntry, heap, DYNAMIC_TYPE_ALTNAME);
                return MEMORY_E;
            }
            dnsEntry->len = strLen;
            XMEMCPY(dnsEntry->name, cur->name, strLen);
            dnsEntry->name[strLen] = '\0';

            dnsEntry->next = *to;
            *to = dnsEntry;
        }
        cur = cur->next;
    }
    return 0;
}
#endif /* OPENSSL_EXTRA */

#ifdef WOLFSSL_CERT_REQ
static int CopyREQAttributes(WOLFSSL_X509* x509, DecodedCert* dCert)
{
    int ret = 0;

    if (dCert->cPwd) {
        if (dCert->cPwdLen < CTC_NAME_SIZE) {
            XMEMCPY(x509->challengePw, dCert->cPwd, dCert->cPwdLen);
            x509->challengePw[dCert->cPwdLen] = '\0';
        #if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN)
            if (wolfSSL_X509_REQ_add1_attr_by_NID(x509,
                                        NID_pkcs9_challengePassword,
                                        MBSTRING_ASC,
                                        (const byte*)dCert->cPwd,
                                        dCert->cPwdLen) != WOLFSSL_SUCCESS) {
                ret = REQ_ATTRIBUTE_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
        #endif
        }
        else {
            WOLFSSL_MSG("Challenge password too long");
            ret = MEMORY_E;
        }
    }

    if (dCert->contentType) {
        if (dCert->contentTypeLen < CTC_NAME_SIZE) {
            XMEMCPY(x509->contentType, dCert->contentType, dCert->contentTypeLen);
            x509->contentType[dCert->contentTypeLen] = '\0';
        }
    #if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN)
        if (wolfSSL_X509_REQ_add1_attr_by_NID(x509,
                                        NID_pkcs9_contentType,
                                        MBSTRING_ASC,
                                        (const byte*)dCert->contentType,
                                        dCert->contentTypeLen) !=
                WOLFSSL_SUCCESS) {
            ret = REQ_ATTRIBUTE_E;
            WOLFSSL_ERROR_VERBOSE(ret);
        }
    #endif
    }

    #if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN)
    if (dCert->sNum) {
        if (wolfSSL_X509_REQ_add1_attr_by_NID(x509,
                                        NID_serialNumber,
                                        MBSTRING_ASC,
                                        (const byte*)dCert->sNum,
                                        dCert->sNumLen) != WOLFSSL_SUCCESS) {
            ret = REQ_ATTRIBUTE_E;
            WOLFSSL_ERROR_VERBOSE(ret);
        }
    }
    if (dCert->unstructuredName) {
        if (wolfSSL_X509_REQ_add1_attr_by_NID(x509,
                                        NID_pkcs9_unstructuredName,
                                        MBSTRING_ASC,
                                        (const byte*)dCert->unstructuredName,
                                        dCert->unstructuredNameLen)
                != WOLFSSL_SUCCESS) {
            ret = REQ_ATTRIBUTE_E;
            WOLFSSL_ERROR_VERBOSE(ret);
        }
    }
    if (dCert->surname) {
        if (wolfSSL_X509_REQ_add1_attr_by_NID(x509,
                                        NID_surname,
                                        MBSTRING_ASC,
                                        (const byte*)dCert->surname,
                                        dCert->surnameLen) != WOLFSSL_SUCCESS) {
            ret = REQ_ATTRIBUTE_E;
            WOLFSSL_ERROR_VERBOSE(ret);
        }
    }
    if (dCert->givenName) {
        if (wolfSSL_X509_REQ_add1_attr_by_NID(x509,
                                        NID_givenName,
                                        MBSTRING_ASC,
                                        (const byte*)dCert->givenName,
                                        dCert->givenNameLen) != WOLFSSL_SUCCESS) {
            ret = REQ_ATTRIBUTE_E;
            WOLFSSL_ERROR_VERBOSE(ret);
        }
    }
    if (dCert->dnQualifier) {
        if (wolfSSL_X509_REQ_add1_attr_by_NID(x509,
                                        NID_dnQualifier,
                                        MBSTRING_ASC,
                                        (const byte*)dCert->dnQualifier,
                                        dCert->dnQualifierLen) != WOLFSSL_SUCCESS) {
            ret = REQ_ATTRIBUTE_E;
            WOLFSSL_ERROR_VERBOSE(ret);
        }
    }
    if (dCert->initials) {
        if (wolfSSL_X509_REQ_add1_attr_by_NID(x509,
                                        NID_initials,
                                        MBSTRING_ASC,
                                        (const byte*)dCert->initials,
                                        dCert->initialsLen) != WOLFSSL_SUCCESS) {
            ret = REQ_ATTRIBUTE_E;
            WOLFSSL_ERROR_VERBOSE(ret);
        }
    }
    #endif /* OPENSSL_ALL */

    return ret;
}
#endif /* WOLFSSL_CERT_REQ */

/* Copy parts X509 needs from Decoded cert, 0 on success */
/* The same DecodedCert cannot be copied to WOLFSSL_X509 twice otherwise the
 * altNames pointers could be free'd by second x509 still active by first */
int CopyDecodedToX509(WOLFSSL_X509* x509, DecodedCert* dCert)
{
    int ret = 0;

    if (x509 == NULL || dCert == NULL ||
        dCert->subjectCNLen < 0)
        return BAD_FUNC_ARG;

    if (x509->issuer.name == NULL || x509->subject.name == NULL) {
        WOLFSSL_MSG("Either init was not called on X509 or programming error");
        WOLFSSL_ERROR_VERBOSE(BAD_FUNC_ARG);
        return BAD_FUNC_ARG;
    }

    x509->version = dCert->version + 1;

    CopyDecodedName(&x509->issuer, dCert, ISSUER);
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    if (dCert->issuerName != NULL) {
        wolfSSL_X509_set_issuer_name(x509,
                (WOLFSSL_X509_NAME*)dCert->issuerName);
        x509->issuer.x509 = x509;
    }
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
    CopyDecodedName(&x509->subject, dCert, SUBJECT);
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    if (dCert->subjectName != NULL) {
        wolfSSL_X509_set_subject_name(x509,
                (WOLFSSL_X509_NAME*)dCert->subjectName);
        x509->subject.x509 = x509;
    }
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

    XMEMCPY(x509->serial, dCert->serial, EXTERNAL_SERIAL_SIZE);
    x509->serialSz = dCert->serialSz;
    if (dCert->subjectCN && dCert->subjectCNLen < ASN_NAME_MAX) {
        XMEMCPY(x509->subjectCN, dCert->subjectCN, dCert->subjectCNLen);
        x509->subjectCN[dCert->subjectCNLen] = '\0';
    }
    else
        x509->subjectCN[0] = '\0';

#ifdef WOLFSSL_CERT_REQ
    x509->isCSR = dCert->isCSR;

    /* CSR attributes */
    if (x509->isCSR) {
        ret = CopyREQAttributes(x509, dCert);
    }
#endif /* WOLFSSL_CERT_REQ */

#ifdef WOLFSSL_SEP
    {
        int minSz = min(dCert->deviceTypeSz, EXTERNAL_SERIAL_SIZE);
        if (minSz > 0) {
            x509->deviceTypeSz = minSz;
            XMEMCPY(x509->deviceType, dCert->deviceType, minSz);
        }
        else
            x509->deviceTypeSz = 0;
        minSz = min(dCert->hwTypeSz, EXTERNAL_SERIAL_SIZE);
        if (minSz > 0) {
            x509->hwTypeSz = minSz;
            XMEMCPY(x509->hwType, dCert->hwType, minSz);
        }
        else
            x509->hwTypeSz = 0;
        minSz = min(dCert->hwSerialNumSz, EXTERNAL_SERIAL_SIZE);
        if (minSz > 0) {
            x509->hwSerialNumSz = minSz;
            XMEMCPY(x509->hwSerialNum, dCert->hwSerialNum, minSz);
        }
        else
            x509->hwSerialNumSz = 0;
    }
#endif /* WOLFSSL_SEP */
    {
        int minSz;
        if (dCert->beforeDateLen > 0) {
            minSz = min(dCert->beforeDate[1], MAX_DATE_SZ);
            x509->notBefore.type = dCert->beforeDate[0];
            x509->notBefore.length = minSz;
            XMEMCPY(x509->notBefore.data, &dCert->beforeDate[2], minSz);
        }
        else
            x509->notBefore.length = 0;
        if (dCert->afterDateLen > 0) {
            minSz = min(dCert->afterDate[1], MAX_DATE_SZ);
            x509->notAfter.type = dCert->afterDate[0];
            x509->notAfter.length = minSz;
            XMEMCPY(x509->notAfter.data, &dCert->afterDate[2], minSz);
        }
        else
            x509->notAfter.length = 0;
    }

    if (dCert->publicKey != NULL && dCert->pubKeySize != 0) {
        x509->pubKey.buffer = (byte*)XMALLOC(
                        dCert->pubKeySize, x509->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        if (x509->pubKey.buffer != NULL) {
            x509->pubKeyOID = dCert->keyOID;
            x509->pubKey.length = dCert->pubKeySize;
            XMEMCPY(x509->pubKey.buffer, dCert->publicKey, dCert->pubKeySize);
        }
        else
            ret = MEMORY_E;
#if defined(OPENSSL_ALL)
        if (ret == 0) {
            x509->key.pubKeyOID = dCert->keyOID;

            if (!x509->key.algor) {
                x509->key.algor = wolfSSL_X509_ALGOR_new();
            } else {
                wolfSSL_ASN1_OBJECT_free(x509->key.algor->algorithm);
            }
            if (!x509->key.algor) {
                ret = MEMORY_E;
            } else {
                if (!(x509->key.algor->algorithm =
                    wolfSSL_OBJ_nid2obj(oid2nid(dCert->keyOID, oidKeyType)))) {
                    ret = PUBLIC_KEY_E;
                    WOLFSSL_ERROR_VERBOSE(ret);
                }
            }

            wolfSSL_EVP_PKEY_free(x509->key.pkey);
            if (!(x509->key.pkey = wolfSSL_d2i_PUBKEY(NULL,
                                                      &dCert->publicKey,
                                                      dCert->pubKeySize))) {
                ret = PUBLIC_KEY_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
        }
#endif
    }

    if (dCert->signature != NULL && dCert->sigLength != 0 &&
            dCert->sigLength <= MAX_ENCODED_SIG_SZ) {
        x509->sig.buffer = (byte*)XMALLOC(
                          dCert->sigLength, x509->heap, DYNAMIC_TYPE_SIGNATURE);
        if (x509->sig.buffer == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(x509->sig.buffer, dCert->signature, dCert->sigLength);
            x509->sig.length = dCert->sigLength;
            x509->sigOID = dCert->signatureOID;
        }
#if defined(OPENSSL_ALL)
        wolfSSL_ASN1_OBJECT_free(x509->algor.algorithm);
        if (!(x509->algor.algorithm =
                wolfSSL_OBJ_nid2obj(oid2nid(dCert->signatureOID, oidSigType)))) {
            ret = PUBLIC_KEY_E;
            WOLFSSL_ERROR_VERBOSE(ret);
        }
#endif
    }

    /* if der contains original source buffer then store for potential
     * retrieval */
    if (dCert->source != NULL && dCert->maxIdx > 0) {
        if (AllocDer(&x509->derCert, dCert->maxIdx, CERT_TYPE, x509->heap)
                                                                         == 0) {
            XMEMCPY(x509->derCert->buffer, dCert->source, dCert->maxIdx);
        }
        else {
            ret = MEMORY_E;
        }
    }

    x509->altNames       = dCert->altNames;
    dCert->weOwnAltNames = 0;
#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)) && \
    !defined(IGNORE_NAME_CONSTRAINTS)
    /* add copies of email names from dCert to X509 */
    if (CopyAdditionalAltNames(&x509->altNames, dCert->altEmailNames,
                ASN_RFC822_TYPE, x509->heap) != 0) {
        return MEMORY_E;
    }
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
#if defined(OPENSSL_EXTRA) && !defined(IGNORE_NAME_CONSTRAINTS)
    /* add copies of alternate directory names from dCert to X509 */
    if (CopyAdditionalAltNames(&x509->altNames, dCert->altDirNames,
                ASN_DIR_TYPE, x509->heap) != 0) {
        return MEMORY_E;
    }
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
    x509->altNamesNext   = x509->altNames;  /* index hint */

    x509->isCa = dCert->isCA;
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    x509->pathLength = dCert->pathLength;
    x509->keyUsage = dCert->extKeyUsage;

    x509->CRLdistSet = dCert->extCRLdistSet;
    x509->CRLdistCrit = dCert->extCRLdistCrit;
    if (dCert->extCrlInfoRaw != NULL && dCert->extCrlInfoRawSz > 0) {
        x509->rawCRLInfo = (byte*)XMALLOC(dCert->extCrlInfoRawSz, x509->heap,
            DYNAMIC_TYPE_X509_EXT);
        if (x509->rawCRLInfo != NULL) {
            XMEMCPY(x509->rawCRLInfo, dCert->extCrlInfoRaw, dCert->extCrlInfoRawSz);
            x509->rawCRLInfoSz = dCert->extCrlInfoRawSz;
        }
        else {
            ret = MEMORY_E;
        }
    }
    if (dCert->extCrlInfo != NULL && dCert->extCrlInfoSz > 0) {
        x509->CRLInfo = (byte*)XMALLOC(dCert->extCrlInfoSz, x509->heap,
            DYNAMIC_TYPE_X509_EXT);
        if (x509->CRLInfo != NULL) {
            XMEMCPY(x509->CRLInfo, dCert->extCrlInfo, dCert->extCrlInfoSz);
            x509->CRLInfoSz = dCert->extCrlInfoSz;
        }
        else {
            ret = MEMORY_E;
        }
    }
    x509->authInfoSet = dCert->extAuthInfoSet;
    x509->authInfoCrit = dCert->extAuthInfoCrit;
    if (dCert->extAuthInfo != NULL && dCert->extAuthInfoSz > 0) {
        x509->authInfo = (byte*)XMALLOC(dCert->extAuthInfoSz, x509->heap,
                DYNAMIC_TYPE_X509_EXT);
        if (x509->authInfo != NULL) {
            XMEMCPY(x509->authInfo, dCert->extAuthInfo, dCert->extAuthInfoSz);
            x509->authInfoSz = dCert->extAuthInfoSz;
        }
        else {
            ret = MEMORY_E;
        }
    }
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
    if (dCert->extAuthInfoCaIssuer != NULL && dCert->extAuthInfoCaIssuerSz > 0) {
        x509->authInfoCaIssuer = (byte*)XMALLOC(dCert->extAuthInfoCaIssuerSz, x509->heap,
                DYNAMIC_TYPE_X509_EXT);
        if (x509->authInfoCaIssuer != NULL) {
            XMEMCPY(x509->authInfoCaIssuer, dCert->extAuthInfoCaIssuer, dCert->extAuthInfoCaIssuerSz);
            x509->authInfoCaIssuerSz = dCert->extAuthInfoCaIssuerSz;
        }
        else {
            ret = MEMORY_E;
        }
    }
    #endif
    x509->basicConstSet = dCert->extBasicConstSet;
    x509->basicConstCrit = dCert->extBasicConstCrit;
    x509->basicConstPlSet = dCert->pathLengthSet;
    x509->subjAltNameSet = dCert->extSubjAltNameSet;
    x509->subjAltNameCrit = dCert->extSubjAltNameCrit;
    x509->authKeyIdSet = dCert->extAuthKeyIdSet;
    x509->authKeyIdCrit = dCert->extAuthKeyIdCrit;
    if (dCert->extAuthKeyIdSrc != NULL && dCert->extAuthKeyIdSz != 0) {
    #ifdef WOLFSSL_AKID_NAME
        if (dCert->extRawAuthKeyIdSrc != NULL &&
                dCert->extAuthKeyIdSrc > dCert->extRawAuthKeyIdSrc &&
                dCert->extAuthKeyIdSrc <
                    (dCert->extRawAuthKeyIdSrc + dCert->extRawAuthKeyIdSz)) {
            /* Confirmed: extAuthKeyIdSrc points inside extRawAuthKeyIdSrc */
            x509->authKeyIdSrc = (byte*)XMALLOC(dCert->extRawAuthKeyIdSz,
                    x509->heap, DYNAMIC_TYPE_X509_EXT);
            if (x509->authKeyIdSrc != NULL) {
                XMEMCPY(x509->authKeyIdSrc, dCert->extRawAuthKeyIdSrc,
                        dCert->extRawAuthKeyIdSz);
                x509->authKeyIdSrcSz = dCert->extRawAuthKeyIdSz;
                /* Set authKeyId to same offset inside authKeyIdSrc */
                x509->authKeyId = x509->authKeyIdSrc +
                        (dCert->extAuthKeyIdSrc - dCert->extRawAuthKeyIdSrc);
                x509->authKeyIdSz = dCert->extAuthKeyIdSz;
            }
            else
                ret = MEMORY_E;
        }
    #else
        x509->authKeyId = (byte*)XMALLOC(dCert->extAuthKeyIdSz, x509->heap,
                                         DYNAMIC_TYPE_X509_EXT);
        if (x509->authKeyId != NULL) {
            XMEMCPY(x509->authKeyId,
                                 dCert->extAuthKeyIdSrc, dCert->extAuthKeyIdSz);
            x509->authKeyIdSz = dCert->extAuthKeyIdSz;
        }
    #endif
        else
            ret = MEMORY_E;
    }
    x509->subjKeyIdSet = dCert->extSubjKeyIdSet;
    x509->subjKeyIdCrit = dCert->extSubjKeyIdCrit;
    if (dCert->extSubjKeyIdSrc != NULL && dCert->extSubjKeyIdSz != 0) {
        x509->subjKeyId = (byte*)XMALLOC(dCert->extSubjKeyIdSz, x509->heap,
                                         DYNAMIC_TYPE_X509_EXT);
        if (x509->subjKeyId != NULL) {
            XMEMCPY(x509->subjKeyId,
                                 dCert->extSubjKeyIdSrc, dCert->extSubjKeyIdSz);
            x509->subjKeyIdSz = dCert->extSubjKeyIdSz;
        }
        else
            ret = MEMORY_E;
    }
    x509->keyUsageSet = dCert->extKeyUsageSet;
    x509->keyUsageCrit = dCert->extKeyUsageCrit;
    if (dCert->extExtKeyUsageSrc != NULL && dCert->extExtKeyUsageSz > 0) {
        x509->extKeyUsageSrc = (byte*)XMALLOC(dCert->extExtKeyUsageSz,
                x509->heap, DYNAMIC_TYPE_X509_EXT);
        if (x509->extKeyUsageSrc != NULL) {
            XMEMCPY(x509->extKeyUsageSrc, dCert->extExtKeyUsageSrc,
                                                       dCert->extExtKeyUsageSz);
            x509->extKeyUsage      = dCert->extExtKeyUsage;
            x509->extKeyUsageSz    = dCert->extExtKeyUsageSz;
            x509->extKeyUsageCrit  = dCert->extExtKeyUsageCrit;
            x509->extKeyUsageCount = dCert->extExtKeyUsageCount;
        }
        else {
            ret = MEMORY_E;
        }
    }
    #ifndef IGNORE_NETSCAPE_CERT_TYPE
    x509->nsCertType = dCert->nsCertType;
    #endif
    #if defined(WOLFSSL_SEP) || defined(WOLFSSL_QT)
        x509->certPolicySet = dCert->extCertPolicySet;
        x509->certPolicyCrit = dCert->extCertPolicyCrit;
    #endif /* WOLFSSL_SEP || WOLFSSL_QT */
    #ifdef WOLFSSL_CERT_EXT
        {
            int i;
            for (i = 0; i < dCert->extCertPoliciesNb && i < MAX_CERTPOL_NB; i++)
                XMEMCPY(x509->certPolicies[i], dCert->extCertPolicies[i],
                                                                MAX_CERTPOL_SZ);
            x509->certPoliciesNb = dCert->extCertPoliciesNb;
        }
    #endif /* WOLFSSL_CERT_EXT */
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
#ifdef OPENSSL_ALL
    if (dCert->extSubjAltNameSrc != NULL && dCert->extSubjAltNameSz != 0) {
        x509->subjAltNameSrc = (byte*)XMALLOC(dCert->extSubjAltNameSz, x509->heap,
                                         DYNAMIC_TYPE_X509_EXT);
        if (x509->subjAltNameSrc != NULL) {
            XMEMCPY(x509->subjAltNameSrc,
                                 dCert->extSubjAltNameSrc, dCert->extSubjAltNameSz);
            x509->subjAltNameSz = dCert->extSubjAltNameSz;
        }
        else
            ret = MEMORY_E;
    }
#endif
#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
    x509->pkCurveOID = dCert->pkCurveOID;
#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

    return ret;
}

#endif /* KEEP_PEER_CERT || SESSION_CERTS */

#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
     (defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2) && !defined(WOLFSSL_NO_TLS12))
static int ProcessCSR(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                      word32 status_length)
{
    int ret = 0;
    OcspRequest* request;

    #ifdef WOLFSSL_SMALL_STACK
        CertStatus* status;
        OcspEntry* single;
        OcspResponse* response;
    #else
        CertStatus status[1];
        OcspEntry single[1];
        OcspResponse response[1];
    #endif

    WOLFSSL_ENTER("ProcessCSR");

    do {
        #ifdef HAVE_CERTIFICATE_STATUS_REQUEST
            if (ssl->status_request) {
                request = (OcspRequest*)TLSX_CSR_GetRequest(ssl->extensions);
                ssl->status_request = 0;
                break;
            }
        #endif

        #ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
            if (ssl->status_request_v2) {
                request = (OcspRequest*)TLSX_CSR2_GetRequest(ssl->extensions,
                                                          WOLFSSL_CSR2_OCSP, 0);
                ssl->status_request_v2 = 0;
                break;
            }
        #endif

        return BUFFER_ERROR;
    } while(0);

    if (request == NULL)
        return BAD_CERTIFICATE_STATUS_ERROR; /* not expected */

    #ifdef WOLFSSL_SMALL_STACK
        status = (CertStatus*)XMALLOC(sizeof(CertStatus), ssl->heap,
                                                    DYNAMIC_TYPE_OCSP_STATUS);
        single = (OcspEntry*)XMALLOC(sizeof(OcspEntry), ssl->heap,
                                                    DYNAMIC_TYPE_OCSP_ENTRY);
        response = (OcspResponse*)XMALLOC(sizeof(OcspResponse), ssl->heap,
                                                    DYNAMIC_TYPE_OCSP_REQUEST);

        if (status == NULL || single == NULL || response == NULL) {
            if (status)
                XFREE(status, ssl->heap, DYNAMIC_TYPE_OCSP_STATUS);
            if (single)
                XFREE(single, ssl->heap, DYNAMIC_TYPE_OCSP_ENTRY);
            if (response)
                XFREE(response, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);

            return MEMORY_ERROR;
        }
    #endif

    InitOcspResponse(response, single, status, input +*inOutIdx, status_length, ssl->heap);

    if (OcspResponseDecode(response, SSL_CM(ssl), ssl->heap, 0) != 0)
        ret = BAD_CERTIFICATE_STATUS_ERROR;
    else if (CompareOcspReqResp(request, response) != 0)
        ret = BAD_CERTIFICATE_STATUS_ERROR;
    else if (response->responseStatus != OCSP_SUCCESSFUL)
        ret = BAD_CERTIFICATE_STATUS_ERROR;
    else if (response->single->status->status == CERT_REVOKED)
        ret = OCSP_CERT_REVOKED;
    else if (response->single->status->status != CERT_GOOD)
        ret = BAD_CERTIFICATE_STATUS_ERROR;

    else {
        XMEMCPY(ssl->ocspProducedDate, response->producedDate, sizeof ssl->ocspProducedDate);
        ssl->ocspProducedDateFormat = response->producedDateFormat;
    }

    *inOutIdx += status_length;

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(status,   ssl->heap, DYNAMIC_TYPE_OCSP_STATUS);
        XFREE(single,   ssl->heap, DYNAMIC_TYPE_OCSP_ENTRY);
        XFREE(response, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);
    #endif

    WOLFSSL_LEAVE("ProcessCSR", ret);
    return ret;
}
#endif



#ifdef HAVE_PK_CALLBACKS

#ifdef HAVE_ECC
    static int SigPkCbEccVerify(const unsigned char* sig, unsigned int sigSz,
       const unsigned char* hash, unsigned int hashSz,
       const unsigned char* keyDer, unsigned int keySz,
       int* result, void* ctx)
    {
        int ret = NOT_COMPILED_IN;
        WOLFSSL* ssl = (WOLFSSL*)ctx;

        if (ssl && ssl->ctx->EccVerifyCb) {
            ret = ssl->ctx->EccVerifyCb(ssl, sig, sigSz, hash, hashSz,
                keyDer, keySz, result, ssl->EccVerifyCtx);
        }
        return ret;
    }
#endif
#ifndef NO_RSA
    static int SigPkCbRsaVerify(unsigned char* sig, unsigned int sigSz,
       unsigned char** out, const unsigned char* keyDer, unsigned int keySz,
       void* ctx)
    {
        int ret = NOT_COMPILED_IN;
        WOLFSSL* ssl = (WOLFSSL*)ctx;

        if (ssl && ssl->ctx->RsaVerifyCb) {
            ret = ssl->ctx->RsaVerifyCb(ssl, sig, sigSz, out, keyDer, keySz,
                ssl->RsaVerifyCtx);
        }
        return ret;
    }
#endif

int InitSigPkCb(WOLFSSL* ssl, SignatureCtx* sigCtx)
{
    if (ssl == NULL || sigCtx == NULL)
        return BAD_FUNC_ARG;

    /* only setup the verify callback if a PK is set */
#ifdef HAVE_ECC
    #if defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_TSIP_TLS)
    sigCtx->pkCbEcc = Renesas_cmn_SigPkCbEccVerify;
    sigCtx->pkCtxEcc = (void*)&sigCtx->CertAtt;
    (void)SigPkCbEccVerify;
    #else
    if (ssl->ctx->EccVerifyCb) {
        sigCtx->pkCbEcc = SigPkCbEccVerify;
        sigCtx->pkCtxEcc = ssl;
    }
    #endif

#endif
#ifndef NO_RSA
    /* only setup the verify callback if a PK is set */
    #if defined(WOLFSSL_RENESAS_SCEPROTECT) || defined(WOLFSSL_RENESAS_TSIP_TLS)
    sigCtx->pkCbRsa = Renesas_cmn_SigPkCbRsaVerify;
    sigCtx->pkCtxRsa = (void*)&sigCtx->CertAtt;
    (void)SigPkCbRsaVerify;
    #else
    if (ssl->ctx->RsaVerifyCb) {
        sigCtx->pkCbRsa = SigPkCbRsaVerify;
        sigCtx->pkCtxRsa = ssl;
    }
    #endif

#endif

    return 0;
}

#endif /* HAVE_PK_CALLBACKS */


#if !defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)
void DoCertFatalAlert(WOLFSSL* ssl, int ret)
{
    int alertWhy;
    if (ssl == NULL || ret == 0) {
        return;
    }
    WOLFSSL_ERROR(ret);

    /* Determine alert reason */
    alertWhy = bad_certificate;
    if (ret == ASN_AFTER_DATE_E || ret == ASN_BEFORE_DATE_E) {
        alertWhy = certificate_expired;
    } else if (ret == ASN_NO_SIGNER_E) {
        alertWhy = unknown_ca;
    }
#if (defined(OPENSSL_ALL) || defined(WOLFSSL_APACHE_HTTPD))
    else if (ret == CRL_CERT_REVOKED) {
        alertWhy = certificate_revoked;
    }
#endif
    else if (ret == NO_PEER_CERT) {
#ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3) {
            alertWhy = certificate_required;
        }
        else
#endif
        {
            alertWhy = handshake_failure;
        }
    }

    /* send fatal alert and mark connection closed */
    SendAlert(ssl, alert_fatal, alertWhy); /* try to send */
    ssl->options.isClosed = 1;
}

/* WOLFSSL_ALWAYS_VERIFY_CB: Use verify callback for success or failure cases */
/* WOLFSSL_VERIFY_CB_ALL_CERTS: Issue callback for all intermediate certificates */

/* Callback is issued for certificate presented in TLS Certificate (11) packet.
 * The intermediates are done first then peer leaf cert last. Use the
 * store->error_depth member to determine index (0=peer, >1 intermediates)
 */

int DoVerifyCallback(WOLFSSL_CERT_MANAGER* cm, WOLFSSL* ssl, int ret,
                                                        ProcPeerCertArgs* args)
{
    int verify_ok = 0, use_cb = 0;
    void *heap;

    if (cm == NULL) {
        return BAD_FUNC_ARG;
    }

    heap = (ssl != NULL) ? ssl->heap : cm->heap;

    /* Determine if verify was okay */
    if (ret == 0) {
        verify_ok = 1;
    }

    /* Determine if verify callback should be used */
    if (ret != 0) {
        if ((ssl != NULL) && (!ssl->options.verifyNone)) {
            use_cb = 1; /* always report errors */
        }
    }
#ifdef WOLFSSL_ALWAYS_VERIFY_CB
    /* always use verify callback on peer leaf cert */
    if (args->certIdx == 0) {
        use_cb = 1;
    }
#endif
#ifdef WOLFSSL_VERIFY_CB_ALL_CERTS
    /* perform verify callback on other intermediate certs (not just peer) */
    if (args->certIdx > 0) {
        use_cb = 1;
    }
#endif
#if defined(OPENSSL_EXTRA)
    /* Perform domain and IP check only for the leaf certificate */
    if (args->certIdx == 0) {
        /* perform domain name check on the peer certificate */
        if (args->dCertInit && args->dCert && (ssl != NULL) &&
                ssl->param && ssl->param->hostName[0]) {
            /* If altNames names is present, then subject common name is ignored */
            if (args->dCert->altNames != NULL) {
                if (CheckForAltNames(args->dCert, ssl->param->hostName, NULL) != 1) {
                    if (ret == 0) {
                        ret = DOMAIN_NAME_MISMATCH;
                        WOLFSSL_ERROR_VERBOSE(ret);
                    }
                }
            }
        #ifndef WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY
            else {
                if (args->dCert->subjectCN) {
                    if (MatchDomainName(args->dCert->subjectCN,
                                        args->dCert->subjectCNLen,
                                        ssl->param->hostName) == 0) {
                        if (ret == 0) {
                            ret = DOMAIN_NAME_MISMATCH;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                    }
                }
            }
        #else
            else {
                if (ret == 0) {
                    ret = DOMAIN_NAME_MISMATCH;
                    WOLFSSL_ERROR_VERBOSE(ret);
                }
            }
        #endif /* !WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY */
        }

        /* perform IP address check on the peer certificate */
        if ((args->dCertInit != 0) && (args->dCert != NULL) && (ssl != NULL) &&
            (ssl->param != NULL) && (XSTRLEN(ssl->param->ipasc) > 0)) {
            if (CheckIPAddr(args->dCert, ssl->param->ipasc) != 0) {
                if (ret == 0) {
                    ret = IPADDR_MISMATCH;
                    WOLFSSL_ERROR_VERBOSE(ret);
                }
            }
        }
    }
#endif
    /* if verify callback has been set */
    if ((use_cb && (ssl != NULL) && ((ssl->verifyCallback != NULL)
    #ifdef OPENSSL_ALL
        || (ssl->ctx->verifyCertCb != NULL)
    #endif
        ))
    #ifndef NO_WOLFSSL_CM_VERIFY
        || (cm->verifyCallback != NULL)
    #endif
        ) {
        int verifyFail = 0;
    #ifdef WOLFSSL_SMALL_STACK
        WOLFSSL_X509_STORE_CTX* store;
        #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        WOLFSSL_X509* x509;
        #endif
        char* domain = NULL;
    #else
        WOLFSSL_X509_STORE_CTX store[1];
        #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        WOLFSSL_X509           x509[1];
        #endif
        char domain[ASN_NAME_MAX];
    #endif
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        int x509Free = 0;
    #endif

    #ifdef WOLFSSL_SMALL_STACK
        store = (WOLFSSL_X509_STORE_CTX*)XMALLOC(
            sizeof(WOLFSSL_X509_STORE_CTX), heap, DYNAMIC_TYPE_X509_STORE);
        if (store == NULL) {
            return MEMORY_E;
        }
        #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        x509 = (WOLFSSL_X509*)XMALLOC(sizeof(WOLFSSL_X509), heap,
            DYNAMIC_TYPE_X509);
        if (x509 == NULL) {
            XFREE(store, heap, DYNAMIC_TYPE_X509_STORE);
            return MEMORY_E;
        }
        #endif
        domain = (char*)XMALLOC(ASN_NAME_MAX, heap, DYNAMIC_TYPE_STRING);
        if (domain == NULL) {
            XFREE(store, heap, DYNAMIC_TYPE_X509_STORE);
            #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
            XFREE(x509, heap, DYNAMIC_TYPE_X509);
            #endif
            return MEMORY_E;
        }
    #endif /* WOLFSSL_SMALL_STACK */

        XMEMSET(store, 0, sizeof(WOLFSSL_X509_STORE_CTX));
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        XMEMSET(x509, 0, sizeof(WOLFSSL_X509));
    #endif
        domain[0] = '\0';

        /* build subject CN as string to return in store */
        if (args->dCertInit && args->dCert && args->dCert->subjectCN) {
            int subjectCNLen = args->dCert->subjectCNLen;
            if (subjectCNLen > ASN_NAME_MAX-1)
                subjectCNLen = ASN_NAME_MAX-1;
            if (subjectCNLen > 0) {
                XMEMCPY(domain, args->dCert->subjectCN, subjectCNLen);
                domain[subjectCNLen] = '\0';
            }
        }

#ifndef OPENSSL_COMPATIBLE_DEFAULTS
        store->error = ret;
#else
        store->error = GetX509Error(ret);
#endif
        store->error_depth = args->certIdx;
        store->discardSessionCerts = 0;
        store->domain = domain;
        if (ssl != NULL) {
            if (ssl->verifyCbCtx != NULL) {
                /* Use the WOLFSSL user context if set */
                store->userCtx = ssl->verifyCbCtx;
            }
            else {
                /* Else use the WOLFSSL_CTX user context */
                store->userCtx = ssl->ctx->verifyCbCtx;
            }
        }
        else {
            store->userCtx = cm;
        }
        store->certs = args->certs;
        store->totalCerts = args->totalCerts;
    #if defined(HAVE_EX_DATA) && \
        (defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL))
        if (wolfSSL_CRYPTO_set_ex_data(&store->ex_data, 0, ssl)
                != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("Failed to store ssl context in WOLFSSL_X509_STORE_CTX");
        }
    #endif

        if (ssl != NULL) {
    #if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
            store->store = SSL_STORE(ssl);
    #if defined(OPENSSL_EXTRA)
            store->depth = args->count;
            store->param = (WOLFSSL_X509_VERIFY_PARAM*)XMALLOC(
                            sizeof(WOLFSSL_X509_VERIFY_PARAM),
                            heap, DYNAMIC_TYPE_OPENSSL);
            if (store->param == NULL) {
        #ifdef WOLFSSL_SMALL_STACK
                XFREE(domain, heap, DYNAMIC_TYPE_STRING);
            #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                XFREE(x509, heap, DYNAMIC_TYPE_X509);
            #endif
                XFREE(store, heap, DYNAMIC_TYPE_X509_STORE);
        #endif
                return MEMORY_E;
            }
            XMEMSET(store->param, 0, sizeof(WOLFSSL_X509_VERIFY_PARAM));
            /* Overwrite with non-default param values in SSL */
            if (ssl->param) {
                if (ssl->param->check_time)
                    store->param->check_time = ssl->param->check_time;

                if (ssl->param->flags)
                    store->param->flags = ssl->param->flags;

                if (ssl->param->hostName[0])
                    XMEMCPY(store->param->hostName, ssl->param->hostName,
                            WOLFSSL_HOST_NAME_MAX);

            }
    #endif /* defined(OPENSSL_EXTRA) */
    #endif /* defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)*/
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        #ifdef KEEP_PEER_CERT
            if (args->certIdx == 0) {
                store->current_cert = &ssl->peerCert; /* use existing X509 */
            }
            else
        #endif
            {
                InitX509(x509, 0, heap);
                if (CopyDecodedToX509(x509, args->dCert) == 0) {
                    store->current_cert = x509;
                    x509Free = 1;
                }
                else {
                    FreeX509(x509);
                }
            }
    #endif
    #ifdef SESSION_CERTS
            store->sesChain = &ssl->session->chain;
    #endif
        }
    #ifndef NO_WOLFSSL_CM_VERIFY
        /* non-zero return code indicates failure override */
        if (cm->verifyCallback != NULL) {
            store->userCtx = cm;
            if (cm->verifyCallback(verify_ok, store)) {
                if (ret != 0) {
                    WOLFSSL_MSG("Verify CM callback overriding error!");
                    ret = 0;
                }
            }
            else {
                verifyFail = 1;
            }
        }
    #endif

        if (ssl != NULL) {
    #ifdef OPENSSL_ALL
            /* non-zero return code indicates failure override */
            if (ssl->ctx->verifyCertCb) {
                if (ssl->ctx->verifyCertCb(store, ssl->ctx->verifyCertCbArg)) {
                    if (ret != 0) {
                        WOLFSSL_MSG("Verify Cert callback overriding error!");
                        ret = 0;
                    }
                }
                else {
                    verifyFail = 1;
                }
            }
    #endif

            /* non-zero return code indicates failure override */
            if (ssl->verifyCallback) {
                if (ssl->verifyCallback(verify_ok, store)) {
                    if (ret != 0) {
                        WOLFSSL_MSG("Verify callback overriding error!");
                        ret = 0;
                    }
                }
                else {
                    verifyFail = 1;
                }
            }
        }

        if (verifyFail) {
            /* induce error if one not present */
            if (ret == 0) {
                ret = VERIFY_CERT_ERROR;
                WOLFSSL_ERROR_VERBOSE(ret);
            }

            /* mark as verify error */
            args->verifyErr = 1;
        }
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        if (x509Free) {
            FreeX509(x509);
        }
    #endif
    #if defined(SESSION_CERTS) && defined(OPENSSL_EXTRA)
        wolfSSL_sk_X509_pop_free(store->chain, NULL);
        store->chain = NULL;
    #endif
    #ifdef SESSION_CERTS
        if ((ssl != NULL) && (store->discardSessionCerts)) {
            WOLFSSL_MSG("Verify callback requested discard sess certs");
            ssl->session->chain.count = 0;
        #ifdef WOLFSSL_ALT_CERT_CHAINS
            ssl->session->altChain.count = 0;
        #endif
        }
    #endif /* SESSION_CERTS */
#ifdef OPENSSL_EXTRA
        if ((ssl != NULL) && (store->param)) {
            XFREE(store->param, heap, DYNAMIC_TYPE_OPENSSL);
        }
#endif
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(domain, heap, DYNAMIC_TYPE_STRING);
        #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        XFREE(x509, heap, DYNAMIC_TYPE_X509);
        #endif
        XFREE(store, heap, DYNAMIC_TYPE_X509_STORE);
    #endif
    }

    (void)heap;

    return ret;
}

static void FreeProcPeerCertArgs(WOLFSSL* ssl, void* pArgs)
{
    ProcPeerCertArgs* args = (ProcPeerCertArgs*)pArgs;

    (void)ssl;

    if (args->certs) {
        XFREE(args->certs, ssl->heap, DYNAMIC_TYPE_DER);
        args->certs = NULL;
    }
#ifdef WOLFSSL_TLS13
    if (args->exts) {
        XFREE(args->exts, ssl->heap, DYNAMIC_TYPE_CERT_EXT);
        args->exts = NULL;
    }
#endif
    if (args->dCert) {
        if (args->dCertInit) {
            FreeDecodedCert(args->dCert);
            args->dCertInit = 0;
        }
        XFREE(args->dCert, ssl->heap, DYNAMIC_TYPE_DCERT);
        args->dCert = NULL;
    }
}
#if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
/* load certificate file which has the form <hash>.(r)N[0..N]       */
/* in the folder.                                                   */
/* (r), in the case of CRL file                                     */
/* @param store  a pointer to X509_STORE structure                  */
/* @param issuer a pointer to X509_NAME that presents an issuer     */
/* @param type   X509_LU_X509 or X509_LU_CRL                        */
/* @return WOLFSSL_SUCCESS on successful, otherwise WOLFSSL_FAILURE */
int LoadCertByIssuer(WOLFSSL_X509_STORE* store, X509_NAME* issuer, int type)
{
    const int MAX_SUFFIX = 10;/* The number comes from CA_TABLE_SIZE=10 */
    int ret = WOLFSSL_SUCCESS;
    WOLFSSL_X509_LOOKUP* lookup;
    WOLFSSL_BY_DIR_entry* entry;
    WOLFSSL_BY_DIR_HASH   hash_tmp;
    WOLFSSL_BY_DIR_HASH*  ph = NULL;
    WOLFSSL_X509* x509;
    unsigned long hash = 0;
    char*   filename = NULL;
    const char* post = "";
    byte*   pbuf = NULL;
    int     len, num, i, idx;
    int    suffix = 0;
    int retHash = NOT_COMPILED_IN;
    byte dgt[WC_MAX_DIGEST_SIZE];

    WOLFSSL_ENTER("LoadCertByIssuer");

    /* sanity check */
    if (store == NULL || issuer == NULL || (type != X509_LU_X509 && type != X509_LU_CRL)) {
        return WOLFSSL_FAILURE;
    }
    lookup = &store->lookup;
    if (lookup->dirs == NULL || lookup->type != 1) {
        return WOLFSSL_FAILURE;
    }

    len = wolfSSL_i2d_X509_NAME_canon(issuer, &pbuf);
    if (len > 0) {
        #ifndef NO_SHA
        retHash = wc_ShaHash((const byte*)pbuf, len, dgt);
        #endif
        if (retHash == 0) {
            /* 4 bytes in little endian as unsigned long */
            hash = (((unsigned long)dgt[3] << 24) |
                    ((unsigned long)dgt[2] << 16) |
                    ((unsigned long)dgt[1] <<  8) |
                    ((unsigned long)dgt[0]));
        } else {
            WOLFSSL_MSG("failed hash operation");
            return WOLFSSL_FAILURE;
        }
        wolfSSL_OPENSSL_free(pbuf);
    }

    /* try to load each hashed name file in path */
#if !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)

    if (type == X509_LU_CRL) {
        post = "r";
    }

    num = wolfSSL_sk_BY_DIR_entry_num(lookup->dirs->dir_entry);

    for (i=0; i<num; i++) {

        entry = wolfSSL_sk_BY_DIR_entry_value(lookup->dirs->dir_entry, i);

        if (type == X509_LU_CRL && entry->hashes != NULL &&
            wolfSSL_sk_BY_DIR_HASH_num(entry->hashes) > 0) {
            /* lock the list */
            if (wc_LockMutex(&lookup->dirs->lock) != 0) {
                WOLFSSL_MSG("wc_LockMutex cdir Lock error");
                return BAD_MUTEX_E;
            }

            hash_tmp.hash_value = hash;
            idx = wolfSSL_sk_BY_DIR_HASH_find(entry->hashes, &hash_tmp);
            if (idx >= 0) {
                WOLFSSL_MSG("find hashed CRL in list");
                ph = wolfSSL_sk_BY_DIR_HASH_value(entry->hashes, idx);
                suffix = ph->last_suffix;
            } else {
                ph = NULL;
                suffix = 0;
            }

            wc_UnLockMutex(&lookup->dirs->lock);
        }

        /* Additional buffer length for file name memory allocation :   */
        /* / <hashvalue>.(r)N\0                                         */
        /*|1|     8    |1|1|1|1|           => 13                        */
        len = (int)XSTRLEN(entry->dir_name) + 13;
        if (filename != NULL) {
            XFREE(filename, NULL, DYNAMIC_TYPE_OPENSSL);
        }

        filename = (char*)XMALLOC(len, NULL, DYNAMIC_TYPE_OPENSSL);
        if (filename == NULL) {
            WOLFSSL_MSG("memory allocation error");
            return MEMORY_E;
        }

        /* set as FAILURE, if successfully loading cert of CRL, this becomes */
        /* WOLFSSL_SUCCESS                                                  */
        ret = WOLFSSL_FAILURE;

        for (; suffix < MAX_SUFFIX; suffix++) {
            /* /folder-path/<hash>.(r)N[0..9] */
            if (XSNPRINTF(filename, len, "%s/%08lx.%s%d", entry->dir_name,
                                                       hash, post, suffix)
                >= len)
            {
                WOLFSSL_MSG("buffer overrun in LoadCertByIssuer");
                ret = BUFFER_E;
                break;
            }

            if(wc_FileExists(filename) == 0/*0 file exists */) {

                if (type == X509_LU_X509) {
                    x509 = wolfSSL_X509_load_certificate_file(filename,
                                                        WOLFSSL_FILETYPE_PEM);
                    if (x509 != NULL) {
                       ret = wolfSSL_X509_STORE_add_cert(store, x509);
                       wolfSSL_X509_free(x509);
                    } else {
                       WOLFSSL_MSG("failed to load certificate");
                       ret = WOLFSSL_FAILURE;
                       break;
                    }
                }
                else if (type == X509_LU_CRL) {
#if defined(HAVE_CRL)
                    ret = wolfSSL_X509_load_crl_file(&store->lookup, filename,
                                                     entry->dir_type);
                    if (ret != WOLFSSL_SUCCESS) {
                        WOLFSSL_MSG("failed to load CRL");
                        break;
                    }
#else
                    WOLFSSL_MSG("CRL is not supported");
                    ret = WOLFSSL_FAILURE;
                    break;
#endif /* HAVE_CRL  */
                }
            } else
                break;
        }

        if (ret != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG("not found file");
            ret = WOLFSSL_FAILURE;
        } else {
            if (type == X509_LU_CRL) {
                if (wc_LockMutex(&lookup->dirs->lock) != 0) {
                    WOLFSSL_MSG("wc_LockMutex cdir Lock error");
                    XFREE(filename, NULL, DYNAMIC_TYPE_OPENSSL);
                    WOLFSSL_ERROR_VERBOSE(BAD_MUTEX_E);
                    return BAD_MUTEX_E;
                }
                if (ph == NULL) {
                    ph = wolfSSL_BY_DIR_HASH_new();
                    if (ph == NULL) {
                        WOLFSSL_MSG("failed to allocate hash stack");
                        ret = WOLFSSL_FAILURE;
                    } else {
                        ph->hash_value = hash;
                        ph->last_suffix = suffix;

                        ret = wolfSSL_sk_BY_DIR_HASH_push(entry->hashes, ph);
                    }
                }
                wc_UnLockMutex(&lookup->dirs->lock);
            }
        }

        XFREE(filename, NULL, DYNAMIC_TYPE_OPENSSL);
    }
#else
    (void) type;
    (void) ret;
    (void) x509;
    (void) filename;
    (void) suffix;
    (void) num;
    (void) i;
    ret = WOLFSSL_NOT_IMPLEMENTED;
#endif
    WOLFSSL_LEAVE("LoadCertByIssuer", ret);

    return ret;
}
#endif


static int ProcessPeerCertParse(WOLFSSL* ssl, ProcPeerCertArgs* args,
    int certType, int verify, byte** pSubjectHash, int* pAlreadySigner)
{
    int ret = 0;
    buffer* cert;
    byte* subjectHash = NULL;
    int alreadySigner = 0;
#ifdef WOLFSSL_SMALL_CERT_VERIFY
    int sigRet = 0;
#endif

    if (ssl == NULL || args == NULL
    #ifndef WOLFSSL_SMALL_CERT_VERIFY
        || args->dCert == NULL
    #endif
    ) {
        return BAD_FUNC_ARG;
    }

    /* check to make sure certificate index is valid */
    if (args->certIdx > args->count)
        return BUFFER_E;

    /* check if returning from non-blocking OCSP */
    /* skip this section because cert is already initialized and parsed */
#ifdef WOLFSSL_NONBLOCK_OCSP
    if (args->lastErr == OCSP_WANT_READ) {
        args->lastErr = 0; /* clear error */
        return 0;
    }
#endif

#ifdef WOLFSSL_TRUST_PEER_CERT
    /* we have trusted peer */
    if (args->haveTrustPeer) {
        return 0;
    }
#endif

    /* get certificate buffer */
    cert = &args->certs[args->certIdx];

#ifdef WOLFSSL_SMALL_CERT_VERIFY
    if (verify == VERIFY) {
        /* for small cert verify, release decoded cert during signature check to
            reduce peak memory usage */
        if (args->dCert != NULL) {
            if (args->dCertInit) {
                FreeDecodedCert(args->dCert);
                args->dCertInit = 0;
            }
            XFREE(args->dCert, ssl->heap, DYNAMIC_TYPE_DCERT);
            args->dCert = NULL;
        }

        /* perform cert parsing and signature check */
        sigRet = CheckCertSignature(cert->buffer, cert->length,
                                         ssl->heap, SSL_CM(ssl));
        /* fail on errors here after the ParseCertRelative call, so dCert is populated */

        /* verify name only in ParseCertRelative below, signature check done */
        verify = VERIFY_NAME;
    }
#endif /* WOLFSSL_SMALL_CERT_VERIFY */

    /* make sure the decoded cert structure is allocated and initialized */
    if (!args->dCertInit
    #ifdef WOLFSSL_SMALL_CERT_VERIFY
        || args->dCert == NULL
    #endif
    ) {
    #ifdef WOLFSSL_SMALL_CERT_VERIFY
        if (args->dCert == NULL) {
            args->dCert = (DecodedCert*)XMALLOC(
                                 sizeof(DecodedCert), ssl->heap,
                                 DYNAMIC_TYPE_DCERT);
            if (args->dCert == NULL) {
                return MEMORY_E;
            }
        }
    #endif

        InitDecodedCert(args->dCert, cert->buffer, cert->length, ssl->heap);

        args->dCertInit = 1;
        args->dCert->sigCtx.devId = ssl->devId;
    #ifdef WOLFSSL_ASYNC_CRYPT
        args->dCert->sigCtx.asyncCtx = ssl;
    #endif

    #ifdef HAVE_PK_CALLBACKS
        /* setup the PK callback context */
        ret = InitSigPkCb(ssl, &args->dCert->sigCtx);
        if (ret != 0)
            return ret;
    #endif
    }

    /* Parse Certificate */
    ret = ParseCertRelative(args->dCert, certType, verify, SSL_CM(ssl));
    /* perform below checks for date failure cases */
    if (ret == 0 || ret == ASN_BEFORE_DATE_E || ret == ASN_AFTER_DATE_E) {
        /* get subject and determine if already loaded */
    #ifndef NO_SKID
        if (args->dCert->extAuthKeyIdSet)
            subjectHash = args->dCert->extSubjKeyId;
        else
    #endif
            subjectHash = args->dCert->subjectHash;
        alreadySigner = AlreadySigner(SSL_CM(ssl), subjectHash);
    }

#ifdef WOLFSSL_SMALL_CERT_VERIFY
    /* get signature check failures from above */
    if (ret == 0)
        ret = sigRet;
#endif

    if (pSubjectHash)
        *pSubjectHash = subjectHash;
    if (pAlreadySigner)
        *pAlreadySigner = alreadySigner;

#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        ret = wolfSSL_AsyncPush(ssl,
            args->dCert->sigCtx.asyncDev);
    }
#endif

#if defined(WOLFSSL_PUBLIC_ASN) && defined(HAVE_PK_CALLBACKS)
    /* This block gives the callback a chance to process the peer cert.
     * If there is no callback set or it returns NOT_COMPILED_IN, then the
     * original return code is returned. */
    if (ssl->ctx && ssl->ctx->ProcessPeerCertCb) {
        int new_ret = ssl->ctx->ProcessPeerCertCb(ssl, args->dCert);
        if (new_ret != NOT_COMPILED_IN) {
            ret = new_ret;
        }
    }
#endif /* WOLFSSL_PUBLIC_ASN && HAVE_PK_CALLBACKS */

    return ret;
}

/* Check key sizes for certs. Is redundant check since
   ProcessBuffer also performs this check. */
static int ProcessPeerCertCheckKey(WOLFSSL* ssl, ProcPeerCertArgs* args)
{
    int ret = 0;

    if (ssl->options.verifyNone) {
        return ret;
    }

    switch (args->dCert->keyOID) {
    #ifndef NO_RSA
        #ifdef WC_RSA_PSS
        case RSAPSSk:
        #endif
        case RSAk:
            if (ssl->options.minRsaKeySz < 0 ||
                    args->dCert->pubKeySize <
                     (word16)ssl->options.minRsaKeySz) {
                WOLFSSL_MSG(
                    "RSA key size in cert chain error");
                ret = RSA_KEY_SIZE_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
            break;
    #endif /* !NO_RSA */
    #ifdef HAVE_ECC
        case ECDSAk:
            if (ssl->options.minEccKeySz < 0 ||
                    args->dCert->pubKeySize <
                     (word16)ssl->options.minEccKeySz) {
                WOLFSSL_MSG(
                    "ECC key size in cert chain error");
                ret = ECC_KEY_SIZE_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
            break;
    #endif /* HAVE_ECC */
    #ifdef HAVE_ED25519
        case ED25519k:
            if (ssl->options.minEccKeySz < 0 ||
                    ED25519_KEY_SIZE < (word16)ssl->options.minEccKeySz) {
                WOLFSSL_MSG(
                    "ECC key size in cert chain error");
                ret = ECC_KEY_SIZE_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
            break;
    #endif /* HAVE_ED25519 */
    #ifdef HAVE_ED448
        case ED448k:
            if (ssl->options.minEccKeySz < 0 ||
                    ED448_KEY_SIZE < (word16)ssl->options.minEccKeySz) {
                WOLFSSL_MSG(
                    "ECC key size in cert chain error");
                ret = ECC_KEY_SIZE_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
            break;
    #endif /* HAVE_ED448 */
    #if defined(HAVE_PQC)
    #if defined(HAVE_FALCON)
        case FALCON_LEVEL1k:
            if (ssl->options.minFalconKeySz < 0 ||
                FALCON_LEVEL1_KEY_SIZE < (word16)ssl->options.minFalconKeySz) {
                WOLFSSL_MSG("Falcon key size in cert chain error");
                ret = FALCON_KEY_SIZE_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
            break;
        case FALCON_LEVEL5k:
            if (ssl->options.minFalconKeySz < 0 ||
                FALCON_LEVEL5_KEY_SIZE < (word16)ssl->options.minFalconKeySz) {
                WOLFSSL_MSG("Falcon key size in cert chain error");
                ret = FALCON_KEY_SIZE_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
            break;
    #endif /* HAVE_FALCON */
    #endif /* HAVE_PQC */
    #if defined(HAVE_DILITHIUM)
        case DILITHIUM_LEVEL2k:
        case DILITHIUM_AES_LEVEL2k:
            if (ssl->options.minDilithiumKeySz < 0 ||
                DILITHIUM_LEVEL2_KEY_SIZE
                < (word16)ssl->options.minDilithiumKeySz) {
                WOLFSSL_MSG("Dilithium key size in cert chain error");
                ret = DILITHIUM_KEY_SIZE_E;
            }
            break;
        case DILITHIUM_LEVEL3k:
        case DILITHIUM_AES_LEVEL3k:
            if (ssl->options.minDilithiumKeySz < 0 ||
                DILITHIUM_LEVEL3_KEY_SIZE
                < (word16)ssl->options.minDilithiumKeySz) {
                WOLFSSL_MSG( "Dilithium key size in cert chain error");
                ret = DILITHIUM_KEY_SIZE_E;
            }
            break;
        case DILITHIUM_LEVEL5k:
        case DILITHIUM_AES_LEVEL5k:
            if (ssl->options.minDilithiumKeySz < 0 ||
                DILITHIUM_LEVEL5_KEY_SIZE
                < (word16)ssl->options.minDilithiumKeySz) {
                WOLFSSL_MSG("Dilithium key size in cert chain error");
                ret = DILITHIUM_KEY_SIZE_E;
            }
            break;
    #endif /* HAVE_DILITHIUM */
        default:
            WOLFSSL_MSG("Key size not checked");
            /* key not being checked for size if not in
               switch */
            break;
    }

    return ret;
}

int ProcessPeerCerts(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                     word32 totalSz)
{
    int ret = 0;
#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
    ProcPeerCertArgs* args = NULL;
    WOLFSSL_ASSERT_SIZEOF_GE(ssl->async->args, *args);
#elif defined(WOLFSSL_SMALL_STACK)
    ProcPeerCertArgs* args = NULL;
#else
    ProcPeerCertArgs  args[1];
#endif
    byte* subjectHash = NULL;
    int alreadySigner = 0;

    WOLFSSL_ENTER("ProcessPeerCerts");

#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
    if (ssl->async == NULL) {
        ssl->async = (struct WOLFSSL_ASYNC*)
                XMALLOC(sizeof(struct WOLFSSL_ASYNC), ssl->heap,
                        DYNAMIC_TYPE_ASYNC);
        if (ssl->async == NULL)
            ERROR_OUT(MEMORY_E, exit_ppc);
    }
    args = (ProcPeerCertArgs*)ssl->async->args;
#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
    if (ret != WC_NOT_PENDING_E) {
        /* Check for error */
        if (ret < 0)
            goto exit_ppc;
    }
    else
#endif /* WOLFSSL_ASYNC_CRYPT */
#ifdef WOLFSSL_NONBLOCK_OCSP
    if (ssl->error == OCSP_WANT_READ) {
        /* Re-entry after non-blocking OCSP */
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* if async operationg not pending, reset error code */
        if (ret == WC_NOT_PENDING_E)
            ret = 0;
    #endif
    }
    else
#endif /* WOLFSSL_NONBLOCK_OCSP */
#elif defined(WOLFSSL_SMALL_STACK)
    args = (ProcPeerCertArgs*)XMALLOC(
        sizeof(ProcPeerCertArgs), ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (args == NULL) {
        ERROR_OUT(MEMORY_E, exit_ppc);
    }
#endif /* WOLFSSL_ASYNC_CRYPT || WOLFSSL_NONBLOCK_OCSP */
    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(ProcPeerCertArgs));
        args->idx = *inOutIdx;
        args->begin = *inOutIdx;
    #if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
        ssl->async->freeArgs = FreeProcPeerCertArgs;
    #endif
    }

    switch (ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
            word32 listSz;

        #ifdef WOLFSSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName(ssl, "Certificate");
            if (ssl->toInfoOn)
                AddLateName("Certificate", &ssl->timeoutInfo);
        #endif

        #ifdef WOLFSSL_TLS13
            if (ssl->options.tls1_3) {
                byte ctxSz;

                /* Certificate Request Context */
                if ((args->idx - args->begin) + OPAQUE8_LEN > totalSz)
                    ERROR_OUT(BUFFER_ERROR, exit_ppc);
                ctxSz = *(input + args->idx);
                args->idx++;
                if ((args->idx - args->begin) + ctxSz > totalSz)
                    ERROR_OUT(BUFFER_ERROR, exit_ppc);
            #ifndef NO_WOLFSSL_CLIENT
                /* Must be empty when received from server. */
                if (ssl->options.side == WOLFSSL_CLIENT_END) {
                    if (ctxSz != 0) {
                        WOLFSSL_ERROR_VERBOSE(INVALID_CERT_CTX_E);
                        ERROR_OUT(INVALID_CERT_CTX_E, exit_ppc);
                    }
                }
            #endif
            #ifndef NO_WOLFSSL_SERVER
                /* Must contain value sent in request. */
                if (ssl->options.side == WOLFSSL_SERVER_END) {
                    if (ssl->options.handShakeState != HANDSHAKE_DONE &&
                                                                   ctxSz != 0) {
                        WOLFSSL_ERROR_VERBOSE(INVALID_CERT_CTX_E);
                        ERROR_OUT(INVALID_CERT_CTX_E, exit_ppc);
                    }
                    else if (ssl->options.handShakeState == HANDSHAKE_DONE) {
                #ifdef WOLFSSL_POST_HANDSHAKE_AUTH
                         CertReqCtx* curr = ssl->certReqCtx;
                         CertReqCtx* prev = NULL;
                         while (curr != NULL) {
                             if ((ctxSz == curr->len) &&
                                 XMEMCMP(&curr->ctx, input + args->idx, ctxSz)
                                                                         == 0) {
                                     if (prev != NULL)
                                         prev->next = curr->next;
                                     else
                                         ssl->certReqCtx = curr->next;
                                     XFREE(curr, ssl->heap,
                                           DYNAMIC_TYPE_TMP_BUFFER);
                                     break;
                             }
                             prev = curr;
                             curr = curr->next;
                        }
                        if (curr == NULL)
                #endif
                        {
                            WOLFSSL_ERROR_VERBOSE(INVALID_CERT_CTX_E);
                            ERROR_OUT(INVALID_CERT_CTX_E, exit_ppc);
                        }
                    }
                }
            #endif
                args->idx += ctxSz;

                /* allocate buffer for cert extensions */
                args->exts = (buffer*)XMALLOC(sizeof(buffer) *
                     MAX_CHAIN_DEPTH, ssl->heap, DYNAMIC_TYPE_CERT_EXT);
                if (args->exts == NULL) {
                    ERROR_OUT(MEMORY_E, exit_ppc);
                }
            }
        #endif

            /* allocate buffer for certs */
            args->certs = (buffer*)XMALLOC(sizeof(buffer) * MAX_CHAIN_DEPTH,
                                            ssl->heap, DYNAMIC_TYPE_DER);
            if (args->certs == NULL) {
                ERROR_OUT(MEMORY_E, exit_ppc);
            }
            XMEMSET(args->certs, 0, sizeof(buffer) * MAX_CHAIN_DEPTH);

            /* Certificate List */
            if ((args->idx - args->begin) + OPAQUE24_LEN > totalSz) {
                ERROR_OUT(BUFFER_ERROR, exit_ppc);
            }
            c24to32(input + args->idx, &listSz);
            args->idx += OPAQUE24_LEN;
            if (listSz > MAX_CERTIFICATE_SZ) {
                ERROR_OUT(BUFFER_ERROR, exit_ppc);
            }
            if ((args->idx - args->begin) + listSz != totalSz) {
                ERROR_OUT(BUFFER_ERROR, exit_ppc);
            }

            WOLFSSL_MSG("Loading peer's cert chain");
            /* first put cert chain into buffer so can verify top down
               we're sent bottom up */
            while (listSz) {
                word32 certSz;


            #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                if (args->totalCerts >= MAX_CHAIN_DEPTH) {
                    if (ssl->peerVerifyRet == 0) /* Return first cert error here */
                        ssl->peerVerifyRet = X509_V_ERR_CERT_CHAIN_TOO_LONG;
                    ret = MAX_CHAIN_ERROR;
                    WOLFSSL_ERROR_VERBOSE(ret);
                    WOLFSSL_MSG("Too many certs for MAX_CHAIN_DEPTH");
                    break; /* break out to avoid reading more certs then buffer
                            * can hold */
                }
            #else
                if (args->totalCerts >= ssl->verifyDepth ||
                        args->totalCerts >= MAX_CHAIN_DEPTH) {
                    WOLFSSL_ERROR_VERBOSE(MAX_CHAIN_ERROR);
                    ERROR_OUT(MAX_CHAIN_ERROR, exit_ppc);
                }
            #endif

                if ((args->idx - args->begin) + OPAQUE24_LEN > totalSz) {
                    ERROR_OUT(BUFFER_ERROR, exit_ppc);
                }

                c24to32(input + args->idx, &certSz);
                args->idx += OPAQUE24_LEN;

                if ((args->idx - args->begin) + certSz > totalSz) {
                    ERROR_OUT(BUFFER_ERROR, exit_ppc);
                }

                args->certs[args->totalCerts].length = certSz;
                args->certs[args->totalCerts].buffer = input + args->idx;

            #ifdef SESSION_CERTS
                AddSessionCertToChain(&ssl->session->chain,
                    input + args->idx, certSz);
            #endif /* SESSION_CERTS */

                args->idx += certSz;
                listSz -= certSz + CERT_HEADER_SZ;

            #ifdef WOLFSSL_TLS13
                /* Extensions */
                if (ssl->options.tls1_3) {
                    word16 extSz;

                    if (args->exts == NULL) {
                        ERROR_OUT(BUFFER_ERROR, exit_ppc);
                    }
                    if ((args->idx - args->begin) + OPAQUE16_LEN > totalSz) {
                        ERROR_OUT(BUFFER_ERROR, exit_ppc);
                    }
                    ato16(input + args->idx, &extSz);
                    args->idx += OPAQUE16_LEN;
                    if ((args->idx - args->begin) + extSz > totalSz) {
                        ERROR_OUT(BUFFER_ERROR, exit_ppc);
                    }
                    /* Store extension data info for later processing. */
                    args->exts[args->totalCerts].length = extSz;
                    args->exts[args->totalCerts].buffer = input + args->idx;
                    args->idx += extSz;
                    listSz -= extSz + OPAQUE16_LEN;
                    WOLFSSL_MSG_EX("\tParsing %d bytes of cert extensions",
                            args->exts[args->totalCerts].length);
                    #if !defined(NO_TLS)
                    ret = TLSX_Parse(ssl, args->exts[args->totalCerts].buffer,
                        (word16)args->exts[args->totalCerts].length,
                        certificate, NULL);
                    #endif /* !NO_TLS */
                    if (ret < 0) {
                        WOLFSSL_ERROR_VERBOSE(ret);
                        ERROR_OUT(ret, exit_ppc);
                    }
                }
            #endif

                args->totalCerts++;
                WOLFSSL_MSG("\tPut another cert into chain");
            } /* while (listSz) */

            args->count = args->totalCerts;
            args->certIdx = 0; /* select peer cert (first one) */

            if (args->count == 0) {
                /* Empty certificate message. */
                if ((ssl->options.side == WOLFSSL_SERVER_END) &&
                    (ssl->options.mutualAuth || (ssl->options.failNoCert &&
                                             IsAtLeastTLSv1_3(ssl->version)))) {
                    WOLFSSL_MSG("No peer cert from Client");
                    ret = NO_PEER_CERT;
                    WOLFSSL_ERROR_VERBOSE(ret);
                    DoCertFatalAlert(ssl, ret);
                }
                else if ((ssl->options.side == WOLFSSL_CLIENT_END) &&
                         IsAtLeastTLSv1_3(ssl->version)) {
                    WOLFSSL_MSG("No peer cert from Server");
                    ret = NO_PEER_CERT;
                    WOLFSSL_ERROR_VERBOSE(ret);
                    SendAlert(ssl, alert_fatal, decode_error);
                }
            }

            args->dCertInit = 0;
        #ifndef WOLFSSL_SMALL_CERT_VERIFY
            args->dCert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), ssl->heap,
                                                       DYNAMIC_TYPE_DCERT);
            if (args->dCert == NULL) {
                ERROR_OUT(MEMORY_E, exit_ppc);
            }
            XMEMSET(args->dCert, 0, sizeof(DecodedCert));
        #endif

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;

        case TLS_ASYNC_BUILD:
        {
            if (args->count > 0) {

                /* check for trusted peer and get untrustedDepth */
            #if defined(WOLFSSL_TRUST_PEER_CERT) || defined(OPENSSL_EXTRA)
                if (args->certIdx == 0) {
                #ifdef WOLFSSL_TRUST_PEER_CERT
                    TrustedPeerCert* tp;
                #endif

                    ret = ProcessPeerCertParse(ssl, args, CERT_TYPE, NO_VERIFY,
                        &subjectHash, &alreadySigner);
                    if (ret != 0)
                        goto exit_ppc;

                #ifdef OPENSSL_EXTRA
                    /* Determine untrusted depth */
                    if (!alreadySigner && (!args->dCert ||
                            !args->dCertInit || !args->dCert->selfSigned)) {
                        args->untrustedDepth = 1;
                    }
                #endif

                #ifdef WOLFSSL_TRUST_PEER_CERT
                    tp = GetTrustedPeer(SSL_CM(ssl), args->dCert);
                    WOLFSSL_MSG("Checking for trusted peer cert");

                    if (tp && MatchTrustedPeer(tp, args->dCert)) {
                        WOLFSSL_MSG("Found matching trusted peer cert");
                        args->haveTrustPeer = 1;
                    }
                    else if (tp == NULL) {
                        /* no trusted peer cert */
                        WOLFSSL_MSG("No matching trusted peer cert. Checking CAs");
                    }
                    else {
                        WOLFSSL_MSG("Trusted peer cert did not match!");
                    }
                    if (!args->haveTrustPeer)
                #endif
                    {
                        /* free cert if not trusted peer */
                        FreeDecodedCert(args->dCert);
                        args->dCertInit = 0;
                    }
                }
            #endif /* WOLFSSL_TRUST_PEER_CERT || OPENSSL_EXTRA */

                /* check certificate up to peer's first */
                /* do not verify chain if trusted peer cert found */
                while (args->count > 1
                #ifdef WOLFSSL_TRUST_PEER_CERT
                    && !args->haveTrustPeer
                #endif /* WOLFSSL_TRUST_PEER_CERT */
                ) {
                    int skipAddCA = 0;

                    /* select last certificate */
                    args->certIdx = args->count - 1;

                    ret = ProcessPeerCertParse(ssl, args, CERT_TYPE,
                        !ssl->options.verifyNone ? VERIFY : NO_VERIFY,
                        &subjectHash, &alreadySigner);
#if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
                    if (ret == ASN_NO_SIGNER_E || ret == ASN_SELF_SIGNED_E) {
                        WOLFSSL_MSG("try to load certificate if hash dir is set");
                        ret = LoadCertByIssuer(SSL_STORE(ssl),
                           (WOLFSSL_X509_NAME*)args->dCert->issuerName,
                                                          X509_LU_X509);
                        if (ret == WOLFSSL_SUCCESS) {
                            FreeDecodedCert(args->dCert);
                            args->dCertInit = 0;
                            /* once again */
                            ret = ProcessPeerCertParse(ssl, args, CERT_TYPE,
                                !ssl->options.verifyNone ? VERIFY : NO_VERIFY,
                                &subjectHash, &alreadySigner);
                        }
                        else {
                            ret = ASN_NO_SIGNER_E;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                    }
#endif
                #ifdef WOLFSSL_ASYNC_CRYPT
                    if (ret == WC_PENDING_E)
                        goto exit_ppc;
                #endif
                    if (ret == 0) {
                        ret = ProcessPeerCertCheckKey(ssl, args);
                    }

                    if (ret == 0 && args->dCert->isCA == 0) {
                        WOLFSSL_MSG("Chain cert is not a CA, not adding as one");
                    }
                    else if (ret == 0 && ssl->options.verifyNone) {
                        WOLFSSL_MSG("Chain cert not verified by option, "
                            "not adding as CA");
                    }
                    else if (ret == 0) {
                    #ifdef OPENSSL_EXTRA
                        if (args->certIdx > args->untrustedDepth) {
                            args->untrustedDepth = (char)args->certIdx + 1;
                        }
                    #endif

                        if (alreadySigner) {
                            WOLFSSL_MSG("Verified CA from chain and already had it");
                        }
                    }
                    else {
                        WOLFSSL_MSG("Failed to verify CA from chain");
                    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                        if (ssl->peerVerifyRet == 0) /* Return first cert error here */
                            ssl->peerVerifyRet = X509_V_ERR_INVALID_CA;
                    #endif
                    }

                    if (ret == 0) {
                #ifdef HAVE_OCSP
                    #ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
                        if (ssl->status_request_v2) {
                            ret = TLSX_CSR2_InitRequests(ssl->extensions,
                                                    args->dCert, 0, ssl->heap);
                        }
                        else /* skips OCSP and force CRL check */
                    #endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */
                        if (SSL_CM(ssl)->ocspEnabled &&
                                            SSL_CM(ssl)->ocspCheckAll) {
                            WOLFSSL_MSG("Doing Non Leaf OCSP check");
                            ret = CheckCertOCSP_ex(SSL_CM(ssl)->ocsp,
                                                    args->dCert, NULL, ssl);
                        #ifdef WOLFSSL_NONBLOCK_OCSP
                            if (ret == OCSP_WANT_READ) {
                                args->lastErr = ret;
                                goto exit_ppc;
                            }
                        #endif
                            if (ret != 0) {
                                WOLFSSL_ERROR_VERBOSE(ret);
                                WOLFSSL_MSG("\tOCSP Lookup not ok");
                            }
                        }
                #endif /* HAVE_OCSP */

                #ifdef HAVE_CRL
                        if (SSL_CM(ssl)->crlEnabled &&
                                SSL_CM(ssl)->crlCheckAll) {
                            int doCrlLookup = 1;

                        #ifdef HAVE_OCSP
                            if (SSL_CM(ssl)->ocspEnabled &&
                                    SSL_CM(ssl)->ocspCheckAll) {
                                /* If the cert status is unknown to the OCSP
                                   responder, do a CRL lookup. If any other
                                   error, skip the CRL lookup and fail the
                                   certificate. */
                                doCrlLookup = (ret == OCSP_CERT_UNKNOWN);
                            }
                        #endif /* HAVE_OCSP */

                            if (doCrlLookup) {
                                WOLFSSL_MSG("Doing Non Leaf CRL check");
                                ret = CheckCertCRL(SSL_CM(ssl)->crl,
                                        args->dCert);
                            #ifdef WOLFSSL_NONBLOCK_OCSP
                                /* The CRL lookup I/O callback is using the
                                 * same WOULD_BLOCK error code as OCSP's I/O
                                 * callback, and it is enabling it using the
                                 * same flag. */
                                if (ret == OCSP_WANT_READ) {
                                    args->lastErr = ret;
                                    goto exit_ppc;
                                }
                            #endif
                                if (ret != 0) {
                                    WOLFSSL_ERROR_VERBOSE(ret);
                                    WOLFSSL_MSG("\tCRL check not ok");
                                }
                            }
                        }
                #endif /* HAVE_CRL */
                    }
            #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                    if (ret == 0 &&
                        /* extend the limit "+1" until reaching
                         * an ultimately trusted issuer.*/
                        args->count > (ssl->verifyDepth + 1)) {
                        if (ssl->peerVerifyRet == 0) /* Return first cert error here */
                            ssl->peerVerifyRet = X509_V_ERR_CERT_CHAIN_TOO_LONG;
                        ret = MAX_CHAIN_ERROR;
                        WOLFSSL_ERROR_VERBOSE(ret);
                    }
            #endif
                #ifdef WOLFSSL_ALT_CERT_CHAINS
                    /* For alternate cert chain, its okay for a CA cert to fail
                        with ASN_NO_SIGNER_E here. The "alternate" certificate
                        chain mode only requires that the peer certificate
                        validate to a trusted CA */
                    if (ret != 0 && args->dCert->isCA) {
                        if (ret == ASN_NO_SIGNER_E || ret == ASN_SELF_SIGNED_E) {
                            if (!ssl->options.usingAltCertChain) {
                                WOLFSSL_MSG("Trying alternate cert chain");
                                ssl->options.usingAltCertChain = 1;
                            }

                            ret = 0; /* clear errors and continue */
                    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                            ssl->peerVerifyRet = 0;
                    #endif
                            args->verifyErr = 0;
                        }

                        /* do not add to certificate manager */
                        skipAddCA = 1;
                    }
                #endif /* WOLFSSL_ALT_CERT_CHAINS */

                    /* Do verify callback */
                    ret = DoVerifyCallback(SSL_CM(ssl), ssl, ret, args);
                    if (ssl->options.verifyNone &&
                              (ret == CRL_MISSING || ret == CRL_CERT_REVOKED ||
                               ret == CRL_CERT_DATE_ERR)) {
                        WOLFSSL_MSG("Ignoring CRL problem based on verify setting");
                        ret = ssl->error = 0;
                    }



                    /* If valid CA then add to Certificate Manager */
                    if (ret == 0 && args->dCert->isCA &&
                            !ssl->options.verifyNone && !skipAddCA) {
                        buffer* cert = &args->certs[args->certIdx];

                        /* Is valid CA */
                    #if defined(SESSION_CERTS) && defined(WOLFSSL_ALT_CERT_CHAINS)
                        /* if using alternate chain, store the cert used */
                        if (ssl->options.usingAltCertChain) {
                            AddSessionCertToChain(&ssl->session->altChain,
                                cert->buffer, cert->length);
                        }
                    #endif /* SESSION_CERTS && WOLFSSL_ALT_CERT_CHAINS */
                        if (!alreadySigner) {
                            DerBuffer* add = NULL;
                            ret = AllocDer(&add, cert->length, CA_TYPE, ssl->heap);
                            if (ret < 0)
                                goto exit_ppc;

                            XMEMCPY(add->buffer, cert->buffer, cert->length);

                            /* CA already verified above in ParseCertRelative */
                            WOLFSSL_MSG("Adding CA from chain");
                            ret = AddCA(SSL_CM(ssl), &add, WOLFSSL_CHAIN_CA,
                                NO_VERIFY);
                            if (ret == WOLFSSL_SUCCESS) {
                                ret = 0;
                            }
                        }
                    }

                    /* Handle error codes */
                    if (ret != 0) {
                        if (!ssl->options.verifyNone) {
                            WOLFSSL_ERROR_VERBOSE(ret);
                            DoCertFatalAlert(ssl, ret);
                        }
                        ssl->error = ret; /* Report SSL error */

                        if (args->lastErr == 0) {
                            args->lastErr = ret; /* save error from last time */
                            ret = 0; /* reset error */
                        }
                    }

                    FreeDecodedCert(args->dCert);
                    args->dCertInit = 0;
                    args->count--;
                } /* while (count > 0 && !args->haveTrustPeer) */
            } /* if (count > 0) */

            /* Check for error */
            if (ret != 0) {
                goto exit_ppc;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */
        FALL_THROUGH;

        case TLS_ASYNC_DO:
        {
            /* peer's, may not have one if blank client cert sent by TLSv1.2 */
            if (args->count > 0) {
                WOLFSSL_MSG("Verifying Peer's cert");

                /* select peer cert (first one) */
                args->certIdx = 0;

                ret = ProcessPeerCertParse(ssl, args, CERT_TYPE,
                        !ssl->options.verifyNone ? VERIFY : NO_VERIFY,
                        &subjectHash, &alreadySigner);
#if defined(OPENSSL_ALL) && defined(WOLFSSL_CERT_GEN) && \
    (defined(WOLFSSL_CERT_REQ) || defined(WOLFSSL_CERT_EXT)) && \
    !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
                    if (ret == ASN_NO_SIGNER_E || ret == ASN_SELF_SIGNED_E) {
                        int lastErr = ret; /* save error from last time */
                        WOLFSSL_MSG("try to load certificate if hash dir is set");
                        ret = LoadCertByIssuer(SSL_STORE(ssl),
                           (WOLFSSL_X509_NAME*)args->dCert->issuerName,
                                                          X509_LU_X509);
                        if (ret == WOLFSSL_SUCCESS) {
                            FreeDecodedCert(args->dCert);
                            args->dCertInit = 0;
                            /* once again */
                            ret = ProcessPeerCertParse(ssl, args, CERT_TYPE,
                                !ssl->options.verifyNone ? VERIFY : NO_VERIFY,
                                &subjectHash, &alreadySigner);
                        }
                        else {
                            ret = lastErr; /* restore error */
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                    }
#endif
            #ifdef WOLFSSL_ASYNC_CRYPT
                if (ret == WC_PENDING_E)
                    goto exit_ppc;
            #endif
                if (ret == 0) {
                    WOLFSSL_MSG("Verified Peer's cert");
                #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                    if (ssl->peerVerifyRet == 0) /* Return first cert error here */
                        ssl->peerVerifyRet = X509_V_OK;
                #endif
                #if defined(SESSION_CERTS) && defined(WOLFSSL_ALT_CERT_CHAINS)
                    /* if using alternate chain, store the cert used */
                    if (ssl->options.usingAltCertChain) {
                        buffer* cert = &args->certs[args->certIdx];
                        AddSessionCertToChain(&ssl->session->altChain,
                            cert->buffer, cert->length);
                    }
                #endif /* SESSION_CERTS && WOLFSSL_ALT_CERT_CHAINS */

                #ifndef OPENSSL_COMPATIBLE_DEFAULTS
                    /* Check peer's certificate version number. TLS 1.2 / 1.3
                     * requires the clients certificate be version 3 unless a
                     * different version has been negotiated using RFC 7250.
                     * OpenSSL doesn't appear to be performing this check.
                     * For TLS 1.3 see RFC8446 Section 4.4.2.3 */
                    if (ssl->options.side == WOLFSSL_SERVER_END) {
                        if (args->dCert->version != WOLFSSL_X509_V3) {
                            WOLFSSL_MSG("Peers certificate was not version 3!");
                            args->lastErr = ASN_VERSION_E;
                            /* setting last error but not considering it fatal
                             * giving the user a chance to override */
                        }
                    }
                #endif

                    /* check if fatal error */
                    if (args->verifyErr) {
                        args->fatal = 1;
                        ret = args->lastErr;
                    }
                    else {
                        args->fatal = 0;
                    }
                }
                else if (ret == ASN_PARSE_E || ret == BUFFER_E) {
                    WOLFSSL_MSG("Got Peer cert ASN PARSE or BUFFER ERROR");
                #if defined(WOLFSSL_EXTRA_ALERTS) || defined(OPENSSL_EXTRA) || \
                                               defined(OPENSSL_EXTRA_X509_SMALL)
                    DoCertFatalAlert(ssl, ret);
                #endif
                #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                    if (ssl->peerVerifyRet == 0) /* Return first cert error here */
                        ssl->peerVerifyRet = X509_V_ERR_CERT_REJECTED;
                #endif
                    args->fatal = 1;
                }
                else {
                    WOLFSSL_MSG("Failed to verify Peer's cert");
                    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                    if (ssl->peerVerifyRet == 0) { /* Return first cert error here */
                        if (ret == ASN_BEFORE_DATE_E) {
                            ssl->peerVerifyRet =
                                   (unsigned long)X509_V_ERR_CERT_NOT_YET_VALID;
                        }
                        else if (ret == ASN_AFTER_DATE_E) {
                            ssl->peerVerifyRet =
                                   (unsigned long)X509_V_ERR_CERT_HAS_EXPIRED;
                        }
                        else {
                            ssl->peerVerifyRet =
                                   (unsigned long)
                                   X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
                        }
                    }
                    #endif
                    if (ssl->verifyCallback) {
                        WOLFSSL_MSG(
                            "\tCallback override available, will continue");
                        /* check if fatal error */
                        args->fatal = (args->verifyErr) ? 1 : 0;
                        if (args->fatal)
                            DoCertFatalAlert(ssl, ret);
                    }
                    else {
                        WOLFSSL_MSG("\tNo callback override available, fatal");
                        args->fatal = 1;
                        DoCertFatalAlert(ssl, ret);
                    }
                }

            #ifdef HAVE_SECURE_RENEGOTIATION
                if (args->fatal == 0 && !IsAtLeastTLSv1_3(ssl->version)
                                     && ssl->secure_renegotiation
                                     && ssl->secure_renegotiation->enabled) {

                    if (IsEncryptionOn(ssl, 0)) {
                        /* compare against previous time */
                        if (ssl->secure_renegotiation->subject_hash_set) {
                            if (XMEMCMP(args->dCert->subjectHash,
                                        ssl->secure_renegotiation->subject_hash,
                                        KEYID_SIZE) != 0) {
                                WOLFSSL_MSG(
                                  "Peer sent different cert during scr, fatal");
                                args->fatal = 1;
                                ret = SCR_DIFFERENT_CERT_E;
                                WOLFSSL_ERROR_VERBOSE(ret);
                            }
                        }
                    }

                    /* cache peer's hash */
                    if (args->fatal == 0) {
                        XMEMCPY(ssl->secure_renegotiation->subject_hash,
                                args->dCert->subjectHash, KEYID_SIZE);
                        ssl->secure_renegotiation->subject_hash_set = 1;
                    }
                }
            #endif /* HAVE_SECURE_RENEGOTIATION */
            } /* if (count > 0) */

            /* Check for error */
            if (args->fatal && ret != 0) {
                goto exit_ppc;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */
        FALL_THROUGH;

        case TLS_ASYNC_VERIFY:
        {
            if (args->count > 0) {
            #if defined(HAVE_OCSP) || defined(HAVE_CRL)
                /* only attempt to check OCSP or CRL if not previous error such
                 * as ASN_BEFORE_DATE_E or ASN_AFTER_DATE_E */
                if (args->fatal == 0 && ret == 0) {
                    int doLookup = 1;

                    WOLFSSL_MSG("Checking if ocsp needed");

                    if (ssl->options.side == WOLFSSL_CLIENT_END) {
                #ifdef HAVE_CERTIFICATE_STATUS_REQUEST
                        if (ssl->status_request) {
                            args->fatal = (TLSX_CSR_InitRequest(ssl->extensions,
                                                args->dCert, ssl->heap) != 0);
                            doLookup = 0;
                            WOLFSSL_MSG("\tHave status request");
                        #if defined(WOLFSSL_TLS13)
                            if (ssl->options.tls1_3) {
                                TLSX* ext = TLSX_Find(ssl->extensions,
                                                           TLSX_STATUS_REQUEST);
                                if (ext != NULL) {
                                    word32 idx = 0;
                                    CertificateStatusRequest* csr =
                                           (CertificateStatusRequest*)ext->data;
                                    ret = ProcessCSR(ssl, csr->response.buffer,
                                                    &idx, csr->response.length);
                                    if (ret < 0) {
                                        WOLFSSL_ERROR_VERBOSE(ret);
                                        goto exit_ppc;
                                    }
                                }
                            }
                        #endif
                        }
                        /* Ensure a stapling response was seen */
                        else if (ssl->options.tls1_3 &&
                                                 SSL_CM(ssl)->ocspMustStaple) {
                             ret = OCSP_CERT_UNKNOWN;
                             goto exit_ppc;
                        }
                #endif /* HAVE_CERTIFICATE_STATUS_REQUEST */
                #ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
                        if (ssl->status_request_v2) {
                            args->fatal = (TLSX_CSR2_InitRequests(ssl->extensions,
                                                 args->dCert, 1, ssl->heap) != 0);
                            doLookup = 0;
                            WOLFSSL_MSG("\tHave status request v2");
                        }
                #endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */
                    }

                #ifdef HAVE_OCSP
                    if (doLookup && SSL_CM(ssl)->ocspEnabled) {
                        WOLFSSL_MSG("Doing Leaf OCSP check");
                        ret = CheckCertOCSP_ex(SSL_CM(ssl)->ocsp,
                                                    args->dCert, NULL, ssl);
                    #ifdef WOLFSSL_NONBLOCK_OCSP
                        if (ret == OCSP_WANT_READ) {
                            goto exit_ppc;
                        }
                    #endif
                        doLookup = (ret == OCSP_CERT_UNKNOWN);
                        if (ret != 0) {
                            WOLFSSL_MSG("\tOCSP Lookup not ok");
                            args->fatal = 0;
                        #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                            if (ssl->peerVerifyRet == 0) {
                                /* Return first cert error here */
                                ssl->peerVerifyRet =
                                        ret == OCSP_CERT_REVOKED
                                            ? X509_V_ERR_CERT_REVOKED
                                            : X509_V_ERR_CERT_REJECTED;
                            }
                        #endif
                        }
                    }
                #endif /* HAVE_OCSP */

                #ifdef HAVE_CRL
                    if (ret == 0 && doLookup && SSL_CM(ssl)->crlEnabled) {
                        WOLFSSL_MSG("Doing Leaf CRL check");
                        ret = CheckCertCRL(SSL_CM(ssl)->crl, args->dCert);
                    #ifdef WOLFSSL_NONBLOCK_OCSP
                        /* The CRL lookup I/O callback is using the
                         * same WOULD_BLOCK error code as OCSP's I/O
                         * callback, and it is enabling it using the
                         * same flag. */
                        if (ret == OCSP_WANT_READ) {
                            goto exit_ppc;
                        }
                    #endif
                        if (ret != 0) {
                            WOLFSSL_MSG("\tCRL check not ok");
                            args->fatal = 0;
                        #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                            if (ssl->peerVerifyRet == 0) {
                                /* Return first cert error here */
                                ssl->peerVerifyRet =
                                        ret == CRL_CERT_REVOKED
                                            ? X509_V_ERR_CERT_REVOKED
                                            : X509_V_ERR_CERT_REJECTED;;
                            }
                        #endif
                        }
                    }
                #endif /* HAVE_CRL */
                    (void)doLookup;
                }
            #endif /* HAVE_OCSP || HAVE_CRL */

            #ifdef KEEP_PEER_CERT
                if (args->fatal == 0) {
                    int copyRet = 0;

                    #ifdef WOLFSSL_POST_HANDSHAKE_AUTH
                        if (ssl->options.handShakeDone) {
                            FreeX509(&ssl->peerCert);
                            InitX509(&ssl->peerCert, 0, ssl->heap);
                        }
                        else
                    #endif
                    #ifdef HAVE_SECURE_RENEGOTIATION
                        if (ssl->secure_renegotiation &&
                                           ssl->secure_renegotiation->enabled) {
                            /* free old peer cert */
                            FreeX509(&ssl->peerCert);
                            InitX509(&ssl->peerCert, 0, ssl->heap);
                        }
                        else
                    #endif
                        {
                        }

                    /* set X509 format for peer cert */
                    copyRet = CopyDecodedToX509(&ssl->peerCert, args->dCert);
                    if (copyRet == MEMORY_E) {
                        args->fatal = 1;
                    }
                }
            #endif /* KEEP_PEER_CERT */

            #ifndef IGNORE_KEY_EXTENSIONS
                #if defined(OPENSSL_EXTRA)
                  /* when compatibility layer is turned on and no verify is
                   * set then ignore the certificate key extension */
                    if (args->dCert->extKeyUsageSet &&
                          args->dCert->extKeyUsageCrit == 0 &&
                          ssl->options.verifyNone) {
                        WOLFSSL_MSG("Not verifying certificate key usage");
                    }
                    else
                #endif
                if (args->dCert->extKeyUsageSet) {
                    if ((ssl->specs.kea == rsa_kea) &&
                        (ssl->options.side == WOLFSSL_CLIENT_END) &&
                        (args->dCert->extKeyUsage & KEYUSE_KEY_ENCIPHER) == 0) {
                        ret = KEYUSE_ENCIPHER_E;
                        WOLFSSL_ERROR_VERBOSE(ret);
                    }
                    if ((ssl->specs.kea != rsa_kea) &&
                        (ssl->specs.sig_algo == rsa_sa_algo ||
                            (ssl->specs.sig_algo == ecc_dsa_sa_algo &&
                                 !ssl->specs.static_ecdh)) &&
                        (args->dCert->extKeyUsage & KEYUSE_DIGITAL_SIG) == 0) {
                        WOLFSSL_MSG("KeyUse Digital Sig not set");
                        ret = KEYUSE_SIGNATURE_E;
                        WOLFSSL_ERROR_VERBOSE(ret);
                    }
                }

                #if defined(OPENSSL_EXTRA)
                    /* when compatibility layer is turned on and no verify is
                     * set then ignore the certificate key extension */
                    if (args->dCert->extExtKeyUsageSet &&
                            args->dCert->extExtKeyUsageCrit == 0 &&
                          ssl->options.verifyNone) {
                                WOLFSSL_MSG("Not verifying certificate ext key usage");
                    }
                    else
                #endif
                if (args->dCert->extExtKeyUsageSet) {
                    if (ssl->options.side == WOLFSSL_CLIENT_END) {
                        if ((args->dCert->extExtKeyUsage &
                                (EXTKEYUSE_ANY | EXTKEYUSE_SERVER_AUTH)) == 0) {
                            WOLFSSL_MSG("ExtKeyUse Server Auth not set");
                            ret = EXTKEYUSE_AUTH_E;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                    }
                    else {
                        if ((args->dCert->extExtKeyUsage &
                                (EXTKEYUSE_ANY | EXTKEYUSE_CLIENT_AUTH)) == 0) {
                            WOLFSSL_MSG("ExtKeyUse Client Auth not set");
                            ret = EXTKEYUSE_AUTH_E;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                    }
                }
            #endif /* IGNORE_KEY_EXTENSIONS */

                if (args->fatal) {
                    ssl->error = ret;
                #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
                    SendAlert(ssl, alert_fatal, bad_certificate);
                    if (ssl->peerVerifyRet == 0) /* Return first cert error here */
                        ssl->peerVerifyRet = X509_V_ERR_CERT_REJECTED;
                #endif
                    goto exit_ppc;
                }

                /* Certificate validated and stored. */
                ssl->options.havePeerCert = 1;
            #if !defined(NO_WOLFSSL_CLIENT) && !defined(NO_RSA)
                if (ssl->options.side == WOLFSSL_CLIENT_END &&
                    ssl->specs.sig_algo == rsa_kea) {
                    /* CLIENT: No ServerKeyExchange message sent by server. */
                    ssl->options.peerAuthGood = 1;
                }
            #endif
            #if !defined(NO_WOLFSSL_CLIENT) && defined(HAVE_ECC)
                if (ssl->options.side == WOLFSSL_CLIENT_END &&
                    ssl->specs.static_ecdh) {
                    /* CLIENT: No ServerKeyExchange message sent by server. */
                    ssl->options.peerAuthGood = 1;
                }
            #endif


                if (!ssl->options.verifyNone && ssl->buffers.domainName.buffer) {
                #ifndef WOLFSSL_ALLOW_NO_CN_IN_SAN
                    /* Per RFC 5280 section 4.2.1.6, "Whenever such identities
                     * are to be bound into a certificate, the subject
                     * alternative name extension MUST be used." */
                    if (args->dCert->altNames) {
                        if (CheckForAltNames(args->dCert,
                                (char*)ssl->buffers.domainName.buffer,
                                NULL) != 1) {
                            WOLFSSL_MSG("DomainName match on alt names failed");
                            /* try to get peer key still */
                            ret = DOMAIN_NAME_MISMATCH;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                    }
                    else {
                        if (MatchDomainName(
                                 args->dCert->subjectCN,
                                 args->dCert->subjectCNLen,
                                 (char*)ssl->buffers.domainName.buffer) == 0) {
                            WOLFSSL_MSG("DomainName match on common name failed");
                            ret = DOMAIN_NAME_MISMATCH;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                    }
                #else /* WOLFSSL_ALL_NO_CN_IN_SAN */
                    /* Old behavior. */
                    if (MatchDomainName(args->dCert->subjectCN,
                                args->dCert->subjectCNLen,
                                (char*)ssl->buffers.domainName.buffer) == 0) {
                        WOLFSSL_MSG("DomainName match on common name failed");
                        if (CheckForAltNames(args->dCert,
                                 (char*)ssl->buffers.domainName.buffer,
                                 NULL) != 1) {
                            WOLFSSL_MSG(
                                "DomainName match on alt names failed too");
                            /* try to get peer key still */
                            ret = DOMAIN_NAME_MISMATCH;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                    }
                #endif /* WOLFSSL_ALL_NO_CN_IN_SAN */
                }

                /* decode peer key */
                switch (args->dCert->keyOID) {
                #ifndef NO_RSA
                    #ifdef WC_RSA_PSS
                    case RSAPSSk:
                    #endif
                    case RSAk:
                    {
                        word32 keyIdx = 0;
                        int keyRet = 0;

                        if (ssl->peerRsaKey == NULL) {
                            keyRet = AllocKey(ssl, DYNAMIC_TYPE_RSA,
                                                (void**)&ssl->peerRsaKey);
                        } else if (ssl->peerRsaKeyPresent) {
                            keyRet = ReuseKey(ssl, DYNAMIC_TYPE_RSA,
                                              ssl->peerRsaKey);
                            ssl->peerRsaKeyPresent = 0;
                        }

                        if (keyRet != 0 || wc_RsaPublicKeyDecode(
                               args->dCert->publicKey, &keyIdx, ssl->peerRsaKey,
                                                args->dCert->pubKeySize) != 0) {
                            ret = PEER_KEY_ERROR;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                        else {
                            ssl->peerRsaKeyPresent = 1;
                    #if defined(WOLFSSL_RENESAS_TSIP_TLS) || \
                                             defined(WOLFSSL_RENESAS_SCEPROTECT)
                        /* copy encrypted tsip key index into ssl object */
                        if (args->dCert->sce_tsip_encRsaKeyIdx) {
                            if (!ssl->peerSceTsipEncRsaKeyIndex) {
                                ssl->peerSceTsipEncRsaKeyIndex = (byte*)XMALLOC(
                                    TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY,
                                    ssl->heap, DYNAMIC_TYPE_RSA);
                                if (!ssl->peerSceTsipEncRsaKeyIndex) {
                                    args->lastErr = MEMORY_E;
                                    goto exit_ppc;
                                }
                            }

                            XMEMCPY(ssl->peerSceTsipEncRsaKeyIndex,
                                        args->dCert->sce_tsip_encRsaKeyIdx,
                                        TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY);
                         }
                    #endif
                    #ifdef HAVE_PK_CALLBACKS
                        #if defined(HAVE_SECURE_RENEGOTIATION) || \
                                        defined(WOLFSSL_POST_HANDSHAKE_AUTH)
                        if (ssl->buffers.peerRsaKey.buffer) {
                            XFREE(ssl->buffers.peerRsaKey.buffer,
                                    ssl->heap, DYNAMIC_TYPE_RSA);
                            ssl->buffers.peerRsaKey.buffer = NULL;
                        }
                        #endif


                        ssl->buffers.peerRsaKey.buffer =
                               (byte*)XMALLOC(args->dCert->pubKeySize,
                                            ssl->heap, DYNAMIC_TYPE_RSA);
                        if (ssl->buffers.peerRsaKey.buffer == NULL) {
                            ret = MEMORY_ERROR;
                        }
                        else {
                            XMEMCPY(ssl->buffers.peerRsaKey.buffer,
                                    args->dCert->publicKey,
                                    args->dCert->pubKeySize);
                            ssl->buffers.peerRsaKey.length =
                                args->dCert->pubKeySize;
                        }
                    #endif /* HAVE_PK_CALLBACKS */
                        }

                        /* check size of peer RSA key */
                        if (ret == 0 && ssl->peerRsaKeyPresent &&
                                          !ssl->options.verifyNone &&
                                          wc_RsaEncryptSize(ssl->peerRsaKey)
                                              < ssl->options.minRsaKeySz) {
                            ret = RSA_KEY_SIZE_E;
                            WOLFSSL_ERROR_VERBOSE(ret);
                            WOLFSSL_MSG("Peer RSA key is too small");
                        }
                        break;
                    }
                #endif /* NO_RSA */
                #ifdef HAVE_ECC
                    case ECDSAk:
                    {
                        int keyRet = 0;
                        word32 idx = 0;
                    #if defined(WOLFSSL_RENESAS_SCEPROTECT) || \
                        defined(WOLFSSL_RENESAS_TSIP_TLS)
                        /* copy encrypted tsip/sce key index into ssl object */
                        if (args->dCert->sce_tsip_encRsaKeyIdx) {
                            if (!ssl->peerSceTsipEncRsaKeyIndex) {
                                ssl->peerSceTsipEncRsaKeyIndex = (byte*)XMALLOC(
                                    TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY,
                                    ssl->heap, DYNAMIC_TYPE_RSA);
                                if (!ssl->peerSceTsipEncRsaKeyIndex) {
                                    args->lastErr = MEMORY_E;
                                    ERROR_OUT(MEMORY_ERROR, exit_ppc);
                                }
                            }

                            XMEMCPY(ssl->peerSceTsipEncRsaKeyIndex,
                                        args->dCert->sce_tsip_encRsaKeyIdx,
                                        TSIP_TLS_ENCPUBKEY_SZ_BY_CERTVRFY);
                         }
                    #endif
                        if (ssl->peerEccDsaKey == NULL) {
                            /* alloc/init on demand */
                            keyRet = AllocKey(ssl, DYNAMIC_TYPE_ECC,
                                    (void**)&ssl->peerEccDsaKey);
                        } else if (ssl->peerEccDsaKeyPresent) {
                            keyRet = ReuseKey(ssl, DYNAMIC_TYPE_ECC,
                                              ssl->peerEccDsaKey);
                            ssl->peerEccDsaKeyPresent = 0;
                        }

                        if (keyRet != 0 ||
                            wc_EccPublicKeyDecode(args->dCert->publicKey, &idx,
                                                ssl->peerEccDsaKey,
                                                args->dCert->pubKeySize) != 0) {
                            ret = PEER_KEY_ERROR;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                        else {
                            ssl->peerEccDsaKeyPresent = 1;

                    #ifdef HAVE_PK_CALLBACKS
                            if (ssl->buffers.peerEccDsaKey.buffer)
                                XFREE(ssl->buffers.peerEccDsaKey.buffer,
                                      ssl->heap, DYNAMIC_TYPE_ECC);
                            ssl->buffers.peerEccDsaKey.buffer =
                                   (byte*)XMALLOC(args->dCert->pubKeySize,
                                           ssl->heap, DYNAMIC_TYPE_ECC);
                            if (ssl->buffers.peerEccDsaKey.buffer == NULL) {
                                ERROR_OUT(MEMORY_ERROR, exit_ppc);
                            }
                            else {
                                XMEMCPY(ssl->buffers.peerEccDsaKey.buffer,
                                        args->dCert->publicKey,
                                        args->dCert->pubKeySize);
                                ssl->buffers.peerEccDsaKey.length =
                                        args->dCert->pubKeySize;
                            }
                    #endif /* HAVE_PK_CALLBACKS */
                        }

                        /* check size of peer ECC key */
                        if (ret == 0 && ssl->peerEccDsaKeyPresent &&
                                              !ssl->options.verifyNone &&
                                              wc_ecc_size(ssl->peerEccDsaKey)
                                              < ssl->options.minEccKeySz) {
                            ret = ECC_KEY_SIZE_E;
                            WOLFSSL_ERROR_VERBOSE(ret);
                            WOLFSSL_MSG("Peer ECC key is too small");
                        }

                        /* populate curve oid - if missing */
                        if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->ecdhCurveOID == 0)
                            ssl->ecdhCurveOID = args->dCert->pkCurveOID;
                        break;
                    }
                #endif /* HAVE_ECC */
                #if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
                    case ED25519k:
                    {
                        int keyRet = 0;
                        if (ssl->peerEd25519Key == NULL) {
                            /* alloc/init on demand */
                            keyRet = AllocKey(ssl, DYNAMIC_TYPE_ED25519,
                                    (void**)&ssl->peerEd25519Key);
                        } else if (ssl->peerEd25519KeyPresent) {
                            keyRet = ReuseKey(ssl, DYNAMIC_TYPE_ED25519,
                                              ssl->peerEd25519Key);
                            ssl->peerEd25519KeyPresent = 0;
                        }

                        if (keyRet != 0 ||
                            wc_ed25519_import_public(args->dCert->publicKey,
                                                     args->dCert->pubKeySize,
                                                     ssl->peerEd25519Key)
                                                                         != 0) {
                            ret = PEER_KEY_ERROR;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                        else {
                            ssl->peerEd25519KeyPresent = 1;
                    #ifdef HAVE_PK_CALLBACKS
                            ssl->buffers.peerEd25519Key.buffer =
                                   (byte*)XMALLOC(args->dCert->pubKeySize,
                                           ssl->heap, DYNAMIC_TYPE_ED25519);
                            if (ssl->buffers.peerEd25519Key.buffer == NULL) {
                                ERROR_OUT(MEMORY_ERROR, exit_ppc);
                            }
                            else {
                                XMEMCPY(ssl->buffers.peerEd25519Key.buffer,
                                        args->dCert->publicKey,
                                        args->dCert->pubKeySize);
                                ssl->buffers.peerEd25519Key.length =
                                        args->dCert->pubKeySize;
                            }
                    #endif /*HAVE_PK_CALLBACKS */
                        }

                        /* check size of peer ECC key */
                        if (ret == 0 && ssl->peerEd25519KeyPresent &&
                                  !ssl->options.verifyNone &&
                                  ED25519_KEY_SIZE < ssl->options.minEccKeySz) {
                            ret = ECC_KEY_SIZE_E;
                            WOLFSSL_ERROR_VERBOSE(ret);
                            WOLFSSL_MSG("Peer ECC key is too small");
                        }

                        /* populate curve oid - if missing */
                        if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->ecdhCurveOID == 0)
                            ssl->ecdhCurveOID = ECC_X25519_OID;
                        break;
                    }
                #endif /* HAVE_ED25519 && HAVE_ED25519_KEY_IMPORT */
                #if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
                    case ED448k:
                    {
                        int keyRet = 0;
                        if (ssl->peerEd448Key == NULL) {
                            /* alloc/init on demand */
                            keyRet = AllocKey(ssl, DYNAMIC_TYPE_ED448,
                                    (void**)&ssl->peerEd448Key);
                        } else if (ssl->peerEd448KeyPresent) {
                            keyRet = ReuseKey(ssl, DYNAMIC_TYPE_ED448,
                                    ssl->peerEd448Key);
                            ssl->peerEd448KeyPresent = 0;
                        }

                        if (keyRet != 0 ||
                            wc_ed448_import_public(args->dCert->publicKey,
                                    args->dCert->pubKeySize,
                                    ssl->peerEd448Key) != 0) {
                            ret = PEER_KEY_ERROR;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                        else {
                            ssl->peerEd448KeyPresent = 1;
                    #ifdef HAVE_PK_CALLBACKS
                            ssl->buffers.peerEd448Key.buffer =
                                   (byte*)XMALLOC(args->dCert->pubKeySize,
                                           ssl->heap, DYNAMIC_TYPE_ED448);
                            if (ssl->buffers.peerEd448Key.buffer == NULL) {
                                ERROR_OUT(MEMORY_ERROR, exit_ppc);
                            }
                            else {
                                XMEMCPY(ssl->buffers.peerEd448Key.buffer,
                                        args->dCert->publicKey,
                                        args->dCert->pubKeySize);
                                ssl->buffers.peerEd448Key.length =
                                        args->dCert->pubKeySize;
                            }
                    #endif /*HAVE_PK_CALLBACKS */
                        }

                        /* check size of peer ECC key */
                        if (ret == 0 && ssl->peerEd448KeyPresent &&
                               !ssl->options.verifyNone &&
                               ED448_KEY_SIZE < ssl->options.minEccKeySz) {
                            ret = ECC_KEY_SIZE_E;
                            WOLFSSL_ERROR_VERBOSE(ret);
                            WOLFSSL_MSG("Peer ECC key is too small");
                        }

                        /* populate curve oid - if missing */
                        if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->ecdhCurveOID == 0)
                            ssl->ecdhCurveOID = ECC_X448_OID;
                        break;
                    }
                #endif /* HAVE_ED448 && HAVE_ED448_KEY_IMPORT */
                #if defined(HAVE_PQC)
                #if defined(HAVE_FALCON)
                    case FALCON_LEVEL1k:
                    case FALCON_LEVEL5k:
                    {
                        int keyRet = 0;
                        if (ssl->peerFalconKey == NULL) {
                            /* alloc/init on demand */
                            keyRet = AllocKey(ssl, DYNAMIC_TYPE_FALCON,
                                    (void**)&ssl->peerFalconKey);
                        } else if (ssl->peerFalconKeyPresent) {
                            keyRet = ReuseKey(ssl, DYNAMIC_TYPE_FALCON,
                                    ssl->peerFalconKey);
                            ssl->peerFalconKeyPresent = 0;
                        }

                        if (keyRet == 0) {
                            if (args->dCert->keyOID == FALCON_LEVEL1k) {
                                keyRet = wc_falcon_set_level(ssl->peerFalconKey,
                                1);
                            }
                            else {
                                keyRet = wc_falcon_set_level(ssl->peerFalconKey,
                                5);
                            }
                        }

                        if (keyRet != 0 ||
                            wc_falcon_import_public(args->dCert->publicKey,
                                                    args->dCert->pubKeySize,
                                                    ssl->peerFalconKey) != 0) {
                            ret = PEER_KEY_ERROR;
                            WOLFSSL_ERROR_VERBOSE(ret);
                        }
                        else {
                            ssl->peerFalconKeyPresent = 1;
                        }

                        /* check size of peer Falcon key */
                        if (ret == 0 && ssl->peerFalconKeyPresent &&
                               !ssl->options.verifyNone &&
                               FALCON_MAX_KEY_SIZE <
                               ssl->options.minFalconKeySz) {
                            ret = FALCON_KEY_SIZE_E;
                            WOLFSSL_ERROR_VERBOSE(ret);
                            WOLFSSL_MSG("Peer Falcon key is too small");
                        }
                        break;
                    }
                #endif /* HAVE_FALCON */
                #if defined(HAVE_DILITHIUM)
                    case DILITHIUM_LEVEL2k:
                    case DILITHIUM_LEVEL3k:
                    case DILITHIUM_LEVEL5k:
                    case DILITHIUM_AES_LEVEL2k:
                    case DILITHIUM_AES_LEVEL3k:
                    case DILITHIUM_AES_LEVEL5k:
                    {
                        int keyRet = 0;
                        if (ssl->peerDilithiumKey == NULL) {
                            /* alloc/init on demand */
                            keyRet = AllocKey(ssl, DYNAMIC_TYPE_DILITHIUM,
                                    (void**)&ssl->peerDilithiumKey);
                        } else if (ssl->peerDilithiumKeyPresent) {
                            keyRet = ReuseKey(ssl, DYNAMIC_TYPE_DILITHIUM,
                                    ssl->peerDilithiumKey);
                            ssl->peerDilithiumKeyPresent = 0;
                        }

                        if (keyRet == 0) {
                            if (args->dCert->keyOID == DILITHIUM_LEVEL2k) {
                                keyRet = wc_dilithium_set_level_and_sym(
                                             ssl->peerDilithiumKey, 2,
                                             SHAKE_VARIANT);
                            }
                            else if (args->dCert->keyOID == DILITHIUM_LEVEL3k) {
                                keyRet = wc_dilithium_set_level_and_sym(
                                             ssl->peerDilithiumKey, 3,
                                             SHAKE_VARIANT);
                            }
                            else if (args->dCert->keyOID == DILITHIUM_LEVEL5k) {
                                keyRet = wc_dilithium_set_level_and_sym(
                                             ssl->peerDilithiumKey, 5,
                                             SHAKE_VARIANT);
                            }
                            else if (args->dCert->keyOID
                                     == DILITHIUM_AES_LEVEL2k) {
                                keyRet = wc_dilithium_set_level_and_sym(
                                             ssl->peerDilithiumKey, 2,
                                             AES_VARIANT);
                            }
                            else if (args->dCert->keyOID
                                     == DILITHIUM_AES_LEVEL3k) {
                                keyRet = wc_dilithium_set_level_and_sym(
                                             ssl->peerDilithiumKey, 3,
                                             AES_VARIANT);
                            }
                            else if (args->dCert->keyOID
                                     == DILITHIUM_AES_LEVEL5k) {
                                keyRet = wc_dilithium_set_level_and_sym(
                                             ssl->peerDilithiumKey, 5,
                                             AES_VARIANT);
                            }
                        }

                        if (keyRet != 0 ||
                            wc_dilithium_import_public(args->dCert->publicKey,
                                                       args->dCert->pubKeySize,
                                                       ssl->peerDilithiumKey)
                            != 0) {
                            ret = PEER_KEY_ERROR;
                        }
                        else {
                            ssl->peerDilithiumKeyPresent = 1;
                        }

                        /* check size of peer Dilithium key */
                        if (ret == 0 && ssl->peerDilithiumKeyPresent &&
                               !ssl->options.verifyNone &&
                               DILITHIUM_MAX_KEY_SIZE <
                               ssl->options.minDilithiumKeySz) {
                            ret = DILITHIUM_KEY_SIZE_E;
                            WOLFSSL_MSG("Peer Dilithium key is too small");
                        }
                        break;
                    }
                #endif /* HAVE_DILITHIUM */
                #endif /* HAVE_PQC */
                    default:
                        break;
                }

                /* args->dCert free'd in function cleanup after callback */
            } /* if (count > 0) */

            /* Check for error */
            if (args->fatal && ret != 0) {
                goto exit_ppc;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */
        FALL_THROUGH;

        case TLS_ASYNC_FINALIZE:
        {
            /* load last error */
            if (args->lastErr != 0 && ret == 0) {
                ret = args->lastErr;
            }

        #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
           /* limit compliant with OpenSSL verify Depth + 1
            * OpenSSL tries to expand the chain one longer than limit until
            * reaching an ultimately trusted issuer. Becoming failure if
            * we hit the limit, with X509_V_ERR_CERT_CHAIN_TOO_LONG
            */
            if (args->untrustedDepth > (ssl->options.verifyDepth + 1)) {
                if (ssl->peerVerifyRet == 0) /* Return first cert error here */
                    ssl->peerVerifyRet = X509_V_ERR_CERT_CHAIN_TOO_LONG;
                ret = MAX_CHAIN_ERROR;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
        #endif

            /* Do verify callback */
            ret = DoVerifyCallback(SSL_CM(ssl), ssl, ret, args);

            if (ssl->options.verifyNone &&
                              (ret == CRL_MISSING || ret == CRL_CERT_REVOKED ||
                               ret == CRL_CERT_DATE_ERR)) {
                WOLFSSL_MSG("Ignoring CRL problem based on verify setting");
                ret = ssl->error = 0;
            }

            if (ret != 0) {
                if (!ssl->options.verifyNone) {
                    DoCertFatalAlert(ssl, ret);
                }
                ssl->error = ret; /* Report SSL error */
            }

            if (ret == 0 && ssl->options.side == WOLFSSL_CLIENT_END) {
                ssl->options.serverState = SERVER_CERT_COMPLETE;
            }

            if (IsEncryptionOn(ssl, 0)) {
                args->idx += ssl->keys.padSz;
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                if (ssl->options.startedETMRead)
                    args->idx += MacSize(ssl);
            #endif
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            /* Set final index */
            *inOutIdx = args->idx;

            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
            break;
    } /* switch(ssl->options.asyncState) */

exit_ppc:

    WOLFSSL_LEAVE("ProcessPeerCerts", ret);


#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
    if (ret == WC_PENDING_E || ret == OCSP_WANT_READ) {
        /* Mark message as not received so it can process again */
        ssl->msgsReceived.got_certificate = 0;

        return ret;
    }
#endif /* WOLFSSL_ASYNC_CRYPT || WOLFSSL_NONBLOCK_OCSP */

#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
    /* Cleanup async */
    FreeAsyncCtx(ssl, 0);
#elif defined(WOLFSSL_SMALL_STACK)
    if (args)
    {
        FreeProcPeerCertArgs(ssl, args);
    }
#else
    FreeProcPeerCertArgs(ssl, args);
#endif /* WOLFSSL_ASYNC_CRYPT || WOLFSSL_NONBLOCK_OCSP || WOLFSSL_SMALL_STACK */

#if !defined(WOLFSSL_ASYNC_CRYPT) && defined(WOLFSSL_SMALL_STACK)
    XFREE(args, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    FreeKeyExchange(ssl);

    return ret;
}
#endif

#ifndef WOLFSSL_NO_TLS12
#if !defined(NO_WOLFSSL_CLIENT) || !defined(WOLFSSL_NO_CLIENT_AUTH)

/* handle processing of certificate (11) */
static int DoCertificate(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                                                                word32 size)
{
    int ret;

    WOLFSSL_START(WC_FUNC_CERTIFICATE_DO);
    WOLFSSL_ENTER("DoCertificate");

#ifdef SESSION_CERTS
    /* Reset the session cert chain count in case the session resume failed. */
    ssl->session->chain.count = 0;
    #ifdef WOLFSSL_ALT_CERT_CHAINS
        ssl->session->altChain.count = 0;
    #endif
#endif /* SESSION_CERTS */

    ret = ProcessPeerCerts(ssl, input, inOutIdx, size);
#ifdef WOLFSSL_EXTRA_ALERTS
    if (ret == BUFFER_ERROR || ret == ASN_PARSE_E)
        SendAlert(ssl, alert_fatal, decode_error);
#endif

#ifdef OPENSSL_EXTRA
    ssl->options.serverState = SERVER_CERT_COMPLETE;
#endif

    WOLFSSL_LEAVE("DoCertificate", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_DO);

    return ret;
}

/* handle processing of certificate_status (22) */
static int DoCertificateStatus(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                                                                    word32 size)
{
    int    ret = 0;
    byte   status_type;
    word32 status_length;

    WOLFSSL_START(WC_FUNC_CERTIFICATE_STATUS_DO);
    WOLFSSL_ENTER("DoCertificateStatus");

    if (size < ENUM_LEN + OPAQUE24_LEN)
        return BUFFER_ERROR;

    status_type = input[(*inOutIdx)++];

    c24to32(input + *inOutIdx, &status_length);
    *inOutIdx += OPAQUE24_LEN;

    if (size != ENUM_LEN + OPAQUE24_LEN + status_length)
        return BUFFER_ERROR;

    switch (status_type) {

    #if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
     || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)

        /* WOLFSSL_CSR_OCSP overlaps with WOLFSSL_CSR2_OCSP */
        case WOLFSSL_CSR2_OCSP:
            ret = ProcessCSR(ssl, input, inOutIdx, status_length);
            break;

    #endif

    #if defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)

        case WOLFSSL_CSR2_OCSP_MULTI: {
            OcspRequest* request;
            word32 list_length = status_length;
            byte   idx = 0;

            #ifdef WOLFSSL_SMALL_STACK
                CertStatus*   status;
                OcspEntry*    single;
                OcspResponse* response;
            #else
                CertStatus   status[1];
                OcspEntry    single[1];
                OcspResponse response[1];
            #endif

            do {
                if (ssl->status_request_v2) {
                    ssl->status_request_v2 = 0;
                    break;
                }

                return BUFFER_ERROR;
            } while(0);

            #ifdef WOLFSSL_SMALL_STACK
                status = (CertStatus*)XMALLOC(sizeof(CertStatus), ssl->heap,
                                                       DYNAMIC_TYPE_OCSP_STATUS);
                single = (OcspEntry*)XMALLOC(sizeof(OcspEntry), ssl->heap,
                                                              DYNAMIC_TYPE_OCSP_ENTRY);
                response = (OcspResponse*)XMALLOC(sizeof(OcspResponse), ssl->heap,
                                                             DYNAMIC_TYPE_OCSP_REQUEST);

                if (status == NULL || single == NULL || response == NULL) {
                    if (status)
                        XFREE(status, ssl->heap, DYNAMIC_TYPE_OCSP_STATUS);
                    if (single)
                        XFREE(single, ssl->heap, DYNAMIC_TYPE_OCSP_ENTRY);
                    if (response)
                        XFREE(response, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);

                    return MEMORY_ERROR;
                }
            #endif

            while (list_length && ret == 0) {
                if (OPAQUE24_LEN > list_length) {
                    ret = BUFFER_ERROR;
                    break;
                }

                c24to32(input + *inOutIdx, &status_length);
                *inOutIdx   += OPAQUE24_LEN;
                list_length -= OPAQUE24_LEN;

                if (status_length > list_length) {
                    ret = BUFFER_ERROR;
                    break;
                }

                if (status_length) {
                    InitOcspResponse(response, single, status, input +*inOutIdx,
                                     status_length, ssl->heap);

                    if ((OcspResponseDecode(response, SSL_CM(ssl), ssl->heap,
                                                                        0) != 0)
                    ||  (response->responseStatus != OCSP_SUCCESSFUL)
                    ||  (response->single->status->status != CERT_GOOD))
                        ret = BAD_CERTIFICATE_STATUS_ERROR;

                    while (ret == 0) {
                        request = (OcspRequest*)TLSX_CSR2_GetRequest(
                                ssl->extensions, status_type, idx++);

                        if (request == NULL)
                            ret = BAD_CERTIFICATE_STATUS_ERROR;
                        else if (CompareOcspReqResp(request, response) == 0)
                            break;
                        else if (idx == 1) /* server cert must be OK */
                            ret = BAD_CERTIFICATE_STATUS_ERROR;
                    }
                    FreeOcspResponse(response);

                    *inOutIdx   += status_length;
                    list_length -= status_length;
                }
            }

            ssl->status_request_v2 = 0;

            #ifdef WOLFSSL_SMALL_STACK
                XFREE(status,   NULL, DYNAMIC_TYPE_OCSP_STATUS);
                XFREE(single,   NULL, DYNAMIC_TYPE_OCSP_ENTRY);
                XFREE(response, NULL, DYNAMIC_TYPE_OCSP_REQUEST);
            #endif

        }
        break;

    #endif

        default:
            ret = BUFFER_ERROR;
    }

    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(ret);
        SendAlert(ssl, alert_fatal, bad_certificate_status_response);
    }

    if (IsEncryptionOn(ssl, 0)) {
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead) {
            word32 digestSz = MacSize(ssl);
            if (*inOutIdx + ssl->keys.padSz + digestSz > size)
                return BUFFER_E;
            *inOutIdx += ssl->keys.padSz + digestSz;
        }
        else
    #endif
        {
            if (*inOutIdx + ssl->keys.padSz > size)
                return BUFFER_E;
            *inOutIdx += ssl->keys.padSz;
        }
    }

    WOLFSSL_LEAVE("DoCertificateStatus", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_STATUS_DO);

    return ret;
}

#endif

#endif /* !WOLFSSL_NO_TLS12 */

#endif /* !NO_CERTS */

#ifndef WOLFSSL_NO_TLS12

static int DoHelloRequest(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                                                    word32 size, word32 totalSz)
{
    (void)input;

    WOLFSSL_START(WC_FUNC_HELLO_REQUEST_DO);
    WOLFSSL_ENTER("DoHelloRequest");

    if (size) /* must be 0 */
        return BUFFER_ERROR;

    if (IsEncryptionOn(ssl, 0)) {
        /* If size == totalSz then we are in DtlsMsgDrain so no need to worry
         * about padding */
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead) {
            word32 digestSz = MacSize(ssl);
            if (size != totalSz &&
                    *inOutIdx + ssl->keys.padSz + digestSz > totalSz)
                return BUFFER_E;
            *inOutIdx += ssl->keys.padSz + digestSz;
        }
        else
    #endif
        {
            /* access beyond input + size should be checked against totalSz */
            if (size != totalSz &&
                    *inOutIdx + ssl->keys.padSz > totalSz)
                return BUFFER_E;

            *inOutIdx += ssl->keys.padSz;
        }
    }

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        SendAlert(ssl, alert_fatal, unexpected_message); /* try */
        WOLFSSL_ERROR_VERBOSE(FATAL_ERROR);
        return FATAL_ERROR;
    }
#ifdef HAVE_SECURE_RENEGOTIATION
    else if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled) {
        ssl->secure_renegotiation->startScr = 1;
        WOLFSSL_LEAVE("DoHelloRequest", 0);
        WOLFSSL_END(WC_FUNC_HELLO_REQUEST_DO);
        return 0;
    }
#endif
    else {
        return SendAlert(ssl, alert_warning, no_renegotiation);
    }
}


int DoFinished(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size,
                                                      word32 totalSz, int sniff)
{
    word32 finishedSz = (ssl->options.tls ? TLS_FINISHED_SZ : FINISHED_SZ);

    WOLFSSL_START(WC_FUNC_FINISHED_DO);
    WOLFSSL_ENTER("DoFinished");

    if (finishedSz != size)
        return BUFFER_ERROR;

    /* check against totalSz
     * If size == totalSz then we are in DtlsMsgDrain so no need to worry about
     * padding */
    if (size != totalSz) {
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead) {
            if (*inOutIdx + size + ssl->keys.padSz + MacSize(ssl) > totalSz)
                return BUFFER_E;
        }
        else
    #endif
        {
            if (*inOutIdx + size + ssl->keys.padSz > totalSz)
                return BUFFER_E;
        }
    }

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName(ssl, "Finished");
        if (ssl->toInfoOn) AddLateName("Finished", &ssl->timeoutInfo);
    #endif

    if (sniff == NO_SNIFF) {
        if (XMEMCMP(input + *inOutIdx, &ssl->hsHashes->verifyHashes,size) != 0){
            WOLFSSL_MSG("Verify finished error on hashes");
    #ifdef WOLFSSL_EXTRA_ALERTS
            SendAlert(ssl, alert_fatal, decrypt_error);
    #endif
            WOLFSSL_ERROR_VERBOSE(VERIFY_FINISHED_ERROR);
            return VERIFY_FINISHED_ERROR;
        }
    }

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation) {
        /* save peer's state */
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            XMEMCPY(ssl->secure_renegotiation->server_verify_data,
                    input + *inOutIdx, TLS_FINISHED_SZ);
        else
            XMEMCPY(ssl->secure_renegotiation->client_verify_data,
                    input + *inOutIdx, TLS_FINISHED_SZ);
        ssl->secure_renegotiation->verifySet = 1;
    }
#endif
#ifdef WOLFSSL_HAVE_TLS_UNIQUE
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        XMEMCPY(ssl->serverFinished,
                input + *inOutIdx, TLS_FINISHED_SZ);
        ssl->serverFinished_len = TLS_FINISHED_SZ;
    }
    else {
        XMEMCPY(ssl->clientFinished,
                input + *inOutIdx, TLS_FINISHED_SZ);
        ssl->clientFinished_len = TLS_FINISHED_SZ;
    }
#endif

    /* force input exhaustion at ProcessReply consuming padSz */
    *inOutIdx += size + ssl->keys.padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    if (ssl->options.startedETMRead)
        *inOutIdx += MacSize(ssl);
#endif

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ssl->options.serverState = SERVER_FINISHED_COMPLETE;
#ifdef OPENSSL_EXTRA
        ssl->cbmode = SSL_CB_MODE_WRITE;
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
#endif
        if (!ssl->options.resuming) {
#ifdef OPENSSL_EXTRA
            if (ssl->CBIS != NULL) {
                ssl->CBIS(ssl, SSL_CB_CONNECT_LOOP, SSL_SUCCESS);
            }
#endif
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
    else {
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
#ifdef OPENSSL_EXTRA
        ssl->cbmode = SSL_CB_MODE_READ;
        ssl->options.serverState = SERVER_FINISHED_COMPLETE;
#endif
        if (ssl->options.resuming) {
#ifdef OPENSSL_EXTRA
            if (ssl->CBIS != NULL) {
                ssl->CBIS(ssl, SSL_CB_ACCEPT_LOOP, SSL_SUCCESS);
            }
#endif
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        if ((!ssl->options.resuming && ssl->options.side == WOLFSSL_CLIENT_END) ||
             (ssl->options.resuming && ssl->options.side == WOLFSSL_SERVER_END)){
            DtlsMsgPoolReset(ssl);
            ssl->keys.dtls_handshake_number = 0;
            ssl->keys.dtls_expected_peer_handshake_number = 0;
        }
    }
#endif

    WOLFSSL_LEAVE("DoFinished", 0);
    WOLFSSL_END(WC_FUNC_FINISHED_DO);

    return 0;
}


/* Make sure no duplicates, no fast forward, or other problems; 0 on success */
static int SanityCheckMsgReceived(WOLFSSL* ssl, byte type)
{
    /* verify not a duplicate, mark received, check state */
    switch (type) {

#ifndef NO_WOLFSSL_CLIENT
        case hello_request:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("HelloRequest received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_hello_request) {
                WOLFSSL_MSG("Duplicate HelloRequest received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_hello_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_SERVER
        case client_hello:
        #ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                WOLFSSL_MSG("ClientHello received by client");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_client_hello) {
                WOLFSSL_MSG("Duplicate ClientHello received");
    #ifdef WOLFSSL_EXTRA_ALERTS
                SendAlert(ssl, alert_fatal, unexpected_message);
    #endif
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_client_hello = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_hello:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("ServerHello received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_server_hello) {
                WOLFSSL_MSG("Duplicate ServerHello received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case hello_verify_request:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("HelloVerifyRequest received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_hello_verify_request) {
                WOLFSSL_MSG("Duplicate HelloVerifyRequest received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_hello_verify_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case session_ticket:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("SessionTicket received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_session_ticket) {
                WOLFSSL_MSG("Duplicate SessionTicket received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_session_ticket = 1;

            break;
#endif

        case certificate:
            if (ssl->msgsReceived.got_certificate) {
                WOLFSSL_MSG("Duplicate Certificate received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate = 1;

#ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if ( ssl->msgsReceived.got_server_hello == 0) {
                    WOLFSSL_MSG("No ServerHello before Cert");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
            }
#endif
#ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                if ( ssl->msgsReceived.got_client_hello == 0) {
                    WOLFSSL_MSG("No ClientHello before Cert");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
            }
#endif
            break;

#ifndef NO_WOLFSSL_CLIENT
        case certificate_status:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("CertificateStatus received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_certificate_status) {
                WOLFSSL_MSG("Duplicate CertificateStatus received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_status = 1;

            if (ssl->msgsReceived.got_certificate == 0) {
                WOLFSSL_MSG("No Certificate before CertificateStatus");
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
            }
            if (ssl->msgsReceived.got_server_key_exchange != 0) {
                WOLFSSL_MSG("CertificateStatus after ServerKeyExchange");
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
            }

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_key_exchange:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("ServerKeyExchange received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_server_key_exchange) {
                WOLFSSL_MSG("Duplicate ServerKeyExchange received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_key_exchange = 1;

            if (ssl->msgsReceived.got_server_hello == 0) {
                WOLFSSL_MSG("No ServerHello before ServerKeyExchange");
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
            }
            if (ssl->msgsReceived.got_certificate_status == 0) {
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
                if (ssl->status_request) {
                    int ret;

                    WOLFSSL_MSG("No CertificateStatus before ServerKeyExchange");
                    if ((ret = TLSX_CSR_ForceRequest(ssl)) != 0)
                        return ret;
                }
#endif
#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
                if (ssl->status_request_v2) {
                    int ret;

                    WOLFSSL_MSG("No CertificateStatus before ServerKeyExchange");
                    if ((ret = TLSX_CSR2_ForceRequest(ssl)) != 0)
                        return ret;
                }
#endif
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
                                     defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
                /* Check that a status request extension was seen as the
                 * CertificateStatus wasn't when an OCSP staple is required.
                 */
                if (
    #ifdef HAVE_CERTIFICATE_STATUS_REQUEST
                     !ssl->status_request &&
    #endif
    #ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
                     !ssl->status_request_v2 &&
    #endif
                                                 SSL_CM(ssl)->ocspMustStaple) {
                    WOLFSSL_ERROR_VERBOSE(OCSP_CERT_UNKNOWN);
                    return OCSP_CERT_UNKNOWN;
                }
                #endif
            }

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case certificate_request:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("CertificateRequest received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_certificate_request) {
                WOLFSSL_MSG("Duplicate CertificateRequest received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_hello_done:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("ServerHelloDone received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_server_hello_done) {
                WOLFSSL_MSG("Duplicate ServerHelloDone received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello_done = 1;

            if (ssl->msgsReceived.got_certificate == 0) {
                if (ssl->specs.kea == psk_kea ||
                    ssl->specs.kea == dhe_psk_kea ||
                    ssl->specs.kea == ecdhe_psk_kea ||
                    ssl->options.usingAnon_cipher) {
                    WOLFSSL_MSG("No Cert required");
                }
                else {
                    WOLFSSL_MSG("No Certificate before ServerHelloDone");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
            }
            if (ssl->msgsReceived.got_server_key_exchange == 0) {
                int pskNoServerHint = 0;  /* not required in this case */

                #ifndef NO_PSK
                    if (ssl->specs.kea == psk_kea &&
                        ssl->arrays != NULL &&
                        ssl->arrays->server_hint[0] == 0)
                        pskNoServerHint = 1;
                #endif
                if (ssl->specs.static_ecdh == 1 ||
                    ssl->specs.kea == rsa_kea ||
                    pskNoServerHint) {
                    WOLFSSL_MSG("No KeyExchange required");
                }
                else {
                    WOLFSSL_MSG("No ServerKeyExchange before ServerDone");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
            }
            break;
#endif

#ifndef NO_WOLFSSL_SERVER
        case certificate_verify:
        #ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                WOLFSSL_MSG("CertificateVerify received by client");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_certificate_verify) {
                WOLFSSL_MSG("Duplicate CertificateVerify received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_verify = 1;

            if ( ssl->msgsReceived.got_certificate == 0) {
                WOLFSSL_MSG("No Cert before CertVerify");
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
            }
            break;
#endif

#ifndef NO_WOLFSSL_SERVER
        case client_key_exchange:
        #ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                WOLFSSL_MSG("ClientKeyExchange received by client");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_client_key_exchange) {
                WOLFSSL_MSG("Duplicate ClientKeyExchange received");
    #ifdef WOLFSSL_EXTRA_ALERTS
                SendAlert(ssl, alert_fatal, unexpected_message);
    #endif
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_client_key_exchange = 1;

            if (ssl->msgsReceived.got_client_hello == 0) {
                WOLFSSL_MSG("No ClientHello before ClientKeyExchange");
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
            }
            break;
#endif

        case finished:
            if (ssl->msgsReceived.got_finished) {
                WOLFSSL_MSG("Duplicate Finished received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
#ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                if (ssl->keys.curEpoch == 0) {
                    WOLFSSL_MSG("Finished received with epoch 0");
                    WOLFSSL_ERROR_VERBOSE(SEQUENCE_ERROR);
                    return SEQUENCE_ERROR;
                }
            }
#endif
            ssl->msgsReceived.got_finished = 1;

            if (ssl->msgsReceived.got_change_cipher == 0) {
                WOLFSSL_MSG("Finished received before ChangeCipher");
    #ifdef WOLFSSL_EXTRA_ALERTS
                SendAlert(ssl, alert_fatal, unexpected_message);
    #endif
                WOLFSSL_ERROR_VERBOSE(NO_CHANGE_CIPHER_E);
                return NO_CHANGE_CIPHER_E;
            }
            break;

        case change_cipher_hs:
            if (ssl->msgsReceived.got_change_cipher) {
                WOLFSSL_MSG("Duplicate ChangeCipher received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            /* DTLS is going to ignore the CCS message if the client key
             * exchange message wasn't received yet. */
            if (!ssl->options.dtls)
                ssl->msgsReceived.got_change_cipher = 1;

#ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if (!ssl->options.resuming) {
                   if (ssl->msgsReceived.got_server_hello_done == 0) {
                        WOLFSSL_MSG("No ServerHelloDone before ChangeCipher");
                        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                        return OUT_OF_ORDER_E;
                   }
                }
                else {
                    if (ssl->msgsReceived.got_server_hello == 0) {
                        WOLFSSL_MSG("No ServerHello before ChangeCipher on "
                                    "Resume");
                        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                        return OUT_OF_ORDER_E;
                    }
                }
                #ifdef HAVE_SESSION_TICKET
                    if (ssl->expect_session_ticket) {
                        WOLFSSL_MSG("Expected session ticket missing");
                        #ifdef WOLFSSL_DTLS
                            if (ssl->options.dtls) {
                                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                                return OUT_OF_ORDER_E;
                            }
                        #endif
                        WOLFSSL_ERROR_VERBOSE(SESSION_TICKET_EXPECT_E);
                        return SESSION_TICKET_EXPECT_E;
                    }
                #endif
            }
#endif
#ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                if (!ssl->options.resuming &&
                               ssl->msgsReceived.got_client_key_exchange == 0) {
                    WOLFSSL_MSG("No ClientKeyExchange before ChangeCipher");
    #ifdef WOLFSSL_EXTRA_ALERTS
                    SendAlert(ssl, alert_fatal, unexpected_message);
    #endif
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
                #ifndef NO_CERTS
                    if (ssl->options.verifyPeer &&
                        ssl->options.havePeerCert) {

                        if (!ssl->options.havePeerVerify ||
                                !ssl->msgsReceived.got_certificate_verify) {
                            WOLFSSL_MSG("client didn't send cert verify");
                            #ifdef WOLFSSL_DTLS
                                if (ssl->options.dtls) {
                                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                                    return OUT_OF_ORDER_E;
                                }
                            #endif
                            WOLFSSL_ERROR_VERBOSE(NO_PEER_VERIFY);
                            return NO_PEER_VERIFY;
                        }
                    }
                #endif
            }
#endif
            if (ssl->options.dtls)
                ssl->msgsReceived.got_change_cipher = 1;
            break;

        default:
            WOLFSSL_MSG("Unknown message type");
            WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
            return SANITY_MSG_E;
    }

    return 0;
}


static int DoHandShakeMsgType(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                          byte type, word32 size, word32 totalSz)
{
    int ret = 0;
    word32 expectedIdx;

    WOLFSSL_ENTER("DoHandShakeMsgType");

#ifdef WOLFSSL_TLS13
    if (type == hello_retry_request) {
        return DoTls13HandShakeMsgType(ssl, input, inOutIdx, type, size,
                                       totalSz);
    }
#endif

    /* make sure can read the message */
    if (*inOutIdx + size > totalSz) {
        WOLFSSL_MSG("Incomplete Data");
        WOLFSSL_ERROR_VERBOSE(INCOMPLETE_DATA);
        return INCOMPLETE_DATA;
    }

    expectedIdx = *inOutIdx + size +
                  (ssl->keys.encryptionOn ? ssl->keys.padSz : 0);
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    if (ssl->options.startedETMRead && ssl->keys.encryptionOn)
        expectedIdx += MacSize(ssl);
#endif

#if !defined(NO_WOLFSSL_SERVER) && \
    defined(HAVE_SECURE_RENEGOTIATION) && \
    defined(HAVE_SERVER_RENEGOTIATION_INFO)
    if (ssl->options.handShakeDone && type == client_hello &&
            ssl->secure_renegotiation &&
            ssl->secure_renegotiation->enabled)
    {
        WOLFSSL_MSG("Reset handshake state");
        XMEMSET(&ssl->msgsReceived, 0, sizeof(MsgsReceived));
        ssl->options.serverState = NULL_STATE;
        ssl->options.clientState = NULL_STATE;
        ssl->options.connectState = CONNECT_BEGIN;
        ssl->options.acceptState = ACCEPT_FIRST_REPLY_DONE;
        ssl->options.handShakeState = NULL_STATE;
        ssl->secure_renegotiation->cache_status = SCR_CACHE_NEEDED;

        ret = InitHandshakeHashes(ssl);
        if (ret != 0)
            return ret;
    }
#endif

    /* sanity check msg received */
    if ( (ret = SanityCheckMsgReceived(ssl, type)) != 0) {
        WOLFSSL_MSG("Sanity Check on handshake message type received failed");
        return ret;
    }

#if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
    /* add name later, add the handshake header part back on and record layer
     * header */
    if (ssl->toInfoOn) {
        ret = AddPacketInfo(ssl, 0, handshake, input + *inOutIdx -
            HANDSHAKE_HEADER_SZ, size + HANDSHAKE_HEADER_SZ, READ_PROTO,
            RECORD_HEADER_SZ, ssl->heap);
        if (ret != 0)
            return ret;
        #ifdef WOLFSSL_CALLBACKS
        AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
        #endif
    }
#endif

    if (ssl->options.handShakeState == HANDSHAKE_DONE && type != hello_request){
        WOLFSSL_MSG("HandShake message after handshake complete");
        SendAlert(ssl, alert_fatal, unexpected_message);
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->options.dtls == 0 &&
               ssl->options.serverState == NULL_STATE && type != server_hello) {
        WOLFSSL_MSG("First server message not server hello");
        SendAlert(ssl, alert_fatal, unexpected_message);
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->options.dtls &&
            type == server_hello_done &&
            ssl->options.serverState < SERVER_HELLO_COMPLETE) {
        WOLFSSL_MSG("Server hello done received before server hello in DTLS");
        SendAlert(ssl, alert_fatal, unexpected_message);
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_SERVER_END &&
               ssl->options.clientState == NULL_STATE && type != client_hello) {
        WOLFSSL_MSG("First client message not client hello");
        SendAlert(ssl, alert_fatal, unexpected_message);
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }

    /* above checks handshake state */
    /* hello_request not hashed */
    /* Also, skip hashing the client_hello message here for DTLS. It will be
     * hashed later if the DTLS cookie is correct. */
    if (type != hello_request
    #ifdef WOLFSSL_ASYNC_CRYPT
            && ssl->error != WC_PENDING_E
    #endif
    #ifdef WOLFSSL_NONBLOCK_OCSP
            && ssl->error != OCSP_WANT_READ
    #endif
    ) {
        ret = HashInput(ssl, input + *inOutIdx, size);
        if (ret != 0) {
            WOLFSSL_MSG("Incomplete handshake hashes");
            return ret;
        }
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        switch (type) {
        case certificate:
        case server_key_exchange:
        case certificate_request:
        case server_hello_done:
            if (ssl->options.resuming) {
#ifdef WOLFSSL_WPAS
                /* This can occur when ssl->sessionSecretCb is set. EAP-FAST
                 * (RFC 4851) allows for detecting server session resumption
                 * based on the msg received after the ServerHello. */
                WOLFSSL_MSG("Not resuming as thought");
                ssl->options.resuming = 0;
                /* No longer resuming, reset peer authentication state. */
                ssl->options.peerAuthGood = 0;
#else
                /* Fatal error. Only try to send an alert. RFC 5246 does not
                 * allow for reverting back to a full handshake after the
                 * server has indicated the intention to do a resumption. */
                (void)SendAlert(ssl, alert_fatal, unexpected_message);
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
#endif
            }
        }
    }

#ifdef OPENSSL_EXTRA
    if (ssl->CBIS != NULL){
        ssl->cbmode = SSL_CB_MODE_READ;
        ssl->cbtype = type;
        ssl->CBIS(ssl, SSL_CB_ACCEPT_LOOP, SSL_SUCCESS);
    }
#endif

    switch (type) {

    case hello_request:
        WOLFSSL_MSG("processing hello request");
        ret = DoHelloRequest(ssl, input, inOutIdx, size, totalSz);
        break;

#ifndef NO_WOLFSSL_CLIENT
    case hello_verify_request:
        WOLFSSL_MSG("processing hello verify request");
        ret = DoHelloVerifyRequest(ssl, input,inOutIdx, size);
        if (IsEncryptionOn(ssl, 0)) {
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMRead) {
                word32 digestSz = MacSize(ssl);
                if (*inOutIdx + ssl->keys.padSz + digestSz > totalSz)
                    return BUFFER_E;
                *inOutIdx += ssl->keys.padSz + digestSz;
            }
            else
        #endif
            {
                /* access beyond input + size should be checked against totalSz
                 */
                if (*inOutIdx + ssl->keys.padSz > totalSz)
                    return BUFFER_E;

                *inOutIdx += ssl->keys.padSz;
            }
        }
        break;

    case server_hello:
        WOLFSSL_MSG("processing server hello");
        ret = DoServerHello(ssl, input, inOutIdx, size);
    #if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
        if (ssl->options.resuming || !IsAtLeastTLSv1_2(ssl) ||
                                               IsAtLeastTLSv1_3(ssl->version)) {

        #if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
            if (ret != WC_PENDING_E && ret != OCSP_WANT_READ)
        #endif
            {
                ssl->options.cacheMessages = 0;
                if ((ssl->hsHashes != NULL) && (ssl->hsHashes->messages != NULL)) {
                    ForceZero(ssl->hsHashes->messages, ssl->hsHashes->length);
                    XFREE(ssl->hsHashes->messages, ssl->heap,
                        DYNAMIC_TYPE_HASHES);
                    ssl->hsHashes->messages = NULL;
                }
            }
        }
    #endif
        break;

#ifndef NO_CERTS
    case certificate_request:
        WOLFSSL_MSG("processing certificate request");
        ret = DoCertificateRequest(ssl, input, inOutIdx, size);
        break;
#endif

    case server_key_exchange:
        WOLFSSL_MSG("processing server key exchange");
        ret = DoServerKeyExchange(ssl, input, inOutIdx, size);
        break;

#ifdef HAVE_SESSION_TICKET
    case session_ticket:
        WOLFSSL_MSG("processing session ticket");
        ret = DoSessionTicket(ssl, input, inOutIdx, size);
        break;
#endif /* HAVE_SESSION_TICKET */
#endif

#if !defined(NO_CERTS) && (!defined(NO_WOLFSSL_CLIENT) || \
                                               !defined(WOLFSSL_NO_CLIENT_AUTH))
    case certificate:
        WOLFSSL_MSG("processing certificate");
        ret = DoCertificate(ssl, input, inOutIdx, size);
        break;

    case certificate_status:
        WOLFSSL_MSG("processing certificate status");
        ret = DoCertificateStatus(ssl, input, inOutIdx, size);
        break;
#endif

    case server_hello_done:
        WOLFSSL_MSG("processing server hello done");
    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "ServerHelloDone");
        if (ssl->toInfoOn)
            AddLateName("ServerHelloDone", &ssl->timeoutInfo);
    #endif
        ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
        if (IsEncryptionOn(ssl, 0)) {
            *inOutIdx += ssl->keys.padSz;
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMRead)
                *inOutIdx += MacSize(ssl);
        #endif
        }
        break;

    case finished:
        WOLFSSL_MSG("processing finished");
        ret = DoFinished(ssl, input, inOutIdx, size, totalSz, NO_SNIFF);
        break;

#ifndef NO_WOLFSSL_SERVER
    case client_hello:
        WOLFSSL_MSG("processing client hello");
        ret = DoClientHello(ssl, input, inOutIdx, size);
    #if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
        if (ssl->options.resuming || !ssl->options.verifyPeer || \
                     !IsAtLeastTLSv1_2(ssl) || IsAtLeastTLSv1_3(ssl->version)) {
        #if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
            if (ret != WC_PENDING_E && ret != OCSP_WANT_READ)
        #endif
            {
                ssl->options.cacheMessages = 0;
                if ((ssl->hsHashes != NULL) && (ssl->hsHashes->messages != NULL)) {
                    ForceZero(ssl->hsHashes->messages, ssl->hsHashes->length);
                    XFREE(ssl->hsHashes->messages, ssl->heap, DYNAMIC_TYPE_HASHES);
                    ssl->hsHashes->messages = NULL;
                }
            }
        }
    #endif
        /* If size == totalSz then we are in DtlsMsgDrain so no need to worry
         * about padding */
        if (IsEncryptionOn(ssl, 0)) {
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMRead) {
                word32 digestSz = MacSize(ssl);
                if (size != totalSz &&
                        *inOutIdx + ssl->keys.padSz + digestSz > totalSz)
                    return BUFFER_E;
                *inOutIdx += ssl->keys.padSz + digestSz;
            }
            else
        #endif
            {
                /* access beyond input + size should be checked against totalSz
                 */
                if (size != totalSz &&
                        *inOutIdx + ssl->keys.padSz > totalSz)
                    return BUFFER_E;
                *inOutIdx += ssl->keys.padSz;
            }
        }
        break;

    case client_key_exchange:
        WOLFSSL_MSG("processing client key exchange");
        ret = DoClientKeyExchange(ssl, input, inOutIdx, size);
        break;

#if (!defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
                        defined(HAVE_ED448)) && !defined(WOLFSSL_NO_CLIENT_AUTH)
    case certificate_verify:
        WOLFSSL_MSG("processing certificate verify");
        ret = DoCertificateVerify(ssl, input, inOutIdx, size);
        break;
#endif /* (!NO_RSA || ECC || ED25519 || ED448) && !WOLFSSL_NO_CLIENT_AUTH */

#endif /* !NO_WOLFSSL_SERVER */

    default:
        WOLFSSL_MSG("Unknown handshake message type");
        ret = UNKNOWN_HANDSHAKE_TYPE;
        break;
    }
    if (ret == 0 && expectedIdx != *inOutIdx) {
        WOLFSSL_MSG("Extra data in handshake message");
        if (!ssl->options.dtls)
            SendAlert(ssl, alert_fatal, decode_error);
        ret = DECODE_E;
        WOLFSSL_ERROR_VERBOSE(ret);
    }

#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
    /* if async, offset index so this msg will be processed again */
    if ((ret == WC_PENDING_E || ret == OCSP_WANT_READ) && *inOutIdx > 0) {
        *inOutIdx -= HANDSHAKE_HEADER_SZ;
    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            *inOutIdx -= DTLS_HANDSHAKE_EXTRA;
        }
    #endif
    }

    /* make sure async error is cleared */
    if (ret == 0 && (ssl->error == WC_PENDING_E || ssl->error == OCSP_WANT_READ)) {
        ssl->error = 0;
    }
#endif /* WOLFSSL_ASYNC_CRYPT || WOLFSSL_NONBLOCK_OCSP */

#ifdef WOLFSSL_DTLS
    if (ret == 0) {
        if (type == client_hello) {
            /* Advance expected number only if cookie exchange complete */
            if (ssl->msgsReceived.got_client_hello)
                ssl->keys.dtls_expected_peer_handshake_number =
                    ssl->keys.dtls_peer_handshake_number + 1;
        }
        else if (type != finished) {
            ssl->keys.dtls_expected_peer_handshake_number++;
        }
    }
#endif

    WOLFSSL_LEAVE("DoHandShakeMsgType()", ret);
    return ret;
}


static int DoHandShakeMsg(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                          word32 totalSz)
{
    int    ret = 0;
    word32 inputLength;

    WOLFSSL_ENTER("DoHandShakeMsg()");

    if (ssl->arrays == NULL) {
        byte   type;
        word32 size;

        if (GetHandShakeHeader(ssl,input,inOutIdx,&type, &size, totalSz) != 0) {
            WOLFSSL_ERROR_VERBOSE(PARSE_ERROR);
            return PARSE_ERROR;
        }

        return DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);
    }

    inputLength = ssl->buffers.inputBuffer.length - *inOutIdx;

    /* If there is a pending fragmented handshake message,
     * pending message size will be non-zero. */
    if (ssl->arrays->pendingMsgSz == 0) {
        byte   type;
        word32 size;

        if (GetHandShakeHeader(ssl, input, inOutIdx, &type, &size,
                               totalSz) != 0) {
            WOLFSSL_ERROR_VERBOSE(PARSE_ERROR);
            return PARSE_ERROR;
        }

        /* Cap the maximum size of a handshake message to something reasonable.
         * By default is the maximum size of a certificate message assuming
         * nine 2048-bit RSA certificates in the chain. */
        if (size > MAX_HANDSHAKE_SZ) {
            WOLFSSL_MSG("Handshake message too large");
            WOLFSSL_ERROR_VERBOSE(HANDSHAKE_SIZE_ERROR);
            return HANDSHAKE_SIZE_ERROR;
        }

        /* size is the size of the certificate message payload */
        if (inputLength - HANDSHAKE_HEADER_SZ < size) {
            ssl->arrays->pendingMsgType = type;
            ssl->arrays->pendingMsgSz = size + HANDSHAKE_HEADER_SZ;
            ssl->arrays->pendingMsg = (byte*)XMALLOC(size + HANDSHAKE_HEADER_SZ,
                                                     ssl->heap,
                                                     DYNAMIC_TYPE_ARRAYS);
            if (ssl->arrays->pendingMsg == NULL)
                return MEMORY_E;
            XMEMCPY(ssl->arrays->pendingMsg,
                    input + *inOutIdx - HANDSHAKE_HEADER_SZ,
                    inputLength);
            ssl->arrays->pendingMsgOffset = inputLength;
            *inOutIdx += inputLength - HANDSHAKE_HEADER_SZ;
            return 0;
        }

        ret = DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);
    }
    else {
        word32 pendSz =
            ssl->arrays->pendingMsgSz - ssl->arrays->pendingMsgOffset;

        /* Catch the case where there may be the remainder of a fragmented
         * handshake message and the next handshake message in the same
         * record. */
        if (inputLength > pendSz)
            inputLength = pendSz;

    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ssl->error != WC_PENDING_E)
    #endif
        {
            /* for async this copy was already done, do not replace, since
             * contents may have been changed for inline operations */
            XMEMCPY(ssl->arrays->pendingMsg + ssl->arrays->pendingMsgOffset,
                    input + *inOutIdx, inputLength);
        }
        ssl->arrays->pendingMsgOffset += inputLength;
        *inOutIdx += inputLength;

        if (ssl->arrays->pendingMsgOffset == ssl->arrays->pendingMsgSz)
        {
            word32 idx = HANDSHAKE_HEADER_SZ;
            ret = DoHandShakeMsgType(ssl,
                                     ssl->arrays->pendingMsg,
                                     &idx, ssl->arrays->pendingMsgType,
                                     ssl->arrays->pendingMsgSz - idx,
                                     ssl->arrays->pendingMsgSz);
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E) {
                /* setup to process fragment again */
                ssl->arrays->pendingMsgOffset -= inputLength;
                *inOutIdx -= inputLength;
            }
            else
        #endif
            {
                XFREE(ssl->arrays->pendingMsg, ssl->heap, DYNAMIC_TYPE_ARRAYS);
                ssl->arrays->pendingMsg = NULL;
                ssl->arrays->pendingMsgSz = 0;
            }
        }
    }

    WOLFSSL_LEAVE("DoHandShakeMsg()", ret);
    return ret;
}

#endif /* !WOLFSSL_NO_TLS12 */

#ifdef WOLFSSL_DTLS

static int _DtlsCheckWindow(WOLFSSL* ssl)
{
    word32* window;
    word16 cur_hi, next_hi;
    word32 cur_lo, next_lo, diff;
    int curLT;
    WOLFSSL_DTLS_PEERSEQ* peerSeq = NULL;

    if (!ssl->options.haveMcast)
        peerSeq = ssl->keys.peerSeq;
    else {
#ifdef WOLFSSL_MULTICAST
        WOLFSSL_DTLS_PEERSEQ* p;
        int i;

        for (i = 0, p = ssl->keys.peerSeq;
             i < WOLFSSL_DTLS_PEERSEQ_SZ;
             i++, p++) {

            if (p->peerId == ssl->keys.curPeerId) {
                peerSeq = p;
                break;
            }
        }
#endif
    }

    if (peerSeq == NULL) {
        WOLFSSL_MSG("Could not find peer sequence");
        return 0;
    }

    if (ssl->keys.curEpoch == peerSeq->nextEpoch) {
        next_hi = peerSeq->nextSeq_hi;
        next_lo = peerSeq->nextSeq_lo;
        window = peerSeq->window;
    }
    else if (ssl->keys.curEpoch == peerSeq->nextEpoch - 1) {
        next_hi = peerSeq->prevSeq_hi;
        next_lo = peerSeq->prevSeq_lo;
        window = peerSeq->prevWindow;
    }
    else {
        return 0;
    }

    cur_hi = ssl->keys.curSeq_hi;
    cur_lo = ssl->keys.curSeq_lo;

    /* If the difference between next and cur is > 2^32, way outside window. */
    if ((cur_hi > next_hi + 1) || (next_hi > cur_hi + 1)) {
        WOLFSSL_MSG("Current record from way too far in the future.");
        return 0;
    }

    if (cur_hi == next_hi) {
        curLT = cur_lo < next_lo;
        diff = curLT ? next_lo - cur_lo : cur_lo - next_lo;
    }
    else {
        curLT = cur_hi < next_hi;
        diff = curLT ? cur_lo - next_lo : next_lo - cur_lo;
    }

    /* Check to see that the next value is greater than the number of messages
     * trackable in the window, and that the difference between the next
     * expected sequence number and the received sequence number is inside the
     * window. */
    if ((next_hi || next_lo > DTLS_SEQ_BITS) &&
        curLT && (diff > DTLS_SEQ_BITS)) {

        WOLFSSL_MSG("Current record sequence number from the past.");
        return 0;
    }
#ifdef WOLFSSL_DTLS_DISALLOW_FUTURE
    else if (!curLT && (diff > DTLS_SEQ_BITS)) {
        WOLFSSL_MSG("Rejecting message too far into the future.");
        return 0;
    }
#endif
    else if (curLT) {
        word32 idx;
        word32 newDiff;
        if (diff == 0) {
            WOLFSSL_MSG("DTLS sanity check failed");
            return 0;
        }
        diff--;
        idx = diff / DTLS_WORD_BITS;
        newDiff = diff % DTLS_WORD_BITS;

        /* verify idx is valid for window array */
        if (idx >= WOLFSSL_DTLS_WINDOW_WORDS) {
            WOLFSSL_MSG("Invalid DTLS windows index");
            return 0;
        }

        if (window[idx] & (1 << newDiff)) {
            WOLFSSL_MSG("Current record sequence number already received.");
            return 0;
        }
    }

    return 1;
}

#ifdef WOLFSSL_DTLS13
static WC_INLINE int Dtls13CheckWindow(WOLFSSL* ssl)
{
    w64wrapper nextSeq, seq;
    w64wrapper diff64;
    word32 *window;
    int wordOffset;
    int wordIndex;
    word32 diff;

    if (ssl->dtls13DecryptEpoch == NULL) {
        WOLFSSL_MSG("Can't find decrypting epoch");
        return 0;
    }

    nextSeq = ssl->dtls13DecryptEpoch->nextPeerSeqNumber;
    window = ssl->dtls13DecryptEpoch->window;
    seq = ssl->keys.curSeq;

    if (w64GTE(seq, nextSeq))
        return 1;

    /* seq < nextSeq, nextSeq - seq */
    diff64 = w64Sub(nextSeq, seq);

    /* diff >= DTLS_SEQ_BITS, outside of the window */
    if (w64GT(diff64, w64From32(0, DTLS_SEQ_BITS)))
        return 0;

    /* we are assuming DTLS_SEQ_BITS <= 2**32 */
    diff = w64GetLow32(diff64);

    /* zero based index */
    diff--;

    wordIndex = ((int)diff) / DTLS_WORD_BITS;
    wordOffset = ((int)diff) % DTLS_WORD_BITS;

    if (window[wordIndex] & (1 << wordOffset))
        return 0;

    return 1;
}

#endif /* WOLFSSL_DTLS13 */

#ifdef WOLFSSL_MULTICAST
static WC_INLINE word32 UpdateHighwaterMark(word32 cur, word32 first,
                                         word32 second, word32 high)
{
    word32 newCur = 0;

    if (cur < first)
        newCur = first;
    else if (cur < second)
        newCur = second;
    else if (cur < high)
        newCur = high;

    return newCur;
}
#endif /* WOLFSSL_MULTICAST */

/* diff is the difference between the message sequence and the
 * expected sequence number. 0 is special where it is an overflow. */
static void _DtlsUpdateWindowGTSeq(word32 diff, word32* window)
{
    word32 idx, temp, i;
    word32 oldWindow[WOLFSSL_DTLS_WINDOW_WORDS];

    if (diff == 0 || diff >= DTLS_SEQ_BITS)
        XMEMSET(window, 0, DTLS_SEQ_SZ);
    else {
        temp = 0;
        idx = diff / DTLS_WORD_BITS;
        diff %= DTLS_WORD_BITS;

        XMEMCPY(oldWindow, window, sizeof(oldWindow));

        for (i = 0; i < WOLFSSL_DTLS_WINDOW_WORDS; i++) {
            if (i < idx)
                window[i] = 0;
            else {
                temp |= (oldWindow[i-idx] << diff);
                window[i] = temp;
                if (diff > 0)
                    temp = oldWindow[i-idx] >> (DTLS_WORD_BITS - diff);
                else
                    temp = 0;
            }
        }
    }
    window[0] |= 1;
}

int wolfSSL_DtlsUpdateWindow(word16 cur_hi, word32 cur_lo,
        word16* next_hi, word32* next_lo, word32 *window)
{
    word32 diff;
    int curLT;

    if (cur_hi == *next_hi) {
        curLT = cur_lo < *next_lo;
        diff = curLT ? *next_lo - cur_lo : cur_lo - *next_lo;
    }
    else {
        if (cur_hi > *next_hi + 1) {
            /* reset window */
            _DtlsUpdateWindowGTSeq(0, window);
            *next_lo = cur_lo + 1;
            if (*next_lo == 0)
                *next_hi = cur_hi + 1;
            else
                *next_hi = cur_hi;
            return 1;
        }
        else if (*next_hi > cur_hi + 1) {
            return 1;
        }
        else {
            curLT = cur_hi < *next_hi;
            if (curLT) {
                if (*next_lo < DTLS_SEQ_BITS &&
                        cur_lo >= (((word32)0xFFFFFFFF) - DTLS_SEQ_BITS)) {
                    /* diff here can still result in a difference that can not
                     * be stored in the window. The index is checked against
                     * WOLFSSL_DTLS_WINDOW_WORDS later. */
                    diff = *next_lo + ((word32)0xFFFFFFFF - cur_lo) + 1;
                }
                else {
                    /* Too far back to update */
                    return 1;
                }
            }
            else {
                if (*next_lo >= (((word32)0xFFFFFFFF) - DTLS_SEQ_BITS) &&
                        cur_lo < DTLS_SEQ_BITS) {
                    /* diff here can still result in a difference that can not
                     * be stored in the window. The index is checked against
                     * WOLFSSL_DTLS_WINDOW_WORDS later. */
                    diff = cur_lo - *next_lo;
                }
                else {
                    _DtlsUpdateWindowGTSeq(0, window);
                    *next_lo = cur_lo + 1;
                    if (*next_lo == 0)
                        *next_hi = cur_hi + 1;
                    else
                        *next_hi = cur_hi;
                    return 1;
                }
            }
        }
    }

    if (curLT) {
        word32 idx;

        diff--;
        idx = diff / DTLS_WORD_BITS;
        diff %= DTLS_WORD_BITS;

        if (idx < WOLFSSL_DTLS_WINDOW_WORDS)
            window[idx] |= (1 << diff);
    }
    else {
        _DtlsUpdateWindowGTSeq(diff + 1, window);
        *next_lo = cur_lo + 1;
        if (*next_lo == 0)
            *next_hi = cur_hi + 1;
        else
            *next_hi = cur_hi;
    }

    return 1;
}

static int _DtlsUpdateWindow(WOLFSSL* ssl)
{
    WOLFSSL_DTLS_PEERSEQ* peerSeq = ssl->keys.peerSeq;
    word16 *next_hi;
    word32 *next_lo;
    word32* window;

#ifdef WOLFSSL_MULTICAST
    word32 cur_lo = ssl->keys.curSeq_lo;

    if (ssl->options.haveMcast) {
        WOLFSSL_DTLS_PEERSEQ* p;
        int i;

        peerSeq = NULL;
        for (i = 0, p = ssl->keys.peerSeq;
             i < WOLFSSL_DTLS_PEERSEQ_SZ;
             i++, p++) {

            if (p->peerId == ssl->keys.curPeerId) {
                peerSeq = p;
                break;
            }
        }

        if (peerSeq == NULL) {
            WOLFSSL_MSG("Couldn't find that peer ID to update window.");
            return 0;
        }

        if (p->highwaterMark && cur_lo >= p->highwaterMark) {
            int cbError = 0;

            if (ssl->ctx->mcastHwCb)
                cbError = ssl->ctx->mcastHwCb(p->peerId,
                                              ssl->ctx->mcastMaxSeq,
                                              cur_lo, ssl->mcastHwCbCtx);
            if (cbError) {
                WOLFSSL_MSG("Multicast highwater callback returned an error.");
                return MCAST_HIGHWATER_CB_E;
            }

            p->highwaterMark = UpdateHighwaterMark(cur_lo,
                                                   ssl->ctx->mcastFirstSeq,
                                                   ssl->ctx->mcastSecondSeq,
                                                   ssl->ctx->mcastMaxSeq);
        }
    }
#endif

    if (ssl->keys.curEpoch == peerSeq->nextEpoch) {
        next_hi = &peerSeq->nextSeq_hi;
        next_lo = &peerSeq->nextSeq_lo;
        window = peerSeq->window;
    }
    else {
        next_hi = &peerSeq->prevSeq_hi;
        next_lo = &peerSeq->prevSeq_lo;
        window = peerSeq->prevWindow;
    }

    return wolfSSL_DtlsUpdateWindow(ssl->keys.curSeq_hi, ssl->keys.curSeq_lo,
            next_hi, next_lo, window);
}

#ifdef WOLFSSL_DTLS13
static WC_INLINE int Dtls13UpdateWindow(WOLFSSL* ssl)
{
    w64wrapper nextSeq, seq;
    w64wrapper diff64;
    word32 *window;
    int wordOffset;
    int wordIndex;
    word32 diff;

    if (ssl->dtls13DecryptEpoch == NULL) {
        WOLFSSL_MSG("Can't find decrypting Epoch");
        return BAD_STATE_E;
    }

    nextSeq = ssl->dtls13DecryptEpoch->nextPeerSeqNumber;
    window = ssl->dtls13DecryptEpoch->window;
    seq = ssl->keys.curSeq;

    /* seq < nextSeq */
    if (w64LT(seq, nextSeq)) {
        diff64 = w64Sub(nextSeq, seq);

        /* zero based index */
        w64Decrement(&diff64);

        /* FIXME: check that diff64 < DTLS_WORDS_BITS */
        diff = w64GetLow32(diff64);
        wordIndex = ((int)diff) / DTLS_WORD_BITS;
        wordOffset = ((int)diff) % DTLS_WORD_BITS;

        if (wordIndex >= WOLFSSL_DTLS_WINDOW_WORDS) {
            WOLFSSL_MSG("Invalid sequence number to Dtls13UpdateWindow");
            return BAD_STATE_E;
        }

        window[wordIndex] |= (1 << wordOffset);
        return 1;
    }

    /* seq >= nextSeq, seq - nextSeq */
    diff64 = w64Sub(seq, nextSeq);

    /* as we are considering nextSeq inside the window, we should add + 1 */
    w64Increment(&diff64);
    _DtlsUpdateWindowGTSeq(w64GetLow32(diff64), window);

    w64Increment(&seq);
    ssl->dtls13DecryptEpoch->nextPeerSeqNumber = seq;

    return 1;
}
#endif /* WOLFSSL_DTLS13 */


int DtlsMsgDrain(WOLFSSL* ssl)
{
    DtlsMsg* item = ssl->dtls_rx_msg_list;
    int ret = 0;

    WOLFSSL_ENTER("DtlsMsgDrain()");

    /* While there is an item in the store list, and it is the expected
     * message, and it is complete, and there hasn't been an error in the
     * last message... */
    while (item != NULL &&
            ssl->keys.dtls_expected_peer_handshake_number == item->seq &&
            item->ready && ret == 0) {
        word32 idx = 0;

    #ifdef WOLFSSL_NO_TLS12
        ret = DoTls13HandShakeMsgType(ssl, item->fullMsg, &idx, item->type,
                                      item->sz, item->sz);
    #else
        ret = DoHandShakeMsgType(ssl, item->fullMsg, &idx, item->type,
                                      item->sz, item->sz);
    #endif
        if (ret == 0) {
            DtlsTxMsgListClean(ssl);
        }
    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ret == WC_PENDING_E) {
            break;
        }
    #endif
        ssl->dtls_rx_msg_list = item->next;
        DtlsMsgDelete(item, ssl->heap);
        item = ssl->dtls_rx_msg_list;
        ssl->dtls_rx_msg_list_sz--;
    }

    WOLFSSL_LEAVE("DtlsMsgDrain()", ret);
    return ret;
}


static int DoDtlsHandShakeMsg(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                          word32 totalSz)
{
    byte type;
    word32 size;
    word32 fragOffset, fragSz;
    int ret = 0;
    int ignoreFinished = 0;

    WOLFSSL_ENTER("DoDtlsHandShakeMsg()");

    /* parse header */
    if (GetDtlsHandShakeHeader(ssl, input, inOutIdx, &type,
                               &size, &fragOffset, &fragSz, totalSz) != 0) {
        WOLFSSL_ERROR(PARSE_ERROR);
        return PARSE_ERROR;
    }

    /* Cap the maximum size of a handshake message to something reasonable.
     * By default is the maximum size of a certificate message assuming
     * nine 2048-bit RSA certificates in the chain. */
    if (size > MAX_HANDSHAKE_SZ) {
        WOLFSSL_MSG("Handshake message too large");
        return HANDSHAKE_SIZE_ERROR;
    }

    /* check that we have complete fragment */
    if (*inOutIdx + fragSz > totalSz) {
        WOLFSSL_ERROR(INCOMPLETE_DATA);
        return INCOMPLETE_DATA;
    }

    /* check that the fragment is contained in the message */
    if (fragOffset + fragSz > size) {
        WOLFSSL_ERROR(LENGTH_ERROR);
        return LENGTH_ERROR;
    }

    if (type == finished && ssl->keys.dtls_peer_handshake_number >=
                            ssl->keys.dtls_expected_peer_handshake_number &&
                            ssl->keys.curEpoch == ssl->keys.dtls_epoch) {
        /* finished msg should be ignore from the current epoch
         * if it comes from a previous handshake */
        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            ignoreFinished = ssl->options.connectState < FINISHED_DONE;
        }
        else {
            ignoreFinished = ssl->options.acceptState < ACCEPT_FINISHED_DONE;
        }
    }

#if !defined(NO_WOLFSSL_SERVER)
    if (ssl->options.side == WOLFSSL_SERVER_END &&
            ssl->options.acceptState < ACCEPT_FIRST_REPLY_DONE &&
            type != client_hello) {
        WOLFSSL_MSG("Ignoring other messages before we verify a ClientHello");
        *inOutIdx = totalSz;
        return 0;
    }
#endif

    /* Check the handshake sequence number first. If out of order,
     * add the current message to the list. If the message is in order,
     * but it is a fragment, add the current message to the list, then
     * check the head of the list to see if it is complete, if so, pop
     * it out as the current message. If the message is complete and in
     * order, process it. Check the head of the list to see if it is in
     * order, if so, process it. (Repeat until list exhausted.) If the
     * head is out of order, return for more processing.
     */
    if (ssl->keys.dtls_peer_handshake_number >
            ssl->keys.dtls_expected_peer_handshake_number &&
            /* Only client_hello shouldn't be ignored if the handshake
             * num is greater */
            (type == client_hello ||
                    ssl->options.handShakeState != HANDSHAKE_DONE) &&
            !ignoreFinished) {
        /* Current message is out of order. It will get stored in the list.
         * Storing also takes care of defragmentation. If the messages is a
         * client hello, we need to process this out of order; the server
         * is not supposed to keep state, but the second client hello will
         * have a different handshake sequence number than is expected, and
         * the server shouldn't be expecting any particular handshake sequence
         * number. (If the cookie changes multiple times in quick succession,
         * the client could be sending multiple new client hello messages
         * with newer and newer cookies.) */
        if (type != client_hello) {
            WOLFSSL_MSG("Current message is out of order");
            if (ssl->dtls_rx_msg_list_sz >= DTLS_POOL_SZ) {
                WOLFSSL_MSG("Reached rx msg limit error");
                return DTLS_TOO_MANY_FRAGMENTS_E;
            }

            DtlsMsgStore(ssl, ssl->keys.curEpoch,
                         ssl->keys.dtls_peer_handshake_number,
                         input + *inOutIdx, size, type,
                         fragOffset, fragSz, ssl->heap);
            *inOutIdx += fragSz;
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMRead && ssl->keys.curEpoch != 0) {
                word32 digestSz = MacSize(ssl);
                if (*inOutIdx + ssl->keys.padSz + digestSz > totalSz) {
                    WOLFSSL_ERROR(BUFFER_E);
                    return BUFFER_E;
                }
                *inOutIdx += digestSz;
            }
            else
            #endif
            {
                if (*inOutIdx + ssl->keys.padSz > totalSz) {
                    WOLFSSL_ERROR(BUFFER_E);
                    return BUFFER_E;
                }
            }
            *inOutIdx += ssl->keys.padSz;
            ret = 0;
            #ifndef WOLFSSL_DTLS_RESEND_ONLY_TIMEOUT
            /* If we receive an out of order last flight msg then retransmit */
            if (type == server_hello_done || type == finished) {
                ret = DtlsMsgPoolSend(ssl, 0);
            }
            #endif
        }
        else {
            if (fragSz < size) {
                /* a fragmented ClientHello, very probably forged or
                   erroneous. Even if the packet is valid, we don't want to save
                   state while processing a ClientHello to avoid DoS attacks */
                WOLFSSL_MSG("Ignoring datagram with fragmented ClientHello");
                *inOutIdx = totalSz;
            }
            else {
            #ifdef WOLFSSL_NO_TLS12
                ret = DoTls13HandShakeMsgType(ssl, input, inOutIdx, type, size,
                    totalSz);
            #else
                ret = DoHandShakeMsgType(ssl, input, inOutIdx, type, size,
                    totalSz);
            #endif
            }
        }
    }
    else if (ssl->keys.dtls_peer_handshake_number <
                ssl->keys.dtls_expected_peer_handshake_number ||
            /* ignore all handshake messages if we are done with the
             * handshake */
            (ssl->keys.dtls_peer_handshake_number >
                ssl->keys.dtls_expected_peer_handshake_number &&
                ssl->options.handShakeState == HANDSHAKE_DONE) ||
            ignoreFinished) {
        /* Already saw this message and processed it. It can be ignored. */
        WOLFSSL_MSG("Already saw this message and processed it");
        *inOutIdx += fragSz;
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead && ssl->keys.curEpoch != 0) {
            word32 digestSz = MacSize(ssl);
            if (*inOutIdx + ssl->keys.padSz + digestSz > totalSz) {
                WOLFSSL_ERROR(BUFFER_E);
                return BUFFER_E;
            }
            *inOutIdx += digestSz;
        }
        else
        #endif
        {
            if (*inOutIdx + ssl->keys.padSz > totalSz) {
                WOLFSSL_ERROR(BUFFER_E);
                return BUFFER_E;
            }
        }
        #ifndef WOLFSSL_DTLS_RESEND_ONLY_TIMEOUT
        if (IsDtlsNotSctpMode(ssl) &&
            VerifyForDtlsMsgPoolSend(ssl, type, fragOffset)) {

            ret = DtlsMsgPoolSend(ssl, 0);
        }
        #endif
        *inOutIdx += ssl->keys.padSz;
    }
    else if (fragSz < size) {
        /* Since this branch is in order, but fragmented, dtls_rx_msg_list will
         * be pointing to the message with this fragment in it. Check it to see
         * if it is completed. */
        WOLFSSL_MSG("Branch is in order, but fragmented");

        if (type == client_hello) {
            WOLFSSL_MSG("Ignoring datagram with fragmented ClientHello");
            *inOutIdx = totalSz;
            return 0;
        }

        if (ssl->dtls_rx_msg_list_sz >= DTLS_POOL_SZ) {
            WOLFSSL_MSG("Reached rx msg limit error");
            WOLFSSL_ERROR(DTLS_TOO_MANY_FRAGMENTS_E);
            return DTLS_TOO_MANY_FRAGMENTS_E;
        }
        DtlsMsgStore(ssl, ssl->keys.curEpoch,
                     ssl->keys.dtls_peer_handshake_number,
                     input + *inOutIdx, size, type,
                     fragOffset, fragSz, ssl->heap);
        *inOutIdx += fragSz;
        *inOutIdx += ssl->keys.padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead && ssl->keys.curEpoch != 0) {
            word32 digestSz = MacSize(ssl);
            if (*inOutIdx + digestSz > totalSz) {
                WOLFSSL_ERROR(BUFFER_E);
                return BUFFER_E;
            }
            *inOutIdx += digestSz;
        }
#endif
        ret = 0;
        if (ssl->dtls_rx_msg_list != NULL && ssl->dtls_rx_msg_list->ready)
            ret = DtlsMsgDrain(ssl);
    }
    else {
        /* This branch is in order next, and a complete message. On success
         * clean the tx list. */
        WOLFSSL_MSG("Branch is in order and a complete message");

#ifdef WOLFSSL_ASYNC_CRYPT
        if (ssl->devId != INVALID_DEVID) {
            word32 idx = *inOutIdx;
            if (ssl->dtls_rx_msg_list_sz >= DTLS_POOL_SZ) {
                WOLFSSL_ERROR(BUFFER_ERROR);
                return BUFFER_ERROR;
            }
            if (idx + fragSz + ssl->keys.padSz > totalSz)
                return BUFFER_E;
            *inOutIdx = idx + fragSz + ssl->keys.padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMRead && ssl->keys.curEpoch != 0) {
                word32 digestSz = MacSize(ssl);
                if (*inOutIdx + digestSz > totalSz)
                    return BUFFER_E;
                *inOutIdx += digestSz;
            }
#endif
            /* In async mode always store the message and process it with
             * DtlsMsgDrain because in case of a WC_PENDING_E it will be
             * easier this way. */
            if (ssl->dtls_rx_msg_list_sz >= DTLS_POOL_SZ) {
                WOLFSSL_MSG("Reached rx msg limit error");
                return DTLS_TOO_MANY_FRAGMENTS_E;
            }
            DtlsMsgStore(ssl, ssl->keys.curEpoch,
                         ssl->keys.dtls_peer_handshake_number,
                         input + idx, size, type,
                         fragOffset, fragSz, ssl->heap);
            ret = DtlsMsgDrain(ssl);
        }
        else
#endif
        {
#ifdef WOLFSSL_NO_TLS12
            ret = DoTls13HandShakeMsgType(ssl, input, inOutIdx, type, size,
                                  totalSz);
#else
            ret = DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);
#endif
            if (ret == 0) {
                DtlsTxMsgListClean(ssl);
                if (ssl->dtls_rx_msg_list != NULL) {
                    ret = DtlsMsgDrain(ssl);
                }
            }
        }
    }

    WOLFSSL_LEAVE("DoDtlsHandShakeMsg()", ret);
    return ret;
}
#endif /* WOLFSSL_DTLS13 */

#ifndef WOLFSSL_NO_TLS12

#ifdef HAVE_AEAD

#if (!defined(NO_PUBLIC_GCM_SET_IV) && \
    ((defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2)))) || \
    (defined(HAVE_POLY1305) && defined(HAVE_CHACHA))
static WC_INLINE void AeadIncrementExpIV(WOLFSSL* ssl)
{
    int i;
    for (i = AEAD_MAX_EXP_SZ-1; i >= 0; i--) {
        if (++ssl->keys.aead_exp_IV[i]) return;
    }
}
#endif


#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && !defined(NO_CHAPOL_AEAD)
/* Used for the older version of creating AEAD tags with Poly1305 */
static int Poly1305TagOld(WOLFSSL* ssl, byte* additional, const byte* out,
                       byte* cipher, word16 sz, byte* tag)
{
    int ret       = 0;
    int msglen    = (sz - ssl->specs.aead_mac_size);
    word32 keySz  = 32;
    byte padding[8]; /* used to temporarily store lengths */

#ifdef CHACHA_AEAD_TEST
      printf("Using old version of poly1305 input.\n");
#endif

    if (msglen < 0)
        return INPUT_CASE_ERROR;

    if ((ret = wc_Poly1305SetKey(ssl->auth.poly1305, cipher, keySz)) != 0)
        return ret;

    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, additional,
                   AEAD_AUTH_DATA_SZ)) != 0)
        return ret;

    /* length of additional input plus padding */
    XMEMSET(padding, 0, sizeof(padding));
    padding[0] = AEAD_AUTH_DATA_SZ;
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, padding,
                    sizeof(padding))) != 0)
        return ret;


    /* add cipher info and then its length */
    XMEMSET(padding, 0, sizeof(padding));
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, out, msglen)) != 0)
        return ret;

    /* 32 bit size of cipher to 64 bit endian */
    padding[0] =  msglen        & 0xff;
    padding[1] = (msglen >>  8) & 0xff;
    padding[2] = ((word32)msglen >> 16) & 0xff;
    padding[3] = ((word32)msglen >> 24) & 0xff;
    if ((ret = wc_Poly1305Update(ssl->auth.poly1305, padding, sizeof(padding)))
        != 0)
        return ret;

    /* generate tag */
    if ((ret = wc_Poly1305Final(ssl->auth.poly1305, tag)) != 0)
        return ret;

    return ret;
}


/* When the flag oldPoly is not set this follows RFC7905. When oldPoly is set
 * the implementation follows an older draft for creating the nonce and MAC.
 * The flag oldPoly gets set automatically depending on what cipher suite was
 * negotiated in the handshake. This is able to be done because the IDs for the
 * cipher suites was updated in RFC7905 giving unique values for the older
 * draft in comparison to the more recent RFC.
 *
 * ssl   WOLFSSL structure to get cipher and TLS state from
 * out   output buffer to hold encrypted data
 * input data to encrypt
 * sz    size of input
 *
 * Return 0 on success negative values in error case
 */
int ChachaAEADEncrypt(WOLFSSL* ssl, byte* out, const byte* input,
                              word16 sz)
{
    const byte* additionalSrc = input - RECORD_HEADER_SZ;
    int ret       = 0;
    word32 msgLen = (sz - ssl->specs.aead_mac_size);
    byte tag[POLY1305_AUTH_SZ];
    byte add[AEAD_AUTH_DATA_SZ];
    byte nonce[CHACHA20_NONCE_SZ];
    byte poly[CHACHA20_256_KEY_SIZE]; /* generated key for poly1305 */
    #ifdef CHACHA_AEAD_TEST
        int i;
    #endif
    Keys* keys = &ssl->keys;

    XMEMSET(tag,   0, sizeof(tag));
    XMEMSET(nonce, 0, sizeof(nonce));
    XMEMSET(poly,  0, sizeof(poly));
    XMEMSET(add,   0, sizeof(add));

#if defined(WOLFSSL_DTLS) && defined(HAVE_SECURE_RENEGOTIATION)
    /*
     * For epochs 2+:
     * * use ssl->secure_renegotiation when encrypting the current epoch as it
     *   has the current epoch cipher material
     * * use PREV_ORDER if encrypting the epoch not in
     *   ssl->secure_renegotiation
     */
    /* opaque SEQ number stored for AD */
    if (ssl->options.dtls && DtlsSCRKeysSet(ssl)) {
        if (ssl->keys.dtls_epoch ==
                    ssl->secure_renegotiation->tmp_keys.dtls_epoch) {
            keys = &ssl->secure_renegotiation->tmp_keys;
            WriteSEQ(ssl, CUR_ORDER, add);
        }
        else
            WriteSEQ(ssl, PREV_ORDER, add);
    }
    else
#endif
        WriteSEQ(ssl, CUR_ORDER, add);

    if (ssl->options.oldPoly != 0) {
        /* get nonce. SEQ should not be incremented again here */
        XMEMCPY(nonce + CHACHA20_OLD_OFFSET, add, OPAQUE32_LEN * 2);
    }

    /* Store the type, version. Unfortunately, they are in
     * the input buffer ahead of the plaintext. */
    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            additionalSrc -= DTLS_HANDSHAKE_EXTRA;
        }
    #endif

    /* add TLS message size to additional data */
    add[AEAD_AUTH_DATA_SZ - 2] = (msgLen >> 8) & 0xff;
    add[AEAD_AUTH_DATA_SZ - 1] =  msgLen       & 0xff;

    XMEMCPY(add + AEAD_TYPE_OFFSET, additionalSrc, 3);

    #ifdef CHACHA_AEAD_TEST
        printf("Encrypt Additional : ");
        for (i = 0; i < AEAD_AUTH_DATA_SZ; i++) {
            printf("%02x", add[i]);
        }
        printf("\n\n");
        printf("input before encryption :\n");
        for (i = 0; i < sz; i++) {
            printf("%02x", input[i]);
            if ((i + 1) % 16 == 0)
                printf("\n");
        }
        printf("\n");
    #endif

    if (ssl->options.oldPoly == 0) {
        /* nonce is formed by 4 0x00 byte padded to the left followed by 8 byte
         * record sequence number XORed with client_write_IV/server_write_IV */
        XMEMCPY(nonce, keys->aead_enc_imp_IV, CHACHA20_IMP_IV_SZ);
        nonce[4]  ^= add[0];
        nonce[5]  ^= add[1];
        nonce[6]  ^= add[2];
        nonce[7]  ^= add[3];
        nonce[8]  ^= add[4];
        nonce[9]  ^= add[5];
        nonce[10] ^= add[6];
        nonce[11] ^= add[7];
    }
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("ChachaAEADEncrypt nonce", nonce, CHACHA20_NONCE_SZ);
#endif

    /* set the nonce for chacha and get poly1305 key */
    if ((ret = wc_Chacha_SetIV(ssl->encrypt.chacha, nonce, 0)) != 0) {
        ForceZero(nonce, CHACHA20_NONCE_SZ);
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(nonce, CHACHA20_NONCE_SZ);
    #endif
        return ret;
    }

    /* create Poly1305 key using chacha20 keystream */
    if ((ret = wc_Chacha_Process(ssl->encrypt.chacha, poly,
                                                    poly, sizeof(poly))) != 0) {
        ForceZero(nonce, CHACHA20_NONCE_SZ);
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(nonce, CHACHA20_NONCE_SZ);
    #endif
        return ret;
    }
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("ChachaAEADEncrypt poly", poly, CHACHA20_256_KEY_SIZE);
#endif

    /* set the counter after getting poly1305 key */
    if ((ret = wc_Chacha_SetIV(ssl->encrypt.chacha, nonce, 1)) != 0) {
        ForceZero(nonce, CHACHA20_NONCE_SZ);
        ForceZero(poly, sizeof(poly));
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(nonce, CHACHA20_NONCE_SZ);
        wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
    #endif
        return ret;
    }
    ForceZero(nonce, CHACHA20_NONCE_SZ); /* done with nonce, clear it */
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(nonce, CHACHA20_NONCE_SZ);
#endif

    /* encrypt the plain text */
    if ((ret = wc_Chacha_Process(ssl->encrypt.chacha, out,
                                                         input, msgLen)) != 0) {
        ForceZero(poly, sizeof(poly));
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
    #endif
        return ret;
    }

    /* get the poly1305 tag using either old padding scheme or more recent */
    if (ssl->options.oldPoly != 0) {
        if ((ret = Poly1305TagOld(ssl, add, (const byte* )out,
                                                         poly, sz, tag)) != 0) {
            ForceZero(poly, sizeof(poly));
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
        #endif
            return ret;
        }
    }
    else {
        if ((ret = wc_Poly1305SetKey(ssl->auth.poly1305, poly,
                                                          sizeof(poly))) != 0) {
            ForceZero(poly, sizeof(poly));
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
        #endif
            return ret;
        }
        if ((ret = wc_Poly1305_MAC(ssl->auth.poly1305, add,
                            sizeof(add), out, msgLen, tag, sizeof(tag))) != 0) {
            ForceZero(poly, sizeof(poly));
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
        #endif
            return ret;
        }
    }
    ForceZero(poly, sizeof(poly)); /* done with poly1305 key, clear it */
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
#endif

    /* append tag to ciphertext */
    XMEMCPY(out + msgLen, tag, sizeof(tag));

    AeadIncrementExpIV(ssl);

    #ifdef CHACHA_AEAD_TEST
       printf("mac tag :\n");
        for (i = 0; i < 16; i++) {
           printf("%02x", tag[i]);
           if ((i + 1) % 16 == 0)
               printf("\n");
        }
       printf("\n\noutput after encrypt :\n");
        for (i = 0; i < sz; i++) {
           printf("%02x", out[i]);
           if ((i + 1) % 16 == 0)
               printf("\n");
        }
        printf("\n");
    #endif

    return ret;
}


/* When the flag oldPoly is not set this follows RFC7905. When oldPoly is set
 * the implementation follows an older draft for creating the nonce and MAC.
 * The flag oldPoly gets set automatically depending on what cipher suite was
 * negotiated in the handshake. This is able to be done because the IDs for the
 * cipher suites was updated in RFC7905 giving unique values for the older
 * draft in comparison to the more recent RFC.
 *
 * ssl   WOLFSSL structure to get cipher and TLS state from
 * plain output buffer to hold decrypted data
 * input data to decrypt
 * sz    size of input
 *
 * Return 0 on success negative values in error case
 */
static int ChachaAEADDecrypt(WOLFSSL* ssl, byte* plain, const byte* input,
                           word16 sz)
{
    byte add[AEAD_AUTH_DATA_SZ];
    byte nonce[CHACHA20_NONCE_SZ];
    byte tag[POLY1305_AUTH_SZ];
    byte poly[CHACHA20_256_KEY_SIZE]; /* generated key for mac */
    int ret    = 0;
    int msgLen = (sz - ssl->specs.aead_mac_size);
    Keys* keys = &ssl->keys;

    #ifdef CHACHA_AEAD_TEST
       int i;
       printf("input before decrypt :\n");
        for (i = 0; i < sz; i++) {
           printf("%02x", input[i]);
           if ((i + 1) % 16 == 0)
               printf("\n");
        }
        printf("\n");
    #endif

    XMEMSET(tag,   0, sizeof(tag));
    XMEMSET(poly,  0, sizeof(poly));
    XMEMSET(nonce, 0, sizeof(nonce));
    XMEMSET(add,   0, sizeof(add));

#if defined(WOLFSSL_DTLS) && defined(HAVE_SECURE_RENEGOTIATION)
    /*
     * For epochs 2+:
     * * use ssl->secure_renegotiation when decrypting the latest epoch as it
     *   has the latest epoch cipher material
     */
    if (ssl->options.dtls && DtlsSCRKeysSet(ssl) &&
        ssl->keys.curEpoch == ssl->secure_renegotiation->tmp_keys.dtls_epoch)
        keys = &ssl->secure_renegotiation->tmp_keys;
#endif

    /* sequence number field is 64-bits */
    WriteSEQ(ssl, PEER_ORDER, add);

    if (ssl->options.oldPoly != 0) {
        /* get nonce, SEQ should not be incremented again here */
        XMEMCPY(nonce + CHACHA20_OLD_OFFSET, add, OPAQUE32_LEN * 2);
    }

    /* get AD info */
    /* Store the type, version. */
    add[AEAD_TYPE_OFFSET] = ssl->curRL.type;
    add[AEAD_VMAJ_OFFSET] = ssl->curRL.pvMajor;
    add[AEAD_VMIN_OFFSET] = ssl->curRL.pvMinor;

    /* add TLS message size to additional data */
    add[AEAD_AUTH_DATA_SZ - 2] = (msgLen >> 8) & 0xff;
    add[AEAD_AUTH_DATA_SZ - 1] =  msgLen       & 0xff;

    #ifdef CHACHA_AEAD_TEST
        printf("Decrypt Additional : ");
        for (i = 0; i < AEAD_AUTH_DATA_SZ; i++) {
            printf("%02x", add[i]);
        }
        printf("\n\n");
    #endif

    if (ssl->options.oldPoly == 0) {
        /* nonce is formed by 4 0x00 byte padded to the left followed by 8 byte
         * record sequence number XORed with client_write_IV/server_write_IV */
        XMEMCPY(nonce, keys->aead_dec_imp_IV, CHACHA20_IMP_IV_SZ);
        nonce[4]  ^= add[0];
        nonce[5]  ^= add[1];
        nonce[6]  ^= add[2];
        nonce[7]  ^= add[3];
        nonce[8]  ^= add[4];
        nonce[9]  ^= add[5];
        nonce[10] ^= add[6];
        nonce[11] ^= add[7];
    }
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("ChachaAEADEncrypt nonce", nonce, CHACHA20_NONCE_SZ);
#endif

    /* set nonce and get poly1305 key */
    if ((ret = wc_Chacha_SetIV(ssl->decrypt.chacha, nonce, 0)) != 0) {
        ForceZero(nonce, CHACHA20_NONCE_SZ);
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(nonce, CHACHA20_NONCE_SZ);
    #endif
        return ret;
    }

    /* use chacha20 keystream to get poly1305 key for tag */
    if ((ret = wc_Chacha_Process(ssl->decrypt.chacha, poly,
                                                    poly, sizeof(poly))) != 0) {
        ForceZero(nonce, CHACHA20_NONCE_SZ);
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(nonce, CHACHA20_NONCE_SZ);
    #endif
        return ret;
    }
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("ChachaAEADEncrypt poly", poly, CHACHA20_256_KEY_SIZE);
#endif

    /* set counter after getting poly1305 key */
    if ((ret = wc_Chacha_SetIV(ssl->decrypt.chacha, nonce, 1)) != 0) {
        ForceZero(nonce, CHACHA20_NONCE_SZ);
        ForceZero(poly, sizeof(poly));
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(nonce, CHACHA20_NONCE_SZ);
        wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
    #endif
        return ret;
    }
    ForceZero(nonce, CHACHA20_NONCE_SZ); /* done with nonce, clear it */
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(nonce, CHACHA20_NONCE_SZ);
#endif

    /* get the tag using Poly1305 */
    if (ssl->options.oldPoly != 0) {
        if ((ret = Poly1305TagOld(ssl, add, input, poly, sz, tag)) != 0) {
            ForceZero(poly, sizeof(poly));
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
        #endif
            return ret;
        }
    }
    else {
        if ((ret = wc_Poly1305SetKey(ssl->auth.poly1305, poly,
                                                          sizeof(poly))) != 0) {
            ForceZero(poly, sizeof(poly));
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
        #endif
            return ret;
        }
        if ((ret = wc_Poly1305_MAC(ssl->auth.poly1305, add,
                          sizeof(add), input, msgLen, tag, sizeof(tag))) != 0) {
            ForceZero(poly, sizeof(poly));
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
        #endif
            return ret;
        }
    }
    ForceZero(poly, sizeof(poly)); /* done with poly1305 key, clear it */
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(poly, CHACHA20_256_KEY_SIZE);
#endif

    /* check tag sent along with packet */
    if (ConstantCompare(input + msgLen, tag, ssl->specs.aead_mac_size) != 0) {
        WOLFSSL_MSG("MAC did not match");
        if (!ssl->options.dtls)
            SendAlert(ssl, alert_fatal, bad_record_mac);
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    /* if the tag was good decrypt message */
    if ((ret = wc_Chacha_Process(ssl->decrypt.chacha, plain,
                                                           input, msgLen)) != 0)
        return ret;

    #ifdef CHACHA_AEAD_TEST
       printf("plain after decrypt :\n");
        for (i = 0; i < sz; i++) {
           printf("%02x", plain[i]);
           if ((i + 1) % 16 == 0)
               printf("\n");
        }
        printf("\n");
    #endif

    return ret;
}
#endif /* HAVE_CHACHA && HAVE_POLY1305 && !NO_CHAPOL_AEAD*/
#endif /* HAVE_AEAD */


#if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)

#if !defined(NO_GCM_ENCRYPT_EXTRA) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
/* The following type is used to share code between AES-GCM and AES-CCM. */
    typedef int (*AesAuthEncryptFunc)(Aes* aes, byte* out,
                                       const byte* in, word32 sz,
                                       byte* iv, word32 ivSz,
                                       byte* authTag, word32 authTagSz,
                                       const byte* authIn, word32 authInSz);
    #define AES_AUTH_ENCRYPT_FUNC AesAuthEncryptFunc
    #define AES_GCM_ENCRYPT wc_AesGcmEncrypt_ex
    #define AES_CCM_ENCRYPT wc_AesCcmEncrypt_ex
#else
    #define AES_AUTH_ENCRYPT_FUNC wc_AesAuthEncryptFunc
    #define AES_GCM_ENCRYPT wc_AesGcmEncrypt
    #define AES_CCM_ENCRYPT wc_AesCcmEncrypt
#endif

#endif


static WC_INLINE int EncryptDo(WOLFSSL* ssl, byte* out, const byte* input,
    word16 sz, int asyncOkay)
{
    int ret = 0;
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV* asyncDev = NULL;
    word32 event_flags = WC_ASYNC_FLAG_CALL_AGAIN;
#else
    (void)asyncOkay;
#endif

    (void)out;
    (void)input;
    (void)sz;

    if (input == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (ssl->specs.bulk_cipher_algorithm) {
    #ifdef BUILD_ARC4
        case wolfssl_rc4:
            wc_Arc4Process(ssl->encrypt.arc4, out, input, sz);
            break;
    #endif

    #ifdef BUILD_DES3
        case wolfssl_triple_des:
        #ifdef WOLFSSL_ASYNC_CRYPT
            /* initialize event */
            asyncDev = &ssl->encrypt.des3->asyncDev;
            ret = wolfSSL_AsyncInit(ssl, asyncDev, event_flags);
            if (ret != 0)
                break;
        #endif

            ret = wc_Des3_CbcEncrypt(ssl->encrypt.des3, out, input, sz);
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E && asyncOkay) {
                ret = wolfSSL_AsyncPush(ssl, asyncDev);
            }
        #endif
            break;
    #endif

    #if defined(BUILD_AES) && defined(HAVE_AES_CBC)
        case wolfssl_aes:
        #ifdef WOLFSSL_ASYNC_CRYPT
            /* initialize event */
            asyncDev = &ssl->encrypt.aes->asyncDev;
            ret = wolfSSL_AsyncInit(ssl, asyncDev, event_flags);
            if (ret != 0)
                break;
        #endif
            ret = wc_AesCbcEncrypt(ssl->encrypt.aes, out, input, sz);
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E && asyncOkay) {
                ret = wolfSSL_AsyncPush(ssl, asyncDev);
            }
        #endif
            break;
    #endif

    #if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
        case wolfssl_aes_gcm:
        case wolfssl_aes_ccm:/* GCM AEAD macros use same size as CCM */
        {
            AES_AUTH_ENCRYPT_FUNC aes_auth_fn;
            const byte* additionalSrc;

        #ifdef WOLFSSL_ASYNC_CRYPT
            /* initialize event */
            asyncDev = &ssl->encrypt.aes->asyncDev;
            ret = wolfSSL_AsyncInit(ssl, asyncDev, event_flags);
            if (ret != 0)
                break;
        #endif

        #if defined(BUILD_AESGCM) && defined(HAVE_AESCCM)
            aes_auth_fn = (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm)
                            ? AES_GCM_ENCRYPT : AES_CCM_ENCRYPT;
        #elif defined(BUILD_AESGCM)
            aes_auth_fn = AES_GCM_ENCRYPT;
        #else
            aes_auth_fn = AES_CCM_ENCRYPT;
        #endif
            additionalSrc = input - 5;

            XMEMSET(ssl->encrypt.additional, 0, AEAD_AUTH_DATA_SZ);

            /* sequence number field is 64-bits */
            WriteSEQ(ssl, CUR_ORDER, ssl->encrypt.additional);

            /* Store the type, version. Unfortunately, they are in
             * the input buffer ahead of the plaintext. */
        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                additionalSrc -= DTLS_HANDSHAKE_EXTRA;
            }
        #endif
            XMEMCPY(ssl->encrypt.additional + AEAD_TYPE_OFFSET,
                                                        additionalSrc, 3);

            /* Store the length of the plain text minus the explicit
             * IV length minus the authentication tag size. */
            c16toa(sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                                ssl->encrypt.additional + AEAD_LEN_OFFSET);
#if !defined(NO_PUBLIC_GCM_SET_IV) && \
    ((defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2)))
            XMEMCPY(ssl->encrypt.nonce,
                                ssl->keys.aead_enc_imp_IV, AESGCM_IMP_IV_SZ);
            XMEMCPY(ssl->encrypt.nonce + AESGCM_IMP_IV_SZ,
                                ssl->keys.aead_exp_IV, AESGCM_EXP_IV_SZ);
#endif
        #ifdef HAVE_PK_CALLBACKS
            ret = NOT_COMPILED_IN;
            if (ssl->ctx && ssl->ctx->PerformTlsRecordProcessingCb) {
                ret = ssl->ctx->PerformTlsRecordProcessingCb(ssl, 1,
                         out + AESGCM_EXP_IV_SZ, input + AESGCM_EXP_IV_SZ,
                         sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                         ssl->encrypt.nonce, AESGCM_NONCE_SZ,
                         out + sz - ssl->specs.aead_mac_size,
                         ssl->specs.aead_mac_size,
                         ssl->encrypt.additional, AEAD_AUTH_DATA_SZ);
            }

            if (ret == NOT_COMPILED_IN)
        #endif /* HAVE_PK_CALLBACKS */
            {
                ret = aes_auth_fn(ssl->encrypt.aes,
                        out + AESGCM_EXP_IV_SZ, input + AESGCM_EXP_IV_SZ,
                        sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                        ssl->encrypt.nonce, AESGCM_NONCE_SZ,
                        out + sz - ssl->specs.aead_mac_size,
                        ssl->specs.aead_mac_size,
                        ssl->encrypt.additional, AEAD_AUTH_DATA_SZ);
            }

        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E && asyncOkay) {
                ret = wolfSSL_AsyncPush(ssl, asyncDev);
            }
        #endif
#if !defined(NO_PUBLIC_GCM_SET_IV) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
            XMEMCPY(out,
                    ssl->encrypt.nonce + AESGCM_IMP_IV_SZ, AESGCM_EXP_IV_SZ);
#endif
        }
        break;
    #endif /* BUILD_AESGCM || HAVE_AESCCM */

    #ifdef HAVE_CAMELLIA
        case wolfssl_camellia:
            ret = wc_CamelliaCbcEncrypt(ssl->encrypt.cam, out, input, sz);
            break;
    #endif

    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && \
        !defined(NO_CHAPOL_AEAD)
        case wolfssl_chacha:
            ret = ChachaAEADEncrypt(ssl, out, input, sz);
            break;
    #endif

    #ifdef HAVE_NULL_CIPHER
        case wolfssl_cipher_null:
            if (input != out) {
                XMEMMOVE(out, input, sz);
            }
            break;
    #endif

        default:
            WOLFSSL_MSG("wolfSSL Encrypt programming error");
            ret = ENCRYPT_ERROR;
            WOLFSSL_ERROR_VERBOSE(ret);
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    /* if async is not okay, then block */
    if (ret == WC_PENDING_E && !asyncOkay) {
        ret = wc_AsyncWait(ret, asyncDev, event_flags);
    }
#endif

    return ret;
}

static WC_INLINE int Encrypt(WOLFSSL* ssl, byte* out, const byte* input,
    word16 sz, int asyncOkay)
{
    int ret = 0;

#ifdef WOLFSSL_ASYNC_CRYPT
    if (ssl->error == WC_PENDING_E) {
        ssl->error = 0; /* clear async */
    }
#endif

    switch (ssl->encrypt.state) {
        case CIPHER_STATE_BEGIN:
        {
            if (ssl->encrypt.setup == 0) {
                WOLFSSL_MSG("Encrypt ciphers not setup");
                WOLFSSL_ERROR_VERBOSE(ENCRYPT_ERROR);
                return ENCRYPT_ERROR;
            }

        #ifdef WOLFSSL_CIPHER_TEXT_CHECK
            if (ssl->specs.bulk_cipher_algorithm != wolfssl_cipher_null) {
                XMEMCPY(ssl->encrypt.sanityCheck, input,
                    min(sz, sizeof(ssl->encrypt.sanityCheck)));
            }
        #endif

        #ifdef HAVE_FUZZER
            if (ssl->fuzzerCb)
                ssl->fuzzerCb(ssl, input, sz, FUZZ_ENCRYPT, ssl->fuzzerCtx);
        #endif

        #if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
            /* make sure AES GCM/CCM memory is allocated */
            /* free for these happens in FreeCiphers */
            if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm ||
                ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm) {
                /* make sure auth iv and auth are allocated */
                if (ssl->encrypt.additional == NULL)
                    ssl->encrypt.additional = (byte*)XMALLOC(AEAD_AUTH_DATA_SZ,
                                            ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
                if (ssl->encrypt.nonce == NULL) {
                    ssl->encrypt.nonce = (byte*)XMALLOC(AESGCM_NONCE_SZ,
                                            ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
                #ifdef WOLFSSL_CHECK_MEM_ZERO
                    if (ssl->encrypt.nonce != NULL) {
                        wc_MemZero_Add("Encrypt nonce", ssl->encrypt.nonce,
                            AESGCM_NONCE_SZ);
                    }
                #endif
                }
                if (ssl->encrypt.additional == NULL ||
                         ssl->encrypt.nonce == NULL) {
                    return MEMORY_E;
                }
            }
        #endif /* BUILD_AESGCM || HAVE_AESCCM */

            /* Advance state and proceed */
            ssl->encrypt.state = CIPHER_STATE_DO;
        }
        FALL_THROUGH;

        case CIPHER_STATE_DO:
        {
            ret = EncryptDo(ssl, out, input, sz, asyncOkay);

            /* Advance state */
            ssl->encrypt.state = CIPHER_STATE_END;

        #ifdef WOLFSSL_ASYNC_CRYPT
            /* If pending, then leave and return will resume below */
            if (ret == WC_PENDING_E) {
                return ret;
            }
        #endif
        }
        FALL_THROUGH;

        case CIPHER_STATE_END:
        {
        #ifdef WOLFSSL_CIPHER_TEXT_CHECK
            if (ssl->specs.bulk_cipher_algorithm != wolfssl_cipher_null &&
                XMEMCMP(out, ssl->encrypt.sanityCheck,
                    min(sz, sizeof(ssl->encrypt.sanityCheck))) == 0) {

                WOLFSSL_MSG("Encrypt sanity check failed! Glitch?");
                WOLFSSL_ERROR_VERBOSE(ENCRYPT_ERROR);
                return ENCRYPT_ERROR;
            }
            ForceZero(ssl->encrypt.sanityCheck,
                sizeof(ssl->encrypt.sanityCheck));
        #endif

        #if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
            if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm ||
                ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm)
            {
                /* finalize authentication cipher */
#if !defined(NO_PUBLIC_GCM_SET_IV) && \
    ((defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2)))
                AeadIncrementExpIV(ssl);
#endif
                if (ssl->encrypt.nonce)
                    ForceZero(ssl->encrypt.nonce, AESGCM_NONCE_SZ);
            }
        #endif /* BUILD_AESGCM || HAVE_AESCCM */
        #ifdef WOLFSSL_CHECK_MEM_ZERO
            if ((ssl->specs.bulk_cipher_algorithm != wolfssl_cipher_null) &&
                    (out != input) && (ret == 0)) {
                wc_MemZero_Add("TLS Encrypt plaintext", input, sz);
            }
        #endif
            break;
        }

        default:
            break;
    }

    /* Reset state */
    ssl->encrypt.state = CIPHER_STATE_BEGIN;

    return ret;
}


static WC_INLINE int DecryptDo(WOLFSSL* ssl, byte* plain, const byte* input,
                           word16 sz)
{
    int ret = 0;

    (void)plain;
    (void)input;
    (void)sz;

    switch (ssl->specs.bulk_cipher_algorithm)
    {
    #ifdef BUILD_ARC4
        case wolfssl_rc4:
            wc_Arc4Process(ssl->decrypt.arc4, plain, input, sz);
            break;
    #endif

    #ifdef BUILD_DES3
        case wolfssl_triple_des:
        #ifdef WOLFSSL_ASYNC_CRYPT
            /* initialize event */
            ret = wolfSSL_AsyncInit(ssl, &ssl->decrypt.des3->asyncDev,
                WC_ASYNC_FLAG_CALL_AGAIN);
            if (ret != 0)
                break;
        #endif

            ret = wc_Des3_CbcDecrypt(ssl->decrypt.des3, plain, input, sz);
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E) {
                ret = wolfSSL_AsyncPush(ssl, &ssl->decrypt.des3->asyncDev);
            }
        #endif
            break;
    #endif

    #if defined(BUILD_AES) && defined(HAVE_AES_CBC)
        case wolfssl_aes:
        #ifdef WOLFSSL_ASYNC_CRYPT
            /* initialize event */
            ret = wolfSSL_AsyncInit(ssl, &ssl->decrypt.aes->asyncDev,
                WC_ASYNC_FLAG_CALL_AGAIN);
            if (ret != 0)
                break;
        #endif
            ret = wc_AesCbcDecrypt(ssl->decrypt.aes, plain, input, sz);
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E) {
                ret = wolfSSL_AsyncPush(ssl, &ssl->decrypt.aes->asyncDev);
            }
        #endif
            break;
    #endif

    #if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
        case wolfssl_aes_gcm:
        case wolfssl_aes_ccm: /* GCM AEAD macros use same size as CCM */
        {
            wc_AesAuthDecryptFunc aes_auth_fn;

        #ifdef WOLFSSL_ASYNC_CRYPT
            /* initialize event */
            ret = wolfSSL_AsyncInit(ssl, &ssl->decrypt.aes->asyncDev,
                WC_ASYNC_FLAG_CALL_AGAIN);
            if (ret != 0)
                break;
        #endif

        #if defined(BUILD_AESGCM) && defined(HAVE_AESCCM)
            aes_auth_fn = (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm)
                            ? wc_AesGcmDecrypt : wc_AesCcmDecrypt;
        #elif defined(BUILD_AESGCM)
            aes_auth_fn = wc_AesGcmDecrypt;
        #else
            aes_auth_fn = wc_AesCcmDecrypt;
        #endif

            XMEMSET(ssl->decrypt.additional, 0, AEAD_AUTH_DATA_SZ);

            /* sequence number field is 64-bits */
            WriteSEQ(ssl, PEER_ORDER, ssl->decrypt.additional);

            ssl->decrypt.additional[AEAD_TYPE_OFFSET] = ssl->curRL.type;
            ssl->decrypt.additional[AEAD_VMAJ_OFFSET] = ssl->curRL.pvMajor;
            ssl->decrypt.additional[AEAD_VMIN_OFFSET] = ssl->curRL.pvMinor;

            c16toa(sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                                    ssl->decrypt.additional + AEAD_LEN_OFFSET);

        #if defined(WOLFSSL_DTLS) && defined(HAVE_SECURE_RENEGOTIATION)
            if (ssl->options.dtls && IsDtlsMsgSCRKeys(ssl))
                XMEMCPY(ssl->decrypt.nonce,
                        ssl->secure_renegotiation->tmp_keys.aead_dec_imp_IV,
                        AESGCM_IMP_IV_SZ);
            else
        #endif
                XMEMCPY(ssl->decrypt.nonce, ssl->keys.aead_dec_imp_IV,
                        AESGCM_IMP_IV_SZ);
            XMEMCPY(ssl->decrypt.nonce + AESGCM_IMP_IV_SZ, input,
                                                            AESGCM_EXP_IV_SZ);
        #ifdef HAVE_PK_CALLBACKS
            ret = NOT_COMPILED_IN;
            if (ssl->ctx && ssl->ctx->PerformTlsRecordProcessingCb) {
                ret = ssl->ctx->PerformTlsRecordProcessingCb(ssl, 0,
                        plain + AESGCM_EXP_IV_SZ,
                        input + AESGCM_EXP_IV_SZ,
                        sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                        ssl->decrypt.nonce, AESGCM_NONCE_SZ,
                        (byte *)(input + sz - ssl->specs.aead_mac_size),
                        ssl->specs.aead_mac_size,
                        ssl->decrypt.additional, AEAD_AUTH_DATA_SZ);
            }

            if (ret == NOT_COMPILED_IN)
        #endif /* HAVE_PK_CALLBACKS */
            {
                if ((ret = aes_auth_fn(ssl->decrypt.aes,
                            plain + AESGCM_EXP_IV_SZ,
                            input + AESGCM_EXP_IV_SZ,
                            sz - AESGCM_EXP_IV_SZ - ssl->specs.aead_mac_size,
                            ssl->decrypt.nonce, AESGCM_NONCE_SZ,
                            input + sz - ssl->specs.aead_mac_size,
                            ssl->specs.aead_mac_size,
                            ssl->decrypt.additional, AEAD_AUTH_DATA_SZ)) < 0) {
                #ifdef WOLFSSL_ASYNC_CRYPT
                    if (ret == WC_PENDING_E) {
                        ret = wolfSSL_AsyncPush(ssl,
                                                &ssl->decrypt.aes->asyncDev);
                    }
                #endif
                }
            }
        }
        break;
    #endif /* BUILD_AESGCM || HAVE_AESCCM */

    #ifdef HAVE_CAMELLIA
        case wolfssl_camellia:
            ret = wc_CamelliaCbcDecrypt(ssl->decrypt.cam, plain, input, sz);
            break;
    #endif

    #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && \
        !defined(NO_CHAPOL_AEAD)
        case wolfssl_chacha:
            ret = ChachaAEADDecrypt(ssl, plain, input, sz);
            break;
    #endif

    #ifdef HAVE_NULL_CIPHER
        case wolfssl_cipher_null:
            if (input != plain) {
                XMEMMOVE(plain, input, sz);
            }
            break;
    #endif

        default:
            WOLFSSL_MSG("wolfSSL Decrypt programming error");
            WOLFSSL_ERROR_VERBOSE(DECRYPT_ERROR);
            ret = DECRYPT_ERROR;
    }

#ifdef WOLFSSL_CHECK_MEM_ZERO
    if ((ssl->specs.bulk_cipher_algorithm != wolfssl_cipher_null) &&
            (ret == 0)) {
        wc_MemZero_Add("Decrypted data", plain, sz);
    }
#endif

    return ret;
}

static int DecryptTls(WOLFSSL* ssl, byte* plain, const byte* input, word16 sz)
{
    int ret = 0;

#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wolfSSL_AsyncPop(ssl, &ssl->decrypt.state);
    if (ret != WC_NOT_PENDING_E) {
        /* check for still pending */
        if (ret == WC_PENDING_E)
            return ret;

        ssl->error = 0; /* clear async */

        /* let failures through so CIPHER_STATE_END logic is run */
    }
    else
#endif
    {
        /* Reset state */
        ret = 0;
        ssl->decrypt.state = CIPHER_STATE_BEGIN;
    }

    switch (ssl->decrypt.state) {
        case CIPHER_STATE_BEGIN:
        {
            if (ssl->decrypt.setup == 0) {
                WOLFSSL_MSG("Decrypt ciphers not setup");
                WOLFSSL_ERROR_VERBOSE(DECRYPT_ERROR);
                return DECRYPT_ERROR;
            }

        #if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
            /* make sure AES GCM/CCM memory is allocated */
            /* free for these happens in FreeCiphers */
            if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm ||
                ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm) {
                /* make sure auth iv and auth are allocated */
                if (ssl->decrypt.additional == NULL)
                    ssl->decrypt.additional = (byte*)XMALLOC(AEAD_AUTH_DATA_SZ,
                                            ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
                if (ssl->decrypt.nonce == NULL) {
                    ssl->decrypt.nonce = (byte*)XMALLOC(AESGCM_NONCE_SZ,
                                            ssl->heap, DYNAMIC_TYPE_AES_BUFFER);
                #ifdef WOLFSSL_CHECK_MEM_ZERO
                    if (ssl->decrypt.nonce != NULL) {
                        wc_MemZero_Add("DecryptTls nonce", ssl->decrypt.nonce,
                            AESGCM_NONCE_SZ);
                    }
                #endif
                }
                if (ssl->decrypt.additional == NULL ||
                         ssl->decrypt.nonce == NULL) {
                    return MEMORY_E;
                }
            }
        #endif /* BUILD_AESGCM || HAVE_AESCCM */

            /* Advance state and proceed */
            ssl->decrypt.state = CIPHER_STATE_DO;
        }
        FALL_THROUGH;
        case CIPHER_STATE_DO:
        {
        #if defined(WOLFSSL_DTLS) && defined(HAVE_SECURE_RENEGOTIATION)
            if (ssl->options.dtls && DtlsSCRKeysSet(ssl)) {
                /* For epochs >1 the current cipher parameters are located in
                 * ssl->secure_renegotiation->tmp_keys. Previous cipher
                 * parameters and for epoch 1 use ssl->keys */
                if (ssl->keys.curEpoch ==
                        ssl->secure_renegotiation->tmp_keys.dtls_epoch) {
                    if (ssl->decrypt.src != SCR) {
                        ssl->secure_renegotiation->cache_status =
                                SCR_CACHE_NEEDED;
                        if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
                            break;
                    }
                }
                else {
                    if (ssl->decrypt.src != KEYS) {
                        ssl->secure_renegotiation->cache_status =
                                SCR_CACHE_NULL;
                        if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
                            break;
                    }
                }
            }
        #endif

            ret = DecryptDo(ssl, plain, input, sz);

            /* Advance state */
            ssl->decrypt.state = CIPHER_STATE_END;

        #ifdef WOLFSSL_ASYNC_CRYPT
            /* If pending, leave and return below */
            if (ret == WC_PENDING_E) {
                return ret;
            }
        #endif
        }
        FALL_THROUGH;
        case CIPHER_STATE_END:
        {
        #if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)
            /* make sure AES GCM/CCM nonce is cleared */
            if (ssl->specs.bulk_cipher_algorithm == wolfssl_aes_ccm ||
                ssl->specs.bulk_cipher_algorithm == wolfssl_aes_gcm) {
                if (ssl->decrypt.nonce)
                    ForceZero(ssl->decrypt.nonce, AESGCM_NONCE_SZ);

                if (ret < 0) {
                    ret = VERIFY_MAC_ERROR;
                    WOLFSSL_ERROR_VERBOSE(ret);
                }
            }
        #endif /* BUILD_AESGCM || HAVE_AESCCM */
            break;
        }

        default:
            break;
    }

    /* Reset state */
    ssl->decrypt.state = CIPHER_STATE_BEGIN;

    return ret;
}

#endif /* !WOLFSSL_NO_TLS12 */

/* Check conditions for a cipher to have an explicit IV.
 *
 * ssl  The SSL/TLS object.
 * returns 1 if the cipher in use has an explicit IV and 0 otherwise.
 */
static WC_INLINE int CipherHasExpIV(WOLFSSL *ssl)
{
#ifdef WOLFSSL_TLS13
    if (ssl->options.tls1_3)
        return 0;
#endif
    return (ssl->specs.cipher_type == aead) &&
            (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha);
}

/* check cipher text size for sanity */
static int SanityCheckCipherText(WOLFSSL* ssl, word32 encryptSz)
{
#ifdef HAVE_TRUNCATED_HMAC
    word32 minLength = ssl->truncated_hmac ? (byte)TRUNCATED_HMAC_SZ
                                           : ssl->specs.hash_size;
#else
    word32 minLength = ssl->specs.hash_size; /* covers stream */
#endif

#ifndef WOLFSSL_AEAD_ONLY
    if (ssl->specs.cipher_type == block) {
#ifdef HAVE_ENCRYPT_THEN_MAC
        if (ssl->options.startedETMRead) {
            if ((encryptSz - MacSize(ssl)) % ssl->specs.block_size) {
                WOLFSSL_MSG("Block ciphertext not block size");
                WOLFSSL_ERROR_VERBOSE(SANITY_CIPHER_E);
                return SANITY_CIPHER_E;
            }
        }
        else
#endif
        if (encryptSz % ssl->specs.block_size) {
            WOLFSSL_MSG("Block ciphertext not block size");
            WOLFSSL_ERROR_VERBOSE(SANITY_CIPHER_E);
            return SANITY_CIPHER_E;
        }

        minLength++;  /* pad byte */

        if (ssl->specs.block_size > minLength)
            minLength = ssl->specs.block_size;

        if (ssl->options.tls1_1)
            minLength += ssl->specs.block_size;  /* explicit IV */
    }
    else
#endif
    if (ssl->specs.cipher_type == aead) {
        minLength = ssl->specs.aead_mac_size;    /* authTag size */
        if (CipherHasExpIV(ssl))
            minLength += AESGCM_EXP_IV_SZ;       /* explicit IV  */
    }

    if (encryptSz < minLength) {
        WOLFSSL_MSG("Ciphertext not minimum size");
        WOLFSSL_ERROR_VERBOSE(SANITY_CIPHER_E);
        return SANITY_CIPHER_E;
    }

    return 0;
}


#ifndef WOLFSSL_AEAD_ONLY
#ifdef WOLSSL_OLD_TIMINGPADVERIFY
#define COMPRESS_LOWER      64
#define COMPRESS_UPPER      55
#define COMPRESS_CONSTANT   13

#ifndef NO_OLD_TLS

static WC_INLINE void Md5Rounds(int rounds, const byte* data, int sz)
{
    wc_Md5 md5;
    int i;

    wc_InitMd5(&md5);   /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++)
        wc_Md5Update(&md5, data, sz);
    wc_Md5Free(&md5); /* in case needed to release resources */
}



/* do a dummy sha round */
static WC_INLINE void ShaRounds(int rounds, const byte* data, int sz)
{
    wc_Sha sha;
    int i;

    wc_InitSha(&sha);  /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++)
        wc_ShaUpdate(&sha, data, sz);
    wc_ShaFree(&sha); /* in case needed to release resources */
}
#endif


#ifndef NO_SHA256

static WC_INLINE void Sha256Rounds(int rounds, const byte* data, int sz)
{
    wc_Sha256 sha256;
    int i;

    wc_InitSha256(&sha256);  /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++) {
        wc_Sha256Update(&sha256, data, sz);
        /* no error check on purpose, dummy round */
    }
    wc_Sha256Free(&sha256); /* in case needed to release resources */
}

#endif


#ifdef WOLFSSL_SHA384

static WC_INLINE void Sha384Rounds(int rounds, const byte* data, int sz)
{
    wc_Sha384 sha384;
    int i;

    wc_InitSha384(&sha384);  /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++) {
        wc_Sha384Update(&sha384, data, sz);
        /* no error check on purpose, dummy round */
    }
    wc_Sha384Free(&sha384); /* in case needed to release resources */
}

#endif


#ifdef WOLFSSL_SHA512
static WC_INLINE void Sha512Rounds(int rounds, const byte* data, int sz)
{
    wc_Sha512 sha512;
    int i;

    wc_InitSha512(&sha512);  /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++) {
        wc_Sha512Update(&sha512, data, sz);
        /* no error check on purpose, dummy round */
    }
    wc_Sha512Free(&sha512); /* in case needed to release resources */
}

#endif


#ifdef WOLFSSL_RIPEMD

static WC_INLINE void RmdRounds(int rounds, const byte* data, int sz)
{
    RipeMd ripemd;
    int i;

    wc_InitRipeMd(&ripemd);

    for (i = 0; i < rounds; i++)
        wc_RipeMdUpdate(&ripemd, data, sz);
}

#endif


/* Do dummy rounds */
static WC_INLINE void DoRounds(int type, int rounds, const byte* data, int sz)
{
    (void)rounds;
    (void)data;
    (void)sz;

    switch (type) {
        case no_mac :
            break;

#ifndef NO_OLD_TLS
#ifndef NO_MD5
        case md5_mac :
            Md5Rounds(rounds, data, sz);
            break;
#endif

#ifndef NO_SHA
        case sha_mac :
            ShaRounds(rounds, data, sz);
            break;
#endif
#endif

#ifndef NO_SHA256
        case sha256_mac :
            Sha256Rounds(rounds, data, sz);
            break;
#endif

#ifdef WOLFSSL_SHA384
        case sha384_mac :
            Sha384Rounds(rounds, data, sz);
            break;
#endif

#ifdef WOLFSSL_SHA512
        case sha512_mac :
            Sha512Rounds(rounds, data, sz);
            break;
#endif

#ifdef WOLFSSL_RIPEMD
        case rmd_mac :
            RmdRounds(rounds, data, sz);
            break;
#endif

        default:
            WOLFSSL_MSG("Bad round type");
            break;
    }
}


/* do number of compression rounds on dummy data */
static WC_INLINE void CompressRounds(WOLFSSL* ssl, int rounds, const byte* dummy)
{
    if (rounds)
        DoRounds(ssl->specs.mac_algorithm, rounds, dummy, COMPRESS_LOWER);
}


/* check all length bytes for the pad value, return 0 on success */
static int PadCheck(const byte* a, byte pad, int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ pad;
    }

    return compareSum;
}


/* get compression extra rounds */
static WC_INLINE int GetRounds(int pLen, int padLen, int t)
{
    int  roundL1 = 1;  /* round up flags */
    int  roundL2 = 1;

    int L1 = COMPRESS_CONSTANT + pLen - t;
    int L2 = COMPRESS_CONSTANT + pLen - padLen - 1 - t;

    L1 -= COMPRESS_UPPER;
    L2 -= COMPRESS_UPPER;

    if ( (L1 % COMPRESS_LOWER) == 0)
        roundL1 = 0;
    if ( (L2 % COMPRESS_LOWER) == 0)
        roundL2 = 0;

    L1 /= COMPRESS_LOWER;
    L2 /= COMPRESS_LOWER;

    L1 += roundL1;
    L2 += roundL2;

    return L1 - L2;
}


/* timing resistant pad/verify check, return 0 on success */
 int TimingPadVerify(WOLFSSL* ssl, const byte* input, int padLen, int t,
                     int pLen, int content)
{
    byte verify[WC_MAX_DIGEST_SIZE];
    byte dmy[sizeof(WOLFSSL) >= MAX_PAD_SIZE ? 1 : MAX_PAD_SIZE] = {0};
    byte* dummy = sizeof(dmy) < MAX_PAD_SIZE ? (byte*) ssl : dmy;
    int  ret = 0;

    (void)dmy;

    if ( (t + padLen + 1) > pLen) {
        WOLFSSL_MSG("Plain Len not long enough for pad/mac");
        PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE);
        /* still compare */
        ssl->hmac(ssl, verify, input, pLen - t, -1, content, 1, PEER_ORDER);
        ConstantCompare(verify, input + pLen - t, t);
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    if (PadCheck(input + pLen - (padLen + 1), (byte)padLen, padLen + 1) != 0) {
        WOLFSSL_MSG("PadCheck failed");
        PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE - padLen - 1);
        /* still compare */
        ssl->hmac(ssl, verify, input, pLen - t, -1, content, 1, PEER_ORDER);
        ConstantCompare(verify, input + pLen - t, t);
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE - padLen - 1);
    ret = ssl->hmac(ssl, verify, input, pLen - padLen - 1 - t, -1, content,
                                                                 1, PEER_ORDER);

    CompressRounds(ssl, GetRounds(pLen, padLen, t), dummy);

    if (ConstantCompare(verify, input + (pLen - padLen - 1 - t), t) != 0) {
        WOLFSSL_MSG("Verify MAC compare failed");
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    /* treat any failure as verify MAC error */
    if (ret != 0) {
        ret = VERIFY_MAC_ERROR;
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    return ret;
}
#else

#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
/* check all length bytes for the pad value, return 0 on success */
static int PadCheck(const byte* a, byte pad, int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ pad;
    }

    return compareSum;
}


/* Mask the padding bytes with the expected values.
 * Constant time implementation - does maximum pad size possible.
 *
 * data   Message data.
 * sz     Size of the message including MAC and padding and padding length.
 * macSz  Size of the MAC.
 * returns 0 on success, otherwise failure.
 */
static byte MaskPadding(const byte* data, int sz, int macSz)
{
    int i;
    int checkSz = sz - 1;
    byte paddingSz = data[sz - 1];
    byte mask;
    byte good = ctMaskGT(paddingSz, sz - 1 - macSz);

    if (checkSz > TLS_MAX_PAD_SZ)
        checkSz = TLS_MAX_PAD_SZ;

    for (i = 0; i < checkSz; i++) {
        mask = ctMaskLTE(i, paddingSz);
        good |= mask & (data[sz - 1 - i] ^ paddingSz);
    }

    return good;
}

/* Mask the MAC in the message with the MAC calculated.
 * Constant time implementation - starts looking for MAC where maximum padding
 * size has it.
 *
 * data    Message data.
 * sz      Size of the message including MAC and padding and padding length.
 * macSz   Size of the MAC data.
 * expMac  Expected MAC value.
 * returns 0 on success, otherwise failure.
 */
static byte MaskMac(const byte* data, int sz, int macSz, byte* expMac)
{
    int i, j;
    unsigned char mac[WC_MAX_DIGEST_SIZE];
    int scanStart = sz - 1 - TLS_MAX_PAD_SZ - macSz;
    int macEnd = sz - 1 - data[sz - 1];
    int macStart = macEnd - macSz;
    int r = 0;
    unsigned char started, notEnded;
    unsigned char good = 0;

    scanStart &= ctMaskIntGTE(scanStart, 0);
    macStart &= ctMaskIntGTE(macStart, 0);

    /* Div on Intel has different speeds depending on value.
     * Use a bitwise AND or mod a specific value (converted to mul). */
    if ((macSz & (macSz - 1)) == 0)
        r = (macSz - (scanStart - macStart)) & (macSz - 1);
#ifndef NO_SHA
    else if (macSz == WC_SHA_DIGEST_SIZE)
        r = (macSz - (scanStart - macStart)) % WC_SHA_DIGEST_SIZE;
#endif
#ifdef WOLFSSL_SHA384
    else if (macSz == WC_SHA384_DIGEST_SIZE)
        r = (macSz - (scanStart - macStart)) % WC_SHA384_DIGEST_SIZE;
#endif

    XMEMSET(mac, 0, macSz);
    for (i = scanStart; i < sz; i += macSz) {
        for (j = 0; j < macSz && j + i < sz; j++) {
            started = ctMaskGTE(i + j, macStart);
            notEnded = ctMaskLT(i + j, macEnd);
            mac[j] |= started & notEnded & data[i + j];
        }
    }

    if ((macSz & (macSz - 1)) == 0) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) & (macSz - 1)];
    }
#ifndef NO_SHA
    else if (macSz == WC_SHA_DIGEST_SIZE) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) % WC_SHA_DIGEST_SIZE];
    }
#endif
#ifdef WOLFSSL_SHA384
    else if (macSz == WC_SHA384_DIGEST_SIZE) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) % WC_SHA384_DIGEST_SIZE];
    }
#endif

    return good;
}

/* timing resistant pad/verify check, return 0 on success */
int TimingPadVerify(WOLFSSL* ssl, const byte* input, int padLen, int macSz,
                    int pLen, int content)
{
    byte verify[WC_MAX_DIGEST_SIZE];
    byte good;
    int  ret = 0;

    good = MaskPadding(input, pLen, macSz);
    /* 4th argument has potential to underflow, ssl->hmac function should
     * either increment the size by (macSz + padLen + 1) before use or check on
     * the size to make sure is valid. */
    ret = ssl->hmac(ssl, verify, input, pLen - macSz - padLen - 1, padLen,
                                                        content, 1, PEER_ORDER);
    good |= MaskMac(input, pLen, ssl->specs.hash_size, verify);

    /* Non-zero on failure. */
    good = (byte)~(word32)good;
    good &= good >> 4;
    good &= good >> 2;
    good &= good >> 1;
    /* Make ret negative on masking failure. */
    ret -= 1 - good;

    /* Treat any failure as verify MAC error. */
    if (ret != 0) {
        ret = VERIFY_MAC_ERROR;
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    return ret;
}
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_AEAD_ONLY */
#endif /* WOLSSL_OLD_TIMINGPADVERIFY */
#endif /* WOLFSSL_AEAD_ONLY */

int DoApplicationData(WOLFSSL* ssl, byte* input, word32* inOutIdx, int sniff)
{
    word32 msgSz   = WOLFSSL_IS_QUIC(ssl)? ssl->curSize : ssl->keys.encryptSz;
    word32 idx     = *inOutIdx;
    int    dataSz;
    int    ivExtra = 0;
    byte*  rawData = input + idx;  /* keep current  for hmac */
#ifdef HAVE_LIBZ
    byte   decomp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];
#endif

#ifdef WOLFSSL_EARLY_DATA
    if (ssl->options.tls1_3 && ssl->options.handShakeDone == 0) {
        int process = 0;

        if (ssl->options.side == WOLFSSL_SERVER_END) {
            if ((ssl->earlyData != no_early_data) &&
                          (ssl->options.clientState == CLIENT_HELLO_COMPLETE)) {
                process = 1;
            }
            if (!process) {
                WOLFSSL_MSG("Ignoring EarlyData!");
                *inOutIdx += ssl->curSize;
                if (*inOutIdx > ssl->buffers.inputBuffer.length)
                    return BUFFER_E;

                return 0;
            }
        }
        if (!process) {
            WOLFSSL_MSG("Received App data before a handshake completed");
            if (sniff == NO_SNIFF) {
                SendAlert(ssl, alert_fatal, unexpected_message);
            }
            WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
            return OUT_OF_ORDER_E;
        }
    }
    else
#endif
    if (ssl->options.handShakeDone == 0) {
        WOLFSSL_MSG("Received App data before a handshake completed");
        if (sniff == NO_SNIFF) {
            SendAlert(ssl, alert_fatal, unexpected_message);
        }
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }


#if defined(WOLFSSL_DTLS13) && !defined(WOLFSSL_TLS13_IGNORE_AEAD_LIMITS)
    /* Check if we want to invalidate old epochs. If
     * ssl->dtls13InvalidateBefore is set then we want to mark all old
     * epochs as encrypt only. This is done when we detect too many failed
     * decryptions. We do this here to confirm that the peer has updated its
     * keys and we can stop using the old keys. */
    if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)) {
        if (!w64IsZero(ssl->dtls13InvalidateBefore) &&
                w64Equal(ssl->keys.curEpoch64, ssl->dtls13InvalidateBefore)) {
            Dtls13SetOlderEpochSide(ssl, ssl->dtls13InvalidateBefore,
                                    ENCRYPT_SIDE_ONLY);
            w64Zero(&ssl->dtls13InvalidateBefore);
        }
    }
#endif

#ifndef WOLFSSL_AEAD_ONLY
    if (ssl->specs.cipher_type == block) {
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
    }
    else
#endif
    if (ssl->specs.cipher_type == aead) {
        if (CipherHasExpIV(ssl))
            ivExtra = AESGCM_EXP_IV_SZ;
    }

    dataSz = msgSz - ivExtra - ssl->keys.padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    if (ssl->options.startedETMRead)
        dataSz -= MacSize(ssl);
#endif
    if (dataSz < 0) {
        WOLFSSL_MSG("App data buffer error, malicious input?");
        if (sniff == NO_SNIFF) {
            SendAlert(ssl, alert_fatal, unexpected_message);
        }
        WOLFSSL_ERROR_VERBOSE(BUFFER_ERROR);
        return BUFFER_ERROR;
    }
#ifdef WOLFSSL_EARLY_DATA
    if (ssl->earlyData > early_data_ext) {
        if (ssl->earlyDataSz + dataSz > ssl->options.maxEarlyDataSz) {
            if (sniff == NO_SNIFF) {
                SendAlert(ssl, alert_fatal, unexpected_message);
            }
            return WOLFSSL_FATAL_ERROR;
        }
        ssl->earlyDataSz += dataSz;
    }
#endif

    /* read data */
    if (dataSz) {
        int rawSz = dataSz;       /* keep raw size for idx adjustment */

#ifdef HAVE_LIBZ
        if (ssl->options.usingCompression) {
            dataSz = myDeCompress(ssl, rawData, dataSz, decomp, sizeof(decomp));
            if (dataSz < 0) return dataSz;
        }
#endif
        idx += rawSz;

        ssl->buffers.clearOutputBuffer.buffer = rawData;
        ssl->buffers.clearOutputBuffer.length = dataSz;
    }

    idx += ssl->keys.padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    if (ssl->options.startedETMRead)
        idx += MacSize(ssl);
#endif

#ifdef HAVE_LIBZ
    /* decompress could be bigger, overwrite after verify */
    if (ssl->options.usingCompression)
        XMEMMOVE(rawData, decomp, dataSz);
#endif

    *inOutIdx = idx;
#ifdef HAVE_SECURE_RENEGOTIATION
    if (IsSCR(ssl)) {
        /* Reset the processReply state since
         * we finished processing this message. */
        ssl->options.processReply = doProcessInit;
        /* If we are in a secure renegotiation then APP DATA is treated
         * differently */
        return APP_DATA_READY;
    }
#endif
    return 0;
}

const char* AlertTypeToString(int type)
{
    switch (type) {
        case close_notify:
            {
                static const char close_notify_str[] =
                    "close_notify";
                return close_notify_str;
            }

        case unexpected_message:
            {
                static const char unexpected_message_str[] =
                    "unexpected_message";
                return unexpected_message_str;
            }

        case bad_record_mac:
            {
                static const char bad_record_mac_str[] =
                    "bad_record_mac";
                return bad_record_mac_str;
            }

        case record_overflow:
            {
                static const char record_overflow_str[] =
                    "record_overflow";
                return record_overflow_str;
            }

        case decompression_failure:
            {
                static const char decompression_failure_str[] =
                    "decompression_failure";
                return decompression_failure_str;
            }

        case handshake_failure:
            {
                static const char handshake_failure_str[] =
                    "handshake_failure";
                return handshake_failure_str;
            }

        case no_certificate:
            {
                static const char no_certificate_str[] =
                    "no_certificate";
                return no_certificate_str;
            }

        case bad_certificate:
            {
                static const char bad_certificate_str[] =
                    "bad_certificate";
                return bad_certificate_str;
            }

        case unsupported_certificate:
            {
                static const char unsupported_certificate_str[] =
                    "unsupported_certificate";
                return unsupported_certificate_str;
            }

        case certificate_revoked:
            {
                static const char certificate_revoked_str[] =
                    "certificate_revoked";
                return certificate_revoked_str;
            }

        case certificate_expired:
            {
                static const char certificate_expired_str[] =
                    "certificate_expired";
                return certificate_expired_str;
            }

        case certificate_unknown:
            {
                static const char certificate_unknown_str[] =
                    "certificate_unknown";
                return certificate_unknown_str;
            }

        case illegal_parameter:
            {
                static const char illegal_parameter_str[] =
                    "illegal_parameter";
                return illegal_parameter_str;
            }

        case unknown_ca:
            {
                static const char unknown_ca_str[] =
                    "unknown_ca";
                return unknown_ca_str;
            }

        case access_denied:
            {
                static const char access_denied_str[] =
                    "access_denied";
                return access_denied_str;
            }

        case decode_error:
            {
                static const char decode_error_str[] =
                    "decode_error";
                return decode_error_str;
            }

        case decrypt_error:
            {
                static const char decrypt_error_str[] =
                    "decrypt_error";
                return decrypt_error_str;
            }

        case wolfssl_alert_protocol_version:
            {
                static const char protocol_version_str[] =
                    "protocol_version";
                return protocol_version_str;
            }
        case insufficient_security:
            {
                static const char insufficient_security_str[] =
                    "insufficient_security";
                return insufficient_security_str;
            }

        case internal_error:
            {
                static const char internal_error_str[] =
                    "internal_error";
                return internal_error_str;
            }

        case user_canceled:
            {
                static const char user_canceled_str[] =
                    "user_canceled";
                return user_canceled_str;
            }

        case no_renegotiation:
            {
                static const char no_renegotiation_str[] =
                    "no_renegotiation";
                return no_renegotiation_str;
            }

        case unrecognized_name:
            {
                static const char unrecognized_name_str[] =
                    "unrecognized_name";
                return unrecognized_name_str;
            }

        case bad_certificate_status_response:
            {
                static const char bad_certificate_status_response_str[] =
                    "bad_certificate_status_response";
                return bad_certificate_status_response_str;
            }

        case no_application_protocol:
            {
                static const char no_application_protocol_str[] =
                    "no_application_protocol";
                return no_application_protocol_str;
            }

        default:
            WOLFSSL_MSG("Unknown Alert");
            return NULL;
    }
}

static void LogAlert(int type)
{
#ifdef DEBUG_WOLFSSL
    const char* typeStr;
    char buff[60];

    typeStr = AlertTypeToString(type);
    if (typeStr != NULL) {
        XSNPRINTF(buff, sizeof(buff), "Alert type: %s", typeStr);
        WOLFSSL_MSG(buff);
    }
#else
    (void)type;
#endif /* DEBUG_WOLFSSL */
}

/* process alert, return level */
static int DoAlert(WOLFSSL* ssl, byte* input, word32* inOutIdx, int* type)
{
    byte level;
    byte code;
    word32 dataSz = (word32)ssl->curSize;
    int ivExtra = 0;

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "Alert");
        if (ssl->toInfoOn) {
            /* add record header back on to info + alert bytes level/code */
            int ret = AddPacketInfo(ssl, "Alert", alert, input + *inOutIdx,
                          ALERT_SIZE, READ_PROTO, RECORD_HEADER_SZ, ssl->heap);
            if (ret != 0)
                return ret;
            #ifdef WOLFSSL_CALLBACKS
            AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
            #endif
        }
    #endif

    if (IsEncryptionOn(ssl, 0)) {
#ifndef WOLFSSL_AEAD_ONLY
        if (ssl->specs.cipher_type == block) {
            if (ssl->options.tls1_1)
                ivExtra = ssl->specs.block_size;
        }
        else
#endif
        if (ssl->specs.cipher_type == aead) {
            if (CipherHasExpIV(ssl))
                ivExtra = AESGCM_EXP_IV_SZ;
        }
        dataSz -= ivExtra;
        dataSz -= ssl->keys.padSz;
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead)
            dataSz -= MacSize(ssl);
    #endif
    }

    /* make sure can read the message */
    if (dataSz != ALERT_SIZE) {
#ifdef WOLFSSL_EXTRA_ALERTS
        SendAlert(ssl, alert_fatal, unexpected_message);
#endif
        return BUFFER_E;
    }

    level = input[(*inOutIdx)++];
    code  = input[(*inOutIdx)++];
    ssl->alert_history.last_rx.code = code;
    ssl->alert_history.last_rx.level = level;
    *type = code;
    if (level == alert_fatal) {
        ssl->options.isClosed = 1;  /* Don't send close_notify */
    }

    if (++ssl->options.alertCount >= WOLFSSL_ALERT_COUNT_MAX) {
        WOLFSSL_MSG("Alert count exceeded");
#ifdef WOLFSSL_EXTRA_ALERTS
        if (level != alert_warning || code != close_notify)
            SendAlert(ssl, alert_fatal, unexpected_message);
#endif
        WOLFSSL_ERROR_VERBOSE(ALERT_COUNT_E);
        return ALERT_COUNT_E;
    }

    LogAlert(*type);
    if (*type == close_notify) {
        ssl->options.closeNotify = 1;
    }
    else {
        /*
         * A close_notify alert doesn't mean there's been an error, so we only
         * add other types of alerts to the error queue
         */
        WOLFSSL_ERROR(*type);
    }

    if (IsEncryptionOn(ssl, 0)) {
        *inOutIdx += ssl->keys.padSz;
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead)
            *inOutIdx += MacSize(ssl);
    #endif
    }

    return level;
}

static int GetInputData(WOLFSSL *ssl, word32 size)
{
    int in;
    int inSz;
    int maxLength;
    int usedLength;
    int dtlsExtra = 0;


    /* check max input length */
    usedLength = ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx;
    maxLength  = ssl->buffers.inputBuffer.bufferSize - usedLength;
    inSz       = (int)(size - usedLength);      /* from last partial read */

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        if (size < ssl->dtls_expected_rx)
            dtlsExtra = (int)(ssl->dtls_expected_rx - size);
        inSz = ssl->dtls_expected_rx;
    }
#endif

    /* check that no lengths or size values are negative */
    if (usedLength < 0 || maxLength < 0 || inSz <= 0) {
        return BUFFER_ERROR;
    }

    if (inSz > maxLength) {
        if (GrowInputBuffer(ssl, size + dtlsExtra, usedLength) < 0)
            return MEMORY_E;
    }

    /* Put buffer data at start if not there */
    if (usedLength > 0 && ssl->buffers.inputBuffer.idx != 0)
        XMEMMOVE(ssl->buffers.inputBuffer.buffer,
                ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
                usedLength);

    /* remove processed data */
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = usedLength;

    /* read data from network */
    do {
        in = wolfSSLReceive(ssl,
                     ssl->buffers.inputBuffer.buffer +
                     ssl->buffers.inputBuffer.length,
                     inSz);
        if (in == WANT_READ)
            return WANT_READ;

        if (in < 0) {
            WOLFSSL_ERROR_VERBOSE(SOCKET_ERROR_E);
            return SOCKET_ERROR_E;
        }

        if (in > inSz) {
            WOLFSSL_ERROR_VERBOSE(RECV_OVERFLOW_E);
            return RECV_OVERFLOW_E;
        }

        ssl->buffers.inputBuffer.length += in;
        inSz -= in;

    } while (ssl->buffers.inputBuffer.length < size);

#ifdef WOLFSSL_DEBUG_TLS
    if (ssl->buffers.inputBuffer.idx == 0) {
        WOLFSSL_MSG("Data received");
        WOLFSSL_BUFFER(ssl->buffers.inputBuffer.buffer,
                       ssl->buffers.inputBuffer.length);
    }
#endif

    return 0;
}

#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
static WC_INLINE int VerifyMacEnc(WOLFSSL* ssl, const byte* input, word32 msgSz,
                                  int content)
{
    int    ret;
#ifdef HAVE_TRUNCATED_HMAC
    word32 digestSz = ssl->truncated_hmac ? (byte)TRUNCATED_HMAC_SZ
                                          : ssl->specs.hash_size;
#else
    word32 digestSz = ssl->specs.hash_size;
#endif
    byte   verify[WC_MAX_DIGEST_SIZE];

    WOLFSSL_MSG("Verify MAC of Encrypted Data");

    if (msgSz < digestSz) {
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    ret  = ssl->hmac(ssl, verify, input, msgSz - digestSz, -1, content, 1, PEER_ORDER);
    ret |= ConstantCompare(verify, input + msgSz - digestSz, digestSz);
    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    return 0;
}
#endif

static WC_INLINE int VerifyMac(WOLFSSL* ssl, const byte* input, word32 msgSz,
                            int content, word32* padSz)
{
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    int    ivExtra = 0;
    int    ret;
    word32 pad     = 0;
    word32 padByte = 0;
#ifdef HAVE_TRUNCATED_HMAC
    word32 digestSz = ssl->truncated_hmac ? (byte)TRUNCATED_HMAC_SZ
                                          : ssl->specs.hash_size;
#else
    word32 digestSz = ssl->specs.hash_size;
#endif
    byte   verify[WC_MAX_DIGEST_SIZE];


    if (ssl->specs.cipher_type == block) {
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
        pad = *(input + msgSz - ivExtra - 1);
        padByte = 1;

        if (ssl->options.tls) {
#if !defined(NO_CERTS) && defined(HAVE_PK_CALLBACKS)
            ret = PROTOCOLCB_UNAVAILABLE;
            if(ssl->ctx->VerifyMacCb) {
                void* ctx = wolfSSL_GetVerifyMacCtx(ssl);
                ret = ssl->ctx->VerifyMacCb(ssl, input,
                           (msgSz - ivExtra) - digestSz - pad - 1,
                           digestSz, content, ctx);
                if (ret != 0 && ret != PROTOCOLCB_UNAVAILABLE) {
                    return ret;
                }
            }
            if (!ssl->ctx->VerifyMacCb || ret == PROTOCOLCB_UNAVAILABLE)
#endif
            ret = TimingPadVerify(ssl, input, pad, digestSz, msgSz - ivExtra,
                                  content);
            if (ret != 0)
                return ret;
        }
        else {  /* sslv3, some implementations have bad padding, but don't
                 * allow bad read */
            int  badPadLen = 0;
            byte dmy[sizeof(WOLFSSL) >= MAX_PAD_SIZE ? 1 : MAX_PAD_SIZE];
            byte* dummy = sizeof(dmy) < MAX_PAD_SIZE ? (byte*) ssl : dmy;
            XMEMSET(dmy, 0, sizeof(dmy));

            if (pad > (msgSz - digestSz - 1)) {
                WOLFSSL_MSG("Plain Len not long enough for pad/mac");
                pad       = 0;  /* no bad read */
                badPadLen = 1;
            }
            (void)PadCheck(dummy, (byte)pad, MAX_PAD_SIZE);  /* timing only */
            ret = ssl->hmac(ssl, verify, input, msgSz - digestSz - pad - 1,
                            pad, content, 1, PEER_ORDER);
            if (ConstantCompare(verify, input + msgSz - digestSz - pad - 1,
                                digestSz) != 0) {
                WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
                return VERIFY_MAC_ERROR;
            }
            if (ret != 0 || badPadLen) {
                WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
                return VERIFY_MAC_ERROR;
            }
        }
    }
    else if (ssl->specs.cipher_type == stream) {
        ret = ssl->hmac(ssl, verify, input, msgSz - digestSz, -1, content, 1,
                        PEER_ORDER);
        if (ConstantCompare(verify, input + msgSz - digestSz, digestSz) != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }
    }
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_AEAD_ONLY */

    if (ssl->specs.cipher_type == aead) {
        *padSz = ssl->specs.aead_mac_size;
    }
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    else {
        *padSz = digestSz + pad + padByte;
    }
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_AEAD_ONLY */

    (void)input;
    (void)msgSz;
    (void)content;

    return 0;
}

#ifdef WOLFSSL_DTLS
static int HandleDTLSDecryptFailed(WOLFSSL* ssl)
{
    int ret = 0;
#ifdef WOLFSSL_DTLS_DROP_STATS
    ssl->macDropCount++;
#endif

#if defined(WOLFSSL_DTLS13) && !defined(WOLFSSL_TLS13_IGNORE_AEAD_LIMITS)
    /* Handle AEAD limits specified by the RFC for failed decryption */
    if (IsAtLeastTLSv1_3(ssl->version))
        ret = Dtls13CheckAEADFailLimit(ssl);
#endif

    (void)ssl;
    WOLFSSL_MSG("DTLS: Ignoring failed decryption");
    return ret;
}

static int DtlsShouldDrop(WOLFSSL* ssl, int retcode)
{
    if (ssl->options.handShakeDone && !IsEncryptionOn(ssl, 0)) {
        WOLFSSL_MSG("Silently dropping plaintext DTLS message "
                    "on established connection.");
        return 1;
    }

    if ((ssl->options.handShakeDone && retcode != 0)
        || retcode == SEQUENCE_ERROR || retcode == DTLS_CID_ERROR) {
        WOLFSSL_MSG_EX("Silently dropping DTLS message: %d", retcode);
        return 1;
    }

#ifdef WOLFSSL_DTLS13
    if (IsAtLeastTLSv1_3(ssl->version) && !w64IsZero(ssl->dtls13Epoch)
            && w64IsZero(ssl->keys.curEpoch64) && ssl->curRL.type != ack) {
        WOLFSSL_MSG("Silently dropping plaintext DTLS message "
                    "during encrypted handshake.");
        return 1;
    }
#endif /* WOLFSSL_DTLS13 */

#ifndef NO_WOLFSSL_SERVER
    if (ssl->options.side == WOLFSSL_SERVER_END
            && ssl->curRL.type != handshake) {
        int beforeCookieVerified = 0;
        if (!IsAtLeastTLSv1_3(ssl->version)) {
            beforeCookieVerified =
                ssl->options.acceptState < ACCEPT_FIRST_REPLY_DONE;
        }
#ifdef WOLFSSL_DTLS13
        else {
            beforeCookieVerified =
                ssl->options.acceptState < TLS13_ACCEPT_SECOND_REPLY_DONE;
        }
#endif /* WOLFSSL_DTLS13 */

        if (beforeCookieVerified) {
            WOLFSSL_MSG("Drop non-handshake record before handshake");
            return 1;
        }
    }
#endif /* NO_WOLFSSL_SERVER */

    return 0;
}
#endif /* WOLFSSL_DTLS */

int ProcessReply(WOLFSSL* ssl)
{
    return ProcessReplyEx(ssl, 0);
}

/* Process input requests. Return 0 is done, 1 is call again to complete, and
   negative number is error. If allowSocketErr is set, SOCKET_ERROR_E in
   ssl->error will be whitelisted. This is useful when the connection has been
   closed and the endpoint wants to check for an alert sent by the other end. */
int ProcessReplyEx(WOLFSSL* ssl, int allowSocketErr)
{
    int    ret = 0, type = internal_error, readSz;
    int    atomicUser = 0;
    word32 startIdx = 0;
#if defined(WOLFSSL_DTLS)
    int    used;
#endif

#ifdef ATOMIC_USER
    if (ssl->ctx->DecryptVerifyCb)
        atomicUser = 1;
#endif

    if (ssl->error != 0 && ssl->error != WANT_READ && ssl->error != WANT_WRITE
    #ifdef HAVE_SECURE_RENEGOTIATION
        && ssl->error != APP_DATA_READY
    #endif
    #ifdef WOLFSSL_ASYNC_CRYPT
        && ssl->error != WC_PENDING_E
    #endif
    #ifdef WOLFSSL_NONBLOCK_OCSP
        && ssl->error != OCSP_WANT_READ
    #endif
        && (allowSocketErr != 1 || ssl->error != SOCKET_ERROR_E)
    ) {
        WOLFSSL_MSG("ProcessReply retry in error state, not allowed");
        return ssl->error;
    }

#if defined(WOLFSSL_DTLS) && defined(WOLFSSL_ASYNC_CRYPT)
    /* process any pending DTLS messages - this flow can happen with async */
    if (ssl->dtls_rx_msg_list != NULL) {
        word32 pendingMsg = ssl->dtls_rx_msg_list_sz;
        if(IsAtLeastTLSv1_3(ssl->version)) {
#ifdef WOLFSSL_DTLS13
            ret = Dtls13ProcessBufferedMessages(ssl);
#else
            ret = NOT_COMPILED_IN;
#endif /* WOLFSSL_DTLS13 */
        }
        else {
            ret = DtlsMsgDrain(ssl);
        }
        if (ret != 0) {
            WOLFSSL_ERROR(ret);
            return ret;
        }
        /* we processed some messages, return so connect/accept can make
           progress */
        if (ssl->dtls_rx_msg_list_sz != pendingMsg)
            return ret;
    }
#endif

    ret = RetrySendAlert(ssl);
    if (ret != 0)
        return ret;

    for (;;) {
        switch (ssl->options.processReply) {

        /* in the WOLFSSL_SERVER case, get the first byte for detecting
         * old client hello */
        case doProcessInit:

            readSz = RECORD_HEADER_SZ;

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                readSz = DTLS_RECORD_HEADER_SZ;
#ifdef WOLFSSL_DTLS13
                if (ssl->options.tls1_3) {
                    /* dtls1.3 unified header can be as little as 2 bytes */
                    readSz = DTLS_UNIFIED_HEADER_MIN_SZ;
                }
#endif /* WOLFSSL_DTLS13 */
            }
        #endif

            /* get header or return error */
            if (!ssl->options.dtls) {
                if ((ret = GetInputData(ssl, readSz)) < 0)
                    return ret;
            } else {
            #ifdef WOLFSSL_DTLS
                /* read ahead may already have header */
                used = ssl->buffers.inputBuffer.length -
                       ssl->buffers.inputBuffer.idx;
                if (used < readSz) {
                    if ((ret = GetInputData(ssl, readSz)) < 0)
                        return ret;
                }
            #endif
            }

#ifdef OLD_HELLO_ALLOWED

            /* see if sending SSLv2 client hello */
            if ( ssl->options.side == WOLFSSL_SERVER_END &&
                 ssl->options.clientState == NULL_STATE &&
                 ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx]
                         != handshake) {
                byte b0, b1;

                ssl->options.processReply = runProcessOldClientHello;

                /* sanity checks before getting size at front */
                if (ssl->buffers.inputBuffer.buffer[
                          ssl->buffers.inputBuffer.idx + OPAQUE16_LEN] != OLD_HELLO_ID) {
                    WOLFSSL_MSG("Not a valid old client hello");
                    WOLFSSL_ERROR_VERBOSE(PARSE_ERROR);
                    return PARSE_ERROR;
                }

                if (ssl->buffers.inputBuffer.buffer[
                          ssl->buffers.inputBuffer.idx + OPAQUE24_LEN] != SSLv3_MAJOR &&
                    ssl->buffers.inputBuffer.buffer[
                          ssl->buffers.inputBuffer.idx + OPAQUE24_LEN] != DTLS_MAJOR) {
                    WOLFSSL_MSG("Not a valid version in old client hello");
                    WOLFSSL_ERROR_VERBOSE(PARSE_ERROR);
                    return PARSE_ERROR;
                }

                /* how many bytes need ProcessOldClientHello */
                b0 =
                ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx++];
                b1 =
                ssl->buffers.inputBuffer.buffer[ssl->buffers.inputBuffer.idx++];
                ssl->curSize = (word16)(((b0 & 0x7f) << 8) | b1);
            }
            else {
                ssl->options.processReply = getRecordLayerHeader;
                continue;
            }
            FALL_THROUGH;

        /* in the WOLFSSL_SERVER case, run the old client hello */
        case runProcessOldClientHello:

            /* get sz bytes or return error */
            if (!ssl->options.dtls) {
                if ((ret = GetInputData(ssl, ssl->curSize)) < 0)
                    return ret;
            } else {
            #ifdef WOLFSSL_DTLS
                /* read ahead may already have */
                used = ssl->buffers.inputBuffer.length -
                       ssl->buffers.inputBuffer.idx;
                if (used < ssl->curSize)
                    if ((ret = GetInputData(ssl, ssl->curSize - used)) < 0)
                        return ret;
            #endif  /* WOLFSSL_DTLS */
            }

            ret = ProcessOldClientHello(ssl, ssl->buffers.inputBuffer.buffer,
                                        &ssl->buffers.inputBuffer.idx,
                                        ssl->buffers.inputBuffer.length -
                                        ssl->buffers.inputBuffer.idx,
                                        ssl->curSize);
            if (ret < 0)
                return ret;

            else if (ssl->buffers.inputBuffer.idx ==
                     ssl->buffers.inputBuffer.length) {
                ssl->options.processReply = doProcessInit;
                return 0;
            }

#endif  /* OLD_HELLO_ALLOWED */
            FALL_THROUGH;

        /* get the record layer header */
        case getRecordLayerHeader:

            /* DTLSv1.3 record numbers in the header are encrypted, and AAD
             * uses the unecrypted form. Because of this we need to modify the
             * header, decrypting the numbers inside
             * DtlsParseUnifiedRecordLayer(). This violates the const attribute
             * of the buffer parameter of GetRecordHeader() used here. */
            ret = GetRecordHeader(ssl, &ssl->buffers.inputBuffer.idx,
                                       &ssl->curRL, &ssl->curSize);

#ifdef WOLFSSL_DTLS
            if (ssl->options.dtls && DtlsShouldDrop(ssl, ret)) {
                    ssl->options.processReply = doProcessInit;
                    ssl->buffers.inputBuffer.length = 0;
                    ssl->buffers.inputBuffer.idx = 0;
#ifdef WOLFSSL_DTLS_DROP_STATS
                    ssl->replayDropCount++;
#endif /* WOLFSSL_DTLS_DROP_STATS */

#ifdef WOLFSSL_DTLS13
                    /* return to send ACKS and shortcut rtx timer */
                    if (IsAtLeastTLSv1_3(ssl->version)
                        && ssl->dtls13Rtx.sendAcks)
                        return 0;
#endif /* WOLFSSL_DTLS13 */

                    continue;
            }
#endif
            if (ret != 0)
                return ret;

#ifdef WOLFSSL_TLS13
            if (IsAtLeastTLSv1_3(ssl->version) && IsEncryptionOn(ssl, 0) &&
                                        ssl->curRL.type != application_data &&
                                        ssl->curRL.type != change_cipher_spec) {
                SendAlert(ssl, alert_fatal, unexpected_message);
                WOLFSSL_ERROR_VERBOSE(PARSE_ERROR);
                return PARSE_ERROR;
            }
#endif

            ssl->options.processReply = getData;
            FALL_THROUGH;

        /* retrieve record layer data */
        case getData:

            /* get sz bytes or return error */
            if (!ssl->options.dtls) {
                if ((ret = GetInputData(ssl, ssl->curSize)) < 0) {
#ifdef WOLFSSL_EXTRA_ALERTS
                    if (ret != WANT_READ)
                        SendAlert(ssl, alert_fatal, bad_record_mac);
#endif
                    return ret;
                }
            }
            else {
#ifdef WOLFSSL_DTLS
                /* read ahead may already have */
                used = ssl->buffers.inputBuffer.length -
                       ssl->buffers.inputBuffer.idx;
                if (used < ssl->curSize)
                    if ((ret = GetInputData(ssl, ssl->curSize)) < 0)
                        return ret;
#endif
            }

            if (IsEncryptionOn(ssl, 0)) {
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_EXTRA_ALERTS)
                int tooLong = 0;
#endif

#ifdef WOLFSSL_TLS13
                if (IsAtLeastTLSv1_3(ssl->version)) {
                    tooLong  = ssl->curSize > MAX_TLS13_ENC_SZ;
                    // HACK: ssl->curSize can be "1" (smaller than aead_mac_size == 16), which fails this check:
                    /*tooLong |= ssl->curSize - ssl->specs.aead_mac_size >
                                                             MAX_TLS13_PLAIN_SZ;*/
                }
#endif
#ifdef WOLFSSL_EXTRA_ALERTS
                if (!IsAtLeastTLSv1_3(ssl->version))
                    tooLong = ssl->curSize > MAX_TLS_CIPHER_SZ;
#endif
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_EXTRA_ALERTS)
                if (tooLong) {
                    WOLFSSL_MSG("Encrypted data too long");
                    SendAlert(ssl, alert_fatal, record_overflow);
                    return BUFFER_ERROR;
                }
#endif
            }
            ssl->keys.padSz = 0;

            ssl->options.processReply = verifyEncryptedMessage;
            startIdx = ssl->buffers.inputBuffer.idx;  /* in case > 1 msg per */
            FALL_THROUGH;

        /* verify digest of encrypted message */
        case verifyEncryptedMessage:
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (IsEncryptionOn(ssl, 0) && ssl->keys.decryptedCur == 0 &&
                                   !atomicUser && ssl->options.startedETMRead) {
                ret = VerifyMacEnc(ssl, ssl->buffers.inputBuffer.buffer +
                                   ssl->buffers.inputBuffer.idx,
                                   ssl->curSize, ssl->curRL.type);
            #ifdef WOLFSSL_ASYNC_CRYPT
                if (ret == WC_PENDING_E)
                    return ret;
            #endif
                if (ret < 0) {
                    WOLFSSL_MSG("VerifyMacEnc failed");
                #ifdef WOLFSSL_DTLS
                    /* If in DTLS mode, if the decrypt fails for any
                     * reason, pretend the datagram never happened. */
                    if (ssl->options.dtls) {
                        ssl->options.processReply = doProcessInit;
                        ssl->buffers.inputBuffer.idx =
                                ssl->buffers.inputBuffer.length;
                        return HandleDTLSDecryptFailed(ssl);
                    }
                #endif /* WOLFSSL_DTLS */
                #ifdef WOLFSSL_EXTRA_ALERTS
                    if (!ssl->options.dtls)
                        SendAlert(ssl, alert_fatal, bad_record_mac);
                #endif
                    WOLFSSL_ERROR_VERBOSE(DECRYPT_ERROR);
                    return DECRYPT_ERROR;
                }
                ssl->keys.encryptSz    = ssl->curSize;
            }
#endif
            ssl->options.processReply = decryptMessage;
            FALL_THROUGH;

        /* decrypt message */
        case decryptMessage:

            if (IsEncryptionOn(ssl, 0) && ssl->keys.decryptedCur == 0 &&
                                        (!IsAtLeastTLSv1_3(ssl->version) ||
                                         ssl->curRL.type != change_cipher_spec))
            {
                bufferStatic* in = &ssl->buffers.inputBuffer;

                ret = SanityCheckCipherText(ssl, ssl->curSize);
                if (ret < 0) {
                #ifdef WOLFSSL_EXTRA_ALERTS
                    SendAlert(ssl, alert_fatal, bad_record_mac);
                #endif
                    return ret;
                }

                if (atomicUser) {
        #ifdef ATOMIC_USER
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    if (ssl->options.startedETMRead) {
                        ret = ssl->ctx->VerifyDecryptCb(ssl,
                                     in->buffer + in->idx, in->buffer + in->idx,
                                     ssl->curSize - MacSize(ssl),
                                     ssl->curRL.type, 1, &ssl->keys.padSz,
                                     ssl->DecryptVerifyCtx);
                    }
                    else
            #endif
                    {
                        ret = ssl->ctx->DecryptVerifyCb(ssl,
                                      in->buffer + in->idx,
                                      in->buffer + in->idx,
                                      ssl->curSize, ssl->curRL.type, 1,
                                      &ssl->keys.padSz, ssl->DecryptVerifyCtx);
                    }
        #endif /* ATOMIC_USER */
                }
                else {
                    if (!ssl->options.tls1_3) {
        #ifndef WOLFSSL_NO_TLS12
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    if (ssl->options.startedETMRead) {
                        word32 digestSz = MacSize(ssl);
                        ret = DecryptTls(ssl,
                                      in->buffer + in->idx,
                                      in->buffer + in->idx,
                                      ssl->curSize - (word16)digestSz);
                        if (ret == 0) {
                            byte invalid = 0;
                            byte padding = (byte)-1;
                            word32 i;
                            word32 off = in->idx + ssl->curSize - digestSz - 1;

                            /* Last of padding bytes - indicates length. */
                            ssl->keys.padSz = in->buffer[off];
                            /* Constant time checking of padding - don't leak
                             * the length of the data.
                             */
                            /* Compare max pad bytes or at most data + pad. */
                            for (i = 1; i < MAX_PAD_SIZE && off >= i; i++) {
                                /* Mask on indicates this is expected to be a
                                 * padding byte.
                                 */
                                padding &= ctMaskLTE(i, ssl->keys.padSz);
                                /* When this is a padding byte and not equal
                                 * to length then mask is set.
                                 */
                                invalid |= padding &
                                           ctMaskNotEq(in->buffer[off - i],
                                                       ssl->keys.padSz);
                            }
                            /* If mask is set then there was an error. */
                            if (invalid) {
                                ret = DECRYPT_ERROR;
                            }
                            ssl->keys.padSz += 1;
                            ssl->keys.decryptedCur = 1;
                        }
                    }
                    else
            #endif
                    {
                        ret = DecryptTls(ssl,
                                      in->buffer + in->idx,
                                      in->buffer + in->idx,
                                      ssl->curSize);
                    }
        #else
                        ret = DECRYPT_ERROR;
        #endif
                    }
                    else
                    {
                #ifdef WOLFSSL_TLS13
                        byte *aad = (byte*)&ssl->curRL;
                        word16 aad_size = RECORD_HEADER_SZ;
                    #ifdef WOLFSSL_DTLS13
                        if (ssl->options.dtls) {
                            /* aad now points to the record header */
                            aad = ssl->dtls13CurRL;
                            aad_size = ssl->dtls13CurRlLength;
                        }
                    #endif /* WOLFSSL_DTLS13 */
                        /* Don't send an alert for DTLS. We will just drop it
                         * silently later. */
                        ret = DecryptTls13(ssl,
                                        in->buffer + in->idx,
                                        in->buffer + in->idx,
                                        ssl->curSize,
                                        aad, aad_size);
                #else
                        ret = DECRYPT_ERROR;
                #endif /* WOLFSSL_TLS13 */
                    }
                    (void)in;
                }

            #ifdef WOLFSSL_ASYNC_CRYPT
                if (ret == WC_PENDING_E)
                    return ret;
            #endif

                if (ret >= 0) {
            #ifndef WOLFSSL_NO_TLS12
                    /* handle success */
                #ifndef WOLFSSL_AEAD_ONLY
                    if (ssl->options.tls1_1 && ssl->specs.cipher_type == block)
                        ssl->buffers.inputBuffer.idx += ssl->specs.block_size;
                #endif
                    /* go past TLSv1.1 IV */
                    if (CipherHasExpIV(ssl))
                        ssl->buffers.inputBuffer.idx += AESGCM_EXP_IV_SZ;
            #endif
                }
                else {
                    WOLFSSL_MSG("Decrypt failed");
                #ifdef WOLFSSL_DTLS
                    /* If in DTLS mode, if the decrypt fails for any
                     * reason, pretend the datagram never happened. */
                    if (ssl->options.dtls) {
                        ssl->options.processReply = doProcessInit;
                        ssl->buffers.inputBuffer.idx =
                                ssl->buffers.inputBuffer.length;
                        return HandleDTLSDecryptFailed(ssl);
                    }
                #endif /* WOLFSSL_DTLS */
                #ifdef WOLFSSL_EARLY_DATA
                    if (ssl->options.tls1_3) {
                         if (ssl->options.side == WOLFSSL_SERVER_END &&
                                 ssl->earlyData != no_early_data &&
                                 ssl->options.clientState <
                                                     CLIENT_FINISHED_COMPLETE) {
                            ssl->earlyDataSz += ssl->curSize;
                            if (ssl->earlyDataSz <=
                                                  ssl->options.maxEarlyDataSz) {
                                WOLFSSL_MSG("Ignoring EarlyData!");
                                if (ssl->keys.peer_sequence_number_lo-- == 0)
                                    ssl->keys.peer_sequence_number_hi--;
                                ssl->options.processReply = doProcessInit;
                                ssl->buffers.inputBuffer.idx += ssl->curSize;
                                if (ssl->buffers.inputBuffer.idx >
                                    ssl->buffers.inputBuffer.length) {
                                    WOLFSSL_ERROR(BUFFER_E);
                                    return BUFFER_E;
                                }

                                return 0;
                            }
                            WOLFSSL_MSG("Too much EarlyData!");
                            SendAlert(ssl, alert_fatal, unexpected_message);
                            WOLFSSL_ERROR(TOO_MUCH_EARLY_DATA);
                            return TOO_MUCH_EARLY_DATA;
                        }
                    }
                #endif
                    SendAlert(ssl, alert_fatal, bad_record_mac);
                    /* Push error once we know that we will error out here */
                    WOLFSSL_ERROR(ret);
                    return ret;
                }
            }

            ssl->options.processReply = verifyMessage;
            FALL_THROUGH;

        /* verify digest of message */
        case verifyMessage:

            if (IsEncryptionOn(ssl, 0) && ssl->keys.decryptedCur == 0 &&
                                        (!IsAtLeastTLSv1_3(ssl->version) ||
                                         ssl->curRL.type != change_cipher_spec))
            {
                if (!atomicUser
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                                && !ssl->options.startedETMRead
#endif
                    ) {
                    ret = VerifyMac(ssl, ssl->buffers.inputBuffer.buffer +
                                    ssl->buffers.inputBuffer.idx,
                                    ssl->curSize, ssl->curRL.type,
                                    &ssl->keys.padSz);
                #ifdef WOLFSSL_ASYNC_CRYPT
                    if (ret == WC_PENDING_E)
                        return ret;
                #endif
                    if (ret < 0) {
                    #ifdef WOLFSSL_DTLS
                        /* If in DTLS mode, if the decrypt fails for any
                         * reason, pretend the datagram never happened. */
                        if (ssl->options.dtls) {
                            ssl->options.processReply = doProcessInit;
                            ssl->buffers.inputBuffer.idx =
                                    ssl->buffers.inputBuffer.length;
                            return HandleDTLSDecryptFailed(ssl);
                        }
                    #endif /* WOLFSSL_DTLS */
                    #ifdef WOLFSSL_EXTRA_ALERTS
                        if (!ssl->options.dtls)
                            SendAlert(ssl, alert_fatal, bad_record_mac);
                    #endif
                        WOLFSSL_MSG("VerifyMac failed");
                        WOLFSSL_ERROR_VERBOSE(DECRYPT_ERROR);
                        return DECRYPT_ERROR;
                    }
                }

                ssl->keys.encryptSz    = ssl->curSize;
                ssl->keys.decryptedCur = 1;
#ifdef WOLFSSL_TLS13
                if (ssl->options.tls1_3) {
                    /* end of plaintext */
                    word16 i = (word16)(ssl->buffers.inputBuffer.idx +
                                 ssl->curSize - ssl->specs.aead_mac_size);

                    if (i > ssl->buffers.inputBuffer.length) {
                        WOLFSSL_ERROR(BUFFER_ERROR);
                        return BUFFER_ERROR;
                    }

                    /* Remove padding from end of plain text. */
                    for (--i; i > ssl->buffers.inputBuffer.idx; i--) {
                        if (ssl->buffers.inputBuffer.buffer[i] != 0)
                            break;
                    }

                    /* Get the real content type from the end of the data. */
                    ssl->curRL.type = ssl->buffers.inputBuffer.buffer[i];
                    /* consider both contentType byte and MAC as padding */
                    ssl->keys.padSz = ssl->buffers.inputBuffer.idx
                        + ssl->curSize - i;
                }
#endif
            }

            ssl->options.processReply = runProcessingOneRecord;
            FALL_THROUGH;

        /* the record layer is here */
        case runProcessingOneRecord:
#ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)) {

                if(!Dtls13CheckWindow(ssl)) {
                    /* drop packet */
                    WOLFSSL_MSG(
                            "Dropping DTLS record outside receiving window");
                    ssl->options.processReply = doProcessInit;
                    ssl->buffers.inputBuffer.idx += ssl->curSize;
                    if (ssl->buffers.inputBuffer.idx >
                            ssl->buffers.inputBuffer.length)
                        return BUFFER_E;

                    continue;
                }

                ret = Dtls13UpdateWindow(ssl);
                if (ret != 1) {
                    WOLFSSL_ERROR(ret);
                    return ret;
                }

                ret = Dtls13RecordRecvd(ssl);
                if (ret != 0) {
                    WOLFSSL_ERROR(ret);
                    return ret;
                }
            }
#endif /* WOLFSSL_DTLS13 */
            ssl->options.processReply = runProcessingOneMessage;
            FALL_THROUGH;

        case runProcessingOneMessage:
            /* can't process a message if we have no data.  */
            if (ssl->buffers.inputBuffer.idx
                    >= ssl->buffers.inputBuffer.length) {
                return BUFFER_ERROR;
            }
       #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (IsEncryptionOn(ssl, 0) && ssl->options.startedETMRead) {
                /* For TLS v1.1 the block size and explcit IV are added to idx,
                 * so it needs to be included in this limit check */
                if ((ssl->curSize - ssl->keys.padSz -
                        (ssl->buffers.inputBuffer.idx - startIdx) -
                        MacSize(ssl) > MAX_PLAINTEXT_SZ)
#ifdef WOLFSSL_ASYNC_CRYPT
                        && ssl->buffers.inputBuffer.length !=
                                ssl->buffers.inputBuffer.idx
#endif
                                ) {
                    WOLFSSL_MSG("Plaintext too long - Encrypt-Then-MAC");
            #if defined(WOLFSSL_EXTRA_ALERTS)
                    SendAlert(ssl, alert_fatal, record_overflow);
            #endif
                    WOLFSSL_ERROR_VERBOSE(BUFFER_ERROR);
                    return BUFFER_ERROR;
                }
            }
            else
       #endif
                /* TLS13 plaintext limit is checked earlier before decryption */
                /* For TLS v1.1 the block size and explcit IV are added to idx,
                 * so it needs to be included in this limit check */
                if (!IsAtLeastTLSv1_3(ssl->version)
                        && ssl->curSize - ssl->keys.padSz -
                            (ssl->buffers.inputBuffer.idx - startIdx)
                                > MAX_PLAINTEXT_SZ
#ifdef WOLFSSL_ASYNC_CRYPT
                        && ssl->buffers.inputBuffer.length !=
                                ssl->buffers.inputBuffer.idx
#endif
                                ) {
                WOLFSSL_MSG("Plaintext too long");
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_EXTRA_ALERTS)
                SendAlert(ssl, alert_fatal, record_overflow);
#endif
                WOLFSSL_ERROR_VERBOSE(BUFFER_ERROR);
                return BUFFER_ERROR;
            }

#ifdef WOLFSSL_DTLS
            if (IsDtlsNotSctpMode(ssl) && !IsAtLeastTLSv1_3(ssl->version)) {
                _DtlsUpdateWindow(ssl);
            }

            if (ssl->options.dtls) {
                /* Reset timeout as we have received a valid DTLS message */
                ssl->dtls_timeout = ssl->dtls_timeout_init;
            }
#endif /* WOLFSSL_DTLS */

            WOLFSSL_MSG("received record layer msg");

            switch (ssl->curRL.type) {
                case handshake :
                    WOLFSSL_MSG("got HANDSHAKE");
                    /* debugging in DoHandShakeMsg */
                    if (ssl->options.dtls) {
#ifdef WOLFSSL_DTLS
                        if (!IsAtLeastTLSv1_3(ssl->version)) {
                                ret = DoDtlsHandShakeMsg(ssl,
                                                         ssl->buffers.inputBuffer.buffer,
                                                         &ssl->buffers.inputBuffer.idx,
                                                         ssl->buffers.inputBuffer.length);
                        }
#endif
#ifdef WOLFSSL_DTLS13
                        if (IsAtLeastTLSv1_3(ssl->version)) {
                            ret = Dtls13HandshakeRecv(ssl,
                                ssl->buffers.inputBuffer.buffer,
                                &ssl->buffers.inputBuffer.idx,
                                ssl->buffers.inputBuffer.length);
#ifdef WOLFSSL_EARLY_DATA
                            if (ret == 0 &&
                                ssl->options.side == WOLFSSL_SERVER_END &&
                                ssl->earlyData > early_data_ext &&
                                ssl->options.handShakeState == HANDSHAKE_DONE) {

                                /* return so wolfSSL_read_early_data can return
                                   exit */
                                ssl->earlyData = no_early_data;
                                ssl->options.processReply = doProcessInit;

                                return ZERO_RETURN;
                            }
#endif /* WOLFSSL_EARLY_DATA */

                        }
#endif /* WOLFSSL_DTLS13 */
                    }
                    else if (!IsAtLeastTLSv1_3(ssl->version)
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12)
                            || !TLSv1_3_Capable(ssl)
#endif
                            ) {
#ifndef WOLFSSL_NO_TLS12
                        ret = DoHandShakeMsg(ssl,
                                            ssl->buffers.inputBuffer.buffer,
                                            &ssl->buffers.inputBuffer.idx,
                                            ssl->buffers.inputBuffer.length);
#else
                        ret = BUFFER_ERROR;
#endif
                    }
                    else {
#ifdef WOLFSSL_TLS13
                        ssl->msgsReceived.got_change_cipher = 0;
                        ret = DoTls13HandShakeMsg(ssl,
                                            ssl->buffers.inputBuffer.buffer,
                                            &ssl->buffers.inputBuffer.idx,
                                            ssl->buffers.inputBuffer.length);
    #ifdef WOLFSSL_EARLY_DATA
                        if (ret != 0)
                            return ret;
                        if (ssl->options.side == WOLFSSL_SERVER_END &&
                                ssl->earlyData > early_data_ext &&
                                ssl->options.handShakeState == HANDSHAKE_DONE) {
                            ssl->earlyData = no_early_data;
                            ssl->options.processReply = doProcessInit;
                            return ZERO_RETURN;
                        }
    #endif
#else
                        ret = BUFFER_ERROR;
#endif
                    }
                    if (ret != 0
                            /* DoDtlsHandShakeMsg can return a WANT_WRITE when
                             * calling DtlsMsgPoolSend. This msg is done
                             * processing so let's move on. */
                        && (!ssl->options.dtls
                            || ret != WANT_WRITE)
#ifdef WOLFSSL_ASYNC_CRYPT
                    /* In async case, on pending, move onto next message.
                     * Current message should have been DtlsMsgStore'ed and
                     * should be processed with DtlsMsgDrain */
                            && (!ssl->options.dtls
                                || ret != WC_PENDING_E)
#endif
                    ) {
                        WOLFSSL_ERROR(ret);
                        return ret;
                    }
                    break;

                case change_cipher_spec:
                    WOLFSSL_MSG("got CHANGE CIPHER SPEC");
                    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
                        if (ssl->hsInfoOn)
                            AddPacketName(ssl, "ChangeCipher");
                        /* add record header back on info */
                        if (ssl->toInfoOn) {
                            ret = AddPacketInfo(ssl, "ChangeCipher",
                                change_cipher_spec,
                                ssl->buffers.inputBuffer.buffer +
                                ssl->buffers.inputBuffer.idx,
                                1, READ_PROTO, RECORD_HEADER_SZ, ssl->heap);
                            if (ret != 0)
                                return ret;
                            #ifdef WOLFSSL_CALLBACKS
                            AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
                            #endif
                        }
                    #endif

#ifdef WOLFSSL_TLS13
                    if (IsAtLeastTLSv1_3(ssl->version)) {
                        word32 i = ssl->buffers.inputBuffer.idx;
                        if (ssl->options.handShakeState == HANDSHAKE_DONE) {
                            SendAlert(ssl, alert_fatal, unexpected_message);
                            WOLFSSL_ERROR_VERBOSE(UNKNOWN_RECORD_TYPE);
                            return UNKNOWN_RECORD_TYPE;
                        }
                        if (ssl->curSize != 1 ||
                                      ssl->buffers.inputBuffer.buffer[i] != 1) {
                            SendAlert(ssl, alert_fatal, illegal_parameter);
                            WOLFSSL_ERROR_VERBOSE(UNKNOWN_RECORD_TYPE);
                            return UNKNOWN_RECORD_TYPE;
                        }
                        ssl->buffers.inputBuffer.idx++;
                        if (!ssl->msgsReceived.got_change_cipher) {
                            ssl->msgsReceived.got_change_cipher = 1;
                        }
                        else {
                            SendAlert(ssl, alert_fatal, illegal_parameter);
                            WOLFSSL_ERROR_VERBOSE(UNKNOWN_RECORD_TYPE);
                            return UNKNOWN_RECORD_TYPE;
                        }
                        break;
                    }
#endif

#ifndef WOLFSSL_NO_TLS12
                    if (ssl->buffers.inputBuffer.idx >=
                            ssl->buffers.inputBuffer.length ||
                            ssl->curSize < 1) {
                        WOLFSSL_MSG("ChangeCipher msg too short");
                        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
                        return LENGTH_ERROR;
                    }
                    if (ssl->buffers.inputBuffer.buffer[
                            ssl->buffers.inputBuffer.idx] != 1) {
                        WOLFSSL_MSG("ChangeCipher msg wrong value");
                        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
                        return LENGTH_ERROR;
                    }

                    if (IsEncryptionOn(ssl, 0) && ssl->options.handShakeDone) {
#ifdef HAVE_AEAD
                        if (ssl->specs.cipher_type == aead) {
                            if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
                                ssl->curSize -= AESGCM_EXP_IV_SZ;
                            ssl->buffers.inputBuffer.idx += ssl->specs.aead_mac_size;
                            ssl->curSize -= ssl->specs.aead_mac_size;
                        }
                        else
#endif
                        {
                            ssl->buffers.inputBuffer.idx += ssl->keys.padSz;
                            ssl->curSize -= (word16)ssl->keys.padSz;
                            ssl->curSize -= ssl->specs.iv_size;
                        }

            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                        if (ssl->options.startedETMRead) {
                            word32 digestSz = MacSize(ssl);
                            ssl->buffers.inputBuffer.idx += digestSz;
                            ssl->curSize -= (word16)digestSz;
                        }
            #endif
                    }

                    if (ssl->curSize != 1) {
                        WOLFSSL_MSG("Malicious or corrupted ChangeCipher msg");
                        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
                        return LENGTH_ERROR;
                    }

                    ssl->buffers.inputBuffer.idx++;

                    ret = SanityCheckMsgReceived(ssl, change_cipher_hs);
                    if (ret != 0) {
                        if (!ssl->options.dtls) {
                            return ret;
                        }
                        else {
                        #ifdef WOLFSSL_DTLS
                        /* Check for duplicate CCS message in DTLS mode.
                         * DTLS allows for duplicate messages, and it should be
                         * skipped. Also skip if out of order. */
                            if (ret != DUPLICATE_MSG_E && ret != OUT_OF_ORDER_E)
                                return ret;
                            /* Reset error */
                            ret = 0;
                            break;
                        #endif /* WOLFSSL_DTLS */
                        }
                    }

                    ssl->keys.encryptionOn = 1;

                    /* setup decrypt keys for following messages */
                    /* XXX This might not be what we want to do when
                     * receiving a CCS with multicast. We update the
                     * key when the application updates them. */
                    if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
                        return ret;

            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    ssl->options.startedETMRead = ssl->options.encThenMac;
            #endif

                    #ifdef WOLFSSL_DTLS
                        if (ssl->options.dtls) {
                            WOLFSSL_DTLS_PEERSEQ* peerSeq = ssl->keys.peerSeq;
#ifdef WOLFSSL_MULTICAST
                            if (ssl->options.haveMcast) {
                                peerSeq += ssl->keys.curPeerId;
                                peerSeq->highwaterMark = UpdateHighwaterMark(0,
                                        ssl->ctx->mcastFirstSeq,
                                        ssl->ctx->mcastSecondSeq,
                                        ssl->ctx->mcastMaxSeq);
                            }
#endif
                            peerSeq->nextEpoch++;
                            peerSeq->prevSeq_lo = peerSeq->nextSeq_lo;
                            peerSeq->prevSeq_hi = peerSeq->nextSeq_hi;
                            peerSeq->nextSeq_lo = 0;
                            peerSeq->nextSeq_hi = 0;
                            XMEMCPY(peerSeq->prevWindow, peerSeq->window,
                                    DTLS_SEQ_SZ);
                            XMEMSET(peerSeq->window, 0, DTLS_SEQ_SZ);
                        }
                    #endif

                    #ifdef HAVE_LIBZ
                        if (ssl->options.usingCompression)
                            if ( (ret = InitStreams(ssl)) != 0)
                                return ret;
                    #endif
                    ret = BuildFinished(ssl, &ssl->hsHashes->verifyHashes,
                                       ssl->options.side == WOLFSSL_CLIENT_END ?
                                       kTlsServerStr : kTlsClientStr);
                    if (ret != 0)
                        return ret;
#endif /* !WOLFSSL_NO_TLS12 */
                    break;

                case application_data:
                    WOLFSSL_MSG("got app DATA");
                    #ifdef WOLFSSL_DTLS
                        if (ssl->options.dtls && ssl->options.dtlsHsRetain) {
                        #ifdef HAVE_SECURE_RENEGOTIATION
                            /*
                             * Only free HS resources when not in the process of a
                             * secure renegotiation and we have received APP DATA
                             * from the current epoch
                             */
                            if (!IsSCR(ssl) && (DtlsUseSCRKeys(ssl)
                                    || !DtlsSCRKeysSet(ssl))) {
                                FreeHandshakeResources(ssl);
                                ssl->options.dtlsHsRetain = 0;
                            }
                        #else
                            FreeHandshakeResources(ssl);
                            ssl->options.dtlsHsRetain = 0;
                        #endif
                        }
                    #endif
                    #ifdef WOLFSSL_TLS13
                        if (ssl->keys.keyUpdateRespond) {
                            WOLFSSL_MSG("No KeyUpdate from peer seen");
                            WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
                            return SANITY_MSG_E;
                        }
                    #endif
                    if ((ret = DoApplicationData(ssl,
                                                ssl->buffers.inputBuffer.buffer,
                                                &ssl->buffers.inputBuffer.idx,
                                                              NO_SNIFF)) != 0) {
                        WOLFSSL_ERROR(ret);
                        return ret;
                    }
                    break;

                case alert:
                    WOLFSSL_MSG("got ALERT!");
                    ret = DoAlert(ssl, ssl->buffers.inputBuffer.buffer,
                                  &ssl->buffers.inputBuffer.idx, &type);
                    if (ret == alert_fatal)
                        return FATAL_ERROR;
                    else if (ret < 0)
                        return ret;

                    /* catch warnings that are handled as errors */
                    if (type == close_notify) {
                        ssl->buffers.inputBuffer.idx =
                            ssl->buffers.inputBuffer.length;
                        ssl->options.processReply = doProcessInit;
                        return ssl->error = ZERO_RETURN;
                    }

                    if (type == decrypt_error)
                        return FATAL_ERROR;

                    /* Reset error if we got an alert level in ret */
                    if (ret > 0)
                        ret = 0;
                    break;

#ifdef WOLFSSL_DTLS13
            case ack:
                WOLFSSL_MSG("got ACK");
                if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)) {
                    word32 processedSize = 0;
                    ret = DoDtls13Ack(ssl, ssl->buffers.inputBuffer.buffer +
                                             ssl->buffers.inputBuffer.idx,
                                             ssl->buffers.inputBuffer.length -
                                             ssl->buffers.inputBuffer.idx -
                                             ssl->keys.padSz, &processedSize);
                    ssl->buffers.inputBuffer.idx += processedSize;
                    ssl->buffers.inputBuffer.idx += ssl->keys.padSz;
                    if (ret != 0)
                        return ret;
                    break;
                }
                FALL_THROUGH;
#endif /* WOLFSSL_DTLS13 */
                default:
                    WOLFSSL_ERROR(UNKNOWN_RECORD_TYPE);
                    return UNKNOWN_RECORD_TYPE;
            }

            ssl->options.processReply = doProcessInit;

            /* input exhausted */
            if (ssl->buffers.inputBuffer.idx >= ssl->buffers.inputBuffer.length
#ifdef WOLFSSL_DTLS
                /* If app data was processed then return now to avoid
                 * dropping any app data. */
                || (ssl->options.dtls && ssl->curRL.type == application_data)
#endif
                ) {
                /* Shrink input buffer when we successfully finish record
                 * processing */
                if (ret == 0 && ssl->buffers.inputBuffer.dynamicFlag)
                    ShrinkInputBuffer(ssl, NO_FORCED_FREE);
                return ret;
            }
            /* more messages per record */
            else if ((ssl->buffers.inputBuffer.idx - startIdx) < ssl->curSize) {
                WOLFSSL_MSG("More messages in record");

                ssl->options.processReply = runProcessingOneMessage;

                if (IsEncryptionOn(ssl, 0)) {
                    WOLFSSL_MSG("Bundled encrypted messages, remove middle pad");
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    if (ssl->options.startedETMRead) {
                        word32 digestSz = MacSize(ssl);
                        if (ssl->buffers.inputBuffer.idx >=
                                                   ssl->keys.padSz + digestSz) {
                            ssl->buffers.inputBuffer.idx -=
                                                     ssl->keys.padSz + digestSz;
                        }
                        else {
                            WOLFSSL_MSG("\tmiddle padding error");
                            WOLFSSL_ERROR_VERBOSE(FATAL_ERROR);
                            return FATAL_ERROR;
                        }
                    }
                    else
             #endif
                    {
                        if (ssl->buffers.inputBuffer.idx >= ssl->keys.padSz) {
                            ssl->buffers.inputBuffer.idx -= ssl->keys.padSz;
                        }
                        else {
                            WOLFSSL_MSG("\tmiddle padding error");
                            WOLFSSL_ERROR_VERBOSE(FATAL_ERROR);
                            return FATAL_ERROR;
                        }
                    }
                }
            }
            /* more records */
            else {
                WOLFSSL_MSG("More records in input");
            }
#ifdef WOLFSSL_ASYNC_CRYPT
            /* We are setup to read next message/record but we had an error
             * (probably WC_PENDING_E) so return that so it can be handled
             * by higher layers. */
            if (ret != 0)
                return ret;
#endif
            /* It is safe to shrink the input buffer here now. local vars will
             * be reset to the new starting value. */
            if (ret == 0 && ssl->buffers.inputBuffer.dynamicFlag)
                ShrinkInputBuffer(ssl, NO_FORCED_FREE);
            continue;
        default:
            WOLFSSL_MSG("Bad process input state, programming error");
            WOLFSSL_ERROR_VERBOSE(INPUT_CASE_ERROR);
            return INPUT_CASE_ERROR;
        }
    }
}

#if !defined(WOLFSSL_NO_TLS12) || !defined(NO_OLD_TLS) || \
             (defined(WOLFSSL_TLS13) && defined(WOLFSSL_TLS13_MIDDLEBOX_COMPAT))
int SendChangeCipher(WOLFSSL* ssl)
{
    byte              *output;
    int                sendSz = RECORD_HEADER_SZ + ENUM_LEN;
    int                idx    = RECORD_HEADER_SZ;
    int                ret;

    #ifdef OPENSSL_EXTRA
    ssl->cbmode = SSL_CB_MODE_WRITE;
    if (ssl->options.side == WOLFSSL_SERVER_END){
        ssl->options.serverState = SERVER_CHANGECIPHERSPEC_COMPLETE;
        if (ssl->CBIS != NULL)
            ssl->CBIS(ssl, SSL_CB_ACCEPT_LOOP, SSL_SUCCESS);
    }
    else{
        ssl->options.clientState =
            CLIENT_CHANGECIPHERSPEC_COMPLETE;
        if (ssl->CBIS != NULL)
            ssl->CBIS(ssl, SSL_CB_CONNECT_LOOP, SSL_SUCCESS);
    }
    #endif

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            sendSz += DTLS_RECORD_EXTRA;
            idx    += DTLS_RECORD_EXTRA;
        }
    #endif

    /* are we in scr */
    if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone) {
        sendSz += MAX_MSG_EXTRA;
    }

    /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
     * is not advanced yet */
    ssl->options.buildingMsg = 1;

    /* check for available size */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddRecordHeader(output, 1, change_cipher_spec, ssl, CUR_ORDER);

    output[idx] = 1;             /* turn it on */

    if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone) {
        byte input[ENUM_LEN];
        int  inputSz = ENUM_LEN;

        input[0] = 1;  /* turn it on */
    #ifdef WOLFSSL_DTLS
        if (IsDtlsNotSctpMode(ssl) &&
                (ret = DtlsMsgPoolSave(ssl, input, inputSz, change_cipher_hs)) != 0) {
            return ret;
        }
    #endif
        sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                              change_cipher_spec, 0, 0, 0, CUR_ORDER);
        if (sendSz < 0) {
            return sendSz;
        }
    }
    #ifdef WOLFSSL_DTLS
    else {
        if (IsDtlsNotSctpMode(ssl)) {
            if ((ret = DtlsMsgPoolSave(ssl, output, sendSz, change_cipher_hs)) != 0)
                return ret;
            DtlsSEQIncrement(ssl, CUR_ORDER);
        }
    }
    #endif
    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn) AddPacketName(ssl, "ChangeCipher");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "ChangeCipher", change_cipher_spec, output,
                    sendSz, WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
    #endif
    ssl->buffers.outputBuffer.length += sendSz;

#ifdef WOLFSSL_TLS13
    if (!ssl->options.tls1_3)
#endif
    {
        /* setup encrypt keys */
        if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY)) != 0)
            return ret;

    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        ssl->options.startedETMWrite = ssl->options.encThenMac;
    #endif
    }

    ssl->options.buildingMsg = 0;

    if (ssl->options.groupMessages)
        return 0;
    #if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_DEBUG_DTLS)
    else if (ssl->options.dtls) {
        /* If using DTLS, force the ChangeCipherSpec message to be in the
         * same datagram as the finished message. */
        return 0;
    }
    #endif
    else
        return SendBuffered(ssl);
}
#endif


#if !defined(NO_OLD_TLS) && !defined(WOLFSSL_AEAD_ONLY)
static int SSL_hmac(WOLFSSL* ssl, byte* digest, const byte* in, word32 sz,
                    int padLen, int content, int verify, int epochOrder)
{
    byte   result[WC_MAX_DIGEST_SIZE];
    word32 digestSz = ssl->specs.hash_size;            /* actual sizes */
    word32 padSz    = ssl->specs.pad_size;
    int    ret      = 0;

    wc_Md5 md5;
    wc_Sha sha;

    /* data */
    byte seq[SEQ_SZ];
    byte conLen[ENUM_LEN + LENGTH_SZ];     /* content & length */
    const byte* macSecret = NULL;

    (void)padLen;

#ifdef HAVE_FUZZER
    if (ssl->fuzzerCb)
        ssl->fuzzerCb(ssl, in, sz, FUZZ_HMAC, ssl->fuzzerCtx);
#endif

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls)
        macSecret = wolfSSL_GetDtlsMacSecret(ssl, verify, epochOrder);
    else
        macSecret = wolfSSL_GetMacSecret(ssl, verify);
#else
    macSecret = wolfSSL_GetMacSecret(ssl, verify);
#endif

    XMEMSET(seq, 0, SEQ_SZ);
    conLen[0] = (byte)content;
    c16toa((word16)sz, &conLen[ENUM_LEN]);
    WriteSEQ(ssl, epochOrder, seq);

    if (ssl->specs.mac_algorithm == md5_mac) {
        ret =  wc_InitMd5_ex(&md5, ssl->heap, ssl->devId);
        if (ret != 0)
            return ret;

        /* inner */
        ret =  wc_Md5Update(&md5, macSecret, digestSz);
        ret |= wc_Md5Update(&md5, PAD1, padSz);
        ret |= wc_Md5Update(&md5, seq, SEQ_SZ);
        ret |= wc_Md5Update(&md5, conLen, sizeof(conLen));
        /* in buffer */
        ret |= wc_Md5Update(&md5, in, sz);
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }
        ret = wc_Md5Final(&md5, result);
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* TODO: Make non-blocking */
        if (ret == WC_PENDING_E) {
            ret = wc_AsyncWait(ret, &md5.asyncDev, WC_ASYNC_FLAG_NONE);
        }
    #endif
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }

        /* outer */
        ret =  wc_Md5Update(&md5, macSecret, digestSz);
        ret |= wc_Md5Update(&md5, PAD2, padSz);
        ret |= wc_Md5Update(&md5, result, digestSz);
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }
        ret =  wc_Md5Final(&md5, digest);
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* TODO: Make non-blocking */
        if (ret == WC_PENDING_E) {
            ret = wc_AsyncWait(ret, &md5.asyncDev, WC_ASYNC_FLAG_NONE);
        }
    #endif
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }

        wc_Md5Free(&md5);
    }
    else {
        ret =  wc_InitSha_ex(&sha, ssl->heap, ssl->devId);
        if (ret != 0)
            return ret;

        /* inner */
        ret =  wc_ShaUpdate(&sha, macSecret, digestSz);
        ret |= wc_ShaUpdate(&sha, PAD1, padSz);
        ret |= wc_ShaUpdate(&sha, seq, SEQ_SZ);
        ret |= wc_ShaUpdate(&sha, conLen, sizeof(conLen));
        /* in buffer */
        ret |= wc_ShaUpdate(&sha, in, sz);
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }
        ret = wc_ShaFinal(&sha, result);
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* TODO: Make non-blocking */
        if (ret == WC_PENDING_E) {
            ret = wc_AsyncWait(ret, &sha.asyncDev, WC_ASYNC_FLAG_NONE);
        }
    #endif
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }

        /* outer */
        ret =  wc_ShaUpdate(&sha, macSecret, digestSz);
        ret |= wc_ShaUpdate(&sha, PAD2, padSz);
        ret |= wc_ShaUpdate(&sha, result, digestSz);
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }
        ret =  wc_ShaFinal(&sha, digest);
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* TODO: Make non-blocking */
        if (ret == WC_PENDING_E) {
            ret = wc_AsyncWait(ret, &sha.asyncDev, WC_ASYNC_FLAG_NONE);
        }
    #endif
        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
            return VERIFY_MAC_ERROR;
        }

        wc_ShaFree(&sha);
    }
    return 0;
}
#endif /* !NO_OLD_TLS && !WOLFSSL_AEAD_ONLY */

#if !defined(NO_MD5) && !defined(NO_OLD_TLS)
static int BuildMD5_CertVerify(WOLFSSL* ssl, byte* digest)
{
    int ret;
    byte md5_result[WC_MD5_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Md5* md5 = (wc_Md5*)XMALLOC(sizeof(wc_Md5), ssl->heap, DYNAMIC_TYPE_HASHCTX);
#else
    wc_Md5  md5[1];
#endif

    /* make md5 inner */
    ret = wc_Md5Copy(&ssl->hsHashes->hashMd5, md5); /* Save current position */
    if (ret == 0)
        ret = wc_Md5Update(md5, ssl->arrays->masterSecret,SECRET_LEN);
    if (ret == 0)
        ret = wc_Md5Update(md5, PAD1, PAD_MD5);
    if (ret == 0)
        ret = wc_Md5Final(md5, md5_result);

    /* make md5 outer */
    if (ret == 0) {
        ret = wc_InitMd5_ex(md5, ssl->heap, ssl->devId);
        if (ret == 0) {
            ret = wc_Md5Update(md5, ssl->arrays->masterSecret, SECRET_LEN);
            if (ret == 0)
                ret = wc_Md5Update(md5, PAD2, PAD_MD5);
            if (ret == 0)
                ret = wc_Md5Update(md5, md5_result, WC_MD5_DIGEST_SIZE);
            if (ret == 0)
                ret = wc_Md5Final(md5, digest);
            wc_Md5Free(md5);
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(md5, ssl->heap, DYNAMIC_TYPE_HASHCTX);
#endif

    return ret;
}
#endif /* !NO_MD5 && !NO_OLD_TLS */

#if !defined(NO_SHA) && (!defined(NO_OLD_TLS) || \
                              defined(WOLFSSL_ALLOW_TLS_SHA1))
static int BuildSHA_CertVerify(WOLFSSL* ssl, byte* digest)
{
    int ret;
    byte sha_result[WC_SHA_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    wc_Sha* sha = (wc_Sha*)XMALLOC(sizeof(wc_Sha), ssl->heap, DYNAMIC_TYPE_HASHCTX);
#else
    wc_Sha  sha[1];
#endif

    /* make sha inner */
    ret = wc_ShaCopy(&ssl->hsHashes->hashSha, sha); /* Save current position */
    if (ret == 0)
        ret = wc_ShaUpdate(sha, ssl->arrays->masterSecret,SECRET_LEN);
    if (ret == 0)
        ret = wc_ShaUpdate(sha, PAD1, PAD_SHA);
    if (ret == 0)
        ret = wc_ShaFinal(sha, sha_result);

    /* make sha outer */
    if (ret == 0) {
        ret = wc_InitSha_ex(sha, ssl->heap, ssl->devId);
        if (ret == 0) {
            ret = wc_ShaUpdate(sha, ssl->arrays->masterSecret,SECRET_LEN);
            if (ret == 0)
                ret = wc_ShaUpdate(sha, PAD2, PAD_SHA);
            if (ret == 0)
                ret = wc_ShaUpdate(sha, sha_result, WC_SHA_DIGEST_SIZE);
            if (ret == 0)
                ret = wc_ShaFinal(sha, digest);
            wc_ShaFree(sha);
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(sha, ssl->heap, DYNAMIC_TYPE_HASHCTX);
#endif

    return ret;
}
#endif /* !NO_SHA && (!NO_OLD_TLS || WOLFSSL_ALLOW_TLS_SHA1) */

int BuildCertHashes(WOLFSSL* ssl, Hashes* hashes)
{
    int ret = 0;

    (void)hashes;

    if (ssl->options.tls) {
    #if !defined(NO_MD5) && !defined(NO_OLD_TLS)
        ret = wc_Md5GetHash(&ssl->hsHashes->hashMd5, hashes->md5);
        if (ret != 0)
            return ret;
    #endif
    #if !defined(NO_SHA)
        ret = wc_ShaGetHash(&ssl->hsHashes->hashSha, hashes->sha);
        if (ret != 0)
            return ret;
    #endif
        if (IsAtLeastTLSv1_2(ssl)) {
            #ifndef NO_SHA256
                ret = wc_Sha256GetHash(&ssl->hsHashes->hashSha256,
                                       hashes->sha256);
                if (ret != 0)
                    return ret;
            #endif
            #ifdef WOLFSSL_SHA384
                ret = wc_Sha384GetHash(&ssl->hsHashes->hashSha384,
                                       hashes->sha384);
                if (ret != 0)
                    return ret;
            #endif
            #ifdef WOLFSSL_SHA512
                ret = wc_Sha512GetHash(&ssl->hsHashes->hashSha512,
                                       hashes->sha512);
                if (ret != 0)
                    return ret;
            #endif
        }
    }
    else {
    #if !defined(NO_MD5) && !defined(NO_OLD_TLS)
        ret = BuildMD5_CertVerify(ssl, hashes->md5);
        if (ret != 0)
            return ret;
    #endif
    #if !defined(NO_SHA) && (!defined(NO_OLD_TLS) || \
                              defined(WOLFSSL_ALLOW_TLS_SHA1))
        ret = BuildSHA_CertVerify(ssl, hashes->sha);
        if (ret != 0)
            return ret;
    #endif
    }

    return ret;
}

#ifndef WOLFSSL_NO_TLS12
void FreeBuildMsgArgs(WOLFSSL* ssl, BuildMsgArgs* args)
{
    (void)ssl;
    if (args
#ifdef WOLFSSL_ASYNC_CRYPT
            && ssl->options.buildArgsSet
#endif
        ) {
        /* only free the IV if it was dynamically allocated */
        if (args->iv && (args->iv != args->staticIvBuffer)) {
            XFREE(args->iv, ssl->heap, DYNAMIC_TYPE_SALT);
        }
    }
#ifdef WOLFSSL_ASYNC_CRYPT
    ssl->options.buildArgsSet = 0;
#endif
}
#endif

/* Build SSL Message, encrypted */
int BuildMessage(WOLFSSL* ssl, byte* output, int outSz, const byte* input,
             int inSz, int type, int hashOutput, int sizeOnly, int asyncOkay,
             int epochOrder)
{
#ifndef WOLFSSL_NO_TLS12
    int ret;
    BuildMsgArgs* args;
    BuildMsgArgs  lcl_args;
#endif

    WOLFSSL_ENTER("BuildMessage");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    /* catch mistaken sizeOnly parameter */
    if (!sizeOnly && (output == NULL || input == NULL) ) {
        return BAD_FUNC_ARG;
    }
    if (sizeOnly && (output || input) ) {
        return BAD_FUNC_ARG;
    }

    (void)epochOrder;

#ifndef NO_TLS
#if defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_TLS13)
    return BuildTls13Message(ssl, output, outSz, input, inSz, type,
                                               hashOutput, sizeOnly, asyncOkay);
#else
#ifdef WOLFSSL_TLS13
    if (ssl->options.tls1_3) {
        return BuildTls13Message(ssl, output, outSz, input, inSz, type,
                                 hashOutput, sizeOnly, asyncOkay);
    }
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    ret = WC_NOT_PENDING_E;
    if (asyncOkay) {
        if (ssl->async == NULL) {
            return BAD_FUNC_ARG;
        }
        args = &ssl->async->buildArgs;

        ret = wolfSSL_AsyncPop(ssl, &ssl->options.buildMsgState);
        if (ret != WC_NOT_PENDING_E) {
            /* Check for error */
            if (ret < 0)
                goto exit_buildmsg;
        }
    }
    else
#endif
    {
        args = &lcl_args;
    }

    /* Reset state */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_NOT_PENDING_E)
#endif
    {
        ret = 0;
#ifdef WOLFSSL_ASYNC_CRYPT
        ssl->options.buildArgsSet = 1;
#endif
        ssl->options.buildMsgState = BUILD_MSG_BEGIN;
        XMEMSET(args, 0, sizeof(BuildMsgArgs));

        args->sz = RECORD_HEADER_SZ + inSz;
        args->idx  = RECORD_HEADER_SZ;
        args->headerSz = RECORD_HEADER_SZ;
    }

    switch (ssl->options.buildMsgState) {
        case BUILD_MSG_BEGIN:
        {
        #if defined(WOLFSSL_DTLS) && defined(HAVE_SECURE_RENEGOTIATION)
            if (ssl->options.dtls && DtlsSCRKeysSet(ssl)) {
                /* For epochs >1 the current cipher parameters are located in
                 * ssl->secure_renegotiation->tmp_keys. Previous cipher
                 * parameters and for epoch 1 use ssl->keys */
                switch (epochOrder) {
                case PREV_ORDER:
                    if (ssl->encrypt.src != KEYS) {
                        ssl->secure_renegotiation->cache_status =
                                SCR_CACHE_NULL;
                        if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY)) != 0)
                            ERROR_OUT(ret, exit_buildmsg);
                    }
                    break;
                case CUR_ORDER:
                    if (ssl->keys.dtls_epoch ==
                            ssl->secure_renegotiation->tmp_keys.dtls_epoch) {
                        if (ssl->encrypt.src != SCR) {
                            ssl->secure_renegotiation->cache_status =
                                    SCR_CACHE_NEEDED;
                            if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY))
                                    != 0)
                                ERROR_OUT(ret, exit_buildmsg);
                        }
                    }
                    else {
                        if (ssl->encrypt.src != KEYS) {
                            ssl->secure_renegotiation->cache_status =
                                    SCR_CACHE_NULL;
                            if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY))
                                    != 0)
                                ERROR_OUT(ret, exit_buildmsg);
                        }
                    }
                    break;
                default:
                    WOLFSSL_MSG("BuildMessage only supports PREV_ORDER and "
                                "CUR_ORDER");
                    ERROR_OUT(BAD_FUNC_ARG, exit_buildmsg);
                }
            }
        #endif

            ssl->options.buildMsgState = BUILD_MSG_SIZE;
        }
        FALL_THROUGH;
        case BUILD_MSG_SIZE:
        {
            args->digestSz = ssl->specs.hash_size;
        #ifdef HAVE_TRUNCATED_HMAC
            if (ssl->truncated_hmac)
                args->digestSz = min(TRUNCATED_HMAC_SZ, args->digestSz);
        #endif
            args->sz += args->digestSz;

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                args->sz       += DTLS_RECORD_EXTRA;
                args->idx      += DTLS_RECORD_EXTRA;
                args->headerSz += DTLS_RECORD_EXTRA;
            }
        #endif

        #ifndef WOLFSSL_AEAD_ONLY
            if (ssl->specs.cipher_type == block) {
                word32 blockSz = ssl->specs.block_size;

                if (blockSz == 0) {
                    WOLFSSL_MSG("Invalid block size with block cipher type");
                    ERROR_OUT(BAD_STATE_E, exit_buildmsg);
                }

                if (ssl->options.tls1_1) {
                    args->ivSz = blockSz;
                    args->sz  += args->ivSz;

                    if (args->ivSz > MAX_IV_SZ)
                        ERROR_OUT(BUFFER_E, exit_buildmsg);
                }
                args->sz += 1;       /* pad byte */
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                if (ssl->options.startedETMWrite) {
                    args->pad = (args->sz - args->headerSz -
                                                      args->digestSz) % blockSz;
                }
                else
            #endif
                {
                    args->pad = (args->sz - args->headerSz) % blockSz;
                }
                if (args->pad != 0)
                    args->pad = blockSz - args->pad;
                args->sz += args->pad;
            }
        #endif /* WOLFSSL_AEAD_ONLY */

        #ifdef HAVE_AEAD
            if (ssl->specs.cipher_type == aead) {
                if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
                    args->ivSz = AESGCM_EXP_IV_SZ;

                args->sz += (args->ivSz + ssl->specs.aead_mac_size - args->digestSz);
            }
        #endif

            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            if (args->sz > (word32)outSz) {
                WOLFSSL_MSG("Oops, want to write past output buffer size");
                ERROR_OUT(BUFFER_E, exit_buildmsg);
            }

            if (args->ivSz > 0) {
                if (args->ivSz > sizeof(args->staticIvBuffer)) {
                    args->iv = (byte*)XMALLOC(args->ivSz, ssl->heap,
                                              DYNAMIC_TYPE_SALT);
                    if (args->iv == NULL) {
                        ERROR_OUT(MEMORY_E, exit_buildmsg);
                    }
                }
                else {
                    args->iv = args->staticIvBuffer;
                }

                ret = wc_RNG_GenerateBlock(ssl->rng, args->iv, args->ivSz);
                if (ret != 0)
                    goto exit_buildmsg;
            }
#if !defined(NO_PUBLIC_GCM_SET_IV) && \
    ((defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2)) && \
    defined(HAVE_AEAD))
            if (ssl->specs.cipher_type == aead) {
                if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
                    XMEMCPY(args->iv, ssl->keys.aead_exp_IV, AESGCM_EXP_IV_SZ);
            }
#endif

            args->size = (word16)(args->sz - args->headerSz);    /* include mac and digest */
            AddRecordHeader(output, args->size, (byte)type, ssl, epochOrder);

            /* write to output */
            if (args->ivSz > 0) {
                XMEMCPY(output + args->idx, args->iv,
                                        min(args->ivSz, MAX_IV_SZ));
                args->idx += args->ivSz;
            }
            XMEMCPY(output + args->idx, input, inSz);
            args->idx += inSz;

            ssl->options.buildMsgState = BUILD_MSG_HASH;
        }
        FALL_THROUGH;
        case BUILD_MSG_HASH:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            if (type == handshake && hashOutput) {
                ret = HashOutput(ssl, output, args->headerSz + inSz, args->ivSz);
                if (ret != 0)
                    goto exit_buildmsg;
            }
        #ifndef WOLFSSL_AEAD_ONLY
            if (ssl->specs.cipher_type == block) {
                word32 tmpIdx;
                word32 i;

            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                if (ssl->options.startedETMWrite)
                    tmpIdx = args->idx;
                else
            #endif
                    tmpIdx = args->idx + args->digestSz;

                for (i = 0; i <= args->pad; i++)
                    output[tmpIdx++] = (byte)args->pad; /* pad byte gets pad value */
            }
        #endif

            ssl->options.buildMsgState = BUILD_MSG_VERIFY_MAC;
        }
        FALL_THROUGH;
        case BUILD_MSG_VERIFY_MAC:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            /* User Record Layer Callback handling */
    #ifdef ATOMIC_USER
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMWrite) {
                if (ssl->ctx->EncryptMacCb) {
                    ret = ssl->ctx->EncryptMacCb(ssl, output + args->idx +
                                                 args->pad + 1, type, 0,
                                                 output + args->headerSz,
                                                 output + args->headerSz,
                                                 args->size - args->digestSz,
                                                 ssl->MacEncryptCtx);
                    goto exit_buildmsg;
                }
            }
            else
        #endif
            {
                if (ssl->ctx->MacEncryptCb) {
                    ret = ssl->ctx->MacEncryptCb(ssl, output + args->idx,
                                    output + args->headerSz + args->ivSz, inSz,
                                    type, 0, output + args->headerSz,
                                    output + args->headerSz, args->size,
                                    ssl->MacEncryptCtx);
                    goto exit_buildmsg;
                }
            }
    #endif

        #ifndef WOLFSSL_AEAD_ONLY
            if (ssl->specs.cipher_type != aead
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                                               && !ssl->options.startedETMWrite
            #endif
                ) {
            #ifdef HAVE_TRUNCATED_HMAC
                if (ssl->truncated_hmac &&
                                        ssl->specs.hash_size > args->digestSz) {
                #ifdef WOLFSSL_SMALL_STACK
                    byte* hmac;
                #else
                    byte  hmac[WC_MAX_DIGEST_SIZE];
                #endif

                #ifdef WOLFSSL_SMALL_STACK
                    hmac = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, ssl->heap,
                                                           DYNAMIC_TYPE_DIGEST);
                    if (hmac == NULL)
                        ERROR_OUT(MEMORY_E, exit_buildmsg);
                #endif

                    ret = ssl->hmac(ssl, hmac,
                                     output + args->headerSz + args->ivSz, inSz,
                                     -1, type, 0, epochOrder);
                    XMEMCPY(output + args->idx, hmac, args->digestSz);

                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(hmac, ssl->heap, DYNAMIC_TYPE_DIGEST);
                #endif
                }
                else
            #endif
                {
                    ret = ssl->hmac(ssl, output + args->idx, output +
                                args->headerSz + args->ivSz, inSz, -1, type, 0, epochOrder);
                }
            }
        #endif /* WOLFSSL_AEAD_ONLY */
            if (ret != 0)
                goto exit_buildmsg;

            ssl->options.buildMsgState = BUILD_MSG_ENCRYPT;
        }
        FALL_THROUGH;
        case BUILD_MSG_ENCRYPT:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            {
    #if defined(HAVE_SECURE_RENEGOTIATION) && defined(WOLFSSL_DTLS)
            /* If we want the PREV_ORDER then modify CUR_ORDER sequence number
             * for all encryption algos that use it for encryption parameters */
            word16 dtls_epoch = 0;
            word16 dtls_sequence_number_hi = 0;
            word32 dtls_sequence_number_lo = 0;
            int swap_seq = ssl->options.dtls && epochOrder == PREV_ORDER &&
                    DtlsUseSCRKeys(ssl);
            if (swap_seq) {
                dtls_epoch = ssl->keys.dtls_epoch;
                dtls_sequence_number_hi = ssl->keys.dtls_sequence_number_hi;
                dtls_sequence_number_lo = ssl->keys.dtls_sequence_number_lo;
                ssl->keys.dtls_epoch--;
                ssl->keys.dtls_sequence_number_hi =
                        ssl->keys.dtls_prev_sequence_number_hi;
                ssl->keys.dtls_sequence_number_lo =
                        ssl->keys.dtls_prev_sequence_number_lo;
            }
    #endif
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMWrite) {
                ret = Encrypt(ssl, output + args->headerSz,
                                          output + args->headerSz,
                                          (word16)(args->size - args->digestSz),
                                          asyncOkay);
            }
            else
    #endif
            {
                ret = Encrypt(ssl, output + args->headerSz,
                                output + args->headerSz, args->size, asyncOkay);
            }
    #if defined(HAVE_SECURE_RENEGOTIATION) && defined(WOLFSSL_DTLS)
            /* Restore sequence numbers */
            if (swap_seq) {
                ssl->keys.dtls_epoch = dtls_epoch;
                ssl->keys.dtls_sequence_number_hi = dtls_sequence_number_hi;
                ssl->keys.dtls_sequence_number_lo = dtls_sequence_number_lo;
            }
    #endif
            }

            if (ret != 0) {
            #ifdef WOLFSSL_ASYNC_CRYPT
                if (ret != WC_PENDING_E)
            #endif
                {
                    /* Zeroize plaintext. */
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    if (ssl->options.startedETMWrite) {
                        ForceZero(output + args->headerSz,
                            (word16)(args->size - args->digestSz));
                    }
                    else
            #endif
                    {
                        ForceZero(output + args->headerSz, (word16)args->size);
                    }
                }
                goto exit_buildmsg;
            }
            ssl->options.buildMsgState = BUILD_MSG_ENCRYPTED_VERIFY_MAC;
        }
        FALL_THROUGH;
        case BUILD_MSG_ENCRYPTED_VERIFY_MAC:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMWrite) {
                WOLFSSL_MSG("Calculate MAC of Encrypted Data");

            #ifdef HAVE_TRUNCATED_HMAC
                if (ssl->truncated_hmac &&
                                        ssl->specs.hash_size > args->digestSz) {
                #ifdef WOLFSSL_SMALL_STACK
                    byte* hmac = NULL;
                #else
                    byte  hmac[WC_MAX_DIGEST_SIZE];
                #endif

                #ifdef WOLFSSL_SMALL_STACK
                    hmac = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, ssl->heap,
                                                           DYNAMIC_TYPE_DIGEST);
                    if (hmac == NULL)
                        ERROR_OUT(MEMORY_E, exit_buildmsg);
                #endif

                    ret = ssl->hmac(ssl, hmac, output + args->headerSz,
                                    args->ivSz + inSz + args->pad + 1, -1, type,
                                    0, epochOrder);
                    XMEMCPY(output + args->idx + args->pad + 1, hmac,
                                                                args->digestSz);

                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(hmac, ssl->heap, DYNAMIC_TYPE_DIGEST);
                #endif
                }
                else
            #endif
                {
                    ret = ssl->hmac(ssl, output + args->idx + args->pad + 1,
                                    output + args->headerSz,
                                    args->ivSz + inSz + args->pad + 1, -1, type,
                                    0, epochOrder);
                }
            }
        #endif /* HAVE_ENCRYPT_THEN_MAC && !WOLFSSL_AEAD_ONLY */
        }
        FALL_THROUGH;
        default:
            break;
    }

exit_buildmsg:

    WOLFSSL_LEAVE("BuildMessage", ret);

#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        return ret;
    }
#endif

    /* make sure build message state is reset */
    ssl->options.buildMsgState = BUILD_MSG_BEGIN;

    #ifdef WOLFSSL_DTLS
        if (ret == 0 && ssl->options.dtls && !sizeOnly)
            DtlsSEQIncrement(ssl, epochOrder);
    #endif

    /* return sz on success */
    if (ret == 0) {
        ret = args->sz;
    }
    else {
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    /* Final cleanup */
    FreeBuildMsgArgs(ssl, args);

    return ret;
#endif /* !WOLFSSL_NO_TLS12 */
#else
    (void)outSz;
    (void)inSz;
    (void)type;
    (void)hashOutput;
    (void)asyncOkay;
    return NOT_COMPILED_IN;
#endif /* NO_TLS */

}

#ifndef WOLFSSL_NO_TLS12

int SendFinished(WOLFSSL* ssl)
{
    int              sendSz,
                     finishedSz = ssl->options.tls ? TLS_FINISHED_SZ :
                                                     FINISHED_SZ;
    byte             input[FINISHED_SZ + DTLS_HANDSHAKE_HEADER_SZ];  /* max */
    byte            *output;
    Hashes*          hashes;
    int              ret;
    int              headerSz = HANDSHAKE_HEADER_SZ;
    int              outputSz;

    WOLFSSL_START(WC_FUNC_FINISHED_SEND);
    WOLFSSL_ENTER("SendFinished");

    /* check for available size */
    outputSz = sizeof(input) + MAX_MSG_EXTRA;

    /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
     * is not advanced yet */
    ssl->options.buildingMsg = 1;

    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
        return ret;

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            headerSz += DTLS_HANDSHAKE_EXTRA;
            ssl->keys.dtls_epoch++;
            ssl->keys.dtls_prev_sequence_number_hi =
                    ssl->keys.dtls_sequence_number_hi;
            ssl->keys.dtls_prev_sequence_number_lo =
                    ssl->keys.dtls_sequence_number_lo;
            ssl->keys.dtls_sequence_number_hi = 0;
            ssl->keys.dtls_sequence_number_lo = 0;
        }
    #endif

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddHandShakeHeader(input, finishedSz, 0, finishedSz, finished, ssl);

    /* make finished hashes */
    hashes = (Hashes*)&input[headerSz];
    ret = BuildFinished(ssl, hashes, ssl->options.side == WOLFSSL_CLIENT_END ?
                                                 kTlsClientStr : kTlsServerStr);
    if (ret != 0) return ret;

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation) {
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            XMEMCPY(ssl->secure_renegotiation->client_verify_data, hashes,
                    TLS_FINISHED_SZ);
        else
            XMEMCPY(ssl->secure_renegotiation->server_verify_data, hashes,
                    TLS_FINISHED_SZ);
    }
#endif
#ifdef WOLFSSL_HAVE_TLS_UNIQUE
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        XMEMCPY(ssl->clientFinished,
                hashes, TLS_FINISHED_SZ);
        ssl->clientFinished_len = TLS_FINISHED_SZ;
    }
    else {
        XMEMCPY(ssl->serverFinished,
                hashes, TLS_FINISHED_SZ);
        ssl->serverFinished_len = TLS_FINISHED_SZ;
    }
#endif

    #ifdef WOLFSSL_DTLS
        if (IsDtlsNotSctpMode(ssl)) {
            if ((ret = DtlsMsgPoolSave(ssl, input, headerSz + finishedSz,
                                                              finished)) != 0) {
                return ret;
            }
        }
    #endif

    sendSz = BuildMessage(ssl, output, outputSz, input, headerSz + finishedSz,
                                                 handshake, 1, 0, 0, CUR_ORDER);
    if (sendSz < 0)
        return BUILD_MSG_ERROR;

    if (!ssl->options.resuming) {
#ifndef NO_SESSION_CACHE
        AddSession(ssl);    /* just try */
#endif
        if (ssl->options.side == WOLFSSL_SERVER_END) {
        #ifdef OPENSSL_EXTRA
            ssl->options.serverState = SERVER_FINISHED_COMPLETE;
            ssl->cbmode = SSL_CB_MODE_WRITE;
            if (ssl->CBIS != NULL)
                ssl->CBIS(ssl, SSL_CB_HANDSHAKE_DONE, SSL_SUCCESS);
        #endif
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
    else {
        if (ssl->options.side == WOLFSSL_CLIENT_END) {
        #ifdef OPENSSL_EXTRA
            ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
            ssl->cbmode = SSL_CB_MODE_WRITE;
            if (ssl->CBIS != NULL)
                ssl->CBIS(ssl, SSL_CB_HANDSHAKE_DONE, SSL_SUCCESS);
        #endif
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn) AddPacketName(ssl, "Finished");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "Finished", handshake, output, sendSz,
                          WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
    #endif

    ssl->buffers.outputBuffer.length += sendSz;

    ret = SendBuffered(ssl);

    ssl->options.buildingMsg = 0;

#ifdef WOLFSSL_DTLS
    if ((!ssl->options.resuming &&
            ssl->options.side == WOLFSSL_SERVER_END) ||
        (ssl->options.resuming &&
            ssl->options.side == WOLFSSL_CLIENT_END)) {
        ssl->keys.dtls_handshake_number = 0;
        ssl->keys.dtls_expected_peer_handshake_number = 0;
    }
#endif

    WOLFSSL_LEAVE("SendFinished", ret);
    WOLFSSL_END(WC_FUNC_FINISHED_SEND);

    return ret;
}
#endif /* WOLFSSL_NO_TLS12 */

#ifndef NO_WOLFSSL_SERVER
#if (!defined(WOLFSSL_NO_TLS12) && \
        (defined(HAVE_CERTIFICATE_STATUS_REQUEST) || \
         defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2))) || \
    (defined(WOLFSSL_TLS13) && defined(HAVE_CERTIFICATE_STATUS_REQUEST))
/* Parses and decodes the certificate then initializes "request". In the case
 * of !ssl->buffers.weOwnCert, ssl->ctx->certOcspRequest gets set to "request".
 *
 * Returns 0 on success
 */
static int CreateOcspRequest(WOLFSSL* ssl, OcspRequest* request,
                             DecodedCert* cert, byte* certData, word32 length)
{
    int ret;

    if (request != NULL)
        XMEMSET(request, 0, sizeof(OcspRequest));

    InitDecodedCert(cert, certData, length, ssl->heap);
    /* TODO: Setup async support here */
    ret = ParseCertRelative(cert, CERT_TYPE, VERIFY, SSL_CM(ssl));
    if (ret != 0) {
        WOLFSSL_MSG("ParseCert failed");
    }
    if (ret == 0)
        ret = InitOcspRequest(request, cert, 0, ssl->heap);
    if (ret == 0) {
        /* make sure ctx OCSP request is updated */
        if (!ssl->buffers.weOwnCert) {
            wolfSSL_Mutex* ocspLock = &SSL_CM(ssl)->ocsp_stapling->ocspLock;
            if (wc_LockMutex(ocspLock) == 0) {
                if (ssl->ctx->certOcspRequest == NULL)
                    ssl->ctx->certOcspRequest = request;
                wc_UnLockMutex(ocspLock);
            }
        }
    }

    FreeDecodedCert(cert);

    return ret;
}


/* Creates OCSP response and places it in variable "response". Memory
 * management for "buffer* response" is up to the caller.
 *
 * Also creates an OcspRequest in the case that ocspRequest is null or that
 * ssl->buffers.weOwnCert is set. In those cases managing ocspRequest free'ing
 * is up to the caller. NOTE: in OcspCreateRequest ssl->ctx->certOcspRequest can
 * be set to point to "ocspRequest" and it then should not be free'd since
 * wolfSSL_CTX_free will take care of it.
 *
 * Returns 0 on success
 */
int CreateOcspResponse(WOLFSSL* ssl, OcspRequest** ocspRequest,
                       buffer* response)
{
    int          ret = 0;
    OcspRequest* request = NULL;
    byte createdRequest  = 0;

    if (ssl == NULL || ocspRequest == NULL || response == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(response, 0, sizeof(*response));
    request = *ocspRequest;

    /* unable to fetch status. skip. */
    if (SSL_CM(ssl) == NULL || SSL_CM(ssl)->ocspStaplingEnabled == 0)
        return 0;

    if (request == NULL || ssl->buffers.weOwnCert) {
        DerBuffer* der = ssl->buffers.certificate;
        #ifdef WOLFSSL_SMALL_STACK
            DecodedCert* cert = NULL;
        #else
            DecodedCert  cert[1];
        #endif

        /* unable to fetch status. skip. */
        if (der->buffer == NULL || der->length == 0)
            return 0;

    #ifdef WOLFSSL_SMALL_STACK
        cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), ssl->heap,
                                        DYNAMIC_TYPE_DCERT);
        if (cert == NULL)
            return MEMORY_E;
    #endif
        request = (OcspRequest*)XMALLOC(sizeof(OcspRequest), ssl->heap,
                                                     DYNAMIC_TYPE_OCSP_REQUEST);
        if (request == NULL)
            ret = MEMORY_E;

        createdRequest = 1;
        if (ret == 0) {
            ret = CreateOcspRequest(ssl, request, cert, der->buffer,
                                                                   der->length);
        }

        if (ret != 0) {
            XFREE(request, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);
            request = NULL;
        }

    #ifdef WOLFSSL_SMALL_STACK
        XFREE(cert, ssl->heap, DYNAMIC_TYPE_DCERT);
    #endif
    }

    if (ret == 0) {
        request->ssl = ssl;
        ret = CheckOcspRequest(SSL_CM(ssl)->ocsp_stapling, request, response);

        /* Suppressing, not critical */
        if (ret == OCSP_CERT_REVOKED ||
            ret == OCSP_CERT_UNKNOWN ||
            ret == OCSP_LOOKUP_FAIL) {
            ret = 0;
        }
    }

    /* free request up if error case found otherwise return it */
    if (ret != 0 && createdRequest) {
        FreeOcspRequest(request);
        XFREE(request, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);
    }

    if (ret == 0)
        *ocspRequest = request;

    return ret;
}
#endif
#endif /* !NO_WOLFSSL_SERVER */

int cipherExtraData(WOLFSSL* ssl)
{
    int cipherExtra;
    /* Cipher data that may be added by BuildMessage */
    /* There is always an IV (expect for chacha). For AEAD ciphers,
     * there is the authentication tag (aead_mac_size). For block
     * ciphers we have the hash_size MAC on the message, and one
     * block size for possible padding. */
    if (ssl->specs.cipher_type == aead) {
        cipherExtra = ssl->specs.aead_mac_size;
        /* CHACHA does not have an explicit IV. */
        if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha) {
            cipherExtra += AESGCM_EXP_IV_SZ;
        }
    }
    else {
        cipherExtra = ssl->specs.iv_size + ssl->specs.block_size +
            ssl->specs.hash_size;
    }
    /* Sanity check so we don't ever return negative. */
    return cipherExtra > 0 ? cipherExtra : 0;
}

#ifndef WOLFSSL_NO_TLS12

#ifndef NO_CERTS

/////////////////////////////



/* handle generation of certificate_status (22) */
int SendCertificateStatus(WOLFSSL* ssl)
{
    int ret = 0;
    byte status_type = 0;

    WOLFSSL_START(WC_FUNC_CERTIFICATE_STATUS_SEND);
    WOLFSSL_ENTER("SendCertificateStatus");

    (void) ssl;

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST
    status_type = ssl->status_request;
#endif

#ifdef HAVE_CERTIFICATE_STATUS_REQUEST_V2
    status_type = status_type ? status_type : ssl->status_request_v2;
#endif

    switch (status_type) {

    #ifndef NO_WOLFSSL_SERVER
    #if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
     || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
        /* case WOLFSSL_CSR_OCSP: */
        case WOLFSSL_CSR2_OCSP:
        {
            OcspRequest* request = ssl->ctx->certOcspRequest;
            buffer response;

            ret = CreateOcspResponse(ssl, &request, &response);

            /* if a request was successfully created and not stored in
             * ssl->ctx then free it */
            if (ret == 0 && request != ssl->ctx->certOcspRequest) {
                FreeOcspRequest(request);
                XFREE(request, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);
                request = NULL;
            }

            if (ret == 0 && response.buffer) {
                ret = BuildCertificateStatus(ssl, status_type, &response, 1);

                XFREE(response.buffer, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);
                response.buffer = NULL;
            }
            break;
        }

    #endif /* HAVE_CERTIFICATE_STATUS_REQUEST    */
           /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */

    #if defined HAVE_CERTIFICATE_STATUS_REQUEST_V2
        case WOLFSSL_CSR2_OCSP_MULTI:
        {
            OcspRequest* request = ssl->ctx->certOcspRequest;
            buffer responses[1 + MAX_CHAIN_DEPTH];
            int i = 0;

            XMEMSET(responses, 0, sizeof(responses));

            ret = CreateOcspResponse(ssl, &request, &responses[0]);

            /* if a request was successfully created and not stored in
             * ssl->ctx then free it */
            if (ret == 0 && request != ssl->ctx->certOcspRequest) {
                FreeOcspRequest(request);
                XFREE(request, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);
                request = NULL;
            }

            if (ret == 0 && (!ssl->ctx->chainOcspRequest[0]
                                              || ssl->buffers.weOwnCertChain)) {
                buffer der;
                word32 idx = 0;
            #ifdef WOLFSSL_SMALL_STACK
                DecodedCert* cert;
            #else
                DecodedCert  cert[1];
            #endif
                DerBuffer* chain;

            #ifdef WOLFSSL_SMALL_STACK
                cert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), ssl->heap,
                                                            DYNAMIC_TYPE_DCERT);
                if (cert == NULL)
                    return MEMORY_E;
            #endif
                request = (OcspRequest*)XMALLOC(sizeof(OcspRequest), ssl->heap,
                                                     DYNAMIC_TYPE_OCSP_REQUEST);
                if (request == NULL) {
            #ifdef WOLFSSL_SMALL_STACK
                    XFREE(cert, ssl->heap, DYNAMIC_TYPE_DCERT);
            #endif
                    return MEMORY_E;
                }

                /* use certChain if available, otherwise use peer certificate */
                chain = ssl->buffers.certChain;
                if (chain == NULL) {
                    chain = ssl->buffers.certificate;
                }

                if (chain && chain->buffer) {
                    while (idx + OPAQUE24_LEN < chain->length) {
                        c24to32(chain->buffer + idx, &der.length);
                        idx += OPAQUE24_LEN;

                        der.buffer = chain->buffer + idx;
                        idx += der.length;

                        if (idx > chain->length)
                            break;

                        ret = CreateOcspRequest(ssl, request, cert, der.buffer,
                                                der.length);
                        if (ret == 0) {
                            request->ssl = ssl;
                        ret = CheckOcspRequest(SSL_CM(ssl)->ocsp_stapling,
                                                    request, &responses[i + 1]);

                            /* Suppressing, not critical */
                            if (ret == OCSP_CERT_REVOKED ||
                                ret == OCSP_CERT_UNKNOWN ||
                                ret == OCSP_LOOKUP_FAIL) {
                                ret = 0;
                            }


                            i++;
                            FreeOcspRequest(request);
                        }
                    }
                }

                XFREE(request, ssl->heap, DYNAMIC_TYPE_OCSP_REQUEST);
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(cert, ssl->heap, DYNAMIC_TYPE_DCERT);
            #endif
            }
            else {
                while (ret == 0 &&
                            NULL != (request = ssl->ctx->chainOcspRequest[i])) {
                    request->ssl = ssl;
                    ret = CheckOcspRequest(SSL_CM(ssl)->ocsp_stapling,
                                                request, &responses[++i]);

                    /* Suppressing, not critical */
                    if (ret == OCSP_CERT_REVOKED ||
                        ret == OCSP_CERT_UNKNOWN ||
                        ret == OCSP_LOOKUP_FAIL) {
                        ret = 0;
                    }
                }
            }

            if (responses[0].buffer) {
                if (ret == 0) {
                    ret = BuildCertificateStatus(ssl, status_type, responses,
                                                                   (byte)i + 1);
                }

                for (i = 0; i < 1 + MAX_CHAIN_DEPTH; i++) {
                    if (responses[i].buffer) {
                        XFREE(responses[i].buffer, ssl->heap,
                                                     DYNAMIC_TYPE_OCSP_REQUEST);
                    }
                }
            }

            break;
        }
    #endif /* HAVE_CERTIFICATE_STATUS_REQUEST_V2 */
    #endif /* NO_WOLFSSL_SERVER */

        default:
            break;
    }

    WOLFSSL_LEAVE("SendCertificateStatus", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_STATUS_SEND);

    return ret;
}

#endif /* !NO_CERTS */

#endif /* WOLFSSL_NO_TLS12 */



#if defined(HAVE_SECURE_RENEGOTIATION) && defined(WOLFSSL_DTLS)
/**
 * Check if the SCR keys are set in ssl->secure_renegotiation->tmp_keys.
 */
int DtlsSCRKeysSet(WOLFSSL* ssl)
{
    return ssl->secure_renegotiation &&
           ssl->secure_renegotiation->tmp_keys.dtls_epoch != 0;
}

/**
 * ssl->keys contains the current cipher parameters only for epoch 1. For
 * epochs >1 ssl->secure_renegotiation->tmp_keys contains the current
 * cipher parameters. This function checks if the message currently being
 * processed should use ssl->keys or ssl->secure_renegotiation->tmp_keys.
 */
int IsDtlsMsgSCRKeys(WOLFSSL* ssl)
{
    return DtlsSCRKeysSet(ssl) &&
           ssl->keys.curEpoch ==
                   ssl->secure_renegotiation->tmp_keys.dtls_epoch;
}

/**
 * ssl->keys contains the current cipher parameters only for epoch 1. For
 * epochs >1 ssl->secure_renegotiation->tmp_keys contains the current
 * cipher parameters. This function checks if the message currently being
 * built should use ssl->keys or ssl->secure_renegotiation->tmp_keys.
 */
int DtlsUseSCRKeys(WOLFSSL* ssl)
{
    return DtlsSCRKeysSet(ssl) &&
           ssl->secure_renegotiation->tmp_keys.dtls_epoch ==
                   ssl->keys.dtls_epoch;
}

/**
 * If ssl->secure_renegotiation->tmp_keys.dtls_epoch > ssl->keys.dtls_epoch
 * then PREV_ORDER refers to the current epoch.
 * */
int DtlsCheckOrder(WOLFSSL* ssl, int order)
{
    if (order == PREV_ORDER && ssl->secure_renegotiation &&
            ssl->secure_renegotiation->tmp_keys.dtls_epoch > ssl->keys.dtls_epoch) {
        return CUR_ORDER;
    }
    else {
        return order;
    }
}
#endif /* HAVE_SECURE_RENEGOTIATION && WOLFSSL_DTLS */

/* If secure renegotiation is disabled, this will always return false.
 * Otherwise it checks to see if we are currently renegotiating. */
int IsSCR(WOLFSSL* ssl)
{
#ifndef HAVE_SECURE_RENEGOTIATION
    (void)ssl;
#else /* HAVE_SECURE_RENEGOTIATION */
    if (ssl->secure_renegotiation &&
            ssl->secure_renegotiation->enabled &&  /* Is SCR enabled? */
            ssl->options.handShakeDone && /* At least one handshake done? */
            ssl->options.handShakeState != HANDSHAKE_DONE) /* Currently handshaking? */
        return 1;
#endif /* HAVE_SECURE_RENEGOTIATION */
    return 0;
}


#ifdef WOLFSSL_DTLS
static int ModifyForMTU(WOLFSSL* ssl, int buffSz, int outputSz, int mtuSz)
{
    int recordExtra = outputSz - buffSz;

    (void)ssl;

    if (recordExtra > 0 && outputSz > mtuSz) {
        buffSz = mtuSz - recordExtra;
#ifndef WOLFSSL_AEAD_ONLY
        /* Subtract a block size to be certain that returned fragment
         * size won't get more padding. */
        if (ssl->specs.cipher_type == block)
            buffSz -= ssl->specs.block_size;
#endif
    }

    return buffSz;
}
#endif /* WOLFSSL_DTLS */

#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_TLS13_IGNORE_AEAD_LIMITS)
/*
 * Enforce limits specified in
 * https://www.rfc-editor.org/rfc/rfc8446#section-5.5
 */
static int CheckTLS13AEADSendLimit(WOLFSSL* ssl)
{
    w64wrapper seq;
    w64wrapper limit;

    switch (ssl->specs.bulk_cipher_algorithm) {
#ifdef BUILD_AESGCM
        case wolfssl_aes_gcm:
            /* Limit is 2^24.5 */
            limit = AEAD_AES_LIMIT;
            break;
#endif
#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        case wolfssl_chacha:
            /* For ChaCha20/Poly1305, the record sequence number would wrap
             * before the safety limit is reached. */
            return 0;
#endif
#ifdef HAVE_AESCCM
        case wolfssl_aes_ccm:
            /* Use the limits calculated in the DTLS 1.3 spec
             * https://www.rfc-editor.org/rfc/rfc9147.html#name-analysis-of-limits-on-ccm-u */
#ifdef WOLFSSL_DTLS13
            if (ssl->options.dtls)
                limit = DTLS_AEAD_AES_CCM_LIMIT; /* Limit is 2^23 */
            else
#endif
                limit = AEAD_AES_LIMIT; /* Limit is 2^24.5 */
            break;
#endif
        case wolfssl_cipher_null:
            /* No encryption being done */
            return 0;
        default:
            WOLFSSL_MSG("Unrecognized ciphersuite for AEAD limit check");
            return BAD_STATE_E;

    }
#ifdef WOLFSSL_DTLS13
    if (ssl->options.dtls) {
        seq = ssl->dtls13EncryptEpoch->nextSeqNumber;
    }
    else
#endif
    {
        seq = w64From32(ssl->keys.sequence_number_hi,
                ssl->keys.sequence_number_lo);
    }

    if (w64GTE(seq, limit))
        return Tls13UpdateKeys(ssl); /* Need to generate new keys */

    return 0;
}
#endif /* WOLFSSL_TLS13 && !WOLFSSL_TLS13_IGNORE_AEAD_LIMITS */

int SendData(WOLFSSL* ssl, const void* data, int sz)
{
    int sent = 0,  /* plainText size */
        sendSz,
        ret;
#if defined(WOLFSSL_EARLY_DATA) && defined(WOLFSSL_EARLY_DATA_GROUP)
    int groupMsgs = 0;
#endif

    if (ssl->error == WANT_WRITE
    #ifdef WOLFSSL_ASYNC_CRYPT
        || ssl->error == WC_PENDING_E
    #endif
    ) {
        ssl->error = 0;
    }

    /* don't allow write after decrypt or mac error */
    if (ssl->error == VERIFY_MAC_ERROR || ssl->error == DECRYPT_ERROR) {
        /* For DTLS allow these possible errors and allow the session
            to continue despite them */
        if (ssl->options.dtls) {
            ssl->error = 0;
        }
        else {
            WOLFSSL_MSG("Not allowing write after decrypt or mac error");
            return WOLFSSL_FATAL_ERROR;
        }
    }

#ifdef WOLFSSL_EARLY_DATA
    if (ssl->earlyData != no_early_data) {
        if (ssl->options.handShakeState == HANDSHAKE_DONE) {
            WOLFSSL_MSG("handshake complete, trying to send early data");
            ssl->error = BUILD_MSG_ERROR;
            return WOLFSSL_FATAL_ERROR;
        }
    #ifdef WOLFSSL_EARLY_DATA_GROUP
        groupMsgs = 1;
    #endif
    }
    else
#endif
    if (ssl->options.handShakeState != HANDSHAKE_DONE && !IsSCR(ssl)) {
        int err;
        WOLFSSL_MSG("handshake not complete, trying to finish");
        if ( (err = wolfSSL_negotiate(ssl)) != WOLFSSL_SUCCESS) {
        #ifdef WOLFSSL_ASYNC_CRYPT
            /* if async would block return WANT_WRITE */
            if (ssl->error == WC_PENDING_E) {
                return WOLFSSL_CBIO_ERR_WANT_WRITE;
            }
        #endif
            return  err;
        }
    }

    /* last time system socket output buffer was full, try again to send */
    if (ssl->buffers.outputBuffer.length > 0
    #if defined(WOLFSSL_EARLY_DATA) && defined(WOLFSSL_EARLY_DATA_GROUP)
        && !groupMsgs
    #endif
        ) {
        WOLFSSL_MSG("output buffer was full, trying to send again");
        if ( (ssl->error = SendBuffered(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            if (ssl->error == SOCKET_ERROR_E && (ssl->options.connReset ||
                                                 ssl->options.isClosed)) {
                ssl->error = SOCKET_PEER_CLOSED_E;
                WOLFSSL_ERROR(ssl->error);
                return 0;  /* peer reset or closed */
            }
            return ssl->error;
        }
        else {
            /* advance sent to previous sent + plain size just sent */
            sent = ssl->buffers.prevSent + ssl->buffers.plainSz;
            WOLFSSL_MSG("sent write buffered data");

            if (sent > sz) {
                WOLFSSL_MSG("error: write() after WANT_WRITE with short size");
                return ssl->error = BAD_FUNC_ARG;
            }
        }
    }

    ret = RetrySendAlert(ssl);
    if (ret != 0) {
        ssl->error = ret;
        return WOLFSSL_FATAL_ERROR;
    }

    for (;;) {
        byte* out;
        byte* sendBuffer = (byte*)data + sent;  /* may switch on comp */
        int   buffSz;                           /* may switch on comp */
        int   outputSz;
#ifdef HAVE_LIBZ
        byte  comp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];
#endif

#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_TLS13_IGNORE_AEAD_LIMITS)
        if (IsAtLeastTLSv1_3(ssl->version)) {
            ret = CheckTLS13AEADSendLimit(ssl);
            if (ret != 0) {
                ssl->error = ret;
                return WOLFSSL_FATAL_ERROR;
            }
        }
#endif

#ifdef WOLFSSL_DTLS13
        if (ssl->options.dtls && ssl->options.tls1_3) {
            byte isEarlyData = 0;

            if (ssl->dtls13EncryptEpoch == NULL)
                return ssl->error = BAD_STATE_E;

#ifdef WOLFSSL_EARLY_DATA
            isEarlyData = ssl->earlyData != no_early_data;
#endif

            if (isEarlyData) {
#ifdef WOLFSSL_EARLY_DATA
                ret = Dtls13SetEpochKeys(ssl,
                    w64From32(0x0, DTLS13_EPOCH_EARLYDATA), ENCRYPT_SIDE_ONLY);
                if (ret != 0) {
                    WOLFSSL_MSG(
                        "trying to send early data without epoch 1");
                    ssl->error = BUILD_MSG_ERROR;
                    return WOLFSSL_FATAL_ERROR;
                }
#endif /* WOLFSSL_EARLY_DATA */
            }
            else if (!w64Equal(
                         ssl->dtls13EncryptEpoch->epochNumber,
                         ssl->dtls13Epoch)) {
                ret = Dtls13SetEpochKeys(
                    ssl, ssl->dtls13Epoch, ENCRYPT_SIDE_ONLY);
                if (ret != 0) {
                    ssl->error = BUILD_MSG_ERROR;
                    return WOLFSSL_FATAL_ERROR;
                }
            }
        }
#endif /* WOLFSSL_DTLS13 */

#ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            buffSz = wolfSSL_GetMaxFragSize(ssl, sz - sent);
        }
        else
#endif
        {
            buffSz = wolfSSL_GetMaxFragSize(ssl, sz - sent);

        }

        if (sent == sz) break;

#if defined(WOLFSSL_DTLS) && !defined(WOLFSSL_NO_DTLS_SIZE_CHECK)
        if (ssl->options.dtls && (buffSz < sz - sent)) {
            ssl->error = DTLS_SIZE_ERROR;
            WOLFSSL_ERROR(ssl->error);
            return ssl->error;
        }
#endif
        outputSz = buffSz + COMP_EXTRA + DTLS_RECORD_HEADER_SZ;
        if (IsEncryptionOn(ssl, 1) || ssl->options.tls1_3)
            outputSz += cipherExtraData(ssl);

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
            return ssl->error = ret;

        /* get output buffer */
        out = ssl->buffers.outputBuffer.buffer +
              ssl->buffers.outputBuffer.length;

#ifdef HAVE_LIBZ
        if (ssl->options.usingCompression) {
            buffSz = myCompress(ssl, sendBuffer, buffSz, comp, sizeof(comp));
            if (buffSz < 0) {
                return buffSz;
            }
            sendBuffer = comp;
        }
#endif
        if (!ssl->options.tls1_3) {
#ifdef WOLFSSL_ASYNC_CRYPT
            if (ssl->async == NULL) {
                ssl->async = (struct WOLFSSL_ASYNC*)
                        XMALLOC(sizeof(struct WOLFSSL_ASYNC), ssl->heap,
                                DYNAMIC_TYPE_ASYNC);
                if (ssl->async == NULL)
                    return MEMORY_E;
                ssl->async->freeArgs = NULL;
            }
#endif
            sendSz = BuildMessage(ssl, out, outputSz, sendBuffer, buffSz,
                                  application_data, 0, 0, 1, CUR_ORDER);
        }
        else {
#ifdef WOLFSSL_TLS13
            sendSz = BuildTls13Message(ssl, out, outputSz, sendBuffer, buffSz,
                                       application_data, 0, 0, 1);
#else
            sendSz = BUFFER_ERROR;
#endif
        }
        if (sendSz < 0) {
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (sendSz == WC_PENDING_E)
                ssl->error = sendSz;
        #endif
            return BUILD_MSG_ERROR;
        }

#ifdef WOLFSSL_ASYNC_CRYPT
        FreeAsyncCtx(ssl, 0);
#endif
        ssl->buffers.outputBuffer.length += sendSz;

        if ( (ssl->error = SendBuffered(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            /* store for next call if WANT_WRITE or user embedSend() that
               doesn't present like WANT_WRITE */
            ssl->buffers.plainSz  = buffSz;
            ssl->buffers.prevSent = sent;
            if (ssl->error == SOCKET_ERROR_E && (ssl->options.connReset ||
                                                 ssl->options.isClosed)) {
                ssl->error = SOCKET_PEER_CLOSED_E;
                WOLFSSL_ERROR(ssl->error);
                return 0;  /* peer reset or closed */
            }
            return ssl->error;
        }

        sent += buffSz;

        /* only one message per attempt */
        if (ssl->options.partialWrite == 1) {
            WOLFSSL_MSG("Partial Write on, only sending one record");
            break;
        }
    }

    return sent;
}

/* process input data */
int ReceiveData(WOLFSSL* ssl, byte* output, int sz, int peek)
{
    int size;

    WOLFSSL_ENTER("ReceiveData()");

    /* reset error state */
    if (ssl->error == WANT_READ || ssl->error == WOLFSSL_ERROR_WANT_READ) {
        ssl->error = 0;
    }

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        /* In DTLS mode, we forgive some errors and allow the session
         * to continue despite them. */
        if (ssl->error == VERIFY_MAC_ERROR ||
            ssl->error == DECRYPT_ERROR ||
            ssl->error == DTLS_SIZE_ERROR) {

            ssl->error = 0;
        }
    }
#endif /* WOLFSSL_DTLS */

    if (ssl->error != 0 && ssl->error != WANT_WRITE
#ifdef WOLFSSL_ASYNC_CRYPT
            && ssl->error != WC_PENDING_E
#endif
#ifdef HAVE_SECURE_RENEGOTIATION
            && ssl->error != APP_DATA_READY
#endif
    ) {
        WOLFSSL_MSG("User calling wolfSSL_read in error state, not allowed");
        return ssl->error;
    }

#ifdef WOLFSSL_EARLY_DATA
    if (ssl->earlyData != no_early_data) {
    }
    else
#endif
    {
        int negotiate = 0;
#ifdef HAVE_SECURE_RENEGOTIATION
        if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled) {
            if (ssl->options.handShakeState != HANDSHAKE_DONE
                && ssl->buffers.clearOutputBuffer.length == 0)
                negotiate = 1;
        }
        else
#endif
        if (ssl->options.handShakeState != HANDSHAKE_DONE)
            negotiate = 1;

        if (negotiate) {
            int err;
            WOLFSSL_MSG("Handshake not complete, trying to finish");
            if ( (err = wolfSSL_negotiate(ssl)) != WOLFSSL_SUCCESS) {
            #ifdef WOLFSSL_ASYNC_CRYPT
                /* if async would block return WANT_WRITE */
                if (ssl->error == WC_PENDING_E) {
                    return WOLFSSL_CBIO_ERR_WANT_READ;
                }
            #endif
                return err;
            }
        }
    }

#ifdef HAVE_SECURE_RENEGOTIATION
startScr:
    if (ssl->secure_renegotiation && ssl->secure_renegotiation->startScr) {
        int ret;
        WOLFSSL_MSG("Need to start scr, server requested");
        ret = wolfSSL_Rehandshake(ssl);
        ssl->secure_renegotiation->startScr = 0;  /* only start once */
        if (ret != WOLFSSL_SUCCESS)
            return ret;
    }
#endif

    while (ssl->buffers.clearOutputBuffer.length == 0) {
        if ( (ssl->error = ProcessReply(ssl)) < 0) {
            if (ssl->error == ZERO_RETURN) {
                WOLFSSL_MSG("Zero return, no more data coming");
                return 0; /* no more data coming */
            }
            if (ssl->error == SOCKET_ERROR_E) {
                if (ssl->options.connReset || ssl->options.isClosed) {
                    WOLFSSL_MSG("Peer reset or closed, connection done");
                    ssl->error = SOCKET_PEER_CLOSED_E;
                    WOLFSSL_ERROR(ssl->error);
                    return 0; /* peer reset or closed */
                }
            }
            WOLFSSL_ERROR(ssl->error);
            return ssl->error;
        }

#ifdef WOLFSSL_DTLS13
        if (ssl->options.dtls) {
            /* Dtls13DoScheduledWork(ssl) may return WANT_WRITE */
            if ((ssl->error = Dtls13DoScheduledWork(ssl)) < 0) {
                WOLFSSL_ERROR(ssl->error);
                return ssl->error;
            }
        }
#endif /* WOLFSSL_DTLS13 */
        #ifdef HAVE_SECURE_RENEGOTIATION
            if (ssl->secure_renegotiation &&
                ssl->secure_renegotiation->startScr) {
                goto startScr;
            }
            if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled &&
                    ssl->options.handShakeState != HANDSHAKE_DONE
                    && ssl->buffers.clearOutputBuffer.length == 0) {
                /* ProcessReply processed a handshake packet and not any APP DATA
                 * so let's move the handshake along */
                int err;
                WOLFSSL_MSG("Handshake not complete, trying to finish");
                if ( (err = wolfSSL_negotiate(ssl)) != WOLFSSL_SUCCESS) {
                #ifdef WOLFSSL_ASYNC_CRYPT
                    /* if async would block return WANT_WRITE */
                    if (ssl->error == WC_PENDING_E) {
                        return WOLFSSL_CBIO_ERR_WANT_READ;
                    }
                #endif
                    return err;
                }
            }
        #endif

#ifdef WOLFSSL_DTLS13
            /* if wolfSSL_Peek() is invoked with sz == 0 it will not block (but
             *  it processes pending non-application records) */
            if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version) && peek &&
                sz == 0 && ssl->buffers.inputBuffer.idx
                - ssl->buffers.inputBuffer.length  == 0) {
                return 0;
            }
#endif /* WOLFSSL_DTLS13 */

#ifndef WOLFSSL_TLS13_NO_PEEK_HANDSHAKE_DONE
    #ifdef WOLFSSL_TLS13
        if (IsAtLeastTLSv1_3(ssl->version) && ssl->options.handShakeDone &&
                                         ssl->curRL.type == handshake && peek) {
            WOLFSSL_MSG("Got Handshake Messge in APP data");
            if (ssl->buffers.inputBuffer.length == 0) {
                ssl->error = WOLFSSL_ERROR_WANT_READ;
                return 0;
            }
        }
    #endif
#endif
    }

    size = min(sz, (int)ssl->buffers.clearOutputBuffer.length);

    XMEMCPY(output, ssl->buffers.clearOutputBuffer.buffer, size);

    if (peek == 0) {
        ssl->buffers.clearOutputBuffer.length -= size;
        ssl->buffers.clearOutputBuffer.buffer += size;
    }

    if (ssl->buffers.inputBuffer.dynamicFlag)
       ShrinkInputBuffer(ssl, NO_FORCED_FREE);

    WOLFSSL_LEAVE("ReceiveData()", size);
    return size;
}

static int SendAlert_ex(WOLFSSL* ssl, int severity, int type)
{
    byte input[ALERT_SIZE];
    byte *output;
    int  sendSz;
    int  ret;
    int  outputSz;
    int  dtlsExtra = 0;

    WOLFSSL_ENTER("SendAlert");

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        ret = !ssl->quic.method->send_alert(ssl, ssl->quic.enc_level_write, (uint8_t)type);
        if (ret) {
            WOLFSSL_MSG("QUIC send_alert callback error");
        }
        return ret;
    }
#endif

#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite && ssl->dupSide == READ_DUP_SIDE) {
        int notifyErr = 0;

        WOLFSSL_MSG("Read dup side cannot write alerts, notifying sibling");

        if (type == close_notify) {
            notifyErr = ZERO_RETURN;
        } else if (severity == alert_fatal) {
            notifyErr = FATAL_ERROR;
        }

        if (notifyErr != 0) {
            return NotifyWriteSide(ssl, notifyErr);
        }

        return 0;
    }
#endif

    ssl->pendingAlert.code = type;
    ssl->pendingAlert.level = severity;

   #ifdef OPENSSL_EXTRA
        if (ssl->CBIS != NULL) {
            ssl->CBIS(ssl, SSL_CB_ALERT, type);
        }
   #endif
   #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls)
           dtlsExtra = DTLS_RECORD_EXTRA;
   #endif

    /* check for available size */
    outputSz = ALERT_SIZE + MAX_MSG_EXTRA + dtlsExtra;
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0) {
#ifdef WOLFSSL_DTLS
        /* If CheckAvailableSize returned WANT_WRITE due to a blocking write
         * then discard pending output and just send the alert. */
        if (ssl->options.dtls) {
            if (ret != WANT_WRITE || severity != alert_fatal)
                return ret;
            ShrinkOutputBuffer(ssl);
            if ((ret = CheckAvailableSize(ssl, outputSz)) != 0) {
                return ret;
            }
        }
        else {
            return ret;
        }
#else
        return ret;
#endif
    }

    /* Check output buffer */
    if (ssl->buffers.outputBuffer.buffer == NULL)
        return BUFFER_E;

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    input[0] = (byte)severity;
    input[1] = (byte)type;
    ssl->alert_history.last_tx.code = type;
    ssl->alert_history.last_tx.level = severity;
    if (severity == alert_fatal) {
        ssl->options.isClosed = 1;  /* Don't send close_notify */
    }

    /* send encrypted alert if encryption is on - can be a rehandshake over
     * an existing encrypted channel.
     * TLS 1.3 encrypts handshake packets after the ServerHello
     */
    if (IsEncryptionOn(ssl, 1)) {
#ifdef WOLFSSL_DTLS13
        if (ssl->options.dtls
            && IsAtLeastTLSv1_3(ssl->version)
            && !w64Equal(ssl->dtls13EncryptEpoch->epochNumber, ssl->dtls13Epoch)) {
            ret = Dtls13SetEpochKeys(ssl, ssl->dtls13Epoch, ENCRYPT_SIDE_ONLY);
            if (ret != 0)
                return ret;
        }
#endif /* WOLFSSL_DTLS13 */

        sendSz = BuildMessage(ssl, output, outputSz, input, ALERT_SIZE, alert,
                                                                       0, 0, 0, CUR_ORDER);
    }
    else {

#ifdef WOLFSSL_DTLS13
        if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)) {
            ret = Dtls13RlAddPlaintextHeader(ssl, output, alert, ALERT_SIZE);
            if (ret != 0)
                return ret;
        }
        else
#endif /* WOLFSSL_DTLS13 */
            {
                AddRecordHeader(output, ALERT_SIZE, alert, ssl, CUR_ORDER);
            }

        output += RECORD_HEADER_SZ;
        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls)
                output += DTLS_RECORD_EXTRA;
        #endif
        XMEMCPY(output, input, ALERT_SIZE);

        sendSz = RECORD_HEADER_SZ + ALERT_SIZE;
        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls)
                sendSz += DTLS_RECORD_EXTRA;
        #endif
    }
    if (sendSz < 0)
        return BUILD_MSG_ERROR;

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "Alert");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "Alert", alert, output, sendSz,
                    WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
    #endif

    ssl->buffers.outputBuffer.length += sendSz;

    ret = SendBuffered(ssl);

    ssl->pendingAlert.code = 0;
    ssl->pendingAlert.level = alert_none;

    WOLFSSL_LEAVE("SendAlert", ret);

    return ret;
}

int RetrySendAlert(WOLFSSL* ssl)
{
    int type = ssl->pendingAlert.code;
    int severity = ssl->pendingAlert.level;

    if (severity == alert_none)
        return 0;

    ssl->pendingAlert.code = 0;
    ssl->pendingAlert.level = alert_none;

    return SendAlert_ex(ssl, severity, type);
}

/* send alert message */
int SendAlert(WOLFSSL* ssl, int severity, int type)
{
    int ret;

    if (ssl->pendingAlert.level != alert_none) {
        ret = RetrySendAlert(ssl);
        if (ret != 0) {
            if (ssl->pendingAlert.level == alert_none ||
                    (ssl->pendingAlert.level != alert_fatal &&
                            severity == alert_fatal)) {
                /* Store current alert if pendingAlert is empty or if current
                 * is fatal and previous was not */
                ssl->pendingAlert.code = type;
                ssl->pendingAlert.level = severity;
            }
            return ret;
        }
    }

    return SendAlert_ex(ssl, severity, type);
}

const char* wolfSSL_ERR_reason_error_string(unsigned long e)
{
#ifdef NO_ERROR_STRINGS

    (void)e;
    return "no support for error strings built in";

#else

    int error = (int)e;
#ifdef OPENSSL_EXTRA
    /* OpenSSL uses positive error codes */
    if (error > 0) {
        error = -error;
    }
#endif

    /* pass to wolfCrypt */
    if (error < MAX_CODE_E && error > MIN_CODE_E) {
        return wc_GetErrorString(error);
    }

    switch (error) {

#ifdef OPENSSL_EXTRA
    case 0 :
        return "ok";
#endif

    case UNSUPPORTED_SUITE :
        return "unsupported cipher suite";

    case INPUT_CASE_ERROR :
        return "input state error";

    case PREFIX_ERROR :
        return "bad index to key rounds";

    case MEMORY_ERROR :
        return "out of memory";

    case VERIFY_FINISHED_ERROR :
        return "verify problem on finished";

    case VERIFY_MAC_ERROR :
        return "verify mac problem";

    case PARSE_ERROR :
        return "parse error on header";

    case SIDE_ERROR :
        return "wrong client/server type";

    case NO_PEER_CERT : /* OpenSSL compatibility expects this exact text */
        return "peer did not return a certificate";

    case UNKNOWN_HANDSHAKE_TYPE :
        return "weird handshake type";

    case SOCKET_ERROR_E :
        return "error state on socket";

    case SOCKET_NODATA :
        return "expected data, not there";

    case INCOMPLETE_DATA :
        return "don't have enough data to complete task";

    case UNKNOWN_RECORD_TYPE :
        return "unknown type in record hdr";

    case DECRYPT_ERROR :
        return "error during decryption";

    case FATAL_ERROR :
        return "received alert fatal error";

    case ENCRYPT_ERROR :
        return "error during encryption";

    case FREAD_ERROR :
        return "fread problem";

    case NO_PEER_KEY :
        return "need peer's key";

    case NO_PRIVATE_KEY :
        return "need the private key";

    case NO_DH_PARAMS :
        return "server missing DH params";

    case RSA_PRIVATE_ERROR :
        return "error during rsa priv op";

    case MATCH_SUITE_ERROR :
        return "can't match cipher suite";

    case COMPRESSION_ERROR :
        return "compression mismatch error";

    case BUILD_MSG_ERROR :
        return "build message failure";

    case BAD_HELLO :
        return "client hello malformed";

    case DOMAIN_NAME_MISMATCH :
        return "peer subject name mismatch";

    case IPADDR_MISMATCH :
        return "peer ip address mismatch";

    case WANT_READ :
    case WOLFSSL_ERROR_WANT_READ :
        return "non-blocking socket wants data to be read";

    case NOT_READY_ERROR :
        return "handshake layer not ready yet, complete first";

    case VERSION_ERROR :
        return "record layer version error";

    case WANT_WRITE :
    case WOLFSSL_ERROR_WANT_WRITE :
        return "non-blocking socket write buffer full";

    case BUFFER_ERROR :
        return "malformed buffer input error";

    case VERIFY_CERT_ERROR :
        return "verify problem on certificate";

    case VERIFY_SIGN_ERROR :
        return "verify problem based on signature";

    case CLIENT_ID_ERROR :
        return "psk client identity error";

    case SERVER_HINT_ERROR:
        return "psk server hint error";

    case PSK_KEY_ERROR:
        return "psk key callback error";

    case GETTIME_ERROR:
        return "gettimeofday() error";

    case GETITIMER_ERROR:
        return "getitimer() error";

    case SIGACT_ERROR:
        return "sigaction() error";

    case SETITIMER_ERROR:
        return "setitimer() error";

    case LENGTH_ERROR:
        return "record layer length error";

    case PEER_KEY_ERROR:
        return "cant decode peer key";

    case ZERO_RETURN:
    case WOLFSSL_ERROR_ZERO_RETURN:
        return "peer sent close notify alert";

    case ECC_CURVETYPE_ERROR:
        return "Bad ECC Curve Type or unsupported";

    case ECC_CURVE_ERROR:
        return "Bad ECC Curve or unsupported";

    case ECC_PEERKEY_ERROR:
        return "Bad ECC Peer Key";

    case ECC_MAKEKEY_ERROR:
        return "ECC Make Key failure";

    case ECC_EXPORT_ERROR:
        return "ECC Export Key failure";

    case ECC_SHARED_ERROR:
        return "ECC DHE shared failure";

    case NOT_CA_ERROR:
        return "Not a CA by basic constraint error";

    case BAD_CERT_MANAGER_ERROR:
        return "Bad Cert Manager error";

    case OCSP_CERT_REVOKED:
        return "OCSP Cert revoked";

    case CRL_CERT_REVOKED:
        return "CRL Cert revoked";

    case CRL_MISSING:
        return "CRL missing, not loaded";

    case MONITOR_SETUP_E:
        return "CRL monitor setup error";

    case THREAD_CREATE_E:
        return "Thread creation problem";

    case OCSP_NEED_URL:
        return "OCSP need URL";

    case OCSP_CERT_UNKNOWN:
        return "OCSP Cert unknown";

    case OCSP_LOOKUP_FAIL:
        return "OCSP Responder lookup fail";

    case MAX_CHAIN_ERROR:
        return "Maximum Chain Depth Exceeded";

    case COOKIE_ERROR:
        return "DTLS Cookie Error";

    case SEQUENCE_ERROR:
        return "DTLS Sequence Error";

    case SUITES_ERROR:
        return "Suites Pointer Error";

    case OUT_OF_ORDER_E:
        return "Out of order message, fatal";

    case BAD_KEA_TYPE_E:
        return "Bad KEA type found";

    case SANITY_CIPHER_E:
        return "Sanity check on ciphertext failed";

    case RECV_OVERFLOW_E:
        return "Receive callback returned more than requested";

    case GEN_COOKIE_E:
        return "Generate Cookie Error";

    case NO_PEER_VERIFY:
        return "Need peer certificate verify Error";

    case FWRITE_ERROR:
        return "fwrite Error";

    case CACHE_MATCH_ERROR:
        return "Cache restore header match Error";

    case UNKNOWN_SNI_HOST_NAME_E:
        return "Unrecognized host name Error";

    case UNKNOWN_MAX_FRAG_LEN_E:
        return "Unrecognized max frag len Error";

    case KEYUSE_SIGNATURE_E:
        return "Key Use digitalSignature not set Error";

    case KEYUSE_ENCIPHER_E:
        return "Key Use keyEncipherment not set Error";

    case EXTKEYUSE_AUTH_E:
        return "Ext Key Use server/client auth not set Error";

    case SEND_OOB_READ_E:
        return "Send Callback Out of Bounds Read Error";

    case SECURE_RENEGOTIATION_E:
        return "Invalid Renegotiation Error";

    case SESSION_TICKET_LEN_E:
        return "Session Ticket Too Long Error";

    case SESSION_TICKET_EXPECT_E:
        return "Session Ticket Error";

    case SESSION_SECRET_CB_E:
        return "Session Secret Callback Error";

    case NO_CHANGE_CIPHER_E:
        return "Finished received from peer before Change Cipher Error";

    case SANITY_MSG_E:
        return "Sanity Check on message order Error";

    case DUPLICATE_MSG_E:
        return "Duplicate HandShake message Error";

    case SNI_UNSUPPORTED:
        return "Protocol version does not support SNI Error";

    case SOCKET_PEER_CLOSED_E:
        return "Peer closed underlying transport Error";

    case BAD_TICKET_KEY_CB_SZ:
        return "Bad user session ticket key callback Size Error";

    case BAD_TICKET_MSG_SZ:
        return "Bad session ticket message Size Error";

    case BAD_TICKET_ENCRYPT:
        return "Bad user ticket callback encrypt Error";

    case DH_KEY_SIZE_E:
        return "DH key too small Error";

    case SNI_ABSENT_ERROR:
        return "No Server Name Indication extension Error";

    case RSA_SIGN_FAULT:
        return "RSA Signature Fault Error";

    case HANDSHAKE_SIZE_ERROR:
        return "Handshake message too large Error";

    case UNKNOWN_ALPN_PROTOCOL_NAME_E:
        return "Unrecognized protocol name Error";

    case BAD_CERTIFICATE_STATUS_ERROR:
        return "Bad Certificate Status Message Error";

    case OCSP_INVALID_STATUS:
        return "Invalid OCSP Status Error";

    case OCSP_WANT_READ:
        return "OCSP nonblock wants read";

    case RSA_KEY_SIZE_E:
        return "RSA key too small";

    case ECC_KEY_SIZE_E:
        return "ECC key too small";

    case DTLS_EXPORT_VER_E:
        return "Version needs updated after code change or version mismatch";

    case INPUT_SIZE_E:
        return "Input size too large Error";

    case CTX_INIT_MUTEX_E:
        return "Initialize ctx mutex error";

    case EXT_MASTER_SECRET_NEEDED_E:
        return "Extended Master Secret must be enabled to resume EMS session";

    case DTLS_POOL_SZ_E:
        return "Maximum DTLS pool size exceeded";

    case DECODE_E:
        return "Decode handshake message error";

    case WRITE_DUP_READ_E:
        return "Write dup write side can't read error";

    case WRITE_DUP_WRITE_E:
        return "Write dup read side can't write error";

    case INVALID_CERT_CTX_E:
        return "Certificate context does not match request or not empty";

    case BAD_KEY_SHARE_DATA:
        return "The Key Share data contains group that wasn't in Client Hello";

    case MISSING_HANDSHAKE_DATA:
        return "The handshake message is missing required data";

    case BAD_BINDER: /* OpenSSL compatibility expects this exact text */
        return "binder does not verify";

    case EXT_NOT_ALLOWED:
        return "Extension type not allowed in handshake message type";

    case INVALID_PARAMETER:
        return "The security parameter is invalid";

    case UNSUPPORTED_EXTENSION:
        return "TLS Extension not requested by the client";

    case PRF_MISSING:
        return "Pseudo-random function is not enabled";

    case KEY_SHARE_ERROR:
        return "Key share extension did not contain a valid named group";

    case POST_HAND_AUTH_ERROR:
        return "Client will not do post handshake authentication";

    case HRR_COOKIE_ERROR:
        return "Cookie does not match one sent in HelloRetryRequest";

    case MCAST_HIGHWATER_CB_E:
        return "Multicast highwater callback returned error";

    case ALERT_COUNT_E:
        return "Alert Count exceeded error";

    case EXT_MISSING:
        return "Required TLS extension missing";

    case DTLS_RETX_OVER_TX:
        return "DTLS interrupting flight transmit with retransmit";

    case DH_PARAMS_NOT_FFDHE_E:
        return "Server DH parameters were not from the FFDHE set as required";

    case TCA_INVALID_ID_TYPE:
        return "TLS Extension Trusted CA ID type invalid";

    case TCA_ABSENT_ERROR:
        return "TLS Extension Trusted CA ID response absent";

    case TSIP_MAC_DIGSZ_E:
        return "TSIP MAC size invalid, must be sized for SHA-1 or SHA-256";

    case CLIENT_CERT_CB_ERROR:
        return "Error importing client cert or key from callback";

    case SSL_SHUTDOWN_ALREADY_DONE_E:
        return "Shutdown has already occurred";

    case TLS13_SECRET_CB_E:
        return "TLS1.3 Secret Callback Error";

    case DTLS_SIZE_ERROR:
        return "DTLS trying to send too much in single datagram error";

    case NO_CERT_ERROR:
        return "TLS1.3 No Certificate Set Error";

    case APP_DATA_READY:
        return "Application data is available for reading";

    case TOO_MUCH_EARLY_DATA:
        return "Too much early data";

    case SOCKET_FILTERED_E:
        return "Session stopped by network filter";

#ifdef HAVE_HTTP_CLIENT
    case HTTP_TIMEOUT:
        return "HTTP timeout for OCSP or CRL req";
    case HTTP_RECV_ERR:
        return "HTTP Receive error";
    case HTTP_HEADER_ERR:
        return "HTTP Header error";
    case HTTP_PROTO_ERR:
        return "HTTP Protocol error";
    case HTTP_STATUS_ERR:
        return "HTTP Status error";
    case HTTP_VERSION_ERR:
        return "HTTP Version error";
    case HTTP_APPSTR_ERR:
        return "HTTP Application string error";
#endif
#ifdef OPENSSL_EXTRA
    case -X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        return "unable to get local issuer certificate";
#endif
    case UNSUPPORTED_PROTO_VERSION:
        #ifdef OPENSSL_ALL
        return "WRONG_SSL_VERSION";
        #else
        return "bad/unsupported protocol version";
        #endif

    case FALCON_KEY_SIZE_E:
        return "Wrong key size for Falcon.";
    case DILITHIUM_KEY_SIZE_E:
        return "Wrong key size for Dilithium.";

#ifdef WOLFSSL_QUIC
    case QUIC_TP_MISSING_E:
        return "QUIC transport parameter not set";
    case QUIC_WRONG_ENC_LEVEL:
        return "QUIC data received at wrong encryption level";
#endif
    case DTLS_CID_ERROR:
        return "DTLS ConnectionID mismatch or missing";
    case DTLS_TOO_MANY_FRAGMENTS_E:
        return "Received too many fragmented messages from peer error";

    case DUPLICATE_TLS_EXT_E:
        return "Duplicate TLS extension in message.";

    default :
        return "unknown error number";
    }

#endif /* NO_ERROR_STRINGS */
}

const char* wolfSSL_ERR_func_error_string(unsigned long e)
{
    (void)e;
    WOLFSSL_MSG("wolfSSL_ERR_func_error_string does not return the name of "
                "the function that failed. Please inspect the wolfSSL debug "
                "logs to determine where the error occurred.");
    return "";
}

/* return library name
 * @param e error code
 * @return text library name,
 *    if there is no suitable library found, returns empty string
 */
const char* wolfSSL_ERR_lib_error_string(unsigned long e)
{
    int libe = 0;

    (void)libe;
    (void)e;

#if defined(OPENSSL_EXTRA)
    libe = wolfSSL_ERR_GET_LIB(e);
    switch (libe) {
    case ERR_LIB_PEM:
        return "wolfSSL PEM routines";
    case ERR_LIB_EVP:
        return "wolfSSL digital envelope routines";
    default:
        return "";
    }
#else
    return "";
#endif
}

void SetErrorString(int error, char* str)
{
    XSTRNCPY(str, wolfSSL_ERR_reason_error_string(error), WOLFSSL_MAX_ERROR_SZ);
    str[WOLFSSL_MAX_ERROR_SZ-1] = 0;
}

#ifdef NO_CIPHER_SUITE_ALIASES
    #ifndef NO_ERROR_STRINGS
        #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(y),(z),(w),(v),(u),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u)
        #else
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(y),(z),(w),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u)
        #endif
    #else
        #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT)
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(z),(w),(v),(u),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u)
        #else
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(z),(w),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u)
        #endif
    #endif
#else /* !NO_CIPHER_SUITE_ALIASES */

    /* note that the comma is included at the end of the SUITE_ALIAS() macro
     * definitions, to allow aliases to be gated out by the above null macros
     * in the NO_CIPHER_SUITE_ALIASES section.
     */

    #ifndef NO_ERROR_STRINGS
        #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT) || \
            defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX)
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(y),(z),(w),(v),(u),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u) {(x),"",(z),(w),(v),(u),WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS},
        #else
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(y),(z),(w),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u) {(x),"",(z),(w),WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS},
        #endif
    #else
        #if defined(OPENSSL_ALL) || defined(WOLFSSL_QT) || \
            defined(WOLFSSL_HAPROXY) || defined(WOLFSSL_NGINX)
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(z),(w),(v),(u),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u) {(x),(z),(w),(v),(u),WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS},
        #else
            #define SUITE_INFO(x,y,z,w,v,u) {(x),(z),(w),WOLFSSL_CIPHER_SUITE_FLAG_NONE}
            #define SUITE_ALIAS(x,z,w,v,u) {(x),(z),(w),WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS},
        #endif
    #endif
#endif /* NO_CIPHER_SUITE_ALIASES */

static const CipherSuiteInfo cipher_names[] =
{

#ifdef BUILD_TLS_AES_128_GCM_SHA256
    SUITE_INFO("TLS13-AES128-GCM-SHA256","TLS_AES_128_GCM_SHA256",TLS13_BYTE,TLS_AES_128_GCM_SHA256, TLSv1_3_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_AES_256_GCM_SHA384
    SUITE_INFO("TLS13-AES256-GCM-SHA384","TLS_AES_256_GCM_SHA384",TLS13_BYTE,TLS_AES_256_GCM_SHA384, TLSv1_3_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_CHACHA20_POLY1305_SHA256
    SUITE_INFO("TLS13-CHACHA20-POLY1305-SHA256","TLS_CHACHA20_POLY1305_SHA256",TLS13_BYTE,TLS_CHACHA20_POLY1305_SHA256, TLSv1_3_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_AES_128_CCM_SHA256
    SUITE_INFO("TLS13-AES128-CCM-SHA256","TLS_AES_128_CCM_SHA256",TLS13_BYTE,TLS_AES_128_CCM_SHA256, TLSv1_3_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_AES_128_CCM_8_SHA256
    SUITE_INFO("TLS13-AES128-CCM-8-SHA256","TLS_AES_128_CCM_8_SHA256",TLS13_BYTE,TLS_AES_128_CCM_8_SHA256,TLSv1_3_MINOR, SSLv3_MAJOR),
    SUITE_ALIAS("TLS13-AES128-CCM8-SHA256",TLS13_BYTE,TLS_AES_128_CCM_8_SHA256,TLSv1_3_MINOR, SSLv3_MAJOR)
#endif

#ifdef BUILD_TLS_SHA256_SHA256
    SUITE_INFO("TLS13-SHA256-SHA256","TLS_SHA256_SHA256",ECC_BYTE,TLS_SHA256_SHA256,TLSv1_3_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_SHA384_SHA384
    SUITE_INFO("TLS13-SHA384-SHA384","TLS_SHA384_SHA384",ECC_BYTE,TLS_SHA384_SHA384,TLSv1_3_MINOR, SSLv3_MAJOR),
#endif

#ifndef WOLFSSL_NO_TLS12

#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    SUITE_INFO("RC4-SHA","SSL_RSA_WITH_RC4_128_SHA",CIPHER_BYTE,SSL_RSA_WITH_RC4_128_SHA,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    SUITE_INFO("RC4-MD5","SSL_RSA_WITH_RC4_128_MD5",CIPHER_BYTE,SSL_RSA_WITH_RC4_128_MD5,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    SUITE_INFO("DES-CBC3-SHA","SSL_RSA_WITH_3DES_EDE_CBC_SHA",CIPHER_BYTE,SSL_RSA_WITH_3DES_EDE_CBC_SHA,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    SUITE_INFO("AES128-SHA","TLS_RSA_WITH_AES_128_CBC_SHA",CIPHER_BYTE,TLS_RSA_WITH_AES_128_CBC_SHA,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    SUITE_INFO("AES256-SHA","TLS_RSA_WITH_AES_256_CBC_SHA",CIPHER_BYTE,TLS_RSA_WITH_AES_256_CBC_SHA,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_MD5
    SUITE_INFO("NULL-MD5","TLS_RSA_WITH_NULL_MD5",CIPHER_BYTE,TLS_RSA_WITH_NULL_MD5,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    SUITE_INFO("NULL-SHA","TLS_RSA_WITH_NULL_SHA",CIPHER_BYTE,TLS_RSA_WITH_NULL_SHA,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA256
    SUITE_INFO("NULL-SHA256","TLS_RSA_WITH_NULL_SHA256",CIPHER_BYTE,TLS_RSA_WITH_NULL_SHA256,TLSv1_2_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    SUITE_INFO("DHE-RSA-AES128-SHA","TLS_DHE_RSA_WITH_AES_128_CBC_SHA",CIPHER_BYTE,TLS_DHE_RSA_WITH_AES_128_CBC_SHA,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    SUITE_INFO("DHE-RSA-AES256-SHA","TLS_DHE_RSA_WITH_AES_256_CBC_SHA",CIPHER_BYTE,TLS_DHE_RSA_WITH_AES_256_CBC_SHA,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    SUITE_INFO("DHE-PSK-AES256-GCM-SHA384","TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",CIPHER_BYTE,TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,TLSv1_2_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    SUITE_INFO("DHE-PSK-AES128-GCM-SHA256","TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",CIPHER_BYTE,TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,TLSv1_2_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    SUITE_INFO("PSK-AES256-GCM-SHA384","TLS_PSK_WITH_AES_256_GCM_SHA384",CIPHER_BYTE,TLS_PSK_WITH_AES_256_GCM_SHA384,TLSv1_2_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256
    SUITE_INFO("PSK-AES128-GCM-SHA256","TLS_PSK_WITH_AES_128_GCM_SHA256",CIPHER_BYTE,TLS_PSK_WITH_AES_128_GCM_SHA256,TLSv1_2_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
    SUITE_INFO("DHE-PSK-AES256-CBC-SHA384","TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",CIPHER_BYTE,TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
    SUITE_INFO("DHE-PSK-AES128-CBC-SHA256","TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",CIPHER_BYTE,TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA384
    SUITE_INFO("PSK-AES256-CBC-SHA384","TLS_PSK_WITH_AES_256_CBC_SHA384",CIPHER_BYTE,TLS_PSK_WITH_AES_256_CBC_SHA384,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
    SUITE_INFO("PSK-AES128-CBC-SHA256","TLS_PSK_WITH_AES_128_CBC_SHA256",CIPHER_BYTE,TLS_PSK_WITH_AES_128_CBC_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    SUITE_INFO("PSK-AES128-CBC-SHA","TLS_PSK_WITH_AES_128_CBC_SHA",CIPHER_BYTE,TLS_PSK_WITH_AES_128_CBC_SHA,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    SUITE_INFO("PSK-AES256-CBC-SHA","TLS_PSK_WITH_AES_256_CBC_SHA",CIPHER_BYTE,TLS_PSK_WITH_AES_256_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CCM
    SUITE_INFO("DHE-PSK-AES128-CCM","TLS_DHE_PSK_WITH_AES_128_CCM",ECC_BYTE,TLS_DHE_PSK_WITH_AES_128_CCM,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CCM
    SUITE_INFO("DHE-PSK-AES256-CCM","TLS_DHE_PSK_WITH_AES_256_CCM",ECC_BYTE,TLS_DHE_PSK_WITH_AES_256_CCM,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM
    SUITE_INFO("PSK-AES128-CCM","TLS_PSK_WITH_AES_128_CCM",ECC_BYTE,TLS_PSK_WITH_AES_128_CCM,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM
    SUITE_INFO("PSK-AES256-CCM","TLS_PSK_WITH_AES_256_CCM",ECC_BYTE,TLS_PSK_WITH_AES_256_CCM,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM_8
    SUITE_INFO("PSK-AES128-CCM-8","TLS_PSK_WITH_AES_128_CCM_8",ECC_BYTE,TLS_PSK_WITH_AES_128_CCM_8,TLSv1_MINOR,SSLv3_MAJOR),
    SUITE_ALIAS("PSK-AES128-CCM8",ECC_BYTE,TLS_PSK_WITH_AES_128_CCM_8,TLSv1_MINOR,SSLv3_MAJOR)
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM_8
    SUITE_INFO("PSK-AES256-CCM-8","TLS_PSK_WITH_AES_256_CCM_8",ECC_BYTE,TLS_PSK_WITH_AES_256_CCM_8,TLSv1_MINOR,SSLv3_MAJOR),
    SUITE_ALIAS("PSK-AES256-CCM8",ECC_BYTE,TLS_PSK_WITH_AES_256_CCM_8,TLSv1_MINOR,SSLv3_MAJOR)
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA384
    SUITE_INFO("DHE-PSK-NULL-SHA384","TLS_DHE_PSK_WITH_NULL_SHA384",CIPHER_BYTE,TLS_DHE_PSK_WITH_NULL_SHA384,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA256
    SUITE_INFO("DHE-PSK-NULL-SHA256","TLS_DHE_PSK_WITH_NULL_SHA256",CIPHER_BYTE,TLS_DHE_PSK_WITH_NULL_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA384
    SUITE_INFO("PSK-NULL-SHA384","TLS_PSK_WITH_NULL_SHA384",CIPHER_BYTE,TLS_PSK_WITH_NULL_SHA384,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA256
    SUITE_INFO("PSK-NULL-SHA256","TLS_PSK_WITH_NULL_SHA256",CIPHER_BYTE,TLS_PSK_WITH_NULL_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA
    SUITE_INFO("PSK-NULL-SHA","TLS_PSK_WITH_NULL_SHA",CIPHER_BYTE,TLS_PSK_WITH_NULL_SHA,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    SUITE_INFO("AES128-CCM-8","TLS_RSA_WITH_AES_128_CCM_8",ECC_BYTE,TLS_RSA_WITH_AES_128_CCM_8, TLSv1_2_MINOR, SSLv3_MAJOR),
    SUITE_ALIAS("AES128-CCM8",ECC_BYTE,TLS_RSA_WITH_AES_128_CCM_8, TLSv1_2_MINOR, SSLv3_MAJOR)
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CCM_8
    SUITE_INFO("AES256-CCM-8","TLS_RSA_WITH_AES_256_CCM_8",ECC_BYTE,TLS_RSA_WITH_AES_256_CCM_8, TLSv1_2_MINOR, SSLv3_MAJOR),
    SUITE_ALIAS("AES256-CCM8",ECC_BYTE,TLS_RSA_WITH_AES_256_CCM_8, TLSv1_2_MINOR, SSLv3_MAJOR)
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    SUITE_INFO("ECDHE-ECDSA-AES128-CCM","TLS_ECDHE_ECDSA_WITH_AES_128_CCM",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_128_CCM, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    SUITE_INFO("ECDHE-ECDSA-AES128-CCM-8","TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, TLSv1_2_MINOR, SSLv3_MAJOR),
    SUITE_ALIAS("ECDHE-ECDSA-AES128-CCM8",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, TLSv1_2_MINOR, SSLv3_MAJOR)
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    SUITE_INFO("ECDHE-ECDSA-AES256-CCM-8","TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, TLSv1_2_MINOR, SSLv3_MAJOR),
    SUITE_ALIAS("ECDHE-ECDSA-AES256-CCM8",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8, TLSv1_2_MINOR, SSLv3_MAJOR)
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    SUITE_INFO("ECDHE-RSA-AES128-SHA","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",ECC_BYTE,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    SUITE_INFO("ECDHE-RSA-AES256-SHA","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",ECC_BYTE,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    SUITE_INFO("ECDHE-ECDSA-AES128-SHA","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    SUITE_INFO("ECDHE-ECDSA-AES256-SHA","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
    SUITE_INFO("ECDHE-RSA-RC4-SHA","TLS_ECDHE_RSA_WITH_RC4_128_SHA",ECC_BYTE,TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    SUITE_INFO("ECDHE-RSA-DES-CBC3-SHA","TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",ECC_BYTE,TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    SUITE_INFO("ECDHE-ECDSA-RC4-SHA","TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    SUITE_INFO("ECDHE-ECDSA-DES-CBC3-SHA","TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
    SUITE_INFO("AES128-SHA256","TLS_RSA_WITH_AES_128_CBC_SHA256",CIPHER_BYTE,TLS_RSA_WITH_AES_128_CBC_SHA256, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
    SUITE_INFO("AES256-SHA256","TLS_RSA_WITH_AES_256_CBC_SHA256",CIPHER_BYTE,TLS_RSA_WITH_AES_256_CBC_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    SUITE_INFO("DHE-RSA-AES128-SHA256","TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",CIPHER_BYTE,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    SUITE_INFO("DHE-RSA-AES256-SHA256","TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",CIPHER_BYTE,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    SUITE_INFO("ECDH-RSA-AES128-SHA","TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",ECC_BYTE,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    SUITE_INFO("ECDH-RSA-AES256-SHA","TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",ECC_BYTE,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    SUITE_INFO("ECDH-ECDSA-AES128-SHA","TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",ECC_BYTE,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    SUITE_INFO("ECDH-ECDSA-AES256-SHA","TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",ECC_BYTE,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    SUITE_INFO("ECDH-RSA-RC4-SHA","TLS_ECDH_RSA_WITH_RC4_128_SHA",ECC_BYTE,TLS_ECDH_RSA_WITH_RC4_128_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    SUITE_INFO("ECDH-RSA-DES-CBC3-SHA","TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",ECC_BYTE,TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    SUITE_INFO("ECDH-ECDSA-RC4-SHA","TLS_ECDH_ECDSA_WITH_RC4_128_SHA",ECC_BYTE,TLS_ECDH_ECDSA_WITH_RC4_128_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    SUITE_INFO("ECDH-ECDSA-DES-CBC3-SHA","TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",ECC_BYTE,TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
    SUITE_INFO("AES128-GCM-SHA256","TLS_RSA_WITH_AES_128_GCM_SHA256",CIPHER_BYTE,TLS_RSA_WITH_AES_128_GCM_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
    SUITE_INFO("AES256-GCM-SHA384","TLS_RSA_WITH_AES_256_GCM_SHA384",CIPHER_BYTE,TLS_RSA_WITH_AES_256_GCM_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    SUITE_INFO("DHE-RSA-AES128-GCM-SHA256","TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",CIPHER_BYTE,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    SUITE_INFO("DHE-RSA-AES256-GCM-SHA384","TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",CIPHER_BYTE,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    SUITE_INFO("ECDHE-RSA-AES128-GCM-SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",ECC_BYTE,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    SUITE_INFO("ECDHE-RSA-AES256-GCM-SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",ECC_BYTE,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    SUITE_INFO("ECDHE-ECDSA-AES128-GCM-SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    SUITE_INFO("ECDHE-ECDSA-AES256-GCM-SHA384","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    SUITE_INFO("ECDH-RSA-AES128-GCM-SHA256","TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",ECC_BYTE,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    SUITE_INFO("ECDH-RSA-AES256-GCM-SHA384","TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",ECC_BYTE,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    SUITE_INFO("ECDH-ECDSA-AES128-GCM-SHA256","TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",ECC_BYTE,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    SUITE_INFO("ECDH-ECDSA-AES256-GCM-SHA384","TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",ECC_BYTE,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    SUITE_INFO("CAMELLIA128-SHA","TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",CIPHER_BYTE,TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    SUITE_INFO("DHE-RSA-CAMELLIA128-SHA","TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",CIPHER_BYTE,TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    SUITE_INFO("CAMELLIA256-SHA","TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",CIPHER_BYTE,TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    SUITE_INFO("DHE-RSA-CAMELLIA256-SHA","TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",CIPHER_BYTE,TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
    SUITE_INFO("CAMELLIA128-SHA256","TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",CIPHER_BYTE,TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    SUITE_INFO("DHE-RSA-CAMELLIA128-SHA256","TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",CIPHER_BYTE,TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    SUITE_INFO("CAMELLIA256-SHA256","TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",CIPHER_BYTE,TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
    SUITE_INFO("DHE-RSA-CAMELLIA256-SHA256","TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",CIPHER_BYTE,TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    SUITE_INFO("ECDHE-RSA-AES128-SHA256","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",ECC_BYTE,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    SUITE_INFO("ECDHE-ECDSA-AES128-SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    SUITE_INFO("ECDH-RSA-AES128-SHA256","TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",ECC_BYTE,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    SUITE_INFO("ECDH-ECDSA-AES128-SHA256","TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",ECC_BYTE,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    SUITE_INFO("ECDHE-RSA-AES256-SHA384","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",ECC_BYTE,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    SUITE_INFO("ECDHE-ECDSA-AES256-SHA384","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    SUITE_INFO("ECDH-RSA-AES256-SHA384","TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",ECC_BYTE,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    SUITE_INFO("ECDH-ECDSA-AES256-SHA384","TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",ECC_BYTE,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    SUITE_INFO("ECDHE-RSA-CHACHA20-POLY1305","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",CHACHA_BYTE,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    SUITE_INFO("ECDHE-ECDSA-CHACHA20-POLY1305","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",CHACHA_BYTE,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    SUITE_INFO("DHE-RSA-CHACHA20-POLY1305","TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",CHACHA_BYTE,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    SUITE_INFO("ECDHE-RSA-CHACHA20-POLY1305-OLD","TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256",CHACHA_BYTE,TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    SUITE_INFO("ECDHE-ECDSA-CHACHA20-POLY1305-OLD","TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256",CHACHA_BYTE,TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    SUITE_INFO("DHE-RSA-CHACHA20-POLY1305-OLD","TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256",CHACHA_BYTE,TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    SUITE_INFO("ADH-AES128-SHA","TLS_DH_anon_WITH_AES_128_CBC_SHA",CIPHER_BYTE,TLS_DH_anon_WITH_AES_128_CBC_SHA, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DH_anon_WITH_AES_256_GCM_SHA384
    SUITE_INFO("ADH-AES256-GCM-SHA384","TLS_DH_anon_WITH_AES_256_GCM_SHA384",CIPHER_BYTE,TLS_DH_anon_WITH_AES_256_GCM_SHA384, TLSv1_2_MINOR, SSLv3_MAJOR),
#endif

#ifdef HAVE_RENEGOTIATION_INDICATION
    SUITE_INFO("RENEGOTIATION-INFO","TLS_EMPTY_RENEGOTIATION_INFO_SCSV",CIPHER_BYTE,TLS_EMPTY_RENEGOTIATION_INFO_SCSV,SSLv3_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_NULL_SHA
    SUITE_INFO("ECDHE-ECDSA-NULL-SHA","TLS_ECDHE_ECDSA_WITH_NULL_SHA",ECC_BYTE,TLS_ECDHE_ECDSA_WITH_NULL_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_NULL_SHA256
    SUITE_INFO("ECDHE-PSK-NULL-SHA256","TLS_ECDHE_PSK_WITH_NULL_SHA256",ECC_BYTE,TLS_ECDHE_PSK_WITH_NULL_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
    SUITE_INFO("ECDHE-PSK-AES128-CBC-SHA256","TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",ECC_BYTE,TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
    SUITE_INFO("ECDHE-PSK-AES128-GCM-SHA256","TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",ECDHE_PSK_BYTE,TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,TLSv1_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
    SUITE_INFO("PSK-CHACHA20-POLY1305","TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",CHACHA_BYTE,TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,TLSv1_2_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    SUITE_INFO("ECDHE-PSK-CHACHA20-POLY1305","TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",CHACHA_BYTE,TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,TLSv1_2_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    SUITE_INFO("DHE-PSK-CHACHA20-POLY1305","TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",CHACHA_BYTE,TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,TLSv1_2_MINOR,SSLv3_MAJOR),
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    SUITE_INFO("EDH-RSA-DES-CBC3-SHA","TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",CIPHER_BYTE,TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA, TLSv1_MINOR, SSLv3_MAJOR),
#endif

#ifdef BUILD_WDM_WITH_NULL_SHA256
    SUITE_INFO("WDM-NULL-SHA256","WDM_WITH_NULL_SHA256",CIPHER_BYTE,WDM_WITH_NULL_SHA256, TLSv1_3_MINOR, SSLv3_MAJOR)
#endif

#endif /* WOLFSSL_NO_TLS12 */
};


/* returns the cipher_names array */
const CipherSuiteInfo* GetCipherNames(void)
{
    return cipher_names;
}


/* returns the number of elements in the cipher_names array */
int GetCipherNamesSize(void)
{
    return (int)(sizeof(cipher_names) / sizeof(CipherSuiteInfo));
}


const char* GetCipherNameInternal(const byte cipherSuite0, const byte cipherSuite)
{
    int i;
    const char* nameInternal = "None";

    for (i = 0; i < GetCipherNamesSize(); i++) {
        if ((cipher_names[i].cipherSuite0 == cipherSuite0) &&
            (cipher_names[i].cipherSuite  == cipherSuite)
#ifndef NO_CIPHER_SUITE_ALIASES
            && (! (cipher_names[i].flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS))
#endif
            ) {
            nameInternal = cipher_names[i].name;
            break;
        }
    }
    return nameInternal;
}

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL)
/* Segment cipher name into n[n0,n1,n2,n4]
 * @param cipher a pointer to WOLFSSL_CIPHER
 * @param n return segment cipher name
 * return cipher name if cipher is in the list,
 *        otherwise NULL
 */
const char* GetCipherSegment(const WOLFSSL_CIPHER* cipher, char n[][MAX_SEGMENT_SZ])
{
    int i,j,k;
    int strLen;
    unsigned long offset;
    const char* name;

    /* sanity check */
    if (cipher == NULL || n == NULL)
        return NULL;

    offset = cipher->offset;

    if (offset >= (unsigned long)GetCipherNamesSize())
        return NULL;

    name = cipher_names[offset].name;

    if (name == NULL)
        return NULL;

    /* Segment cipher name into n[n0,n1,n2,n4]
     * These are used later for comparisons to create:
     * keaStr, authStr, encStr, macStr
     *
     * If cipher_name = ECDHE-ECDSA-AES256-SHA
     * then n0 = "ECDHE", n1 = "ECDSA", n2 = "AES256", n3 = "SHA"
     * and n = [n0,n1,n2,n3,0]
     */
    strLen = (int)XSTRLEN(name);

    for (i = 0, j = 0, k = 0; i <= strLen; i++) {
        if (k >= MAX_SEGMENTS || j >= MAX_SEGMENT_SZ)
            break;

        if (name[i] != '-' && name[i] != '\0') {
            n[k][j] = name[i]; /* Fill kth segment string until '-' */
            j++;
        }
        else {
            n[k][j] = '\0';
            j = 0;
            k++;
        }
    }

    return name;
}

/* gcc-12 and later, building with ASAN at -O2 and higher, generate spurious
 * stringop-overread warnings on some (but not all...) reads of n[1] in
 * GetCipherKeaStr().
 */
#if defined(__GNUC__) && __GNUC__ > 11 && defined(__SANITIZE_ADDRESS__)
PRAGMA_GCC_DIAG_PUSH
PRAGMA_GCC("GCC diagnostic ignored \"-Wstringop-overread\"")
#endif

const char* GetCipherKeaStr(char n[][MAX_SEGMENT_SZ]) {
    const char* keaStr = NULL;

    if (XSTRCMP(n[0],"ECDHE") == 0 && XSTRCMP(n[1],"PSK") == 0)
        keaStr = "ECDHEPSK";
    else if ((XSTRCMP(n[0],"ECDH") == 0) || (XSTRCMP(n[0],"ECDHE") == 0))
        keaStr = "ECDH";
    else if (XSTRCMP(n[0],"DHE") == 0 && XSTRCMP(n[1],"PSK") == 0)
        keaStr = "DHEPSK";
    else if (XSTRCMP(n[0],"DHE") == 0)
        keaStr = "DH";
    else if (XSTRCMP(n[0],"RSA") == 0 && XSTRCMP(n[1],"PSK") == 0)
        keaStr = "RSAPSK";
    else if (XSTRCMP(n[0],"SRP") == 0)
        keaStr = "SRP";
    else if (XSTRCMP(n[0],"PSK") == 0)
        keaStr = "PSK";
    else if (XSTRCMP(n[0],"EDH") == 0)
        keaStr = "EDH";
    else if ((XSTRCMP(n[1],"SHA") == 0) || (XSTRCMP(n[2],"SHA") == 0) ||
             (XSTRCMP(n[3],"SHA") == 0) || (XSTRCMP(n[4],"SHA") == 0) ||
             (XSTRCMP(n[2],"RSA") == 0) || (XSTRCMP(n[0],"AES128") == 0) ||
             (XSTRCMP(n[0],"AES256") == 0) || (XSTRCMP(n[1],"MD5") == 0))
        keaStr = "RSA";
    else if (XSTRCMP(n[0],"NULL") == 0)
        keaStr = "None";
    else
        keaStr = "unknown";

    return keaStr;
}

#if defined(__GNUC__) && __GNUC__ > 11 && defined(__SANITIZE_ADDRESS__)
PRAGMA_GCC_DIAG_POP
#endif

const char* GetCipherAuthStr(char n[][MAX_SEGMENT_SZ]) {

    const char* authStr = NULL;

    if ((XSTRCMP(n[0],"AES128") == 0) || (XSTRCMP(n[0],"AES256") == 0)  ||
        ((XSTRCMP(n[0],"TLS13") == 0) && ((XSTRCMP(n[1],"AES128") == 0) ||
         (XSTRCMP(n[1],"AES256") == 0) || (XSTRCMP(n[1],"CHACHA20") == 0))) ||
        (XSTRCMP(n[0],"RSA") == 0) || (XSTRCMP(n[1],"RSA") == 0) ||
        (XSTRCMP(n[1],"SHA") == 0) || (XSTRCMP(n[2],"SHA") == 0) ||
        (XSTRCMP(n[1],"MD5") == 0))
        authStr = "RSA";
    else if (XSTRCMP(n[0],"PSK") == 0 || XSTRCMP(n[1],"PSK") == 0)
        authStr = "PSK";
    else if (XSTRCMP(n[0],"SRP") == 0 && XSTRCMP(n[1],"AES") == 0)
        authStr = "SRP";
    else if (XSTRCMP(n[1],"ECDSA") == 0)
        authStr = "ECDSA";
    else if (XSTRCMP(n[0],"ADH") == 0 || XSTRCMP(n[0],"NULL") == 0)
        authStr = "None";
    else
        authStr = "unknown";

    return authStr;
}

const char* GetCipherEncStr(char n[][MAX_SEGMENT_SZ]) {
    const char* encStr = NULL;

    if ((XSTRCMP(n[0],"AES256") == 0 && XSTRCMP(n[1],"GCM") == 0) ||
        (XSTRCMP(n[1],"AES256") == 0 && XSTRCMP(n[2],"GCM") == 0) ||
        (XSTRCMP(n[2],"AES256") == 0 && XSTRCMP(n[3],"GCM") == 0))
        encStr = "AESGCM(256)";

    else if ((XSTRCMP(n[0],"AES128") == 0 && XSTRCMP(n[1],"GCM") == 0) ||
             (XSTRCMP(n[1],"AES128") == 0 && XSTRCMP(n[2],"GCM") == 0) ||
             (XSTRCMP(n[2],"AES128") == 0 && XSTRCMP(n[3],"GCM") == 0))
        encStr = "AESGCM(128)";

    else if ((XSTRCMP(n[0],"AES128") == 0 && XSTRCMP(n[1],"CCM") == 0) ||
             (XSTRCMP(n[1],"AES128") == 0 && XSTRCMP(n[2],"CCM") == 0) ||
             (XSTRCMP(n[2],"AES128") == 0 && XSTRCMP(n[3],"CCM") == 0))
        encStr = "AESCCM(128)";

    else if ((XSTRCMP(n[0],"AES128") == 0) ||
             (XSTRCMP(n[1],"AES128") == 0) ||
             (XSTRCMP(n[2],"AES128") == 0) ||
             (XSTRCMP(n[1],"AES") == 0 && XSTRCMP(n[2],"128") == 0) ||
             (XSTRCMP(n[2],"AES") == 0 && XSTRCMP(n[3],"128") == 0))
        encStr = "AES(128)";

    else if ((XSTRCMP(n[0],"AES256") == 0) ||
             (XSTRCMP(n[1],"AES256") == 0) ||
             (XSTRCMP(n[2],"AES256") == 0) ||
             (XSTRCMP(n[1],"AES") == 0 && XSTRCMP(n[2],"256") == 0) ||
             (XSTRCMP(n[2],"AES") == 0 && XSTRCMP(n[3],"256") == 0))
        encStr = "AES(256)";

    else if ((XSTRCMP(n[0],"CAMELLIA256") == 0) ||
             (XSTRCMP(n[2],"CAMELLIA256") == 0))
        encStr = "CAMELLIA(256)";
    else if ((XSTRCMP(n[0],"CAMELLIA128") == 0) ||
             (XSTRCMP(n[2],"CAMELLIA128") == 0))
        encStr = "CAMELLIA(128)";
    else if ((XSTRCMP(n[0],"RC4") == 0) || (XSTRCMP(n[1],"RC4") == 0) ||
            (XSTRCMP(n[2],"RC4") == 0))
        encStr = "RC4";
    else if (((XSTRCMP(n[0],"DES") == 0)  || (XSTRCMP(n[1],"DES") == 0) ||
              (XSTRCMP(n[2],"DES") == 0)) &&
             ((XSTRCMP(n[1],"CBC3") == 0) || (XSTRCMP(n[2],"CBC3") == 0) ||
              (XSTRCMP(n[3],"CBC3") == 0)))
        encStr = "3DES";
    else if ((XSTRCMP(n[1],"CHACHA20") == 0 && XSTRCMP(n[2],"POLY1305") == 0) ||
             (XSTRCMP(n[2],"CHACHA20") == 0 && XSTRCMP(n[3],"POLY1305") == 0))
        encStr = "CHACHA20/POLY1305(256)";
    else if ((XSTRCMP(n[0],"NULL") == 0) || (XSTRCMP(n[1],"NULL") == 0) ||
             (XSTRCMP(n[2],"NULL") == 0) ||
             ((XSTRCMP(n[0],"TLS13") == 0) && (XSTRCMP(n[3],"") == 0)))
        encStr = "None";
    else
        encStr = "unknown";

    return encStr;
}

/* Check if a cipher is AEAD
 * @param n return segment cipher name
 * return 1 if the cipher is AEAD, otherwise 0
 */
int IsCipherAEAD(char n[][MAX_SEGMENT_SZ])
{
    WOLFSSL_ENTER("IsCipherAEAD");

    if (n == NULL) {
        WOLFSSL_MSG("bad function argumet. n is NULL.");
        return 0;
    }

    if ((XSTRCMP(n[2],"GCM") == 0) || (XSTRCMP(n[3],"GCM") == 0) ||
        (XSTRCMP(n[1],"CCM") == 0) ||
        (XSTRCMP(n[2],"CCM") == 0) || (XSTRCMP(n[3],"CCM") == 0) ||
        (XSTRCMP(n[1],"CHACHA20") == 0 && XSTRCMP(n[2],"POLY1305") == 0) ||
        (XSTRCMP(n[2],"CHACHA20") == 0 && XSTRCMP(n[3],"POLY1305") == 0))
        return 1;
    return 0;
}

/* Returns the MAC string of a cipher or "unknown" on failure */
const char* GetCipherMacStr(char n[][MAX_SEGMENT_SZ]) {

    const char* macStr = NULL;

    if ((XSTRCMP(n[4],"SHA256") == 0) || (XSTRCMP(n[3],"SHA256") == 0) ||
        (XSTRCMP(n[2],"SHA256") == 0) || (XSTRCMP(n[1],"SHA256") == 0))
        macStr = "SHA256";
    else if ((XSTRCMP(n[4],"SHA384") == 0) ||
             (XSTRCMP(n[3],"SHA384") == 0) ||
             (XSTRCMP(n[2],"SHA384") == 0) ||
             (XSTRCMP(n[1],"SHA384") == 0))
        macStr = "SHA384";
    else if ((XSTRCMP(n[4],"SHA") == 0) || (XSTRCMP(n[3],"SHA") == 0) ||
             (XSTRCMP(n[2],"SHA") == 0) || (XSTRCMP(n[1],"SHA") == 0) ||
             (XSTRCMP(n[1],"MD5") == 0))
        macStr = "SHA1";
    else if ((XSTRCMP(n[3],"GCM") == 0) ||
             (XSTRCMP(n[1],"CCM") == 0) ||
             (XSTRCMP(n[2],"CCM") == 0) || (XSTRCMP(n[3],"CCM") == 0) ||
             (XSTRCMP(n[1],"CHACHA20") == 0 && XSTRCMP(n[2],"POLY1305") == 0) ||
             (XSTRCMP(n[2],"CHACHA20") == 0 && XSTRCMP(n[3],"POLY1305") == 0))
        macStr = "AEAD";
    else
        macStr = "unknown";

    return macStr;
}

/* Returns the number of bits based on the cipher enc string, or 0 on failure */
int SetCipherBits(const char* enc) {
    int ret = WOLFSSL_FAILURE;

    if ((XSTRCMP(enc,"AESGCM(256)") == 0) ||
        (XSTRCMP(enc,"AES(256)") == 0) ||
        (XSTRCMP(enc,"CAMELLIA(256)") == 0) ||
        (XSTRCMP(enc,"CHACHA20/POLY1305(256)") == 0))
            ret = 256;
    else if
        ((XSTRCMP(enc,"3DES") == 0))
            ret = 168;
    else if
        ((XSTRCMP(enc,"AESGCM(128)") == 0) ||
         (XSTRCMP(enc,"AES(128)") == 0) ||
         (XSTRCMP(enc,"CAMELLIA(128)") == 0) ||
         (XSTRCMP(enc,"RC4") == 0))
            ret = 128;
   else if
        ((XSTRCMP(enc,"DES") == 0))
            ret = 56;

    return ret;
}
#endif /* WOLFSSL_QT || OPENSSL_ALL */

const char* GetCipherNameIana(const byte cipherSuite0, const byte cipherSuite)
{
#ifndef NO_ERROR_STRINGS
    int i;
    const char* nameIana = "NONE";

    for (i = 0; i < GetCipherNamesSize(); i++) {
        if ((cipher_names[i].cipherSuite0 == cipherSuite0) &&
            (cipher_names[i].cipherSuite  == cipherSuite)
#ifndef NO_CIPHER_SUITE_ALIASES
            && (! (cipher_names[i].flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS))
#endif
            ) {
            nameIana = cipher_names[i].name_iana;
            break;
        }
    }
    return nameIana;
#else
    (void)cipherSuite0;
    (void)cipherSuite;
    return NULL;
#endif
}

const char* wolfSSL_get_cipher_name_internal(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return NULL;
    }

    return GetCipherNameInternal(ssl->options.cipherSuite0, ssl->options.cipherSuite);
}

const char* wolfSSL_get_cipher_name_iana(WOLFSSL* ssl)
{
    if (ssl == NULL) {
        return NULL;
    }

    return GetCipherNameIana(ssl->options.cipherSuite0, ssl->options.cipherSuite);
}

int GetCipherSuiteFromName(const char* name, byte* cipherSuite0,
                           byte* cipherSuite, int* flags)
{
    int           ret = BAD_FUNC_ARG;
    int           i;
    unsigned long len;
    const char*   nameDelim;

    /* Support trailing : */
    nameDelim = XSTRSTR(name, ":");
    if (nameDelim)
        len = (unsigned long)(nameDelim - name);
    else
        len = (unsigned long)XSTRLEN(name);

    for (i = 0; i < GetCipherNamesSize(); i++) {
        if ((XSTRNCMP(name, cipher_names[i].name, len) == 0) &&
            (cipher_names[i].name[len] == 0)) {
            *cipherSuite0 = cipher_names[i].cipherSuite0;
            *cipherSuite  = cipher_names[i].cipherSuite;
            *flags = cipher_names[i].flags;
            ret = 0;
            break;
        }
    }

    return ret;
}

/**
Set the enabled cipher suites.

With OPENSSL_EXTRA we attempt to understand some of the available "bulk"
ciphersuites. We can not perfectly filter ciphersuites based on the "bulk"
names but we do what we can. Ciphersuites named explicitly take precedence to
ciphersuites introduced through the "bulk" ciphersuites.

@param [out] suites Suites structure.
@param [in]  list   List of cipher suites, only supports full name from
                    cipher_names[] delimited by ':'.

@return true on success, else false.
*/
int SetCipherList(WOLFSSL_CTX* ctx, Suites* suites, const char* list)
{
    int       ret              = 0;
    int       idx              = 0;
    int       haveRSAsig       = 0;
    int       haveECDSAsig     = 0;
    int       haveFalconSig    = 0;
    int       haveDilithiumSig = 0;
    int       haveAnon         = 0;
#ifdef OPENSSL_EXTRA
    int       haveRSA          = 0;
    int       haveDH           = 0;
    int       haveECC          = 0;
    int       haveStaticRSA    = 1; /* allowed by default if compiled in */
    int       haveStaticECC    = 0;
    int       haveNull         = 1; /* allowed by default if compiled in */
    int       callInitSuites   = 0;
    int       havePSK          = 0;
#endif
    const int suiteSz       = GetCipherNamesSize();
    const char* next        = list;

    if (suites == NULL || list == NULL) {
        WOLFSSL_MSG("SetCipherList parameter error");
        return 0;
    }

    if (next[0] == 0 || XSTRCMP(next, "ALL") == 0 ||
        XSTRCMP(next, "DEFAULT") == 0 || XSTRCMP(next, "HIGH") == 0)
        return 1; /* wolfSSL default */

    do {
        const char* current = next;
        char   name[MAX_SUITE_NAME + 1];
        int    i;
        word32 length;
    #ifdef OPENSSL_EXTRA
        int    allowing = 1;
    #endif

        next = XSTRSTR(next, ":");
        length = MAX_SUITE_NAME;
        if (next != NULL) {
            word32 currLen = (word32)(next - current);
            if (length > currLen) {
                length = currLen;
            }
        }

    #ifdef OPENSSL_EXTRA
        if (length > 1) {
            if (*current == '!') {
                allowing = 0;
                current++;
                length--;
            }
        }
    #endif

        XSTRNCPY(name, current, length);
        name[(length == sizeof(name)) ? length - 1 : length] = 0;

    #ifdef OPENSSL_EXTRA
        if (XSTRCMP(name, "DEFAULT") == 0 || XSTRCMP(name, "ALL") == 0) {
            if (XSTRCMP(name, "ALL") == 0)
                haveAnon = 1;
            else
                haveAnon = 0;
        #ifdef HAVE_ANON
            ctx->haveAnon = haveAnon;
        #endif
            haveRSA = 1;
            haveDH = 1;
            haveECC = 1;

            /* having static ECC will disable all RSA use, do not set
             * static ECC suites here
             * haveStaticECC = 1; */
            haveStaticRSA = 1;
            haveRSAsig = 1;
            havePSK = 1;
            haveNull = 0;

            callInitSuites = 1;
            ret = 1;
            continue;
        }

        /* We don't have a way to disallow high bit sizes. Only disable unsafe
         * ciphersuites. */
        if (XSTRCMP(name, "HIGH") == 0 && allowing) {
            /* Disable static, anonymous, and null ciphers */
            haveAnon = 0;
        #ifdef HAVE_ANON
            ctx->haveAnon = 0;
        #endif
            haveRSA = 1;
            haveDH = 1;
            haveECC = 1;
            haveStaticECC = 0;
            haveStaticRSA = 0;
            haveRSAsig = 1;
            havePSK = 1;
            haveNull = 0;

            callInitSuites = 1;
            ret = 1;
            continue;
        }

        if (XSTRCMP(name, "aNULL") == 0) {
            haveAnon = allowing;
        #ifdef HAVE_ANON
            ctx->haveAnon = allowing;
        #endif
            if (allowing) {
                /* Allow RSA by default. */
                if (!haveECC)
                    haveRSA = 1;
                if (!haveECDSAsig)
                    haveRSAsig = 1;
                callInitSuites = 1;
                ret = 1;
            }
            continue;
        }

        if (XSTRCMP(name, "eNULL") == 0 || XSTRCMP(name, "NULL") == 0) {
            haveNull = allowing;
            if (allowing) {
                /* Allow RSA by default. */
                if (!haveECC)
                    haveRSA = 1;
                if (!haveECDSAsig)
                    haveRSAsig = 1;
                callInitSuites = 1;
                ret = 1;
            }
            continue;
        }

        if (XSTRCMP(name, "kDH") == 0) {
            haveStaticECC = allowing;
            if (allowing) {
                haveECC = 1;
                haveECDSAsig = 1;
                callInitSuites = 1;
                ret = 1;
            }
            continue;
        }

        if (XSTRCMP(name, "kRSA") == 0 || XSTRCMP(name, "RSA") == 0) {
            haveStaticRSA = allowing;
            if (allowing) {
                haveRSA = 1;
                haveRSAsig = 1;
                callInitSuites = 1;
                ret = 1;
            }
            continue;
        }

        if (XSTRCMP(name, "PSK") == 0) {
            havePSK = allowing;
            haveRSAsig = 1;
            if (allowing) {
                /* Allow RSA by default. */
                if (!haveECC)
                    haveRSA = 1;
                if (!haveECDSAsig)
                    haveRSAsig = 1;
                callInitSuites = 1;
                ret = 1;
            }
            continue;
        }

        if (XSTRCMP(name, "LOW") == 0 || XSTRCMP(name, "MEDIUM") == 0) {
            /* No way to limit or allow low bit sizes */
            if (allowing) {
                /* Allow RSA by default */
                haveRSA = 1;
                haveRSAsig = 1;
                callInitSuites = 1;
                ret = 1;
            }
            continue;
        }

        if (XSTRCMP(name, "DSS") == 0) {
            /* No support for DSA ciphersuites */
            continue;
        }

        if (XSTRCMP(name, "EXP") == 0 || XSTRCMP(name, "EXPORT") == 0) {
            /* wolfSSL doesn't support "export" ciphers. We can skip this */
            continue;
        }
    #endif /* OPENSSL_EXTRA */

        for (i = 0; i < suiteSz; i++) {
            int j;

            if (XSTRNCMP(name, cipher_names[i].name, sizeof(name)) == 0
            #ifndef NO_ERROR_STRINGS
                || XSTRNCMP(name, cipher_names[i].name_iana, sizeof(name)) == 0
            #endif
             ) {
            #ifdef WOLFSSL_DTLS
                /* don't allow stream ciphers with DTLS */
                if (ctx->method->version.major == DTLS_MAJOR) {
                    if (XSTRSTR(name, "RC4"))
                    {
                        WOLFSSL_MSG("Stream ciphers not supported with DTLS");
                        continue;
                    }

                }
            #endif /* WOLFSSL_DTLS */

                for (j = 0; j < idx; j += 2) {
                    if ((suites->suites[j+0] == cipher_names[i].cipherSuite0) &&
                        (suites->suites[j+1] == cipher_names[i].cipherSuite)) {
                        break;
                    }
                }
                /* Silently drop duplicates from list. */
                if (j != idx) {
                    break;
                }

                if (idx + 1 >= WOLFSSL_MAX_SUITE_SZ) {
                    WOLFSSL_MSG("WOLFSSL_MAX_SUITE_SZ set too low");
                    return 0; /* suites buffer not large enough, error out */
                }

                suites->suites[idx++] = cipher_names[i].cipherSuite0;
                suites->suites[idx++] = cipher_names[i].cipherSuite;
                /* The suites are either ECDSA, RSA, PSK, or Anon. The RSA
                 * suites don't necessarily have RSA in the name. */
            #ifdef WOLFSSL_TLS13
                if (cipher_names[i].cipherSuite0 == TLS13_BYTE ||
                         (cipher_names[i].cipherSuite0 == ECC_BYTE &&
                          (cipher_names[i].cipherSuite == TLS_SHA256_SHA256 ||
                           cipher_names[i].cipherSuite == TLS_SHA384_SHA384))) {
                #ifndef NO_RSA
                    haveRSAsig = 1;
                #endif
                #if defined(HAVE_ECC) || defined(HAVE_ED25519) || \
                                                             defined(HAVE_ED448)
                    haveECDSAsig = 1;
                #endif
                #if defined(HAVE_PQC)
                #ifdef HAVE_FALCON
                    haveFalconSig = 1;
                #endif /* HAVE_FALCON */
                #ifdef HAVE_DILITHIUM
                    haveDilithiumSig = 1;
                #endif /* HAVE_DILITHIUM */
                #endif /* HAVE_PQC */
                }
                else
            #endif
            #if defined(HAVE_ECC) || defined(HAVE_ED25519) || \
                                                             defined(HAVE_ED448)
                if ((haveECDSAsig == 0) && XSTRSTR(name, "ECDSA"))
                    haveECDSAsig = 1;
                else
            #endif
            #ifdef HAVE_ANON
                if (XSTRSTR(name, "ADH"))
                    haveAnon = 1;
                else
            #endif
                if (haveRSAsig == 0
                    #ifndef NO_PSK
                        && (XSTRSTR(name, "PSK") == NULL)
                    #endif
                   ) {
                    haveRSAsig = 1;
                }

                ret = 1; /* found at least one */
                break;
            }
        }
    }
    while (next++); /* ++ needed to skip ':' */

    if (ret) {
        int keySz = 0;
    #ifndef NO_CERTS
        keySz = ctx->privateKeySz;
    #endif
    #ifdef OPENSSL_EXTRA
        if (callInitSuites) {
            byte tmp[WOLFSSL_MAX_SUITE_SZ];
            XMEMCPY(tmp, suites->suites, idx); /* Store copy */
            suites->setSuites = 0; /* Force InitSuites */
            suites->hashSigAlgoSz = 0; /* Force InitSuitesHashSigAlgo call
                                        * inside InitSuites */
            InitSuites(suites, ctx->method->version, keySz, (word16)haveRSA,
                       (word16)havePSK, (word16)haveDH, (word16)haveECDSAsig,
                       (word16)haveECC, (word16)haveStaticRSA,
                       (word16)haveStaticECC, (word16)haveFalconSig,
                       (word16)haveDilithiumSig, (word16)haveAnon,
                       (word16)haveNull, ctx->method->side);
            /* Restore user ciphers ahead of defaults */
            XMEMMOVE(suites->suites + idx, suites->suites,
                    min(suites->suiteSz, WOLFSSL_MAX_SUITE_SZ-idx));
            suites->suiteSz += (word16)idx;
        }
        else
    #endif
        {
            suites->suiteSz   = (word16)idx;
            InitSuitesHashSigAlgo(suites, haveECDSAsig, haveRSAsig,
                                  haveFalconSig, haveDilithiumSig, haveAnon,
                                  1, keySz);
        }
        suites->setSuites = 1;
    }

    (void)ctx;

    return ret;
}



#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_CERTS)
static int MatchSigAlgo(WOLFSSL* ssl, int sigAlgo)
{
#ifdef HAVE_ED25519
    if (ssl->pkCurveOID == ECC_ED25519_OID) {
        /* Certificate has Ed25519 key, only match with Ed25519 sig alg  */
        return sigAlgo == ed25519_sa_algo;
    }
#endif
#ifdef HAVE_ED448
    if (ssl->pkCurveOID == ECC_ED448_OID) {
        /* Certificate has Ed448 key, only match with Ed448 sig alg  */
        return sigAlgo == ed448_sa_algo;
    }
#endif
#ifdef HAVE_PQC
#ifdef HAVE_FALCON
    if (ssl->pkCurveOID == CTC_FALCON_LEVEL1) {
        /* Certificate has Falcon level 1 key, only match with Falcon level 1
         * sig alg  */
        return sigAlgo == falcon_level1_sa_algo;
    }
    if (ssl->pkCurveOID == CTC_FALCON_LEVEL5) {
        /* Certificate has Falcon level 5 key, only match with Falcon level 5
         * sig alg  */
        return sigAlgo == falcon_level5_sa_algo;
    }
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    if (ssl->pkCurveOID == CTC_DILITHIUM_LEVEL2) {
        /* Certificate has Dilithium level 2 key, only match with it. */
        return sigAlgo == dilithium_level2_sa_algo;
    }
    if (ssl->pkCurveOID == CTC_DILITHIUM_LEVEL3) {
        /* Certificate has Dilithium level 3 key, only match with it. */
        return sigAlgo == dilithium_level3_sa_algo;
    }
    if (ssl->pkCurveOID == CTC_DILITHIUM_LEVEL5) {
        /* Certificate has Dilithium level 5 key, only match with it. */
        return sigAlgo == dilithium_level5_sa_algo;
    }
    if (ssl->pkCurveOID == CTC_DILITHIUM_AES_LEVEL2) {
        /* Certificate has Dilithium AES level 2 key, only match with it. */
        return sigAlgo == dilithium_aes_level2_sa_algo;
    }
    if (ssl->pkCurveOID == CTC_DILITHIUM_AES_LEVEL3) {
        /* Certificate has Dilithium AES level 3 key, only match with it. */
        return sigAlgo == dilithium_aes_level3_sa_algo;
    }
    if (ssl->pkCurveOID == CTC_DILITHIUM_AES_LEVEL5) {
        /* Certificate has Dilithium AES level 5 key, only match with it. */
        return sigAlgo == dilithium_aes_level5_sa_algo;
    }
#endif /* HAVE_DILITHIUM */
#endif /* HAVE_PQC */
#ifdef WC_RSA_PSS
    /* RSA certificate and PSS sig alg. */
    if (ssl->suites->sigAlgo == rsa_sa_algo) {
    #if defined(WOLFSSL_TLS13)
        /* TLS 1.3 only supports RSA-PSS. */
        if (IsAtLeastTLSv1_3(ssl->version))
            return sigAlgo == rsa_pss_sa_algo;
    #endif
        /* TLS 1.2 and below - RSA-PSS allowed. */
        if (sigAlgo == rsa_pss_sa_algo)
            return 1;
    }
#endif
    /* Signature algorithm matches certificate. */
    return sigAlgo == ssl->suites->sigAlgo;
}

#if defined(HAVE_ECC) && defined(WOLFSSL_TLS13) || \
                                              defined(USE_ECDSA_KEYSZ_HASH_ALGO)
static int CmpEccStrength(int hashAlgo, int curveSz)
{
    int dgstSz = GetMacDigestSize((byte)hashAlgo);
    if (dgstSz <= 0)
        return -1;
    return dgstSz - (curveSz & (~0x3));
}
#endif

static byte MinHashAlgo(WOLFSSL* ssl)
{
#ifdef WOLFSSL_TLS13
    if (IsAtLeastTLSv1_3(ssl->version)) {
        return sha256_mac;
    }
#endif
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_ALLOW_TLS_SHA1)
    if (IsAtLeastTLSv1_2(ssl)) {
        return sha256_mac;
    }
#endif /* WOLFSSL_NO_TLS12 */
    (void)ssl;
    return sha_mac;
}

int PickHashSigAlgo(WOLFSSL* ssl, const byte* hashSigAlgo, word32 hashSigAlgoSz)
{
    word32 i;
    int ret = MATCH_SUITE_ERROR;
    byte minHash;

    /* set defaults */
    if (IsAtLeastTLSv1_3(ssl->version)) {
    #ifndef NO_CERTS
        /* TLS 1.3 cipher suites don't have public key algorithms in them.
         * Using the one in the certificate - if any.
         */
        ssl->suites->sigAlgo = ssl->buffers.keyType;
    #endif
    }
    else {
        ssl->suites->sigAlgo = ssl->specs.sig_algo;
    }
    if (ssl->suites->sigAlgo == anonymous_sa_algo) {
        /* PSK ciphersuite - get digest to use from cipher suite */
        ssl->suites->hashAlgo = ssl->specs.mac_algorithm;
        return 0;
    }
    ssl->suites->hashAlgo = minHash = MinHashAlgo(ssl);

    /* No list means go with the defaults. */
    if (hashSigAlgoSz == 0)
        return 0;

    /* i+1 since two bytes used to describe hash and signature algorithm */
    for (i = 0; (i+1) < hashSigAlgoSz; i += HELLO_EXT_SIGALGO_SZ) {
        byte hashAlgo = 0, sigAlgo = 0;

        DecodeSigAlg(&hashSigAlgo[i], &hashAlgo, &sigAlgo);
        /* Keep looking if hash algorithm not strong enough. */
        if (hashAlgo < minHash)
            continue;
        /* Keep looking if signature algorithm isn't supported by cert. */
        if (!MatchSigAlgo(ssl, sigAlgo))
            continue;

    #ifdef HAVE_ED25519
        if (ssl->pkCurveOID == ECC_ED25519_OID) {
            /* Matched Ed25519 - set chosen and finished. */
            ssl->suites->sigAlgo = sigAlgo;
            ssl->suites->hashAlgo = hashAlgo;
            ret = 0;
            break;
        }
    #endif
    #ifdef HAVE_ED448
        if (ssl->pkCurveOID == ECC_ED448_OID) {
            /* Matched Ed448 - set chosen and finished. */
            ssl->suites->sigAlgo = sigAlgo;
            ssl->suites->hashAlgo = hashAlgo;
            ret = 0;
            break;
        }
    #endif
    #if defined(HAVE_PQC)
    #if defined(HAVE_FALCON)
        if (ssl->pkCurveOID == CTC_FALCON_LEVEL1 ||
            ssl->pkCurveOID == CTC_FALCON_LEVEL5 ) {
            /* Matched Falcon - set chosen and finished. */
            ssl->suites->sigAlgo = sigAlgo;
            ssl->suites->hashAlgo = hashAlgo;
            ret = 0;
            break;
        }
    #endif /* HAVE_FALCON */
    #if defined(HAVE_DILITHIUM)
        if (ssl->pkCurveOID == CTC_DILITHIUM_LEVEL2 ||
            ssl->pkCurveOID == CTC_DILITHIUM_LEVEL3 ||
            ssl->pkCurveOID == CTC_DILITHIUM_LEVEL5 ||
            ssl->pkCurveOID == CTC_DILITHIUM_AES_LEVEL2 ||
            ssl->pkCurveOID == CTC_DILITHIUM_AES_LEVEL3 ||
            ssl->pkCurveOID == CTC_DILITHIUM_AES_LEVEL5 ) {
            /* Matched Dilithium - set chosen and finished. */
            ssl->suites->sigAlgo = sigAlgo;
            ssl->suites->hashAlgo = hashAlgo;
            ret = 0;
            break;
        }
    #endif /* HAVE_DILITHIUM */
    #endif /* HAVE_PQC */

    #if defined(WOLFSSL_ECDSA_MATCH_HASH) && defined(USE_ECDSA_KEYSZ_HASH_ALGO)
        #error "WOLFSSL_ECDSA_MATCH_HASH and USE_ECDSA_KEYSZ_HASH_ALGO cannot "
               "be used together"
    #endif

    #if defined(HAVE_ECC) && (defined(WOLFSSL_TLS13) || \
                                              defined(WOLFSSL_ECDSA_MATCH_HASH))
        if (sigAlgo == ecc_dsa_sa_algo
        #ifndef WOLFSSL_ECDSA_MATCH_HASH
            && IsAtLeastTLSv1_3(ssl->version)
        #endif
            ) {
            /* Must be exact match. */
            if (CmpEccStrength(hashAlgo, ssl->buffers.keySz) != 0)
                continue;

            /* Matched ECDSA exaclty - set chosen and finished. */
            ssl->suites->hashAlgo = hashAlgo;
            ssl->suites->sigAlgo = sigAlgo;
            ret = 0;
            break;
        }
    #endif

    /* For ECDSA the `USE_ECDSA_KEYSZ_HASH_ALGO` build option will choose a hash
     * algorithm that matches the ephemeral ECDHE key size or the next highest
     * available. This workaround resolves issue with some peer's that do not
     * properly support scenarios such as a P-256 key hashed with SHA512.
     */
    #if defined(HAVE_ECC) && defined(USE_ECDSA_KEYSZ_HASH_ALGO)
        if (sigAlgo == ecc_dsa_sa_algo) {
            int cmp = CmpEccStrength(hashAlgo, ssl->eccTempKeySz);

            /* Keep looking if digest not strong enough. */
            if (cmp < 0)
                continue;

            /* Looking for exact match or next highest. */
            if (ret != 0 || hashAlgo <= ssl->suites->hashAlgo) {
                ssl->suites->hashAlgo = hashAlgo;
                ssl->suites->sigAlgo = sigAlgo;
            #if defined(WOLFSSL_TLS13) || defined(HAVE_FFDHE)
                ssl->namedGroup = 0;
            #endif
                ret = 0;
            }

            /* Continue looking if not the same strength. */
            if (cmp > 0)
                continue;
            /* Exact match - finished. */
            break;
        }
    #endif

        switch (hashAlgo) {
        #ifndef NO_SHA
            case sha_mac:
        #endif
        #ifdef WOLFSSL_SHA224
            case sha224_mac:
        #endif
        #ifndef NO_SHA256
            case sha256_mac:
        #endif
        #ifdef WOLFSSL_SHA384
            case sha384_mac:
        #endif
        #ifdef WOLFSSL_SHA512
            case sha512_mac:
        #endif
            #ifdef WOLFSSL_STRONGEST_HASH_SIG
                /* Is hash algorithm weaker than chosen/min? */
                if (hashAlgo < ssl->suites->hashAlgo)
                    break;
            #else
                /* Is hash algorithm stonger than last chosen? */
                if (ret == 0 && hashAlgo > ssl->suites->hashAlgo)
                    break;
            #endif
                /* The chosen one - but keep looking. */
                ssl->suites->hashAlgo = hashAlgo;
                ssl->suites->sigAlgo = sigAlgo;
                ret = 0;
                break;
            default:
                /* Support for hash algorithm not compiled in. */
                break;
        }
    }

    return ret;
}
#endif /* !defined(NO_WOLFSSL_SERVER) || !defined(NO_CERTS) */

#if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)

    /* Initialize HandShakeInfo */
    void InitHandShakeInfo(HandShakeInfo* info, WOLFSSL* ssl)
    {
        int i;

        info->ssl = ssl;
        info->cipherName[0] = 0;
        for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++)
            info->packetNames[i][0] = 0;
        info->numberPackets = 0;
        info->negotiationError = 0;
    }

    /* Set Final HandShakeInfo parameters */
    void FinishHandShakeInfo(HandShakeInfo* info)
    {
        int i;
        int sz = GetCipherNamesSize();

        for (i = 0; i < sz; i++) {
#ifndef NO_CIPHER_SUITE_ALIASES
            if (cipher_names[i].flags & WOLFSSL_CIPHER_SUITE_FLAG_NAMEALIAS)
                continue;
#endif
            if (info->ssl->options.cipherSuite ==
                                            (byte)cipher_names[i].cipherSuite) {
                if (info->ssl->options.cipherSuite0 == ECC_BYTE)
                    continue;   /* ECC suites at end */
                XSTRNCPY(info->cipherName, cipher_names[i].name, MAX_CIPHERNAME_SZ);
                info->cipherName[MAX_CIPHERNAME_SZ] = '\0';
                break;
            }
        }

        /* error max and min are negative numbers */
        if (info->ssl->error <= MIN_PARAM_ERR && info->ssl->error >= MAX_PARAM_ERR)
            info->negotiationError = info->ssl->error;
    }


    /* Add name to info packet names, increase packet name count */
    void AddPacketName(WOLFSSL* ssl, const char* name)
    {
    #ifdef WOLFSSL_CALLBACKS
        HandShakeInfo* info = &ssl->handShakeInfo;
        if (info->numberPackets < MAX_PACKETS_HANDSHAKE) {
            char* packetName = info->packetNames[info->numberPackets];
            XSTRNCPY(packetName, name, MAX_PACKETNAME_SZ);
            packetName[MAX_PACKETNAME_SZ] = '\0';
            info->numberPackets++;
        }
    #endif
        (void)ssl;
        (void)name;
    }


    #ifdef WOLFSSL_CALLBACKS
    /* Initialize TimeoutInfo */
    void InitTimeoutInfo(TimeoutInfo* info)
    {
        XMEMSET(info, 0, sizeof(TimeoutInfo));
    }


    /* Free TimeoutInfo */
    void FreeTimeoutInfo(TimeoutInfo* info, void* heap)
    {
        int i;
        (void)heap;
        for (i = 0; i < MAX_PACKETS_HANDSHAKE; i++) {
            if (info->packets[i].bufferValue) {
                XFREE(info->packets[i].bufferValue, heap, DYNAMIC_TYPE_INFO);
                info->packets[i].bufferValue = NULL;
            }
        }
    }

    /* Add packet name to previously added packet info */
    void AddLateName(const char* name, TimeoutInfo* info)
    {
        /* make sure we have a valid previous one */
        if (info->numberPackets > 0 && info->numberPackets <
                                                        MAX_PACKETS_HANDSHAKE) {
            char* packetName = info->packets[info->numberPackets-1].packetName;
            XSTRNCPY(packetName, name, MAX_PACKETNAME_SZ);
            packetName[MAX_PACKETNAME_SZ] = '\0';
        }
    }

    /* Add record header to previously added packet info */
    void AddLateRecordHeader(const RecordLayerHeader* rl, TimeoutInfo* info)
    {
        /* make sure we have a valid previous one */
        if (info->numberPackets > 0 && info->numberPackets <
                                                        MAX_PACKETS_HANDSHAKE) {
            if (info->packets[info->numberPackets - 1].bufferValue)
                XMEMCPY(info->packets[info->numberPackets - 1].bufferValue, rl,
                       RECORD_HEADER_SZ);
            else
                XMEMCPY(info->packets[info->numberPackets - 1].value, rl,
                       RECORD_HEADER_SZ);
        }
    }

    #endif /* WOLFSSL_CALLBACKS */


    /* Add PacketInfo to TimeoutInfo
     *
     * ssl   WOLFSSL structure sending or receiving packet
     * name  name of packet being sent
     * type  type of packet being sent
     * data  data bing sent with packet
     * sz    size of data buffer
     * lateRL  save space for record layer in TimoutInfo struct
     * written 1 if this packet is being written to wire, 0 if being read
     * heap  custom heap to use for mallocs/frees
     */
    int AddPacketInfo(WOLFSSL* ssl, const char* name, int type,
            const byte* data, int sz, int written, int lateRL, void* heap)
    {
    #ifdef WOLFSSL_CALLBACKS
        TimeoutInfo* info = &ssl->timeoutInfo;

        if (info->numberPackets < (MAX_PACKETS_HANDSHAKE - 1)) {
            WOLFSSL_TIMEVAL currTime;
            int totalSz;

            /* add in space for post record layer */
            totalSz = sz + lateRL;

            /* may add name after */
            if (name) {
                char* packetName = info->packets[info->numberPackets].packetName;
                XSTRNCPY(packetName, name, MAX_PACKETNAME_SZ);
                packetName[MAX_PACKETNAME_SZ] = '\0';
            }

            /* add data, put in buffer if bigger than static buffer */
            info->packets[info->numberPackets].valueSz = totalSz;
            if (totalSz < MAX_VALUE_SZ) {
                XMEMCPY(info->packets[info->numberPackets].value, data + lateRL,
                               sz);
            }
            else {
                info->packets[info->numberPackets].bufferValue =
                               (byte*)XMALLOC(totalSz, heap, DYNAMIC_TYPE_INFO);
                if (!info->packets[info->numberPackets].bufferValue) {
                    /* let next alloc catch, just don't fill, not fatal here  */
                    info->packets[info->numberPackets].valueSz = 0;
                }
                else {
                    /* copy over data (which has the handshake header), leaving
                     * room for post record layer header if set */
                    XMEMCPY(info->packets[info->numberPackets].bufferValue +
                            lateRL, data, sz);
                }
            }

            if (gettimeofday(&currTime, 0) < 0)
                return SYSLIB_FAILED_E;

            info->packets[info->numberPackets].timestamp.tv_sec  =
                                                             currTime.tv_sec;
            info->packets[info->numberPackets].timestamp.tv_usec =
                                                             currTime.tv_usec;
            info->numberPackets++;
        }
    #endif /* WOLFSSL_CALLBACKS */
    #ifdef OPENSSL_EXTRA
        if ((ssl->protoMsgCb != NULL) && (sz > 0) &&
            (ssl->keys.encryptionOn != 1)) {
            /* version from hex to dec  16 is 16^1, 256 from 16^2 and
               4096 from 16^3 */
            int version = (ssl->version.minor & 0x0F) +
                          ((ssl->version.minor & 0xF0) << 4) +
                          ((ssl->version.major & 0x0F) << 8) +
                          ((ssl->version.major & 0xF0) << 12);

            ssl->protoMsgCb(written, version, type,
                         (const void *)data, (size_t)sz,
                         ssl, ssl->protoMsgCtx);
        }
    #endif /* OPENSSL_EXTRA */
        (void)written;
        (void)name;
        (void)heap;
        (void)type;
        (void)ssl;
        (void)lateRL;

        return 0;
    }

#endif /* WOLFSSL_CALLBACKS */

#if !defined(NO_CERTS)

#if defined(WOLF_PRIVATE_KEY_ID) && !defined(NO_CHECK_PRIVATE_KEY)
/* Create a private key for a device.
 *
 * pkey    Key object.
 * data    Data to identify key.
 * length  Length of data.
 * hsType  Type of the key to create.
 * heap    Custom heap to use for mallocs/frees
 * devId   Id for device.
 * return  0 on success.
 * return  NOT_COMPILED_IN if algorithm type not supported.
 * return  MEMORY_E on memory allocation failure.
 * return  other internal error
 */
int CreateDevPrivateKey(void** pkey, byte* data, word32 length, int hsType,
                        int label, int id, void* heap, int devId)
{
    int ret = NOT_COMPILED_IN;

    if (hsType == DYNAMIC_TYPE_RSA) {
#ifndef NO_RSA
        RsaKey* rsaKey;

        rsaKey = (RsaKey*)XMALLOC(sizeof(RsaKey), heap, DYNAMIC_TYPE_RSA);
        if (rsaKey == NULL) {
            return MEMORY_E;
        }

        if (label) {
            ret = wc_InitRsaKey_Label(rsaKey, (char*)data, heap, devId);
        }
        else if (id) {
            ret = wc_InitRsaKey_Id(rsaKey, data, length, heap, devId);
        }
        if (ret == 0) {
            *pkey = (void*)rsaKey;
        }
        else {
            XFREE(rsaKey, heap, DYNAMIC_TYPE_RSA);
        }
#endif
    }
    else if (hsType == DYNAMIC_TYPE_ECC) {
#ifdef HAVE_ECC
        ecc_key* ecKey;

        ecKey = (ecc_key*)XMALLOC(sizeof(ecc_key), heap, DYNAMIC_TYPE_ECC);
        if (ecKey == NULL) {
            return MEMORY_E;
        }

        if (label) {
            ret = wc_ecc_init_label(ecKey, (char*)data, heap, devId);
        }
        else if (id) {
            ret = wc_ecc_init_id(ecKey, data, length, heap, devId);
        }
        if (ret == 0) {
            *pkey = (void*)ecKey;
        }
        else {
            XFREE(ecKey, heap, DYNAMIC_TYPE_ECC);
        }
#endif
    }

    return ret;
}
#endif /* WOLF_PRIVATE_KEY_ID && !NO_CHECK_PRIVATE_KEY */

/* Decode the private key - RSA/ECC/Ed25519/Ed448/Falcon/Dilithium - and
 * creates a key object.
 *
 * The signature type is set as well.
 * The maximum length of a signature is returned.
 *
 * ssl     The SSL/TLS object.
 * length  The length of a signature.
 * returns 0 on success, otherwise failure.
 */
int DecodePrivateKey(WOLFSSL *ssl, word16* length)
{
    int      ret = BAD_FUNC_ARG;
    int      keySz;
    word32   idx;

    /* make sure private key exists */
    if (ssl->buffers.key == NULL || ssl->buffers.key->buffer == NULL) {
        /* allow no private key if using external */
    #ifdef WOLF_PRIVATE_KEY_ID
        if (ssl->devId != INVALID_DEVID
        #ifdef HAVE_PK_CALLBACKS
            || wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)
        #endif
        ) {
            *length = GetPrivateKeySigSize(ssl);
            return 0;
        }
        else
    #endif
        {
            WOLFSSL_MSG("Private key missing!");
            ERROR_OUT(NO_PRIVATE_KEY, exit_dpk);
        }
    }

#ifdef WOLF_PRIVATE_KEY_ID
    if (ssl->buffers.keyDevId != INVALID_DEVID && (ssl->buffers.keyId ||
                                                       ssl->buffers.keyLabel)) {
        if (ssl->buffers.keyType == rsa_sa_algo)
            ssl->hsType = DYNAMIC_TYPE_RSA;
        else if (ssl->buffers.keyType == ecc_dsa_sa_algo)
            ssl->hsType = DYNAMIC_TYPE_ECC;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

        if (ssl->buffers.keyType == rsa_sa_algo) {
    #ifndef NO_RSA
            if (ssl->buffers.keyLabel) {
                ret = wc_InitRsaKey_Label((RsaKey*)ssl->hsKey,
                                          (char*)ssl->buffers.key->buffer,
                                          ssl->heap, ssl->buffers.keyDevId);
            }
            else if (ssl->buffers.keyId) {
                ret = wc_InitRsaKey_Id((RsaKey*)ssl->hsKey,
                                       ssl->buffers.key->buffer,
                                       ssl->buffers.key->length, ssl->heap,
                                       ssl->buffers.keyDevId);
            }
            if (ret == 0) {
                if (ssl->buffers.keySz < ssl->options.minRsaKeySz) {
                    WOLFSSL_MSG("RSA key size too small");
                    ERROR_OUT(RSA_KEY_SIZE_E, exit_dpk);
                }

                /* Return the maximum signature length. */
                *length = (word16)ssl->buffers.keySz;
            }
    #else
            ret = NOT_COMPILED_IN;
    #endif
        }
        else if (ssl->buffers.keyType == ecc_dsa_sa_algo) {
    #ifdef HAVE_ECC
            if (ssl->buffers.keyLabel) {
                ret = wc_ecc_init_label((ecc_key*)ssl->hsKey,
                                        (char*)ssl->buffers.key->buffer,
                                        ssl->heap, ssl->buffers.keyDevId);
            }
            else if (ssl->buffers.keyId) {
                ret = wc_ecc_init_id((ecc_key*)ssl->hsKey,
                                     ssl->buffers.key->buffer,
                                     ssl->buffers.key->length, ssl->heap,
                                     ssl->buffers.keyDevId);
            }
            if (ret == 0) {
                if (ssl->buffers.keySz < ssl->options.minEccKeySz) {
                    WOLFSSL_MSG("ECC key size too small");
                    ERROR_OUT(ECC_KEY_SIZE_E, exit_dpk);
                }

                /* Return the maximum signature length. */
                *length = (word16)wc_ecc_sig_size_calc(ssl->buffers.keySz);
            }
    #else
            ret = NOT_COMPILED_IN;
    #endif
        }
        goto exit_dpk;
    }
#endif /* WOLF_PRIVATE_KEY_ID */

#ifndef NO_RSA
    if (ssl->buffers.keyType == rsa_sa_algo || ssl->buffers.keyType == 0) {
        ssl->hsType = DYNAMIC_TYPE_RSA;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

        WOLFSSL_MSG("Trying RSA private key");

        /* Set start of data to beginning of buffer. */
        idx = 0;
        /* Decode the key assuming it is an RSA private key. */
        ret = wc_RsaPrivateKeyDecode(ssl->buffers.key->buffer, &idx,
                    (RsaKey*)ssl->hsKey, ssl->buffers.key->length);
    #ifdef WOLF_PRIVATE_KEY_ID
        /* if using external key then allow using a public key */
        if (ret != 0 && (ssl->devId != INVALID_DEVID
        #ifdef HAVE_PK_CALLBACKS
            || wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)
        #endif
        )) {
            WOLFSSL_MSG("Trying RSA public key with crypto callbacks");
            idx = 0;
            ret = wc_RsaPublicKeyDecode(ssl->buffers.key->buffer, &idx,
                        (RsaKey*)ssl->hsKey, ssl->buffers.key->length);
        }
    #endif
        if (ret == 0) {
            WOLFSSL_MSG("Using RSA private key");

            /* It worked so check it meets minimum key size requirements. */
            keySz = wc_RsaEncryptSize((RsaKey*)ssl->hsKey);
            if (keySz < 0) { /* check if keySz has error case */
                ERROR_OUT(keySz, exit_dpk);
            }

            if (keySz < ssl->options.minRsaKeySz) {
                WOLFSSL_MSG("RSA key size too small");
                ERROR_OUT(RSA_KEY_SIZE_E, exit_dpk);
            }

            /* Return the maximum signature length. */
            *length = (word16)keySz;

            goto exit_dpk;
        }
    }
#endif /* !NO_RSA */

#ifdef HAVE_ECC
#ifndef NO_RSA
    FreeKey(ssl, ssl->hsType, (void**)&ssl->hsKey);
#endif /* !NO_RSA */

    if (ssl->buffers.keyType == ecc_dsa_sa_algo || ssl->buffers.keyType == 0) {
        ssl->hsType = DYNAMIC_TYPE_ECC;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

    #ifndef NO_RSA
        WOLFSSL_MSG("Trying ECC private key, RSA didn't work");
    #else
        WOLFSSL_MSG("Trying ECC private key");
    #endif

        /* Set start of data to beginning of buffer. */
        idx = 0;
        /* Decode the key assuming it is an ECC private key. */
        ret = wc_EccPrivateKeyDecode(ssl->buffers.key->buffer, &idx,
                                     (ecc_key*)ssl->hsKey,
                                     ssl->buffers.key->length);
    #ifdef WOLF_PRIVATE_KEY_ID
        /* if using external key then allow using a public key */
        if (ret != 0 && (ssl->devId != INVALID_DEVID
        #ifdef HAVE_PK_CALLBACKS
            || wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)
        #endif
        )) {
            WOLFSSL_MSG("Trying ECC public key with crypto callbacks");
            idx = 0;
            ret = wc_EccPublicKeyDecode(ssl->buffers.key->buffer, &idx,
                                     (ecc_key*)ssl->hsKey,
                                     ssl->buffers.key->length);
        }
    #endif
        if (ret == 0) {
            WOLFSSL_MSG("Using ECC private key");

            /* Check it meets the minimum ECC key size requirements. */
            keySz = wc_ecc_size((ecc_key*)ssl->hsKey);
            if (keySz < ssl->options.minEccKeySz) {
                WOLFSSL_MSG("ECC key size too small");
                ERROR_OUT(ECC_KEY_SIZE_E, exit_dpk);
            }

            /* Return the maximum signature length. */
            *length = (word16)wc_ecc_sig_size((ecc_key*)ssl->hsKey);

            goto exit_dpk;
        }
    }
#endif
#if defined(HAVE_ED25519) && defined(HAVE_ED25519_KEY_IMPORT)
    #if !defined(NO_RSA) || defined(HAVE_ECC)
        FreeKey(ssl, ssl->hsType, (void**)&ssl->hsKey);
    #endif

    if (ssl->buffers.keyType == ed25519_sa_algo || ssl->buffers.keyType == 0) {
        ssl->hsType = DYNAMIC_TYPE_ED25519;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

        #ifdef HAVE_ECC
            WOLFSSL_MSG("Trying ED25519 private key, ECC didn't work");
        #elif !defined(NO_RSA)
            WOLFSSL_MSG("Trying ED25519 private key, RSA didn't work");
        #else
            WOLFSSL_MSG("Trying ED25519 private key");
        #endif

        /* Set start of data to beginning of buffer. */
        idx = 0;
        /* Decode the key assuming it is an ED25519 private key. */
        ret = wc_Ed25519PrivateKeyDecode(ssl->buffers.key->buffer, &idx,
                                         (ed25519_key*)ssl->hsKey,
                                         ssl->buffers.key->length);
    #ifdef WOLF_PRIVATE_KEY_ID
        /* if using external key then allow using a public key */
        if (ret != 0 && (ssl->devId != INVALID_DEVID
        #ifdef HAVE_PK_CALLBACKS
            || wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)
        #endif
        )) {
            WOLFSSL_MSG("Trying ED25519 public key with crypto callbacks");
            idx = 0;
            ret = wc_Ed25519PublicKeyDecode(ssl->buffers.key->buffer, &idx,
                                           (ed25519_key*)ssl->hsKey,
                                            ssl->buffers.key->length);
        }
    #endif
        if (ret == 0) {
            WOLFSSL_MSG("Using ED25519 private key");

            /* Check it meets the minimum ECC key size requirements. */
            if (ED25519_KEY_SIZE < ssl->options.minEccKeySz) {
                WOLFSSL_MSG("ED25519 key size too small");
                ERROR_OUT(ECC_KEY_SIZE_E, exit_dpk);
            }

            /* Return the maximum signature length. */
            *length = ED25519_SIG_SIZE;

            goto exit_dpk;
        }
    }
#endif /* HAVE_ED25519 && HAVE_ED25519_KEY_IMPORT */
#if defined(HAVE_ED448) && defined(HAVE_ED448_KEY_IMPORT)
    #if !defined(NO_RSA) || defined(HAVE_ECC)
        FreeKey(ssl, ssl->hsType, (void**)&ssl->hsKey);
    #endif

    if (ssl->buffers.keyType == ed448_sa_algo || ssl->buffers.keyType == 0) {
        ssl->hsType = DYNAMIC_TYPE_ED448;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

        #ifdef HAVE_ED25519
            WOLFSSL_MSG("Trying ED448 private key, ED25519 didn't work");
        #elif defined(HAVE_ECC)
            WOLFSSL_MSG("Trying ED448 private key, ECC didn't work");
        #elif !defined(NO_RSA)
            WOLFSSL_MSG("Trying ED448 private key, RSA didn't work");
        #else
            WOLFSSL_MSG("Trying ED448 private key");
        #endif

        /* Set start of data to beginning of buffer. */
        idx = 0;
        /* Decode the key assuming it is an ED448 private key. */
        ret = wc_Ed448PrivateKeyDecode(ssl->buffers.key->buffer, &idx,
                                       (ed448_key*)ssl->hsKey,
                                       ssl->buffers.key->length);
    #ifdef WOLF_PRIVATE_KEY_ID
        /* if using external key then allow using a public key */
        if (ret != 0 && (ssl->devId != INVALID_DEVID
        #ifdef HAVE_PK_CALLBACKS
            || wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)
        #endif
        )) {
            WOLFSSL_MSG("Trying ED25519 public key with crypto callbacks");
            idx = 0;
            ret = wc_Ed448PublicKeyDecode(ssl->buffers.key->buffer, &idx,
                                          (ed448_key*)ssl->hsKey,
                                          ssl->buffers.key->length);
        }
    #endif
        if (ret == 0) {
            WOLFSSL_MSG("Using ED448 private key");

            /* Check it meets the minimum ECC key size requirements. */
            if (ED448_KEY_SIZE < ssl->options.minEccKeySz) {
                WOLFSSL_MSG("ED448 key size too small");
                ERROR_OUT(ECC_KEY_SIZE_E, exit_dpk);
            }

            /* Return the maximum signature length. */
            *length = ED448_SIG_SIZE;

            goto exit_dpk;
        }
    }
#endif /* HAVE_ED448 && HAVE_ED448_KEY_IMPORT */
#if defined(HAVE_PQC)
#if defined(HAVE_FALCON)
    if (ssl->buffers.keyType == falcon_level1_sa_algo ||
        ssl->buffers.keyType == falcon_level5_sa_algo ||
        ssl->buffers.keyType == 0) {

        ssl->hsType = DYNAMIC_TYPE_FALCON;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

        if (ssl->buffers.keyType == falcon_level1_sa_algo) {
            ret = wc_falcon_set_level((falcon_key*)ssl->hsKey, 1);
        }
        else if (ssl->buffers.keyType == falcon_level5_sa_algo) {
            ret = wc_falcon_set_level((falcon_key*)ssl->hsKey, 5);
        }
        else {
            /* What if ssl->buffers.keyType is 0? We might want to do something
             * more graceful here. */
            ret = ALGO_ID_E;
        }

        if (ret != 0) {
            goto exit_dpk;
        }

        #if defined(HAVE_ED448)
            WOLFSSL_MSG("Trying Falcon private key, ED448 didn't work");
        #elif defined(HAVE_ED25519)
            WOLFSSL_MSG("Trying Falcon private key, ED25519 didn't work");
        #elif defined(HAVE_ECC)
            WOLFSSL_MSG("Trying Falcon private key, ECC didn't work");
        #elif !defined(NO_RSA)
            WOLFSSL_MSG("Trying Falcon private key, RSA didn't work");
        #else
            WOLFSSL_MSG("Trying Falcon private key");
        #endif

        /* Set start of data to beginning of buffer. */
        idx = 0;
        /* Decode the key assuming it is a Falcon private key. */
        ret = wc_falcon_import_private_only(ssl->buffers.key->buffer,
                                            ssl->buffers.key->length,
                                            (falcon_key*)ssl->hsKey);
        if (ret == 0) {
            WOLFSSL_MSG("Using Falcon private key");

            /* Check it meets the minimum Falcon key size requirements. */
            if (FALCON_MAX_KEY_SIZE < ssl->options.minFalconKeySz) {
                WOLFSSL_MSG("Falcon key size too small");
                ERROR_OUT(FALCON_KEY_SIZE_E, exit_dpk);
            }

            /* Return the maximum signature length. */
            *length = FALCON_MAX_SIG_SIZE;

            goto exit_dpk;
        }
    }
#endif /* HAVE_FALCON */
#if defined(HAVE_DILITHIUM)
    if (ssl->buffers.keyType == dilithium_level2_sa_algo ||
        ssl->buffers.keyType == dilithium_level3_sa_algo ||
        ssl->buffers.keyType == dilithium_level5_sa_algo ||
        ssl->buffers.keyType == dilithium_aes_level2_sa_algo ||
        ssl->buffers.keyType == dilithium_aes_level3_sa_algo ||
        ssl->buffers.keyType == dilithium_aes_level5_sa_algo ||
        ssl->buffers.keyType == 0) {

        ssl->hsType = DYNAMIC_TYPE_DILITHIUM;
        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
        if (ret != 0) {
            goto exit_dpk;
        }

        if (ssl->buffers.keyType == dilithium_level2_sa_algo) {
            ret = wc_dilithium_set_level_and_sym((dilithium_key*)ssl->hsKey,
                                                 2, SHAKE_VARIANT);
        }
        else if (ssl->buffers.keyType == dilithium_level3_sa_algo) {
            ret = wc_dilithium_set_level_and_sym((dilithium_key*)ssl->hsKey,
                                                 3, SHAKE_VARIANT);
        }
        else if (ssl->buffers.keyType == dilithium_level5_sa_algo) {
            ret = wc_dilithium_set_level_and_sym((dilithium_key*)ssl->hsKey,
                                                 5, SHAKE_VARIANT);
        }
        else if (ssl->buffers.keyType == dilithium_aes_level2_sa_algo) {
            ret = wc_dilithium_set_level_and_sym((dilithium_key*)ssl->hsKey,
                                                 2, AES_VARIANT);
        }
        else if (ssl->buffers.keyType == dilithium_aes_level3_sa_algo) {
            ret = wc_dilithium_set_level_and_sym((dilithium_key*)ssl->hsKey,
                                                 3, AES_VARIANT);
        }
        else if (ssl->buffers.keyType == dilithium_aes_level5_sa_algo) {
            ret = wc_dilithium_set_level_and_sym((dilithium_key*)ssl->hsKey,
                                                 5, AES_VARIANT);
        }
        else {
            /* What if ssl->buffers.keyType is 0? We might want to do something
             * more graceful here. */
            ret = ALGO_ID_E;
        }

        if (ret != 0) {
            goto exit_dpk;
        }

        #if defined(HAVE_ED448)
            WOLFSSL_MSG("Trying Dilithium private key, ED448 didn't work");
        #elif defined(HAVE_ED25519)
            WOLFSSL_MSG("Trying Dilithium private key, ED25519 didn't work");
        #elif defined(HAVE_ECC)
            WOLFSSL_MSG("Trying Dilithium private key, ECC didn't work");
        #elif !defined(NO_RSA)
            WOLFSSL_MSG("Trying Dilithium private key, RSA didn't work");
        #elif defined(HAVE_FALCON)
            WOLFSSL_MSG("Trying Dilithium private key, Falcon didn't work");
        #else
            WOLFSSL_MSG("Trying Dilithium private key");
        #endif

        /* Set start of data to beginning of buffer. */
        idx = 0;
        /* Decode the key assuming it is a Dilithium private key. */
        ret = wc_dilithium_import_private_only(ssl->buffers.key->buffer,
                                               ssl->buffers.key->length,
                                               (dilithium_key*)ssl->hsKey);
        if (ret == 0) {
            WOLFSSL_MSG("Using Dilithium private key");

            /* Check it meets the minimum Dilithium key size requirements. */
            if (DILITHIUM_MAX_KEY_SIZE < ssl->options.minDilithiumKeySz) {
                WOLFSSL_MSG("Dilithium key size too small");
                ERROR_OUT(DILITHIUM_KEY_SIZE_E, exit_dpk);
            }

            /* Return the maximum signature length. */
            *length = DILITHIUM_MAX_SIG_SIZE;

            goto exit_dpk;
        }
    }
#endif /* HAVE_DILITHIUM */
#endif /* HAVE_PQC */

    (void)idx;
    (void)keySz;
    (void)length;

exit_dpk:
    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    return ret;
}

#endif /* WOLFSSL_TLS13 || !NO_WOLFSSL_CLIENT */

#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12)
    /* returns 1 if able to do TLS 1.3 otherwise 0 */
    int TLSv1_3_Capable(WOLFSSL* ssl)
    {
    #ifndef WOLFSSL_TLS13
        return 0;
    #else
        int ret = 0;

        if (IsAtLeastTLSv1_3(ssl->ctx->method->version)) {
            ret = 1;
        }

        if ((wolfSSL_get_options(ssl) & WOLFSSL_OP_NO_TLSv1_3)) {
            /* option set at run time to disable TLS 1.3 */
            ret = 0;
        }

        return ret;
    #endif
    }
#endif /* WOLFSSL_TLS13 */

#ifndef WOLFSSL_NO_TLS12
#if (!defined(NO_WOLFSSL_CLIENT) && (!defined(NO_DH) || defined(HAVE_ECC) || \
      defined(HAVE_CURVE25519) || defined(HAVE_CURVE448))) || \
    (!defined(NO_WOLFSSL_SERVER) && (defined(HAVE_ECC) || \
      ((defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) && \
       (defined(HAVE_ED25519) || defined(HAVE_ED448) || !defined(NO_RSA)))) || \
     (!defined(NO_DH) && (!defined(NO_RSA) || defined(HAVE_ANON))))
static int HashSkeData(WOLFSSL* ssl, enum wc_HashType hashType,
    const byte* data, int sz, byte sigAlgo)
{
    int ret = 0;
    int digest_sz = wc_HashGetDigestSize(hashType);

    if (digest_sz <= 0) {
        ret = BUFFER_ERROR;
    }

    if (ret == 0) {
        /* buffer for signature */
        ssl->buffers.sig.buffer = (byte*)XMALLOC(SEED_LEN + sz, ssl->heap,
                                                        DYNAMIC_TYPE_SIGNATURE);
        if (ssl->buffers.sig.buffer == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        ssl->buffers.sig.length = SEED_LEN + sz;

        /* build message to hash */
        XMEMCPY(ssl->buffers.sig.buffer, ssl->arrays->clientRandom, RAN_LEN);
        XMEMCPY(&ssl->buffers.sig.buffer[RAN_LEN], ssl->arrays->serverRandom,
            RAN_LEN);
        /* message */
        XMEMCPY(&ssl->buffers.sig.buffer[RAN_LEN * 2], data, sz);
    }
    if (ret == 0 && sigAlgo != ed25519_sa_algo && sigAlgo != ed448_sa_algo) {
         ssl->buffers.digest.length = (unsigned int)digest_sz;

        /* buffer for hash */
        ssl->buffers.digest.buffer = (byte*)XMALLOC(ssl->buffers.digest.length,
            ssl->heap, DYNAMIC_TYPE_DIGEST);
        if (ssl->buffers.digest.buffer == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0 && sigAlgo != ed25519_sa_algo && sigAlgo != ed448_sa_algo) {
        /* Perform hash. Only wc_Hash supports MD5_SHA1. */
        ret = wc_Hash(hashType, ssl->buffers.sig.buffer,
                                ssl->buffers.sig.length,
                                ssl->buffers.digest.buffer,
                                ssl->buffers.digest.length);
#ifdef HAVE_PK_CALLBACKS
        if (ssl->ctx->ProcessServerSigKexCb == NULL)
#endif
        {
            /* No further processing will be done. It can be freed. */
            XFREE(ssl->buffers.sig.buffer, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
            ssl->buffers.sig.buffer = NULL;
        }
    }

    return ret;
}
#endif
#endif /* !WOLFSSL_NO_TLS12 */



#ifndef NO_CERTS
    /* handle processing of certificate_request (13) */
    static int DoCertificateRequest(WOLFSSL* ssl, const byte* input, word32*
                                    inOutIdx, word32 size)
    {
        word16 len;
        word32 begin = *inOutIdx;
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL) || \
        defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
        int ret;
    #endif
    #ifdef OPENSSL_EXTRA
        WOLFSSL_X509* x509 = NULL;
        WOLFSSL_EVP_PKEY* pkey = NULL;
    #endif

        WOLFSSL_START(WC_FUNC_CERTIFICATE_REQUEST_DO);
        WOLFSSL_ENTER("DoCertificateRequest");

        #ifdef WOLFSSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName(ssl, "CertificateRequest");
            if (ssl->toInfoOn)
                AddLateName("CertificateRequest", &ssl->timeoutInfo);
        #endif

        if (OPAQUE8_LEN > size)
            return BUFFER_ERROR;

        len = input[(*inOutIdx)++];

        if ((*inOutIdx - begin) + len > size)
            return BUFFER_ERROR;

        /* types, read in here */
        *inOutIdx += len;

        /* signature and hash signature algorithm */
        if (IsAtLeastTLSv1_2(ssl)) {
            if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
                return BUFFER_ERROR;

            ato16(input + *inOutIdx, &len);
            *inOutIdx += OPAQUE16_LEN;

            if ((len > size) || ((*inOutIdx - begin) + len > size))
                return BUFFER_ERROR;

            if (PickHashSigAlgo(ssl, input + *inOutIdx, len) != 0 &&
                                             ssl->buffers.certificate &&
                                             ssl->buffers.certificate->buffer) {
            #ifdef HAVE_PK_CALLBACKS
                if (wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)) {
                    WOLFSSL_MSG("Using PK for client private key");
                    WOLFSSL_ERROR_VERBOSE(INVALID_PARAMETER);
                    return INVALID_PARAMETER;
                }
            #endif
                if (ssl->buffers.key && ssl->buffers.key->buffer) {
                    WOLFSSL_ERROR_VERBOSE(INVALID_PARAMETER);
                    return INVALID_PARAMETER;
                }
            }
            *inOutIdx += len;
    #ifdef WC_RSA_PSS
            ssl->pssAlgo = 0;
            if (ssl->suites->sigAlgo == rsa_pss_sa_algo)
                ssl->pssAlgo |= 1 << ssl->suites->hashAlgo;
    #endif
        }

        /* authorities */
        if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
            return BUFFER_ERROR;

        /* DN seq length */
        ato16(input + *inOutIdx, &len);
        *inOutIdx += OPAQUE16_LEN;

        if ((*inOutIdx - begin) + len > size)
            return BUFFER_ERROR;

    #if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
        if (ssl->ca_names != ssl->ctx->ca_names)
            wolfSSL_sk_X509_NAME_pop_free(ssl->ca_names, NULL);
        ssl->ca_names = wolfSSL_sk_X509_NAME_new(NULL);
        if (ssl->ca_names == NULL) {
            return MEMORY_ERROR;
        }
    #endif

        while (len) {
            word16 dnSz;

            if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
                return BUFFER_ERROR;

            ato16(input + *inOutIdx, &dnSz);
            *inOutIdx += OPAQUE16_LEN;

            if ((*inOutIdx - begin) + dnSz > size)
                return BUFFER_ERROR;

        #if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
            {
                WOLFSSL_X509_NAME* name = NULL;
                /* Use a DecodedCert struct to get access to GetName to
                 * parse DN name */
#ifdef WOLFSSL_SMALL_STACK
                DecodedCert *cert = (DecodedCert *)XMALLOC(
                    sizeof(*cert), ssl->heap, DYNAMIC_TYPE_DCERT);
                if (cert == NULL)
                    return MEMORY_ERROR;
#else
                DecodedCert cert[1];
#endif

                InitDecodedCert(cert, input + *inOutIdx, dnSz, ssl->heap);

                ret = GetName(cert, SUBJECT, dnSz);

                if (ret == 0) {
                    if ((name = wolfSSL_X509_NAME_new()) == NULL)
                        ret = MEMORY_ERROR;
                }

                if (ret == 0) {
                    CopyDecodedName(name, cert, SUBJECT);
                }

                if (ret == 0) {
                    if (wolfSSL_sk_X509_NAME_push(ssl->ca_names, name)
                        == WOLFSSL_FAILURE)
                    {
                        ret = MEMORY_ERROR;
                    }
                }

                FreeDecodedCert(cert);

#ifdef WOLFSSL_SMALL_STACK
                XFREE(cert, ssl->heap, DYNAMIC_TYPE_DCERT);
#endif
                if (ret != 0) {
                    if (name != NULL)
                        wolfSSL_X509_NAME_free(name);
                    return ret;
                }
            }
        #endif

            *inOutIdx += dnSz;
            len -= OPAQUE16_LEN + dnSz;
        }

    #ifdef OPENSSL_EXTRA
        /* call client cert callback if no cert has been loaded */
        if ((ssl->ctx->CBClientCert != NULL) &&
            (!ssl->buffers.certificate || !ssl->buffers.certificate->buffer)) {

            ret = ssl->ctx->CBClientCert(ssl, &x509, &pkey);
            if (ret == 1) {
                if ((wolfSSL_use_certificate(ssl, x509) != WOLFSSL_SUCCESS) ||
                    (wolfSSL_use_PrivateKey(ssl, pkey) != WOLFSSL_SUCCESS)) {
                    WOLFSSL_ERROR_VERBOSE(CLIENT_CERT_CB_ERROR);
                    return CLIENT_CERT_CB_ERROR;
                }
                wolfSSL_X509_free(x509);
                wolfSSL_EVP_PKEY_free(pkey);

            }
            else if (ret < 0) {
                return WOLFSSL_ERROR_WANT_X509_LOOKUP;
            }
        }
        if ((ret = CertSetupCbWrapper(ssl)) != 0)
            return ret;
    #endif

        /* don't send client cert or cert verify if user hasn't provided
           cert and private key */
        if (ssl->buffers.certificate && ssl->buffers.certificate->buffer) {
        #ifdef HAVE_PK_CALLBACKS
            if (wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)) {
                WOLFSSL_MSG("Using PK for client private key");
                ssl->options.sendVerify = SEND_CERT;
            }
        #endif
            if (ssl->buffers.key && ssl->buffers.key->buffer) {
                ssl->options.sendVerify = SEND_CERT;
            }
        }
    #ifdef OPENSSL_EXTRA
        else
    #else
        else if (IsTLS(ssl))
    #endif
        {
            ssl->options.sendVerify = SEND_BLANK_CERT;
        }

        if (IsEncryptionOn(ssl, 0)) {
            *inOutIdx += ssl->keys.padSz;
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMRead)
                *inOutIdx += MacSize(ssl);
        #endif
        }

        WOLFSSL_LEAVE("DoCertificateRequest", 0);
        WOLFSSL_END(WC_FUNC_CERTIFICATE_REQUEST_DO);

        return 0;
    }
#endif /* !NO_CERTS */


////////////////////////////////////


/* Persistable DoServerKeyExchange arguments */
typedef struct DskeArgs {
    byte*  output; /* not allocated */
#if !defined(NO_DH) || defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
    byte*  verifySig;
#endif
    word32 idx;
    word32 begin;
#if !defined(NO_DH) || defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
    word16 verifySigSz;
#endif
    word16 sigSz;
    byte   sigAlgo;
    byte   hashAlgo;
#if !defined(NO_RSA) && defined(WC_RSA_PSS)
    int    bits;
#endif
} DskeArgs;

static void FreeDskeArgs(WOLFSSL* ssl, void* pArgs)
{
    DskeArgs* args = (DskeArgs*)pArgs;

    (void)ssl;
    (void)args;

#if !defined(NO_DH) || defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
    if (args->verifySig) {
        XFREE(args->verifySig, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
        args->verifySig = NULL;
    }
#endif
}

#ifndef NO_DH
static int GetDhPublicKey(WOLFSSL* ssl, const byte* input, word32 size,
                          DskeArgs* args)
{
    int             ret = 0;
    word16          length;
#ifdef HAVE_FFDHE
#ifdef HAVE_PUBLIC_FFDHE
    const DhParams* params = NULL;
#endif
    word16          group = 0;
#endif

    if (ssl->buffers.weOwnDH) {
        if (ssl->buffers.serverDH_P.buffer) {
            XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                    DYNAMIC_TYPE_PUBLIC_KEY);
            ssl->buffers.serverDH_P.buffer = NULL;
        }

        if (ssl->buffers.serverDH_G.buffer) {
            XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                    DYNAMIC_TYPE_PUBLIC_KEY);
            ssl->buffers.serverDH_G.buffer = NULL;
        }

    }

    if (ssl->buffers.serverDH_Pub.buffer) {
        XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_Pub.buffer = NULL;
    }

    /* p */
    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    ato16(input + args->idx, &length);
    args->idx += OPAQUE16_LEN;

    if ((args->idx - args->begin) + length > size) {
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    if (length < ssl->options.minDhKeySz) {
        WOLFSSL_MSG("Server using a DH key that is too small");
        SendAlert(ssl, alert_fatal, handshake_failure);
        ERROR_OUT(DH_KEY_SIZE_E, exit_gdpk);
    }
    if (length > ssl->options.maxDhKeySz) {
        WOLFSSL_MSG("Server using a DH key that is too big");
        SendAlert(ssl, alert_fatal, handshake_failure);
        ERROR_OUT(DH_KEY_SIZE_E, exit_gdpk);
    }

    ssl->buffers.serverDH_P.buffer =
        (byte*)XMALLOC(length, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (ssl->buffers.serverDH_P.buffer) {
        ssl->buffers.serverDH_P.length = length;
    }
    else {
        ERROR_OUT(MEMORY_ERROR, exit_gdpk);
    }

    XMEMCPY(ssl->buffers.serverDH_P.buffer, input + args->idx,
                                                        length);
    args->idx += length;

    ssl->options.dhKeySz = length;

    /* g */
    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    ato16(input + args->idx, &length);
    args->idx += OPAQUE16_LEN;

    if ((args->idx - args->begin) + length > size) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    if (length > ssl->options.maxDhKeySz) {
        WOLFSSL_MSG("Server using a DH key generator that is too big");
        SendAlert(ssl, alert_fatal, handshake_failure);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        ERROR_OUT(DH_KEY_SIZE_E, exit_gdpk);
    }

    ssl->buffers.serverDH_G.buffer =
        (byte*)XMALLOC(length, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (ssl->buffers.serverDH_G.buffer) {
        ssl->buffers.serverDH_G.length = length;
    }
    else {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        ERROR_OUT(MEMORY_ERROR, exit_gdpk);
    }

    XMEMCPY(ssl->buffers.serverDH_G.buffer, input + args->idx,
                                                        length);
    args->idx += length;

    /* pub */
    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    ato16(input + args->idx, &length);
    args->idx += OPAQUE16_LEN;

    if ((args->idx - args->begin) + length > size) {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        ERROR_OUT(BUFFER_ERROR, exit_gdpk);
    }

    if (length > ssl->options.maxDhKeySz) {
        WOLFSSL_MSG("Server using a public DH key that is too big");
        SendAlert(ssl, alert_fatal, handshake_failure);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        ERROR_OUT(DH_KEY_SIZE_E, exit_gdpk);
    }

    ssl->buffers.serverDH_Pub.buffer =
        (byte*)XMALLOC(length, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    if (ssl->buffers.serverDH_Pub.buffer) {
        ssl->buffers.serverDH_Pub.length = length;
    }
    else {
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_P.buffer = NULL;
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap,
                DYNAMIC_TYPE_PUBLIC_KEY);
        ssl->buffers.serverDH_G.buffer = NULL;
        ERROR_OUT(MEMORY_ERROR, exit_gdpk);
    }

    XMEMCPY(ssl->buffers.serverDH_Pub.buffer, input + args->idx,
                                                        length);
    ssl->buffers.weOwnDH = 1;
    args->idx += length;

#ifdef HAVE_FFDHE
    switch (ssl->options.dhKeySz) {
    #ifdef HAVE_FFDHE_2048
        case 2048/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe2048_Get();
            #endif
            group = WOLFSSL_FFDHE_2048;
            break;
    #endif
    #ifdef HAVE_FFDHE_3072
        case 3072/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe3072_Get();
            #endif
            group = WOLFSSL_FFDHE_3072;
            break;
    #endif
    #ifdef HAVE_FFDHE_4096
        case 4096/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe4096_Get();
            #endif
            group = WOLFSSL_FFDHE_4096;
            break;
    #endif
    #ifdef HAVE_FFDHE_6144
        case 6144/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe6144_Get();
            #endif
            group = WOLFSSL_FFDHE_6144;
            break;
    #endif
    #ifdef HAVE_FFDHE_8192
        case 8192/8:
            #ifdef HAVE_PUBLIC_FFDHE
            params = wc_Dh_ffdhe8192_Get();
            #endif
            group = WOLFSSL_FFDHE_8192;
            break;
    #endif
        default:
            break;
    }


#ifdef HAVE_PUBLIC_FFDHE
    if (params == NULL || params->g_len != ssl->buffers.serverDH_G.length ||
            (XMEMCMP(ssl->buffers.serverDH_G.buffer, params->g,
                    params->g_len) != 0) ||
            (XMEMCMP(ssl->buffers.serverDH_P.buffer, params->p,
                    params->p_len) != 0))
#else
    if (!wc_DhCmpNamedKey(group, 1,
            ssl->buffers.serverDH_P.buffer, ssl->buffers.serverDH_P.length,
            ssl->buffers.serverDH_G.buffer, ssl->buffers.serverDH_G.length,
            NULL, 0))
#endif
    {
        WOLFSSL_MSG("Server not using FFDHE parameters");
    #ifdef WOLFSSL_REQUIRE_FFDHE
        SendAlert(ssl, alert_fatal, handshake_failure);
        ERROR_OUT(DH_PARAMS_NOT_FFDHE_E, exit_gdpk);
    #endif
    }
    else {
        ssl->namedGroup = group;
    #if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
        !defined(HAVE_SELFTEST)
        ssl->options.dhDoKeyTest = 0;
    #endif
    }
#endif /* HAVE_FFDHE */

exit_gdpk:
    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(ret);
    }
    return ret;
}
#endif

#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
	static int CheckCurveId(int tlsCurveId);
#endif

/* handle processing of server_key_exchange (12) */
static int DoServerKeyExchange(WOLFSSL* ssl, const byte* input,
                               word32* inOutIdx, word32 size)
{
    int ret = 0;
#ifdef WOLFSSL_ASYNC_CRYPT
    DskeArgs* args = NULL;
    WOLFSSL_ASSERT_SIZEOF_GE(ssl->async->args, *args);
#else
    DskeArgs  args[1];
#endif

    (void)input;
    (void)size;

    WOLFSSL_START(WC_FUNC_SERVER_KEY_EXCHANGE_DO);
    WOLFSSL_ENTER("DoServerKeyExchange");

#ifdef WOLFSSL_ASYNC_CRYPT
    if (ssl->async == NULL) {
        ssl->async = (struct WOLFSSL_ASYNC*)
                XMALLOC(sizeof(struct WOLFSSL_ASYNC), ssl->heap,
                        DYNAMIC_TYPE_ASYNC);
        if (ssl->async == NULL)
            ERROR_OUT(MEMORY_E, exit_dske);
    }
    args = (DskeArgs*)ssl->async->args;

    ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
    if (ret != WC_NOT_PENDING_E) {
        /* Check for error */
        if (ret < 0)
            goto exit_dske;
    }
    else
#endif
    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(DskeArgs));
        args->idx = *inOutIdx;
        args->begin = *inOutIdx;
        args->sigAlgo = ssl->specs.sig_algo;
        args->hashAlgo = sha_mac;
    #ifdef WOLFSSL_ASYNC_CRYPT
        ssl->async->freeArgs = FreeDskeArgs;
    #endif
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
        #ifdef WOLFSSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName(ssl, "ServerKeyExchange");
            if (ssl->toInfoOn)
                AddLateName("ServerKeyExchange", &ssl->timeoutInfo);
        #endif

            switch(ssl->specs.kea)
            {
            #ifndef NO_PSK
                case psk_kea:
                {
                    int srvHintLen;
                    word16 length;

                    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    ato16(input + args->idx, &length);
                    args->idx += OPAQUE16_LEN;

                    if ((args->idx - args->begin) + length > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    /* get PSK server hint from the wire */
                    srvHintLen = min(length, MAX_PSK_ID_LEN);
                    XMEMCPY(ssl->arrays->server_hint, input + args->idx,
                                                                    srvHintLen);
                    ssl->arrays->server_hint[srvHintLen] = '\0'; /* null term */
                    args->idx += length;
                    break;
                }
            #endif /* !NO_PSK */
            #ifndef NO_DH
                case diffie_hellman_kea:
                {
                    ret = GetDhPublicKey(ssl, input, size, args);
                    if (ret != 0)
                        goto exit_dske;
                    break;
                }
            #endif /* !NO_DH */

            #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                case ecc_diffie_hellman_kea:
                {
                    byte b;
                #ifdef HAVE_ECC
                    int curveId;
                #endif
                    int curveOid;
                    word16 length;

                    if ((args->idx - args->begin) + ENUM_LEN + OPAQUE16_LEN +
                                                        OPAQUE8_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    b = input[args->idx++];
                    if (b != named_curve) {
                        ERROR_OUT(ECC_CURVETYPE_ERROR, exit_dske);
                    }

                    args->idx += 1;   /* curve type, eat leading 0 */
                    b = input[args->idx++];
                    if ((curveOid = CheckCurveId(b)) < 0) {
                        ERROR_OUT(ECC_CURVE_ERROR, exit_dske);
                    }
                    ssl->ecdhCurveOID = curveOid;
                #if defined(WOLFSSL_TLS13) || defined(HAVE_FFDHE)
                    ssl->namedGroup = 0;
                #endif

                    length = input[args->idx++];
                    if ((args->idx - args->begin) + length > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                #ifdef HAVE_CURVE25519
                    if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                        if (ssl->peerX25519Key == NULL) {
                            ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                           (void**)&ssl->peerX25519Key);
                            if (ret != 0) {
                                goto exit_dske;
                            }
                        } else if (ssl->peerX25519KeyPresent) {
                            ret = ReuseKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                           ssl->peerX25519Key);
                            ssl->peerX25519KeyPresent = 0;
                            if (ret != 0) {
                                goto exit_dske;
                            }
                        }

                        if ((ret = wc_curve25519_check_public(
                                input + args->idx, length,
                                EC25519_LITTLE_ENDIAN)) != 0) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                            if (ret == BUFFER_E)
                                SendAlert(ssl, alert_fatal, decode_error);
                            else if (ret == ECC_OUT_OF_RANGE_E)
                                SendAlert(ssl, alert_fatal, bad_record_mac);
                            else {
                                SendAlert(ssl, alert_fatal, illegal_parameter);
                            }
                        #endif
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                        }

                        if (wc_curve25519_import_public_ex(input + args->idx,
                                length, ssl->peerX25519Key,
                                EC25519_LITTLE_ENDIAN) != 0) {
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                        }

                        args->idx += length;
                        ssl->peerX25519KeyPresent = 1;
                        break;
                    }
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->ecdhCurveOID == ECC_X448_OID) {
                        if (ssl->peerX448Key == NULL) {
                            ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE448,
                                           (void**)&ssl->peerX448Key);
                            if (ret != 0) {
                                goto exit_dske;
                            }
                        } else if (ssl->peerX448KeyPresent) {
                            ret = ReuseKey(ssl, DYNAMIC_TYPE_CURVE448,
                                           ssl->peerX448Key);
                            ssl->peerX448KeyPresent = 0;
                            if (ret != 0) {
                                goto exit_dske;
                            }
                        }

                        if ((ret = wc_curve448_check_public(
                                input + args->idx, length,
                                EC448_LITTLE_ENDIAN)) != 0) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                            if (ret == BUFFER_E)
                                SendAlert(ssl, alert_fatal, decode_error);
                            else if (ret == ECC_OUT_OF_RANGE_E)
                                SendAlert(ssl, alert_fatal, bad_record_mac);
                            else {
                                SendAlert(ssl, alert_fatal, illegal_parameter);
                            }
                        #endif
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                        }

                        if (wc_curve448_import_public_ex(input + args->idx,
                                length, ssl->peerX448Key,
                                EC448_LITTLE_ENDIAN) != 0) {
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                        }

                        args->idx += length;
                        ssl->peerX448KeyPresent = 1;
                        break;
                    }
                #endif
                #ifdef HAVE_ECC
                    if (ssl->peerEccKey == NULL) {
                        ret = AllocKey(ssl, DYNAMIC_TYPE_ECC,
                                       (void**)&ssl->peerEccKey);
                        if (ret != 0) {
                            goto exit_dske;
                        }
                    } else if (ssl->peerEccKeyPresent) {
                        ret = ReuseKey(ssl, DYNAMIC_TYPE_ECC, ssl->peerEccKey);
                        ssl->peerEccKeyPresent = 0;
                        if (ret != 0) {
                            goto exit_dske;
                        }
                    }

                    curveId = wc_ecc_get_oid(curveOid, NULL, NULL);
                    if (wc_ecc_import_x963_ex(input + args->idx, length,
                                        ssl->peerEccKey, curveId) != 0) {
                    #ifdef WOLFSSL_EXTRA_ALERTS
                        SendAlert(ssl, alert_fatal, illegal_parameter);
                    #endif
                        ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                    }

                    args->idx += length;
                    ssl->peerEccKeyPresent = 1;
                #endif
                    break;
                }
            #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
            #if !defined(NO_DH) && !defined(NO_PSK)
                case dhe_psk_kea:
                {
                    int srvHintLen;
                    word16 length;

                    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    ato16(input + args->idx, &length);
                    args->idx += OPAQUE16_LEN;

                    if ((args->idx - args->begin) + length > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    /* get PSK server hint from the wire */
                    srvHintLen = min(length, MAX_PSK_ID_LEN);
                    XMEMCPY(ssl->arrays->server_hint, input + args->idx,
                                                                srvHintLen);
                    ssl->arrays->server_hint[srvHintLen] = '\0'; /* null term */
                    args->idx += length;

                    ret = GetDhPublicKey(ssl, input, size, args);
                    if (ret != 0)
                        goto exit_dske;
                    break;
                }
            #endif /* !NO_DH && !NO_PSK */
            #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                case ecdhe_psk_kea:
                {
                    byte b;
                    int curveOid, curveId;
                    int srvHintLen;
                    word16 length;

                    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    ato16(input + args->idx, &length);
                    args->idx += OPAQUE16_LEN;

                    if ((args->idx - args->begin) + length > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    /* get PSK server hint from the wire */
                    srvHintLen = min(length, MAX_PSK_ID_LEN);
                    XMEMCPY(ssl->arrays->server_hint, input + args->idx,
                                                                    srvHintLen);
                    ssl->arrays->server_hint[srvHintLen] = '\0'; /* null term */

                    args->idx += length;

                    if ((args->idx - args->begin) + ENUM_LEN + OPAQUE16_LEN +
                        OPAQUE8_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    /* Check curve name and ID */
                    b = input[args->idx++];
                    if (b != named_curve) {
                        ERROR_OUT(ECC_CURVETYPE_ERROR, exit_dske);
                    }

                    args->idx += 1;   /* curve type, eat leading 0 */
                    b = input[args->idx++];
                    if ((curveOid = CheckCurveId(b)) < 0) {
                        ERROR_OUT(ECC_CURVE_ERROR, exit_dske);
                    }

                    length = input[args->idx++];
                    if ((args->idx - args->begin) + length > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                #ifdef HAVE_CURVE25519
                    if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                        if (ssl->peerX25519Key == NULL) {
                            ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                           (void**)&ssl->peerX25519Key);
                            if (ret != 0) {
                                goto exit_dske;
                            }
                        } else if (ssl->peerEccKeyPresent) {
                            ret = ReuseKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                           ssl->peerX25519Key);
                            ssl->peerX25519KeyPresent = 0;
                            if (ret != 0) {
                                goto exit_dske;
                            }
                        }

                        if ((ret = wc_curve25519_check_public(
                                input + args->idx, length,
                                EC25519_LITTLE_ENDIAN)) != 0) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                            if (ret == BUFFER_E)
                                SendAlert(ssl, alert_fatal, decode_error);
                            else if (ret == ECC_OUT_OF_RANGE_E)
                                SendAlert(ssl, alert_fatal, bad_record_mac);
                            else {
                                SendAlert(ssl, alert_fatal, illegal_parameter);
                            }
                        #endif
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                        }

                        if (wc_curve25519_import_public_ex(input + args->idx,
                                length, ssl->peerX25519Key,
                                EC25519_LITTLE_ENDIAN) != 0) {
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                        }

                        args->idx += length;
                        ssl->peerX25519KeyPresent = 1;
                        break;
                    }
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->ecdhCurveOID == ECC_X448_OID) {
                        if (ssl->peerX448Key == NULL) {
                            ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE448,
                                           (void**)&ssl->peerX448Key);
                            if (ret != 0) {
                                goto exit_dske;
                            }
                        } else if (ssl->peerEccKeyPresent) {
                            ret = ReuseKey(ssl, DYNAMIC_TYPE_CURVE448,
                                           ssl->peerX448Key);
                            ssl->peerX448KeyPresent = 0;
                            if (ret != 0) {
                                goto exit_dske;
                            }
                        }

                        if ((ret = wc_curve448_check_public(
                                input + args->idx, length,
                                EC448_LITTLE_ENDIAN)) != 0) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                            if (ret == BUFFER_E)
                                SendAlert(ssl, alert_fatal, decode_error);
                            else if (ret == ECC_OUT_OF_RANGE_E)
                                SendAlert(ssl, alert_fatal, bad_record_mac);
                            else {
                                SendAlert(ssl, alert_fatal, illegal_parameter);
                            }
                        #endif
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                        }

                        if (wc_curve448_import_public_ex(input + args->idx,
                                length, ssl->peerX448Key,
                                EC448_LITTLE_ENDIAN) != 0) {
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                        }

                        args->idx += length;
                        ssl->peerX448KeyPresent = 1;
                        break;
                    }
                #endif

                    if (ssl->peerEccKey == NULL) {
                        ret = AllocKey(ssl, DYNAMIC_TYPE_ECC,
                                 (void**)&ssl->peerEccKey);
                        if (ret != 0) {
                            goto exit_dske;
                        }
                    } else if (ssl->peerEccKeyPresent) {
                        ret = ReuseKey(ssl, DYNAMIC_TYPE_ECC, ssl->peerEccKey);
                        ssl->peerEccKeyPresent = 0;
                        if (ret != 0) {
                            goto exit_dske;
                        }
                    }

                    curveId = wc_ecc_get_oid(curveOid, NULL, NULL);
                    if (wc_ecc_import_x963_ex(input + args->idx, length,
                        ssl->peerEccKey, curveId) != 0) {
                        ERROR_OUT(ECC_PEERKEY_ERROR, exit_dske);
                    }

                    args->idx += length;
                    ssl->peerEccKeyPresent = 1;
                    break;
                }
            #endif /* (HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448) && !NO_PSK */
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;

        case TLS_ASYNC_BUILD:
        {
            switch(ssl->specs.kea)
            {
                case psk_kea:
                case dhe_psk_kea:
                case ecdhe_psk_kea:
                {
                    /* Nothing to do in this sub-state */
                    break;
                }

                case diffie_hellman_kea:
                case ecc_diffie_hellman_kea:
                {
            #if defined(NO_DH) && !defined(HAVE_ECC) && \
                            !defined(HAVE_CURVE25519) && !defined(HAVE_CURVE448)
                    ERROR_OUT(NOT_COMPILED_IN, exit_dske);
            #else
                    enum wc_HashType hashType;
                    word16 verifySz;
                    byte sigAlgo;

                    if (ssl->options.usingAnon_cipher) {
                        break;
                    }

                    verifySz = (word16)(args->idx - args->begin);
                    if (verifySz > MAX_DH_SZ) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    if (IsAtLeastTLSv1_2(ssl)) {
                        if ((args->idx - args->begin) + ENUM_LEN + ENUM_LEN >
                                                                        size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dske);
                        }

                        DecodeSigAlg(&input[args->idx], &args->hashAlgo,
                                     &sigAlgo);
                    #ifndef NO_RSA
                        if (sigAlgo == rsa_pss_sa_algo &&
                                                 args->sigAlgo == rsa_sa_algo) {
                            args->sigAlgo = sigAlgo;
                        }
                        else
                    #endif
                    #ifdef HAVE_ED25519
                        if (sigAlgo == ed25519_sa_algo &&
                                             args->sigAlgo == ecc_dsa_sa_algo) {
                            args->sigAlgo = sigAlgo;
                        }
                        else
                    #endif
                    #ifdef HAVE_ED448
                        if (sigAlgo == ed448_sa_algo &&
                                             args->sigAlgo == ecc_dsa_sa_algo) {
                            args->sigAlgo = sigAlgo;
                        }
                        else
                    #endif
                        /* Signature algorithm from message must match signature
                         * algorithm in cipher suite. */
                        if (sigAlgo != args->sigAlgo) {
                            ERROR_OUT(ALGO_ID_E, exit_dske);
                        }
                        args->idx += 2;
                        hashType = HashAlgoToType(args->hashAlgo);
                        if (hashType == WC_HASH_TYPE_NONE) {
                            ERROR_OUT(ALGO_ID_E, exit_dske);
                        }
                    } else {
                        /* only using sha and md5 for rsa */
                        #ifndef NO_OLD_TLS
                            hashType = WC_HASH_TYPE_SHA;
                            if (args->sigAlgo == rsa_sa_algo) {
                                hashType = WC_HASH_TYPE_MD5_SHA;
                            }
                        #else
                            ERROR_OUT(ALGO_ID_E, exit_dske);
                        #endif
                    }

                    /* signature */
                    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    ato16(input + args->idx, &args->verifySigSz);
                    args->idx += OPAQUE16_LEN;

                    if ((args->idx - args->begin) + args->verifySigSz > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    ret = HashSkeData(ssl, hashType, input + args->begin,
                        verifySz, args->sigAlgo);
                    if (ret != 0) {
                        goto exit_dske;
                    }

                    switch (args->sigAlgo)
                    {
                    #ifndef NO_RSA
                    #ifdef WC_RSA_PSS
                        case rsa_pss_sa_algo:
                    #endif
                        case rsa_sa_algo:
                        {
                            if (ssl->peerRsaKey == NULL ||
                                                    !ssl->peerRsaKeyPresent) {
                                ERROR_OUT(NO_PEER_KEY, exit_dske);
                            }
                            break;
                        }
                    #endif /* !NO_RSA */
                    #ifdef HAVE_ECC
                        case ecc_dsa_sa_algo:
                        {
                            if (!ssl->peerEccDsaKeyPresent) {
                                ERROR_OUT(NO_PEER_KEY, exit_dske);
                            }
                            break;
                        }
                    #endif /* HAVE_ECC */
                    #if defined(HAVE_ED25519)
                        case ed25519_sa_algo:
                        {
                            if (!ssl->peerEd25519KeyPresent) {
                                ERROR_OUT(NO_PEER_KEY, exit_dske);
                            }
                            break;
                        }
                    #endif /* HAVE_ED25519 */
                    #if defined(HAVE_ED448)
                        case ed448_sa_algo:
                        {
                            if (!ssl->peerEd448KeyPresent) {
                                ERROR_OUT(NO_PEER_KEY, exit_dske);
                            }
                            break;
                        }
                    #endif /* HAVE_ED448 */

                    default:
                        ret = ALGO_ID_E;
                    } /* switch (args->sigAlgo) */

            #endif /* NO_DH && !HAVE_ECC && !HAVE_ED25519 && !HAVE_ED448 */
                    break;
                }
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */
        FALL_THROUGH;

        case TLS_ASYNC_DO:
        {
            switch(ssl->specs.kea)
            {
                case psk_kea:
                case dhe_psk_kea:
                case ecdhe_psk_kea:
                {
                    /* Nothing to do in this sub-state */
                    break;
                }

                case diffie_hellman_kea:
                case ecc_diffie_hellman_kea:
                {
            #if defined(NO_DH) && !defined(HAVE_ECC) && \
                            !defined(HAVE_CURVE25519) && !defined(HAVE_CURVE448)
                    ERROR_OUT(NOT_COMPILED_IN, exit_dske);
            #else
                    if (ssl->options.usingAnon_cipher) {
                        break;
                    }

                    if (args->verifySig == NULL) {
                        args->verifySig = (byte*)XMALLOC(args->verifySigSz,
                                            ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                        if (args->verifySig == NULL) {
                            ERROR_OUT(MEMORY_E, exit_dske);
                        }
                        XMEMCPY(args->verifySig, input + args->idx,
                                                            args->verifySigSz);
                    }

                    switch (args->sigAlgo)
                    {
                    #ifndef NO_RSA
                    #ifdef WC_RSA_PSS
                        case rsa_pss_sa_algo:
                    #endif
                        case rsa_sa_algo:
                        {
                            ret = RsaVerify(ssl,
                                args->verifySig, args->verifySigSz,
                                &args->output,
                                args->sigAlgo, args->hashAlgo,
                                ssl->peerRsaKey,
                            #ifdef HAVE_PK_CALLBACKS
                                &ssl->buffers.peerRsaKey
                            #else
                                NULL
                            #endif
                            );

                            if (ret >= 0) {
                                args->sigSz = (word16)ret;
                            #ifdef WC_RSA_PSS
                                args->bits = mp_count_bits(&ssl->peerRsaKey->n);
                            #endif
                                ret = 0;
                            }
                        #ifdef WOLFSSL_ASYNC_CRYPT
                            if (ret != WC_PENDING_E)
                        #endif
                            {
                                /* peerRsaKey */
                                FreeKey(ssl, DYNAMIC_TYPE_RSA,
                                                      (void**)&ssl->peerRsaKey);
                                ssl->peerRsaKeyPresent = 0;
                            }
                            break;
                        }
                    #endif /* !NO_RSA */
                    #ifdef HAVE_ECC
                        case ecc_dsa_sa_algo:
                        {
                            ret = NOT_COMPILED_IN;
                        #ifdef HAVE_PK_CALLBACKS
                            if (ssl->ctx && ssl->ctx->ProcessServerSigKexCb) {
                                ret = ssl->ctx->ProcessServerSigKexCb(ssl,
                                    args->sigAlgo,
                                    args->verifySig, args->verifySigSz,
                                    ssl->buffers.sig.buffer, SEED_LEN,
                                    &ssl->buffers.sig.buffer[SEED_LEN],
                                    (ssl->buffers.sig.length - SEED_LEN));
                            }
                        #endif /* HAVE_PK_CALLBACKS */
                            if (ret == NOT_COMPILED_IN) {
                                ret = EccVerify(ssl,
                                    args->verifySig, args->verifySigSz,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    ssl->peerEccDsaKey,
                                #ifdef HAVE_PK_CALLBACKS
                                    &ssl->buffers.peerEccDsaKey
                                #else
                                    NULL
                                #endif
                                );
                            }

                        #ifdef WOLFSSL_ASYNC_CRYPT
                            if (ret != WC_PENDING_E)
                        #endif
                            {
                                /* peerEccDsaKey */
                                FreeKey(ssl, DYNAMIC_TYPE_ECC,
                                                   (void**)&ssl->peerEccDsaKey);
                                ssl->peerEccDsaKeyPresent = 0;
                            }
                            /* CLIENT: Data verified with cert's public key. */
                            ssl->options.peerAuthGood =
                                ssl->options.havePeerCert && (ret == 0);
                            break;
                        }
                    #endif /* HAVE_ECC */
                    #if defined(HAVE_ED25519)
                        case ed25519_sa_algo:
                        {
                            ret = Ed25519Verify(ssl,
                                args->verifySig, args->verifySigSz,
                                ssl->buffers.sig.buffer,
                                ssl->buffers.sig.length,
                                ssl->peerEd25519Key,
                            #ifdef HAVE_PK_CALLBACKS
                                &ssl->buffers.peerEd25519Key
                            #else
                                NULL
                            #endif
                            );

                        #ifdef WOLFSSL_ASYNC_CRYPT
                            if (ret != WC_PENDING_E)
                        #endif
                            {
                                /* peerEccDsaKey */
                                FreeKey(ssl, DYNAMIC_TYPE_ED25519,
                                                  (void**)&ssl->peerEd25519Key);
                                ssl->peerEd25519KeyPresent = 0;
                            }
                            /* CLIENT: Data verified with cert's public key. */
                            ssl->options.peerAuthGood =
                                ssl->options.havePeerCert && (ret == 0);
                            break;
                        }
                    #endif /* HAVE_ED25519 */
                    #if defined(HAVE_ED448)
                        case ed448_sa_algo:
                        {
                            ret = Ed448Verify(ssl,
                                args->verifySig, args->verifySigSz,
                                ssl->buffers.sig.buffer,
                                ssl->buffers.sig.length,
                                ssl->peerEd448Key,
                            #ifdef HAVE_PK_CALLBACKS
                                &ssl->buffers.peerEd448Key
                            #else
                                NULL
                            #endif
                            );

                        #ifdef WOLFSSL_ASYNC_CRYPT
                            if (ret != WC_PENDING_E)
                        #endif
                            {
                                /* peerEccDsaKey */
                                FreeKey(ssl, DYNAMIC_TYPE_ED448,
                                                    (void**)&ssl->peerEd448Key);
                                ssl->peerEd448KeyPresent = 0;
                            }
                            /* CLIENT: Data verified with cert's public key. */
                            ssl->options.peerAuthGood =
                                ssl->options.havePeerCert && (ret == 0);
                            break;
                        }
                    #endif /* HAVE_ED448 */

                    default:
                        ret = ALGO_ID_E;
                    } /* switch (sigAlgo) */
            #endif /* NO_DH && !HAVE_ECC && !HAVE_ED25519 && !HAVE_ED448 */
                    break;
                }
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */
        FALL_THROUGH;

        case TLS_ASYNC_VERIFY:
        {
            switch(ssl->specs.kea)
            {
                case psk_kea:
                case dhe_psk_kea:
                case ecdhe_psk_kea:
                {
                    /* Nothing to do in this sub-state */
                    break;
                }

                case diffie_hellman_kea:
                case ecc_diffie_hellman_kea:
                {
            #if defined(NO_DH) && !defined(HAVE_ECC) && \
                            !defined(HAVE_CURVE25519) && !defined(HAVE_CURVE448)
                    ERROR_OUT(NOT_COMPILED_IN, exit_dske);
            #else
                    if (ssl->options.usingAnon_cipher) {
                        break;
                    }

                    /* increment index after verify is done */
                    args->idx += args->verifySigSz;

                    switch(args->sigAlgo)
                    {
                    #ifndef NO_RSA
                    #ifdef WC_RSA_PSS
                        case rsa_pss_sa_algo:
                        #ifdef HAVE_SELFTEST
                            ret = wc_RsaPSS_CheckPadding(
                                             ssl->buffers.digest.buffer,
                                             ssl->buffers.digest.length,
                                             args->output, args->sigSz,
                                             HashAlgoToType(args->hashAlgo));
                        #else
                            ret = wc_RsaPSS_CheckPadding_ex(
                                             ssl->buffers.digest.buffer,
                                             ssl->buffers.digest.length,
                                             args->output, args->sigSz,
                                             HashAlgoToType(args->hashAlgo),
                                             -1, args->bits);
                        #endif
                            if (ret != 0)
                                goto exit_dske;
                            /* CLIENT: Data verified with cert's public key. */
                            ssl->options.peerAuthGood =
                                ssl->options.havePeerCert;
                            break;
                    #endif
                        case rsa_sa_algo:
                        {
                            #if (defined(WOLFSSL_RENESAS_SCEPROTECT) && \
                                defined(WOLFSSL_RENESAS_SCEPROTECT_ECC)) || \
                                defined(WOLFSSL_RENESAS_TSIP_TLS)
                            /* already checked signature result by SCE */
                            /* skip the sign checks below              */
                            if (Renesas_cmn_usable(ssl, 0)) {
                                break;
                             }
                            #endif
                            if (IsAtLeastTLSv1_2(ssl)) {
                            #ifdef WOLFSSL_SMALL_STACK
                                byte*  encodedSig;
                            #else
                                byte   encodedSig[MAX_ENCODED_SIG_SZ];
                            #endif
                                word32 encSigSz;

                            #ifdef WOLFSSL_SMALL_STACK
                                encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ,
                                                ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                                if (encodedSig == NULL) {
                                    ERROR_OUT(MEMORY_E, exit_dske);
                                }
                            #endif

                                encSigSz = wc_EncodeSignature(encodedSig,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    TypeHash(args->hashAlgo));
                                if (encSigSz != args->sigSz || !args->output ||
                                    XMEMCMP(args->output, encodedSig,
                                            min(encSigSz, MAX_ENCODED_SIG_SZ)) != 0) {
                                    ret = VERIFY_SIGN_ERROR;
                                }
                            #ifdef WOLFSSL_SMALL_STACK
                                XFREE(encodedSig, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                            #endif
                                if (ret != 0) {
                                    goto exit_dske;
                                }
                            }
                            else if (args->sigSz != FINISHED_SZ ||
                                    !args->output ||
                                    XMEMCMP(args->output,
                                            ssl->buffers.digest.buffer,
                                            FINISHED_SZ) != 0) {
                                ERROR_OUT(VERIFY_SIGN_ERROR, exit_dske);
                            }
                            /* CLIENT: Data verified with cert's public key. */
                            ssl->options.peerAuthGood =
                                ssl->options.havePeerCert;
                            break;
                        }
                    #endif /* !NO_RSA */
                    #ifdef HAVE_ECC
                        case ecc_dsa_sa_algo:
                            /* Nothing to do in this algo */
                            break;
                    #endif /* HAVE_ECC */
                    #if defined(HAVE_ED25519)
                        case ed25519_sa_algo:
                            /* Nothing to do in this algo */
                            break;
                    #endif /* HAVE_ED25519 */
                    #if defined(HAVE_ED448)
                        case ed448_sa_algo:
                            /* Nothing to do in this algo */
                            break;
                    #endif /* HAVE_ED448 */
                        default:
                            ret = ALGO_ID_E;
                    } /* switch (sigAlgo) */
            #endif /* NO_DH && !HAVE_ECC && !HAVE_ED25519 && !HAVE_ED448 */
                    break;
                }
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */
        FALL_THROUGH;

        case TLS_ASYNC_FINALIZE:
        {
            if (IsEncryptionOn(ssl, 0)) {
                args->idx += ssl->keys.padSz;
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                if (ssl->options.startedETMRead)
                    args->idx += MacSize(ssl);
            #endif
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            /* return index */
            *inOutIdx = args->idx;

            ssl->options.serverState = SERVER_KEYEXCHANGE_COMPLETE;
            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_dske:

    WOLFSSL_LEAVE("DoServerKeyExchange", ret);
    WOLFSSL_END(WC_FUNC_SERVER_KEY_EXCHANGE_DO);

#ifdef WOLFSSL_ASYNC_CRYPT
    /* Handle async operation */
    if (ret == WC_PENDING_E) {
        /* Mark message as not received so it can process again */
        ssl->msgsReceived.got_server_key_exchange = 0;

        return ret;
    }
    /* Cleanup async */
    FreeAsyncCtx(ssl, 0);
#else
    FreeDskeArgs(ssl, args);
#endif /* WOLFSSL_ASYNC_CRYPT */

    /* Final cleanup */
    FreeKeyExchange(ssl);

    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(ret);
    }
    return ret;
}


////////////////////////////////// >>>


#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)

    static int CheckCurveId(int tlsCurveId)
    {
        int ret = ECC_CURVE_ERROR;

        switch (tlsCurveId) {
    #if (defined(HAVE_ECC160) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 160
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP160R1: return ECC_SECP160R1_OID;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_SECPR2
            case WOLFSSL_ECC_SECP160R2: return ECC_SECP160R2_OID;
        #endif /* HAVE_ECC_SECPR2 */
        #ifdef HAVE_ECC_KOBLITZ
            case WOLFSSL_ECC_SECP160K1: return ECC_SECP160K1_OID;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
    #if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 192
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP192R1: return ECC_SECP192R1_OID;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case WOLFSSL_ECC_SECP192K1: return ECC_SECP192K1_OID;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
    #if (defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 224
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP224R1: return ECC_SECP224R1_OID;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case WOLFSSL_ECC_SECP224K1: return ECC_SECP224K1_OID;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
        #if defined(HAVE_CURVE25519) && ECC_MIN_KEY_SZ <= 256
            case WOLFSSL_ECC_X25519: return ECC_X25519_OID;
        #endif
    #if (!defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 256
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP256R1: return ECC_SECP256R1_OID;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case WOLFSSL_ECC_SECP256K1: return ECC_SECP256K1_OID;
        #endif /* HAVE_ECC_KOBLITZ */
        #ifdef HAVE_ECC_BRAINPOOL
            case WOLFSSL_ECC_BRAINPOOLP256R1: return ECC_BRAINPOOLP256R1_OID;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
        #if defined(HAVE_CURVE448) && ECC_MIN_KEY_SZ <= 448
            case WOLFSSL_ECC_X448: return ECC_X448_OID;
        #endif
    #if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP384R1: return ECC_SECP384R1_OID;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_BRAINPOOL
            case WOLFSSL_ECC_BRAINPOOLP384R1: return ECC_BRAINPOOLP384R1_OID;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
    #if (defined(HAVE_ECC512) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 512
        #ifdef HAVE_ECC_BRAINPOOL
            case WOLFSSL_ECC_BRAINPOOLP512R1: return ECC_BRAINPOOLP512R1_OID;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
    #if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
        #ifndef NO_ECC_SECP
            case WOLFSSL_ECC_SECP521R1: return ECC_SECP521R1_OID;
        #endif /* !NO_ECC_SECP */
    #endif
            default: break;
        }

        return ret;
    }

#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

////////////////////////////////// >>>


#undef ERROR_OUT

#endif /* WOLFCRYPT_ONLY */
