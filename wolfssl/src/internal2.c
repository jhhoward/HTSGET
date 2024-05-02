///////////////////// FORKED FROM internal.c

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>


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

//////////////////////////// <body>

//////////////////////////////

#ifndef WOLFSSL_NO_TLS12

#ifndef NO_CERTS




#ifndef NO_WOLFSSL_SERVER
#if defined(HAVE_CERTIFICATE_STATUS_REQUEST) \
 || defined(HAVE_CERTIFICATE_STATUS_REQUEST_V2)
static int BuildCertificateStatus(WOLFSSL* ssl, byte type, buffer* status,
                                                                     byte count)
{
    byte*  output  = NULL;
    word32 idx     = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    word32 length  = ENUM_LEN;
    int    sendSz  = 0;
    int    ret     = 0;
    int    i       = 0;

    WOLFSSL_ENTER("BuildCertificateStatus");

    switch (type) {
        case WOLFSSL_CSR2_OCSP_MULTI:
            length += OPAQUE24_LEN;
            FALL_THROUGH; /* followed by */

        case WOLFSSL_CSR2_OCSP:
            for (i = 0; i < count; i++)
                length += OPAQUE24_LEN + status[i].length;
        break;

        default:
            return 0;
    }

    sendSz = idx + length;

    if (ssl->keys.encryptionOn)
        sendSz += MAX_MSG_EXTRA;

    /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
     * is not advanced yet */
    ssl->options.buildingMsg = 1;

    if ((ret = CheckAvailableSize(ssl, sendSz)) == 0) {
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, length, certificate_status, ssl);

        output[idx++] = type;

        if (type == WOLFSSL_CSR2_OCSP_MULTI) {
            c32to24(length - (ENUM_LEN + OPAQUE24_LEN), output + idx);
            idx += OPAQUE24_LEN;
        }

        for (i = 0; i < count; i++) {
            c32to24(status[i].length, output + idx);
            idx += OPAQUE24_LEN;

            XMEMCPY(output + idx, status[i].buffer, status[i].length);
            idx += status[i].length;
        }

        if (IsEncryptionOn(ssl, 1)) {
            byte* input;
            int   inputSz = idx; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls)
                recordHeaderSz += DTLS_RECORD_EXTRA;
            inputSz -= recordHeaderSz;
            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            #ifdef WOLFSSL_DTLS
                ret = DtlsMsgPoolSave(ssl, input, inputSz, certificate_status);
            #endif
            if (ret == 0)
                sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                      handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                ret = sendSz;
        }
        else {
            #ifdef WOLFSSL_DTLS
                if (ret == 0 && IsDtlsNotSctpMode(ssl))
                    ret = DtlsMsgPoolSave(ssl, output, sendSz, certificate_status);
                if (ret == 0 && ssl->options.dtls)
                    DtlsSEQIncrement(ssl, CUR_ORDER);
            #endif
            ret = HashOutput(ssl, output, sendSz, 0);
        }

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ret == 0 && ssl->hsInfoOn)
            AddPacketName(ssl, "CertificateStatus");
        if (ret == 0 && ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "CertificateStatus", handshake, output,
                    sendSz, WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
    #endif

        if (ret == 0) {
            ssl->options.buildingMsg = 0;
            ssl->buffers.outputBuffer.length += sendSz;
            if (!ssl->options.groupMessages)
                ret = SendBuffered(ssl);
        }
    }

    WOLFSSL_LEAVE("BuildCertificateStatus", ret);
    return ret;
}
#endif
#endif /* NO_WOLFSSL_SERVER */

/* handle generation of certificate_request (13) */
int SendCertificateRequest(WOLFSSL* ssl)
{
    byte   *output;
    int    ret;
    int    sendSz;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    word32 dnLen = 0;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
    WOLF_STACK_OF(WOLFSSL_X509_NAME)* names;
#endif

    int  typeTotal = 1;  /* only 1 for now */
    int  reqSz = ENUM_LEN + typeTotal + REQ_HEADER_SZ;  /* add auth later */

    WOLFSSL_START(WC_FUNC_CERTIFICATE_REQUEST_SEND);
    WOLFSSL_ENTER("SendCertificateRequest");

    if (IsAtLeastTLSv1_2(ssl))
        reqSz += LENGTH_SZ + ssl->suites->hashSigAlgoSz;

#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
    /* Certificate Authorities */
    names = SSL_CA_NAMES(ssl);
    while (names != NULL) {
        byte seq[MAX_SEQ_SZ];
        WOLFSSL_X509_NAME* name = names->data.name;

        if (name != NULL) {
            /* 16-bit length | SEQ | Len | DER of name */
            dnLen += OPAQUE16_LEN + SetSequence(name->rawLen, seq) +
                        name->rawLen;
        }
        names = names->next;
    }
    reqSz += dnLen;
#endif

    if (ssl->options.usingPSK_cipher || ssl->options.usingAnon_cipher)
        return 0;  /* not needed */

    sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + reqSz;

    if (!ssl->options.dtls) {
        if (IsEncryptionOn(ssl, 1))
            sendSz += MAX_MSG_EXTRA;
    }
    else {
    #ifdef WOLFSSL_DTLS
        sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
        i      += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
    #endif
    }

    if (IsEncryptionOn(ssl, 1))
        sendSz += cipherExtraData(ssl);

    /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
     * is not advanced yet */
    ssl->options.buildingMsg = 1;

    /* check for available size */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    AddHeaders(output, reqSz, certificate_request, ssl);

    /* write to output */
    output[i++] = (byte)typeTotal;  /* # of types */
#ifdef HAVE_ECC
    if ((ssl->options.cipherSuite0 == ECC_BYTE ||
         ssl->options.cipherSuite0 == CHACHA_BYTE) &&
                     ssl->specs.sig_algo == ecc_dsa_sa_algo) {
        output[i++] = ecdsa_sign;
    } else
#endif /* HAVE_ECC */
    {
        output[i++] = rsa_sign;
    }

    /* supported hash/sig */
    if (IsAtLeastTLSv1_2(ssl)) {
        c16toa(ssl->suites->hashSigAlgoSz, &output[i]);
        i += OPAQUE16_LEN;

        XMEMCPY(&output[i],
                         ssl->suites->hashSigAlgo, ssl->suites->hashSigAlgoSz);
        i += ssl->suites->hashSigAlgoSz;
    }

    /* Certificate Authorities */
    c16toa((word16)dnLen, &output[i]);  /* auth's */
    i += REQ_HEADER_SZ;
#if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(HAVE_LIGHTY)
    names = SSL_CA_NAMES(ssl);
    while (names != NULL) {
        byte seq[MAX_SEQ_SZ];
        WOLFSSL_X509_NAME* name = names->data.name;

        if (name != NULL) {
            c16toa((word16)name->rawLen +
                   (word16)SetSequence(name->rawLen, seq), &output[i]);
            i += OPAQUE16_LEN;
            i += SetSequence(name->rawLen, output + i);
            XMEMCPY(output + i, name->raw, name->rawLen);
            i += name->rawLen;
        }
        names = names->next;
    }
#endif
    (void)i;

        if (IsEncryptionOn(ssl, 1)) {
            byte* input = NULL;
            int   inputSz = i; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls)
                recordHeaderSz += DTLS_RECORD_EXTRA;
            inputSz -= recordHeaderSz;

            if (inputSz <= 0) {
                WOLFSSL_MSG("Send Cert Req bad inputSz");
                return BUFFER_E;
            }

            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            #ifdef WOLFSSL_DTLS
            if (IsDtlsNotSctpMode(ssl) &&
                    (ret = DtlsMsgPoolSave(ssl, input, inputSz, certificate_request)) != 0) {
                XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                return ret;
            }
            #endif
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        } else {
            sendSz = i;
            #ifdef WOLFSSL_DTLS
                if (IsDtlsNotSctpMode(ssl)) {
                    if ((ret = DtlsMsgPoolSave(ssl, output, sendSz, certificate_request)) != 0)
                        return ret;
                }
                if (ssl->options.dtls)
                    DtlsSEQIncrement(ssl, CUR_ORDER);
            #endif
            ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0)
                return ret;
        }

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "CertificateRequest");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "CertificateRequest", handshake, output,
                    sendSz, WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
    #endif
    ssl->buffers.outputBuffer.length += sendSz;
    if (ssl->options.groupMessages)
        ret = 0;
    else
        ret = SendBuffered(ssl);

    ssl->options.buildingMsg = 0;

    WOLFSSL_LEAVE("SendCertificateRequest", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_REQUEST_SEND);

    return ret;
}



#if !defined(NO_WOLFSSL_SERVER) || !defined(WOLFSSL_NO_CLIENT_AUTH)

/* handle generation of certificate (11) */
int SendCertificate(WOLFSSL* ssl)
{
    int    ret = 0;
    word32 certSz, certChainSz, headerSz, listSz, payloadSz;
    word32 length, maxFragment;

    WOLFSSL_START(WC_FUNC_CERTIFICATE_SEND);
    WOLFSSL_ENTER("SendCertificate");

    if (ssl->options.usingPSK_cipher || ssl->options.usingAnon_cipher) {
        WOLFSSL_MSG("Not sending certificate msg. Using PSK or ANON cipher.");
        return 0;  /* not needed */
    }

    if (ssl->options.sendVerify == SEND_BLANK_CERT) {
    #ifdef OPENSSL_EXTRA
        if (ssl->version.major == SSLv3_MAJOR
            && ssl->version.minor == SSLv3_MINOR){
            SendAlert(ssl, alert_warning, no_certificate);
            return 0;
        } else {
    #endif
            certSz = 0;
            certChainSz = 0;
            headerSz = CERT_HEADER_SZ;
            length = CERT_HEADER_SZ;
            listSz = 0;
    #ifdef OPENSSL_EXTRA
        }
    #endif
    }
    else {
        if (!ssl->buffers.certificate) {
            WOLFSSL_MSG("Send Cert missing certificate buffer");
            return BUFFER_ERROR;
        }
        certSz = ssl->buffers.certificate->length;
        headerSz = 2 * CERT_HEADER_SZ;
        /* list + cert size */
        length = certSz + headerSz;
        listSz = certSz + CERT_HEADER_SZ;

        /* may need to send rest of chain, already has leading size(s) */
        if (certSz && ssl->buffers.certChain) {
            certChainSz = ssl->buffers.certChain->length;
            length += certChainSz;
            listSz += certChainSz;
        }
        else
            certChainSz = 0;
    }

    payloadSz = length;

    if (ssl->fragOffset != 0)
        length -= (ssl->fragOffset + headerSz);

    maxFragment = MAX_RECORD_SIZE;

    maxFragment = wolfSSL_GetMaxFragSize(ssl, maxFragment);

    while (length > 0 && ret == 0) {
        byte*  output = NULL;
        word32 fragSz = 0;
        word32 i = RECORD_HEADER_SZ;
        int    sendSz = RECORD_HEADER_SZ;

        ssl->options.buildingMsg = 1;

        if (!ssl->options.dtls) {
            if (ssl->fragOffset == 0)  {
                if (headerSz + certSz + certChainSz <=
                    maxFragment - HANDSHAKE_HEADER_SZ) {

                    fragSz = headerSz + certSz + certChainSz;
                }
                else {
                    fragSz = maxFragment - HANDSHAKE_HEADER_SZ;
                }
                sendSz += fragSz + HANDSHAKE_HEADER_SZ;
                i += HANDSHAKE_HEADER_SZ;
            }
            else {
                fragSz = min(length, maxFragment);
                sendSz += fragSz;
            }

            if (IsEncryptionOn(ssl, 1))
                sendSz += MAX_MSG_EXTRA;
        }
        else {
        #ifdef WOLFSSL_DTLS
            fragSz = min(length, maxFragment);
            sendSz += fragSz + DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_HEADER_SZ;
            i      += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_HEADER_SZ;
        #endif
        }

        if (IsEncryptionOn(ssl, 1))
            sendSz += cipherExtraData(ssl);

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        /* Safe to use ssl->fragOffset since it will be incremented immediately
         * after this block. This block needs to be entered only once to not
         * hash the cert msg twice. */
        if (ssl->fragOffset == 0) {
            if (!ssl->options.dtls) {
                AddFragHeaders(output, fragSz, 0, payloadSz, certificate, ssl);
                if (!IsEncryptionOn(ssl, 1))
                    HashRaw(ssl, output + RECORD_HEADER_SZ,
                                  HANDSHAKE_HEADER_SZ);
            }
            else {
            #ifdef WOLFSSL_DTLS
                AddHeaders(output, payloadSz, certificate, ssl);
                HashRaw(ssl,
                        output + RECORD_HEADER_SZ + DTLS_RECORD_EXTRA,
                        HANDSHAKE_HEADER_SZ + DTLS_HANDSHAKE_EXTRA);
                /* Adding the headers increments these, decrement them for
                 * actual message header. */
                ssl->keys.dtls_handshake_number--;
                AddFragHeaders(output, fragSz, 0, payloadSz, certificate, ssl);
                ssl->keys.dtls_handshake_number--;
            #endif /* WOLFSSL_DTLS */
            }

            /* list total */
            c32to24(listSz, output + i);
            if (ssl->options.dtls || !IsEncryptionOn(ssl, 1))
                HashRaw(ssl, output + i, CERT_HEADER_SZ);
            i += CERT_HEADER_SZ;
            length -= CERT_HEADER_SZ;
            fragSz -= CERT_HEADER_SZ;
            if (certSz) {
                c32to24(certSz, output + i);
                if (ssl->options.dtls || !IsEncryptionOn(ssl, 1))
                    HashRaw(ssl, output + i, CERT_HEADER_SZ);
                i += CERT_HEADER_SZ;
                length -= CERT_HEADER_SZ;
                fragSz -= CERT_HEADER_SZ;

                if (ssl->options.dtls || !IsEncryptionOn(ssl, 1)) {
                    HashRaw(ssl, ssl->buffers.certificate->buffer, certSz);
                    if (certChainSz)
                        HashRaw(ssl, ssl->buffers.certChain->buffer,
                                      certChainSz);
                }
            }
        }
        else {
            if (!ssl->options.dtls) {
                AddRecordHeader(output, fragSz, handshake, ssl, CUR_ORDER);
            }
            else {
            #ifdef WOLFSSL_DTLS
                AddFragHeaders(output, fragSz, ssl->fragOffset + headerSz,
                               payloadSz, certificate, ssl);
                ssl->keys.dtls_handshake_number--;
            #endif /* WOLFSSL_DTLS */
            }
        }

        /* member */
        if (certSz && ssl->fragOffset < certSz) {
            word32 copySz = min(certSz - ssl->fragOffset, fragSz);
            XMEMCPY(output + i,
                    ssl->buffers.certificate->buffer + ssl->fragOffset, copySz);
            i += copySz;
            ssl->fragOffset += copySz;
            length -= copySz;
            fragSz -= copySz;
        }
        if (certChainSz && fragSz) {
            word32 copySz = min(certChainSz + certSz - ssl->fragOffset, fragSz);
            XMEMCPY(output + i,
                    ssl->buffers.certChain->buffer + ssl->fragOffset - certSz,
                    copySz);
            i += copySz;
            ssl->fragOffset += copySz;
            length -= copySz;
        }

        if (IsEncryptionOn(ssl, 1)) {
            byte* input = NULL;
            int   inputSz = i; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls)
                recordHeaderSz += DTLS_RECORD_EXTRA;
            inputSz -= recordHeaderSz;

            if (inputSz < 0) {
                WOLFSSL_MSG("Send Cert bad inputSz");
                return BUFFER_E;
            }

            if (inputSz > 0) {  /* clang thinks could be zero, let's help */
                input = (byte*)XMALLOC(inputSz, ssl->heap,
                                       DYNAMIC_TYPE_IN_BUFFER);
                if (input == NULL)
                    return MEMORY_E;
                XMEMCPY(input, output + recordHeaderSz, inputSz);
            }

#ifndef WOLFSSL_DTLS
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                                          handshake, 1, 0, 0, CUR_ORDER);
#else
            if (!ssl->options.dtls)
                sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                                              handshake, 1, 0, 0, CUR_ORDER);
            else /* DTLS 1.2 has to ignore fragmentation in hashing so we need to
                  * calculate the hash ourselves above */ {
                if ((ret = DtlsMsgPoolSave(ssl, input, inputSz, certificate)) != 0) {
                    XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                    return ret;
                }
                sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                                              handshake, 0, 0, 0, CUR_ORDER);
            }
#endif

            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        }
        else {
            sendSz = i;
        #ifdef WOLFSSL_DTLS
            if (IsDtlsNotSctpMode(ssl)) {
                if ((ret = DtlsMsgPoolSave(ssl, output, sendSz, certificate)) != 0)
                    return ret;
            }
            if (ssl->options.dtls)
                DtlsSEQIncrement(ssl, CUR_ORDER);
        #endif
        }

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "Certificate");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "Certificate", handshake, output, sendSz,
                           WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
    #endif

        ssl->buffers.outputBuffer.length += sendSz;
        if (!ssl->options.groupMessages)
            ret = SendBuffered(ssl);
    }

    if (ret != WANT_WRITE) {
        /* Clean up the fragment offset. */
        ssl->options.buildingMsg = 0;
        ssl->fragOffset = 0;
        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls)
                ssl->keys.dtls_handshake_number++;
        #endif
        if (ssl->options.side == WOLFSSL_SERVER_END){
            ssl->options.serverState = SERVER_CERT_COMPLETE;
        }
    }

    WOLFSSL_LEAVE("SendCertificate", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_SEND);

    return ret;
}
#endif /* !NO_WOLFSSL_SERVER || !WOLFSSL_NO_CLIENT_AUTH */

#endif
#endif

//////////////////////////////

#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT)
   /* Does this cipher suite (first, second) have the requirement
       an ephemeral key exchange will still require the key for signing
       the key exchange so ECDHE_RSA requires an rsa key thus rsa_kea */
    static int CipherRequires(byte first, byte second, int requirement)
    {

        (void)requirement;

#ifndef WOLFSSL_NO_TLS12

#ifdef HAVE_CHACHA
        if (first == CHACHA_BYTE) {

        switch (second) {
            case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_RSA)
                    return 1;
                break;

            case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_ECC)
                    return 1;
                break;

            case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_RSA)
                    return 1;
                if (requirement == REQUIRES_DHE)
                    return 1;
                break;

            case TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256 :
                if (requirement == REQUIRES_RSA)
                    return 1;
                break;

            case TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256 :
                if (requirement == REQUIRES_ECC)
                    return 1;
                break;

            case TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256 :
                if (requirement == REQUIRES_RSA)
                    return 1;
                if (requirement == REQUIRES_DHE)
                    return 1;
                break;


            case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_PSK)
                    return 1;
                break;

            case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_PSK)
                    return 1;
                break;

            case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 :
                if (requirement == REQUIRES_PSK)
                    return 1;
                if (requirement == REQUIRES_DHE)
                    return 1;
                break;
        }

        if (requirement == REQUIRES_AEAD)
            return 1;
        }
#endif /* HAVE_CHACHA */

        /* ECC extensions */
        if (first == ECC_BYTE) {

        switch (second) {
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
    #ifndef NO_RSA
        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;

    #ifndef NO_DES3
        case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;
    #endif /* !NO_DES3 */

    #ifndef NO_RC4
        case TLS_ECDHE_RSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;
    #endif /* !NO_RC4 */
    #endif /* NO_RSA */

    #ifndef NO_DES3
        case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;
    #endif /* !NO_DES3  */
    #ifndef NO_RC4
        case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;
    #endif /* !NO_RC4 */
    #ifndef NO_RSA
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            break;
    #endif /* !NO_RSA */

        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;
#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

#ifndef NO_RSA
    #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;
    #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
    #ifdef HAVE_AESCCM
        case TLS_RSA_WITH_AES_128_CCM_8 :
        case TLS_RSA_WITH_AES_256_CCM_8 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;
    #endif /* HAVE_AESCCM */
    #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)

        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 :
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 :
        case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 :
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;
    #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
#endif /* !NO_RSA */

#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM :
        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 :
        case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 :
            if (requirement == REQUIRES_ECC)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 :
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 :
        case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 :
            if (requirement == REQUIRES_ECC)
                return 1;
            if (requirement == REQUIRES_ECC_STATIC)
                return 1;
            break;
#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

#ifndef NO_PSK
        case TLS_PSK_WITH_AES_128_CCM:
        case TLS_PSK_WITH_AES_256_CCM:
        case TLS_PSK_WITH_AES_128_CCM_8:
        case TLS_PSK_WITH_AES_256_CCM_8:
            if (requirement == REQUIRES_PSK)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_DHE_PSK_WITH_AES_128_CCM:
        case TLS_DHE_PSK_WITH_AES_256_CCM:
            if (requirement == REQUIRES_PSK)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;
#endif /* !NO_PSK */
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        case TLS_ECDHE_ECDSA_WITH_NULL_SHA :
            if (requirement == REQUIRES_ECC)
                return 1;
            break;

        case TLS_ECDHE_PSK_WITH_NULL_SHA256 :
            if (requirement == REQUIRES_PSK)
                return 1;
            break;

        case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_PSK)
                return 1;
            break;
#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

#if defined(WOLFSSL_TLS13) && defined(HAVE_NULL_CIPHER)
        case TLS_SHA256_SHA256:
            break;
        case TLS_SHA384_SHA384:
            break;
#endif

        default:
            WOLFSSL_MSG("Unsupported cipher suite, CipherRequires ECC");
            return 0;
        }   /* switch */
        }   /* if     */

        /* ECC extensions */
        if (first == ECDHE_PSK_BYTE) {

        switch (second) {
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        case TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_PSK)
                return 1;
            break;
#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
        default:
            WOLFSSL_MSG("Unsupported cipher suite, CipherRequires ECC PSK");
            return 0;
        }   /* switch */
        }   /* if     */
#endif /* !WOLFSSL_NO_TLS12 */

        /* Distinct TLS v1.3 cipher suites with cipher and digest only. */
        if (first == TLS13_BYTE) {

            switch (second) {
#ifdef WOLFSSL_TLS13
            case TLS_AES_128_GCM_SHA256:
            case TLS_AES_256_GCM_SHA384:
            case TLS_CHACHA20_POLY1305_SHA256:
            case TLS_AES_128_CCM_SHA256:
            case TLS_AES_128_CCM_8_SHA256:
                break;
#endif

            default:
                WOLFSSL_MSG("Unsupported cipher suite, CipherRequires "
                            "TLS v1.3");
                return 0;
            }
        }

#ifndef WOLFSSL_NO_TLS12

        if (first != ECC_BYTE && first != CHACHA_BYTE &&
            first != TLS13_BYTE && first != ECDHE_PSK_BYTE) {
        /* normal suites */
        switch (second) {

#ifndef NO_RSA
    #ifndef NO_RC4
        case SSL_RSA_WITH_RC4_128_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case SSL_RSA_WITH_RC4_128_MD5 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;
    #endif /* NO_RC4 */

        case SSL_RSA_WITH_3DES_EDE_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_AES_256_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_RSA_WITH_NULL_MD5 :
        case TLS_RSA_WITH_NULL_SHA :
        case TLS_RSA_WITH_NULL_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

#endif /* !NO_RSA */

#ifndef NO_PSK
        case TLS_PSK_WITH_AES_128_GCM_SHA256 :
            if (requirement == REQUIRES_PSK)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_PSK_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_PSK)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_PSK_WITH_AES_128_CBC_SHA256 :
        case TLS_PSK_WITH_AES_256_CBC_SHA384 :
        case TLS_PSK_WITH_AES_128_CBC_SHA :
        case TLS_PSK_WITH_AES_256_CBC_SHA :
        case TLS_PSK_WITH_NULL_SHA384 :
        case TLS_PSK_WITH_NULL_SHA256 :
        case TLS_PSK_WITH_NULL_SHA :
            if (requirement == REQUIRES_PSK)
                return 1;
            break;

        case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 :
        case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_DHE)
                return 1;
            if (requirement == REQUIRES_PSK)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 :
        case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 :
        case TLS_DHE_PSK_WITH_NULL_SHA384 :
        case TLS_DHE_PSK_WITH_NULL_SHA256 :
            if (requirement == REQUIRES_DHE)
                return 1;
            if (requirement == REQUIRES_PSK)
                return 1;
            break;
#endif /* NO_PSK */

#ifndef NO_RSA
        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;

        case TLS_RSA_WITH_AES_128_GCM_SHA256 :
        case TLS_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 :
        case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;

#ifdef HAVE_CAMELLIA
        case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA :
        case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA :
        case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 :
        case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            break;

        case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA :
        case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA :
        case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 :
        case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 :
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;
#endif /* HAVE_CAMELLIA */

        case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
            if (requirement == REQUIRES_RSA)
                return 1;
            if (requirement == REQUIRES_RSA_SIG)
                return 1;
            if (requirement == REQUIRES_DHE)
                return 1;
            break;
#endif
#ifdef HAVE_ANON
        case TLS_DH_anon_WITH_AES_128_CBC_SHA :
            if (requirement == REQUIRES_DHE)
                return 1;
            break;
        case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
            if (requirement == REQUIRES_DHE)
                return 1;
            if (requirement == REQUIRES_AEAD)
                return 1;
            break;
#endif
#ifdef WOLFSSL_MULTICAST
        case WDM_WITH_NULL_SHA256 :
            break;
#endif

        default:
            WOLFSSL_MSG("Unsupported cipher suite, CipherRequires");
            return 0;
        }  /* switch */
        }  /* if ECC / Normal suites else */

#endif /* !WOLFSSL_NO_TLS12 */

        return 0;
    }


#endif

///////////////////////////// <<<


/* client only parts */
#ifndef NO_WOLFSSL_CLIENT

#ifndef WOLFSSL_NO_TLS12

    /* handle generation of client_hello (1) */
    int SendClientHello(WOLFSSL* ssl)
    {
        byte              *output;
        word32             length, idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                sendSz;
        int                idSz;
        int                ret;
        word16             extSz = 0;

        if (ssl == NULL) {
            return BAD_FUNC_ARG;
        }

        idSz = ssl->options.resuming ? ssl->session->sessionIDSz : 0;

#ifdef WOLFSSL_TLS13
        if (IsAtLeastTLSv1_3(ssl->version))
            return SendTls13ClientHello(ssl);
#endif

        WOLFSSL_START(WC_FUNC_CLIENT_HELLO_SEND);
        WOLFSSL_ENTER("SendClientHello");

        if (ssl->suites == NULL) {
            WOLFSSL_MSG("Bad suites pointer in SendClientHello");
            return SUITES_ERROR;
        }

#ifdef HAVE_SESSION_TICKET
        if (ssl->options.resuming && ssl->session->ticketLen > 0) {
            SessionTicket* ticket;

            ticket = TLSX_SessionTicket_Create(0, ssl->session->ticket,
                                             ssl->session->ticketLen, ssl->heap);
            if (ticket == NULL) return MEMORY_E;

            ret = TLSX_UseSessionTicket(&ssl->extensions, ticket, ssl->heap);
            if (ret != WOLFSSL_SUCCESS) {
                TLSX_SessionTicket_Free(ticket, ssl->heap);
                return ret;
            }

            idSz = 0;
        }
#endif
        length = VERSION_SZ + RAN_LEN
               + idSz + ENUM_LEN
               + ssl->suites->suiteSz + SUITE_LEN
               + COMP_LEN + ENUM_LEN;

#ifdef HAVE_TLS_EXTENSIONS
        /* auto populate extensions supported unless user defined */
        if ((ret = TLSX_PopulateExtensions(ssl, 0)) != 0)
            return ret;
        extSz = 0;
        ret = TLSX_GetRequestSize(ssl, client_hello, &extSz);
        if (ret != 0)
            return ret;
        length += extSz;
#else
        if (IsAtLeastTLSv1_2(ssl) && ssl->suites->hashSigAlgoSz)
            extSz += HELLO_EXT_SZ + HELLO_EXT_SIGALGO_SZ
                   + ssl->suites->hashSigAlgoSz;
#ifdef HAVE_EXTENDED_MASTER
        if (ssl->options.haveEMS)
            extSz += HELLO_EXT_SZ;
#endif
        if (extSz != 0)
            length += extSz + HELLO_EXT_SZ_SZ;
#endif
        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

        if (ssl->arrays == NULL) {
            return BAD_FUNC_ARG;
        }

#ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            length += ENUM_LEN;   /* cookie */
            if (ssl->arrays->cookieSz != 0) length += ssl->arrays->cookieSz;
            sendSz  = length + DTLS_HANDSHAKE_HEADER_SZ + DTLS_RECORD_HEADER_SZ;
            idx    += DTLS_HANDSHAKE_EXTRA + DTLS_RECORD_EXTRA;
        }
#endif

        if (IsEncryptionOn(ssl, 1))
            sendSz += MAX_MSG_EXTRA;

        /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
         * is not advanced yet */
        ssl->options.buildingMsg = 1;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, length, client_hello, ssl);

        /* client hello, first version */
        output[idx++] = ssl->version.major;
        output[idx++] = ssl->version.minor;
        ssl->chVersion = ssl->version;  /* store in case changed */

        /* then random */
        if (ssl->options.connectState == CONNECT_BEGIN) {
            ret = wc_RNG_GenerateBlock(ssl->rng, output + idx, RAN_LEN);
            if (ret != 0)
                return ret;

            /* store random */
            XMEMCPY(ssl->arrays->clientRandom, output + idx, RAN_LEN);
        } else {
#ifdef WOLFSSL_DTLS
            /* send same random on hello again */
            XMEMCPY(output + idx, ssl->arrays->clientRandom, RAN_LEN);
#endif
        }
        idx += RAN_LEN;

        /* then session id */
        output[idx++] = (byte)idSz;
        if (idSz) {
            XMEMCPY(output + idx, ssl->session->sessionID,
                                                      ssl->session->sessionIDSz);
            idx += ssl->session->sessionIDSz;
        }

        /* then DTLS cookie */
#ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            byte cookieSz = ssl->arrays->cookieSz;

            output[idx++] = cookieSz;
            if (cookieSz) {
                XMEMCPY(&output[idx], ssl->arrays->cookie, cookieSz);
                idx += cookieSz;
            }
        }
#endif
        /* then cipher suites */
        c16toa(ssl->suites->suiteSz, output + idx);
        idx += OPAQUE16_LEN;
        XMEMCPY(output + idx, &ssl->suites->suites, ssl->suites->suiteSz);
        idx += ssl->suites->suiteSz;

        /* last, compression */
        output[idx++] = COMP_LEN;
        if (ssl->options.usingCompression)
            output[idx++] = ZLIB_COMPRESSION;
        else
            output[idx++] = NO_COMPRESSION;

#ifdef HAVE_TLS_EXTENSIONS
        extSz = 0;
        ret = TLSX_WriteRequest(ssl, output + idx, client_hello, &extSz);
        if (ret != 0)
            return ret;
        idx += extSz;

        (void)idx; /* suppress analyzer warning, keep idx current */
#else
        if (extSz != 0) {
            c16toa(extSz, output + idx);
            idx += HELLO_EXT_SZ_SZ;

            if (IsAtLeastTLSv1_2(ssl)) {
                if (ssl->suites->hashSigAlgoSz) {
                    word16 i;
                    /* extension type */
                    c16toa(HELLO_EXT_SIG_ALGO, output + idx);
                    idx += HELLO_EXT_TYPE_SZ;
                    /* extension data length */
                    c16toa(HELLO_EXT_SIGALGO_SZ + ssl->suites->hashSigAlgoSz,
                           output + idx);
                    idx += HELLO_EXT_SZ_SZ;
                    /* sig algos length */
                    c16toa(ssl->suites->hashSigAlgoSz, output + idx);
                    idx += HELLO_EXT_SIGALGO_SZ;
                    for (i=0; i < ssl->suites->hashSigAlgoSz; i++, idx++) {
                        output[idx] = ssl->suites->hashSigAlgo[i];
                    }
                }
            }
#ifdef HAVE_EXTENDED_MASTER
            if (ssl->options.haveEMS) {
                c16toa(HELLO_EXT_EXTMS, output + idx);
                idx += HELLO_EXT_TYPE_SZ;
                c16toa(0, output + idx);
                idx += HELLO_EXT_SZ_SZ;
            }
#endif
        }
#endif

        if (IsEncryptionOn(ssl, 1)) {
            byte* input;
            int   inputSz = idx; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls)
                recordHeaderSz += DTLS_RECORD_EXTRA;
            inputSz -= recordHeaderSz;
            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            #ifdef WOLFSSL_DTLS
            if (IsDtlsNotSctpMode(ssl) &&
                    (ret = DtlsMsgPoolSave(ssl, input, inputSz, client_hello)) != 0) {
                XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                return ret;
            }
            #endif
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        } else {
            #ifdef WOLFSSL_DTLS
                if (IsDtlsNotSctpMode(ssl)) {
                    if ((ret = DtlsMsgPoolSave(ssl, output, sendSz, client_hello)) != 0)
                        return ret;
                }
                if (ssl->options.dtls)
                    DtlsSEQIncrement(ssl, CUR_ORDER);
            #endif
            ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0)
                return ret;
        }

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;
#ifdef OPENSSL_EXTRA
        ssl->cbmode = SSL_CB_MODE_WRITE;
        if (ssl->CBIS != NULL)
            ssl->CBIS(ssl, SSL_CB_CONNECT_LOOP, SSL_SUCCESS);
#endif

#if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn) AddPacketName(ssl, "ClientHello");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "ClientHello", handshake, output, sendSz,
                          WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
#endif

        ssl->options.buildingMsg = 0;

        ssl->buffers.outputBuffer.length += sendSz;

        ret = SendBuffered(ssl);

        WOLFSSL_LEAVE("SendClientHello", ret);
        WOLFSSL_END(WC_FUNC_CLIENT_HELLO_SEND);

        return ret;
    }


    /* handle processing of DTLS hello_verify_request (3) */
    int DoHelloVerifyRequest(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
        word32 size)
    {
        ProtocolVersion pv;
        byte            cookieSz;
        word32          begin = *inOutIdx;

#ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName(ssl, "HelloVerifyRequest");
        if (ssl->toInfoOn) AddLateName("HelloVerifyRequest", &ssl->timeoutInfo);
#endif

#ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            DtlsMsgPoolReset(ssl);
        }
#endif

        if (OPAQUE16_LEN + OPAQUE8_LEN > size)
            return BUFFER_ERROR;

        XMEMCPY(&pv, input + *inOutIdx, OPAQUE16_LEN);
        *inOutIdx += OPAQUE16_LEN;

        if (pv.major != DTLS_MAJOR ||
                         (pv.minor != DTLS_MINOR && pv.minor != DTLSv1_2_MINOR))
            return VERSION_ERROR;

        cookieSz = input[(*inOutIdx)++];

        if (cookieSz) {
            if ((*inOutIdx - begin) + cookieSz > size)
                return BUFFER_ERROR;

#ifdef WOLFSSL_DTLS
            if (cookieSz <= MAX_COOKIE_LEN) {
                XMEMCPY(ssl->arrays->cookie, input + *inOutIdx, cookieSz);
                ssl->arrays->cookieSz = cookieSz;
            }
#endif
            *inOutIdx += cookieSz;
        }

#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_TLS13)
        if (IsAtLeastTLSv1_3(ssl->version) && ssl->options.dtls) {
            /* we sent a TLSv1.3 ClientHello but received a
             * HELLO_VERIFY_REQUEST */
            if (!ssl->options.downgrade ||
                    ssl->options.minDowngrade < pv.minor)
                return VERSION_ERROR;
        }
#endif /* defined(WOLFSSL_DTLS13) && defined(WOLFSSL_TLS13) */

        ssl->options.serverState = SERVER_HELLOVERIFYREQUEST_COMPLETE;

        return 0;
    }


    static WC_INLINE int DSH_CheckSessionId(WOLFSSL* ssl)
    {
        int ret = 0;

#ifdef HAVE_SECRET_CALLBACK
        /* If a session secret callback exists, we are using that
         * key instead of the saved session key. Requires a ticket. */
        ret = ret || (ssl->sessionSecretCb != NULL
#ifdef HAVE_SESSION_TICKET
                && ssl->session->ticketLen > 0
#endif
                );
#endif

#ifdef HAVE_SESSION_TICKET
        /* server may send blank ticket which may not be expected to indicate
         * existing one ok but will also be sending a new one */
        ret = ret || (ssl->session->ticketLen > 0);
#endif

        ret = ret ||
              (ssl->options.haveSessionId && XMEMCMP(ssl->arrays->sessionID,
                                          ssl->session->sessionID, ID_LEN) == 0);

        return ret;
    }

    /* Check the version in the received message is valid and set protocol
     * version to use.
     *
     * ssl  The SSL/TLS object.
     * pv   The protocol version from the packet.
     * returns 0 on success, otherwise failure.
     */
    int CheckVersion(WOLFSSL *ssl, ProtocolVersion pv)
    {
        byte lowerVersion, higherVersion;
    #ifdef WOLFSSL_TLS13_DRAFT
        if (pv.major == TLS_DRAFT_MAJOR) {
            pv.major = SSLv3_MAJOR;
            pv.minor = TLSv1_3_MINOR;
        }
    #endif

        #ifdef OPENSSL_EXTRA
        if (ssl->CBIS != NULL) {
            ssl->CBIS(ssl, SSL_CB_HANDSHAKE_START, SSL_SUCCESS);
        }
        #endif

        if (ssl->options.dtls) {
            if (pv.major != DTLS_MAJOR || pv.minor == DTLS_BOGUS_MINOR) {
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }
            lowerVersion = pv.minor > ssl->version.minor;
            higherVersion = pv.minor < ssl->version.minor;
        }
        else {
            if (pv.major != SSLv3_MAJOR) {
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }
            lowerVersion = pv.minor < ssl->version.minor;
            higherVersion = pv.minor > ssl->version.minor;
        }

        if (higherVersion) {
            WOLFSSL_MSG("Server using higher version, fatal error");
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;
        }
        if (lowerVersion) {
            WOLFSSL_MSG("server using lower version");

            /* Check for downgrade attack. */
            if (!ssl->options.downgrade) {
                WOLFSSL_MSG("\tno downgrade allowed, fatal error");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }
            if ((!ssl->options.dtls && pv.minor < ssl->options.minDowngrade) ||
                (ssl->options.dtls && pv.minor > ssl->options.minDowngrade)) {
                WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }

            #ifdef HAVE_SECURE_RENEGOTIATION
                if (ssl->secure_renegotiation &&
                                         ssl->secure_renegotiation->enabled &&
                                         ssl->options.handShakeDone) {
                    WOLFSSL_MSG("Server changed version during scr");
                    WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                    return VERSION_ERROR;
                }
            #endif

            /* Checks made - OK to downgrade. */
                ssl->version.minor = pv.minor;
                switch(pv.minor) {
                case SSLv3_MINOR:
                    /* turn off tls */
                    WOLFSSL_MSG("\tdowngrading to SSLv3");
                    ssl->options.tls    = 0;
                    ssl->options.tls1_1 = 0;
                    break;
                case TLSv1_MINOR:
                    /* turn off tls 1.1+ */
                    WOLFSSL_MSG("\tdowngrading to TLSv1");
                    ssl->options.tls1_1 = 0;
                    break;
                case TLSv1_1_MINOR:
                    WOLFSSL_MSG("\tdowngrading to TLSv1.1");
                    break;
                case DTLS_MINOR:
                    WOLFSSL_MSG("\tdowngrading to DTLSv1.1");
                    break;
                case TLSv1_2_MINOR:
                    WOLFSSL_MSG("\tdowngrading to TLSv1.2");
                    break;
                case DTLSv1_2_MINOR:
                    WOLFSSL_MSG("\tdowngrading to DTLSv1.2");
                    break;
                default:
                    WOLFSSL_MSG("\tbad minor version");
                    WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                    return VERSION_ERROR;
                }
        }

        /* check if option is set to not allow the current version
         * set from either wolfSSL_set_options or wolfSSL_CTX_set_options */
        if (!ssl->options.dtls && ssl->options.downgrade &&
            ssl->options.mask > 0) {

            if (ssl->version.minor == TLSv1_2_MINOR &&
               (ssl->options.mask & WOLFSSL_OP_NO_TLSv1_2) ==
                WOLFSSL_OP_NO_TLSv1_2) {
                WOLFSSL_MSG("\tOption set to not allow TLSv1.2, Downgrading");
                ssl->version.minor = TLSv1_1_MINOR;
            }

            if (ssl->version.minor == TLSv1_1_MINOR &&
               (ssl->options.mask & WOLFSSL_OP_NO_TLSv1_1) ==
                WOLFSSL_OP_NO_TLSv1_1) {
                WOLFSSL_MSG("\tOption set to not allow TLSv1.1, Downgrading");
                ssl->options.tls1_1 = 0;
                ssl->version.minor = TLSv1_MINOR;
            }

            if (ssl->version.minor == TLSv1_MINOR &&
                (ssl->options.mask & WOLFSSL_OP_NO_TLSv1) ==
                WOLFSSL_OP_NO_TLSv1) {
                WOLFSSL_MSG("\tOption set to not allow TLSv1, Downgrading");
                ssl->options.tls    = 0;
                ssl->options.tls1_1 = 0;
                ssl->version.minor = SSLv3_MINOR;
            }

            if (ssl->version.minor == SSLv3_MINOR &&
                (ssl->options.mask & WOLFSSL_OP_NO_SSLv3) ==
                WOLFSSL_OP_NO_SSLv3) {
                WOLFSSL_MSG("\tError, option set to not allow SSLv3");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }

            if (ssl->version.minor < ssl->options.minDowngrade) {
                WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }
        }

        return 0;
    }

    /* handle processing of server_hello (2) */
    int DoServerHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                      word32 helloSz)
    {
        byte            cs0;   /* cipher suite bytes 0, 1 */
        byte            cs1;
        ProtocolVersion pv;
        byte            compression;
        word32          i = *inOutIdx;
        word32          begin = i;
        int             ret;

        WOLFSSL_START(WC_FUNC_SERVER_HELLO_DO);
        WOLFSSL_ENTER("DoServerHello");

#ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName(ssl, "ServerHello");
        if (ssl->toInfoOn) AddLateName("ServerHello", &ssl->timeoutInfo);
#endif

        /* protocol version, random and session id length check */
        if (OPAQUE16_LEN + RAN_LEN + OPAQUE8_LEN > helloSz)
            return BUFFER_ERROR;

        /* protocol version */
        XMEMCPY(&pv, input + i, OPAQUE16_LEN);
        i += OPAQUE16_LEN;

        ret = CheckVersion(ssl, pv);
        if (ret != 0) {
            SendAlert(ssl, alert_fatal, wolfssl_alert_protocol_version);
            return ret;
        }

#ifdef WOLFSSL_TLS13
        if (IsAtLeastTLSv1_3(pv)) {
            byte type = server_hello;
            return DoTls13ServerHello(ssl, input, inOutIdx, helloSz, &type);
        }
#endif

        /* random */
        XMEMCPY(ssl->arrays->serverRandom, input + i, RAN_LEN);
        i += RAN_LEN;

        /* session id */
        ssl->arrays->sessionIDSz = input[i++];

        if (ssl->arrays->sessionIDSz > ID_LEN) {
            WOLFSSL_MSG("Invalid session ID size");
            ssl->arrays->sessionIDSz = 0;
            return BUFFER_ERROR;
        }
        else if (ssl->arrays->sessionIDSz) {
            if ((i - begin) + ssl->arrays->sessionIDSz > helloSz)
                return BUFFER_ERROR;

            XMEMCPY(ssl->arrays->sessionID, input + i,
                                                      ssl->arrays->sessionIDSz);
            i += ssl->arrays->sessionIDSz;
            ssl->options.haveSessionId = 1;
        }


        /* suite and compression */
        if ((i - begin) + OPAQUE16_LEN + OPAQUE8_LEN > helloSz)
            return BUFFER_ERROR;

        cs0 = input[i++];
        cs1 = input[i++];

#ifdef HAVE_SECURE_RENEGOTIATION
        if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled &&
                                         ssl->options.handShakeDone) {
            if (ssl->options.cipherSuite0 != cs0 ||
                ssl->options.cipherSuite  != cs1) {
                WOLFSSL_MSG("Server changed cipher suite during scr");
                WOLFSSL_ERROR_VERBOSE(MATCH_SUITE_ERROR);
                return MATCH_SUITE_ERROR;
            }
        }
#endif

        ssl->options.cipherSuite0 = cs0;
        ssl->options.cipherSuite  = cs1;
    #ifdef WOLFSSL_DEBUG_TLS
        WOLFSSL_MSG("Chosen cipher suite:");
        WOLFSSL_MSG(GetCipherNameInternal(ssl->options.cipherSuite0,
                                          ssl->options.cipherSuite));
    #endif

        compression = input[i++];

#ifndef WOLFSSL_NO_STRICT_CIPHER_SUITE
        {
            word32 idx, found = 0;
            /* confirm server_hello cipher suite is one sent in client_hello */
            for (idx = 0; idx < ssl->suites->suiteSz; idx += 2) {
                if (ssl->suites->suites[idx]   == cs0 &&
                    ssl->suites->suites[idx+1] == cs1) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                WOLFSSL_MSG("ServerHello did not use cipher suite from ClientHello");
                WOLFSSL_ERROR_VERBOSE(MATCH_SUITE_ERROR);
                return MATCH_SUITE_ERROR;
            }
        }
#endif /* !WOLFSSL_NO_STRICT_CIPHER_SUITE */

        if (compression != NO_COMPRESSION && !ssl->options.usingCompression) {
            WOLFSSL_MSG("Server forcing compression w/o support");
            WOLFSSL_ERROR_VERBOSE(COMPRESSION_ERROR);
            return COMPRESSION_ERROR;
        }

        if (compression != ZLIB_COMPRESSION && ssl->options.usingCompression) {
            WOLFSSL_MSG("Server refused compression, turning off");
            ssl->options.usingCompression = 0;  /* turn off if server refused */
        }

        *inOutIdx = i;

#ifdef HAVE_TLS_EXTENSIONS
        if ( (i - begin) < helloSz) {
            if (TLSX_SupportExtensions(ssl)) {
                word16 totalExtSz;

                if ((i - begin) + OPAQUE16_LEN > helloSz)
                    return BUFFER_ERROR;

                ato16(&input[i], &totalExtSz);
                i += OPAQUE16_LEN;

                if ((i - begin) + totalExtSz > helloSz)
                    return BUFFER_ERROR;

                if ((ret = TLSX_Parse(ssl, (byte *) input + i, totalExtSz,
                                                           server_hello, NULL)))
                    return ret;

                i += totalExtSz;
                *inOutIdx = i;
            }
            else
                *inOutIdx = begin + helloSz; /* skip extensions */
        }
        else
            ssl->options.haveEMS = 0; /* If no extensions, no EMS */
#else
        {
            int allowExt = 0;
            byte pendingEMS = 0;

            if ( (i - begin) < helloSz) {
                if (ssl->version.major == SSLv3_MAJOR &&
                    ssl->version.minor >= TLSv1_MINOR) {

                    allowExt = 1;
                }
#ifdef WOLFSSL_DTLS
                if (ssl->version.major == DTLS_MAJOR)
                    allowExt = 1;
#endif

                if (allowExt) {
                    word16 totalExtSz;

                    if ((i - begin) + OPAQUE16_LEN > helloSz)
                        return BUFFER_ERROR;

                    ato16(&input[i], &totalExtSz);
                    i += OPAQUE16_LEN;

                    if ((i - begin) + totalExtSz > helloSz)
                        return BUFFER_ERROR;

                    while (totalExtSz) {
                        word16 extId, extSz;

                        if (OPAQUE16_LEN + OPAQUE16_LEN > totalExtSz)
                            return BUFFER_ERROR;

                        ato16(&input[i], &extId);
                        i += OPAQUE16_LEN;
                        ato16(&input[i], &extSz);
                        i += OPAQUE16_LEN;

                        if (OPAQUE16_LEN + OPAQUE16_LEN + extSz > totalExtSz)
                            return BUFFER_ERROR;

                        if (extId == HELLO_EXT_EXTMS)
                            pendingEMS = 1;
                        else
                            i += extSz;

                        totalExtSz -= OPAQUE16_LEN + OPAQUE16_LEN + extSz;
                    }

                    *inOutIdx = i;
                }
                else
                    *inOutIdx = begin + helloSz; /* skip extensions */
            }

            if (!pendingEMS && ssl->options.haveEMS)
                ssl->options.haveEMS = 0;
        }
#endif

        ssl->options.serverState = SERVER_HELLO_COMPLETE;

        if (IsEncryptionOn(ssl, 0)) {
            *inOutIdx += ssl->keys.padSz;
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMWrite &&
                                              ssl->specs.cipher_type == block) {
                *inOutIdx += MacSize(ssl);
            }
        #endif
        }

#ifdef HAVE_SECRET_CALLBACK
        if (ssl->sessionSecretCb != NULL
#ifdef HAVE_SESSION_TICKET
                && ssl->session->ticketLen > 0
#endif
                ) {
            int secretSz = SECRET_LEN;
            ret = ssl->sessionSecretCb(ssl, ssl->session->masterSecret,
                                              &secretSz, ssl->sessionSecretCtx);
            if (ret != 0 || secretSz != SECRET_LEN) {
                WOLFSSL_ERROR_VERBOSE(SESSION_SECRET_CB_E);
                return SESSION_SECRET_CB_E;
            }
        }
#endif /* HAVE_SECRET_CALLBACK */

        ret = CompleteServerHello(ssl);

        WOLFSSL_LEAVE("DoServerHello", ret);
        WOLFSSL_END(WC_FUNC_SERVER_HELLO_DO);

        return ret;
    }

    int CompleteServerHello(WOLFSSL* ssl)
    {
        int ret;

        if (!ssl->options.resuming) {
            byte* down = ssl->arrays->serverRandom + RAN_LEN -
                                                         TLS13_DOWNGRADE_SZ - 1;
            byte  vers = ssl->arrays->serverRandom[RAN_LEN - 1];
    #ifdef WOLFSSL_TLS13
            if (TLSv1_3_Capable(ssl)) {
                /* TLS v1.3 capable client not allowed to downgrade when
                 * connecting to TLS v1.3 capable server unless cipher suite
                 * demands it.
                 */
                if (XMEMCMP(down, tls13Downgrade, TLS13_DOWNGRADE_SZ) == 0 &&
                                                     (vers == 0 || vers == 1)) {
                    SendAlert(ssl, alert_fatal, illegal_parameter);
                    WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                    return VERSION_ERROR;
                }
            }
            else
    #endif
            if (ssl->ctx->method->version.major == SSLv3_MAJOR &&
                ssl->ctx->method->version.minor == TLSv1_2_MINOR &&
                (wolfSSL_get_options(ssl) & WOLFSSL_OP_NO_TLSv1_2) == 0) {
                /* TLS v1.2 capable client not allowed to downgrade when
                 * connecting to TLS v1.2 capable server.
                 */
                if (XMEMCMP(down, tls13Downgrade, TLS13_DOWNGRADE_SZ) == 0 &&
                                                                    vers == 0) {
                    SendAlert(ssl, alert_fatal, illegal_parameter);
                    WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                    return VERSION_ERROR;
                }
            }
        }
        else {
            if (DSH_CheckSessionId(ssl)) {
                if (SetCipherSpecs(ssl) == 0) {

                    XMEMCPY(ssl->arrays->masterSecret,
                            ssl->session->masterSecret, SECRET_LEN);
            #ifdef NO_OLD_TLS
                    ret = DeriveTlsKeys(ssl);
            #else
                    ret = -1; /* default value */
                #ifndef NO_TLS
                    if (ssl->options.tls)
                        ret = DeriveTlsKeys(ssl);
                #endif
                    if (!ssl->options.tls)
                        ret = DeriveKeys(ssl);
            #endif /* NO_OLD_TLS */
                    /* SERVER: peer auth based on session secret. */
                    ssl->options.peerAuthGood = (ret == 0);
                    ssl->options.serverState = SERVER_HELLODONE_COMPLETE;

                    return ret;
                }
                else {
                    WOLFSSL_MSG("Unsupported cipher suite, DoServerHello");
                    WOLFSSL_ERROR_VERBOSE(UNSUPPORTED_SUITE);
                    return UNSUPPORTED_SUITE;
                }
            }
            else {
                WOLFSSL_MSG("Server denied resumption attempt");
                ssl->options.resuming = 0; /* server denied resumption try */
            }
        }
        return SetCipherSpecs(ssl);
    }

#endif /* !WOLFSSL_NO_TLS12 */


    /* Make sure client setup is valid for this suite, true on success */
    int VerifyClientSuite(WOLFSSL* ssl)
    {
    #ifndef NO_PSK
        int  havePSK = ssl->options.havePSK;
    #endif
        byte first   = ssl->options.cipherSuite0;
        byte second  = ssl->options.cipherSuite;

        WOLFSSL_ENTER("VerifyClientSuite");

        if (CipherRequires(first, second, REQUIRES_PSK)) {
            WOLFSSL_MSG("Requires PSK");
        #ifndef NO_PSK
            if (havePSK == 0)
        #endif
            {
                WOLFSSL_MSG("Don't have PSK");
                return 0;
            }
        }

        return 1;  /* success */
    }

#ifndef WOLFSSL_NO_TLS12




typedef struct SckeArgs {
    byte*  output; /* not allocated */
    byte*  encSecret;
    byte*  input;
    word32 encSz;
    word32 length;
    int    sendSz;
    int    inputSz;
} SckeArgs;

static void FreeSckeArgs(WOLFSSL* ssl, void* pArgs)
{
    SckeArgs* args = (SckeArgs*)pArgs;

    (void)ssl;

    if (args->encSecret) {
        XFREE(args->encSecret, ssl->heap, DYNAMIC_TYPE_SECRET);
        args->encSecret = NULL;
    }
    if (args->input) {
        XFREE(args->input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
        args->input = NULL;
    }
}

/* handle generation client_key_exchange (16) */
int SendClientKeyExchange(WOLFSSL* ssl)
{
    int ret = 0;
#ifdef WOLFSSL_ASYNC_IO
    SckeArgs* args = NULL;
    WOLFSSL_ASSERT_SIZEOF_GE(ssl->async->args, *args);
#else
    SckeArgs  args[1];
#endif

    WOLFSSL_START(WC_FUNC_CLIENT_KEY_EXCHANGE_SEND);
    WOLFSSL_ENTER("SendClientKeyExchange");

#ifdef OPENSSL_EXTRA
    ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
    ssl->cbmode = SSL_CB_MODE_WRITE;
    if (ssl->CBIS != NULL)
        ssl->CBIS(ssl, SSL_CB_CONNECT_LOOP, SSL_SUCCESS);
#endif

#ifdef WOLFSSL_ASYNC_IO
    if (ssl->async == NULL) {
        ssl->async = (struct WOLFSSL_ASYNC*)
                XMALLOC(sizeof(struct WOLFSSL_ASYNC), ssl->heap,
                        DYNAMIC_TYPE_ASYNC);
        if (ssl->async == NULL)
            ERROR_OUT(MEMORY_E, exit_scke);
        XMEMSET(ssl->async, 0, sizeof(struct WOLFSSL_ASYNC));
    }
    args = (SckeArgs*)ssl->async->args;

#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
    if (ret != WC_NOT_PENDING_E) {
        /* Check for error */
        if (ret < 0)
            goto exit_scke;
    }
    else
#endif
    if (ssl->options.buildingMsg) {
        /* Continue building the message */
    }
    else
#endif
    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(SckeArgs));
        /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
         * is not advanced yet */
        ssl->options.buildingMsg = 1;
    #ifdef WOLFSSL_ASYNC_IO
        ssl->async->freeArgs = FreeSckeArgs;
    #endif
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
            switch (ssl->specs.kea) {
            #ifndef NO_RSA
                case rsa_kea:
                    if (ssl->peerRsaKey == NULL ||
                        ssl->peerRsaKeyPresent == 0) {
                        ERROR_OUT(NO_PEER_KEY, exit_scke);
                    }
                    break;
            #endif
            #ifndef NO_DH
                case diffie_hellman_kea:
                    if (ssl->buffers.serverDH_P.buffer == NULL ||
                        ssl->buffers.serverDH_G.buffer == NULL ||
                        ssl->buffers.serverDH_Pub.buffer == NULL) {
                        ERROR_OUT(NO_PEER_KEY, exit_scke);
                    }
                    break;
            #endif /* NO_DH */
            #ifndef NO_PSK
                case psk_kea:
                    /* sanity check that PSK client callback has been set */
                    if (ssl->options.client_psk_cb == NULL) {
                        WOLFSSL_MSG("No client PSK callback set");
                        ERROR_OUT(PSK_KEY_ERROR, exit_scke);
                    }
                    break;
            #endif /* NO_PSK */
            #if !defined(NO_DH) && !defined(NO_PSK)
                case dhe_psk_kea:
                    if (ssl->buffers.serverDH_P.buffer == NULL ||
                        ssl->buffers.serverDH_G.buffer == NULL ||
                        ssl->buffers.serverDH_Pub.buffer == NULL) {
                        ERROR_OUT(NO_PEER_KEY, exit_scke);
                    }

                    /* sanity check that PSK client callback has been set */
                    if (ssl->options.client_psk_cb == NULL) {
                        WOLFSSL_MSG("No client PSK callback set");
                        ERROR_OUT(PSK_KEY_ERROR, exit_scke);
                    }
                    break;
            #endif /* !NO_DH && !NO_PSK */
            #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                case ecdhe_psk_kea:
                    /* sanity check that PSK client callback has been set */
                    if (ssl->options.client_psk_cb == NULL) {
                        WOLFSSL_MSG("No client PSK callback set");
                        ERROR_OUT(PSK_KEY_ERROR, exit_scke);
                    }

                #ifdef HAVE_CURVE25519
                    if (ssl->peerX25519KeyPresent) {
                        /* Check client ECC public key */
                        if (!ssl->peerX25519Key || !ssl->peerX25519Key->dp) {
                            ERROR_OUT(NO_PEER_KEY, exit_scke);
                        }

                    #ifdef HAVE_PK_CALLBACKS
                        /* if callback then use it for shared secret */
                        if (ssl->ctx->X25519SharedSecretCb != NULL) {
                            break;
                        }
                    #endif

                        /* create private key */
                        ssl->hsType = DYNAMIC_TYPE_CURVE25519;
                        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
                        if (ret != 0) {
                            goto exit_scke;
                        }

                        ret = X25519MakeKey(ssl, (curve25519_key*)ssl->hsKey,
                                            ssl->peerX25519Key);
                        break;
                    }
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->peerX448KeyPresent) {
                        /* Check client ECC public key */
                        if (!ssl->peerX448Key) {
                            ERROR_OUT(NO_PEER_KEY, exit_scke);
                        }

                    #ifdef HAVE_PK_CALLBACKS
                        /* if callback then use it for shared secret */
                        if (ssl->ctx->X448SharedSecretCb != NULL) {
                            break;
                        }
                    #endif

                        /* create private key */
                        ssl->hsType = DYNAMIC_TYPE_CURVE448;
                        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
                        if (ret != 0) {
                            goto exit_scke;
                        }

                        ret = X448MakeKey(ssl, (curve448_key*)ssl->hsKey,
                                          ssl->peerX448Key);
                        break;
                    }
                #endif
                    /* Check client ECC public key */
                    if (!ssl->peerEccKey || !ssl->peerEccKeyPresent ||
                                            !ssl->peerEccKey->dp) {
                        ERROR_OUT(NO_PEER_KEY, exit_scke);
                    }

                #ifdef HAVE_PK_CALLBACKS
                    /* if callback then use it for shared secret */
                    if (ssl->ctx->EccSharedSecretCb != NULL) {
                        break;
                    }
                #endif

                    /* create ephemeral private key */
                    ssl->hsType = DYNAMIC_TYPE_ECC;
                    ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
                    if (ret != 0) {
                        goto exit_scke;
                    }

                    ret = EccMakeKey(ssl, (ecc_key*)ssl->hsKey, ssl->peerEccKey);

                    break;
            #endif /* (HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448) && !NO_PSK */
            #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                case ecc_diffie_hellman_kea:
                {
                #ifdef HAVE_ECC
                    ecc_key* peerKey;
                #endif

            #ifdef HAVE_PK_CALLBACKS
                    /* if callback then use it for shared secret */
                #ifdef HAVE_CURVE25519
                    if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                        if (ssl->ctx->X25519SharedSecretCb != NULL)
                            break;
                    }
                    else
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->ecdhCurveOID == ECC_X448_OID) {
                        if (ssl->ctx->X448SharedSecretCb != NULL)
                            break;
                    }
                    else
                #endif
                #ifdef HAVE_ECC
                    if (ssl->ctx->EccSharedSecretCb != NULL) {
                        break;
                    }
                    else
                #endif
                    {
                    }
            #endif /* HAVE_PK_CALLBACKS */

                #ifdef HAVE_CURVE25519
                    if (ssl->peerX25519KeyPresent) {
                        if (!ssl->peerX25519Key || !ssl->peerX25519Key->dp) {
                            ERROR_OUT(NO_PEER_KEY, exit_scke);
                        }

                        /* create private key */
                        ssl->hsType = DYNAMIC_TYPE_CURVE25519;
                        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
                        if (ret != 0) {
                            goto exit_scke;
                        }

                        ret = X25519MakeKey(ssl, (curve25519_key*)ssl->hsKey,
                                            ssl->peerX25519Key);
                        break;
                    }
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->peerX448KeyPresent) {
                        if (!ssl->peerX448Key) {
                            ERROR_OUT(NO_PEER_KEY, exit_scke);
                        }

                        /* create private key */
                        ssl->hsType = DYNAMIC_TYPE_CURVE448;
                        ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
                        if (ret != 0) {
                            goto exit_scke;
                        }

                        ret = X448MakeKey(ssl, (curve448_key*)ssl->hsKey,
                                          ssl->peerX448Key);
                        break;
                    }
                #endif
                #ifdef HAVE_ECC
                    if (ssl->specs.static_ecdh) {
                        /* Note: EccDsa is really fixed Ecc key here */
                        if (!ssl->peerEccDsaKey || !ssl->peerEccDsaKeyPresent) {
                            ERROR_OUT(NO_PEER_KEY, exit_scke);
                        }
                        peerKey = ssl->peerEccDsaKey;
                    }
                    else {
                        if (!ssl->peerEccKey || !ssl->peerEccKeyPresent) {
                            ERROR_OUT(NO_PEER_KEY, exit_scke);
                        }
                        peerKey = ssl->peerEccKey;
                    }
                    if (peerKey == NULL) {
                        ERROR_OUT(NO_PEER_KEY, exit_scke);
                    }

                    /* create ephemeral private key */
                    ssl->hsType = DYNAMIC_TYPE_ECC;
                    ret = AllocKey(ssl, ssl->hsType, &ssl->hsKey);
                    if (ret != 0) {
                        goto exit_scke;
                    }

                    ret = EccMakeKey(ssl, (ecc_key*)ssl->hsKey, peerKey);
                #endif /* HAVE_ECC */

                    break;
                }
            #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;

        case TLS_ASYNC_BUILD:
        {
            args->encSz = MAX_ENCRYPT_SZ;
            args->encSecret = (byte*)XMALLOC(MAX_ENCRYPT_SZ, ssl->heap,
                                                    DYNAMIC_TYPE_SECRET);
            if (args->encSecret == NULL) {
                ERROR_OUT(MEMORY_E, exit_scke);
            }
            if (ssl->arrays->preMasterSecret == NULL) {
                ssl->arrays->preMasterSz = ENCRYPT_LEN;
                ssl->arrays->preMasterSecret = (byte*)XMALLOC(ENCRYPT_LEN,
                                                ssl->heap, DYNAMIC_TYPE_SECRET);
                if (ssl->arrays->preMasterSecret == NULL) {
                    ERROR_OUT(MEMORY_E, exit_scke);
                }
                XMEMSET(ssl->arrays->preMasterSecret, 0, ENCRYPT_LEN);
            }

            switch(ssl->specs.kea)
            {
            #ifndef NO_RSA
                case rsa_kea:
                {
                    #ifdef HAVE_PK_CALLBACKS
                    if (ssl->ctx->GenPreMasterCb) {
                        void* ctx = wolfSSL_GetGenPreMasterCtx(ssl);
                        ret = ssl->ctx->GenPreMasterCb(ssl,
                            ssl->arrays->preMasterSecret, ENCRYPT_LEN, ctx);
                        if (ret != 0 && ret != PROTOCOLCB_UNAVAILABLE) {
                            goto exit_scke;
                        }
                    }
                    if (!ssl->ctx->GenPreMasterCb || ret == PROTOCOLCB_UNAVAILABLE)
                    #endif
                    {
                        /* build PreMasterSecret with RNG data */
                        ret = wc_RNG_GenerateBlock(ssl->rng,
                            &ssl->arrays->preMasterSecret[VERSION_SZ],
                            SECRET_LEN - VERSION_SZ);
                        if (ret != 0) {
                            goto exit_scke;
                        }

                        ssl->arrays->preMasterSecret[0] = ssl->chVersion.major;
                        ssl->arrays->preMasterSecret[1] = ssl->chVersion.minor;

                        ssl->arrays->preMasterSz = SECRET_LEN;
                    }
                    break;
                }
            #endif /* !NO_RSA */
            #ifndef NO_DH
                case diffie_hellman_kea:
                {
                    ssl->buffers.sig.length = ENCRYPT_LEN;
                    ssl->buffers.sig.buffer = (byte*)XMALLOC(ENCRYPT_LEN,
                                            ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                    if (ssl->buffers.sig.buffer == NULL) {
                        ERROR_OUT(MEMORY_E, exit_scke);
                    }

                    ret = AllocKey(ssl, DYNAMIC_TYPE_DH,
                                            (void**)&ssl->buffers.serverDH_Key);
                    if (ret != 0) {
                        goto exit_scke;
                    }

#if defined(HAVE_FFDHE) && !defined(HAVE_PUBLIC_FFDHE)
                    if (ssl->namedGroup) {
                        ret = wc_DhSetNamedKey(ssl->buffers.serverDH_Key,
                                ssl->namedGroup);
                        if (ret != 0) {
                            goto exit_scke;
                        }
                        ssl->buffers.sig.length =
                            wc_DhGetNamedKeyMinSize(ssl->namedGroup);
                    }
                    else
#endif
                    #if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
                        !defined(WOLFSSL_OLD_PRIME_CHECK)
                    if (ssl->options.dhDoKeyTest &&
                        !ssl->options.dhKeyTested)
                    {
                        ret = wc_DhSetCheckKey(ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length,
                            ssl->buffers.serverDH_G.buffer,
                            ssl->buffers.serverDH_G.length,
                            NULL, 0, 0, ssl->rng);
                        if (ret != 0) {
                            goto exit_scke;
                        }
                        ssl->options.dhKeyTested = 1;
                    }
                    else
                    #endif
                    {
                        ret = wc_DhSetKey(ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length,
                            ssl->buffers.serverDH_G.buffer,
                            ssl->buffers.serverDH_G.length);
                        if (ret != 0) {
                            goto exit_scke;
                        }
                    }

                    /* for DH, encSecret is Yc, agree is pre-master */
                    ret = DhGenKeyPair(ssl, ssl->buffers.serverDH_Key,
                        ssl->buffers.sig.buffer, (word32*)&ssl->buffers.sig.length,
                        args->encSecret, &args->encSz);

                    /* set the max agree result size */
                    ssl->arrays->preMasterSz = ENCRYPT_LEN;
                    break;
                }
            #endif /* !NO_DH */
            #ifndef NO_PSK
                case psk_kea:
                {
                    byte* pms = ssl->arrays->preMasterSecret;
                    int cbret = (int)ssl->options.client_psk_cb(ssl,
                        ssl->arrays->server_hint, ssl->arrays->client_identity,
                        MAX_PSK_ID_LEN, ssl->arrays->psk_key, MAX_PSK_KEY_LEN);

                    if (cbret == 0 || cbret > MAX_PSK_KEY_LEN) {
                        if (cbret != USE_HW_PSK) {
                            ERROR_OUT(PSK_KEY_ERROR, exit_scke);
                        }
                    }

                    if (cbret == USE_HW_PSK) {
                        /* USE_HW_PSK indicates that the hardware has the PSK
                         * and generates the premaster secret. */
                        ssl->arrays->psk_keySz = 0;
                    }
                    else {
                        ssl->arrays->psk_keySz = (word32)cbret;
                    }

                    /* Ensure the buffer is null-terminated. */
                    ssl->arrays->client_identity[MAX_PSK_ID_LEN] = '\0';
                    args->encSz = (word32)XSTRLEN(ssl->arrays->client_identity);
                    if (args->encSz > MAX_PSK_ID_LEN) {
                        ERROR_OUT(CLIENT_ID_ERROR, exit_scke);
                    }
                    XMEMCPY(args->encSecret, ssl->arrays->client_identity,
                            args->encSz);
                    ssl->options.peerAuthGood = 1;
                    if (cbret != USE_HW_PSK) {
                        /* CLIENT: Pre-shared Key for peer authentication. */

                        /* make psk pre master secret */
                        /* length of key + length 0s + length of key + key */
                        c16toa((word16)ssl->arrays->psk_keySz, pms);
                        pms += OPAQUE16_LEN;
                        XMEMSET(pms, 0, ssl->arrays->psk_keySz);
                        pms += ssl->arrays->psk_keySz;
                        c16toa((word16)ssl->arrays->psk_keySz, pms);
                        pms += OPAQUE16_LEN;
                        XMEMCPY(pms, ssl->arrays->psk_key,
                                ssl->arrays->psk_keySz);
                        ssl->arrays->preMasterSz = (ssl->arrays->psk_keySz * 2)
                                                   + (2 * OPAQUE16_LEN);
                        ForceZero(ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                        ssl->arrays->psk_keySz = 0; /* No further need */
                    }
                    break;
                }
            #endif /* !NO_PSK */
            #if !defined(NO_DH) && !defined(NO_PSK)
                case dhe_psk_kea:
                {
                    word32 esSz = 0;
                    args->output = args->encSecret;

                    ssl->arrays->psk_keySz = ssl->options.client_psk_cb(ssl,
                         ssl->arrays->server_hint, ssl->arrays->client_identity,
                         MAX_PSK_ID_LEN, ssl->arrays->psk_key, MAX_PSK_KEY_LEN);
                    if (ssl->arrays->psk_keySz == 0 ||
                                     ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN) {
                        ERROR_OUT(PSK_KEY_ERROR, exit_scke);
                    }
                    ssl->arrays->client_identity[MAX_PSK_ID_LEN] = '\0'; /* null term */
                    esSz = (word32)XSTRLEN(ssl->arrays->client_identity);

                    if (esSz > MAX_PSK_ID_LEN) {
                        ERROR_OUT(CLIENT_ID_ERROR, exit_scke);
                    }
                    /* CLIENT: Pre-shared Key for peer authentication. */
                    ssl->options.peerAuthGood = 1;

                    ssl->buffers.sig.length = ENCRYPT_LEN;
                    ssl->buffers.sig.buffer = (byte*)XMALLOC(ENCRYPT_LEN,
                                            ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                    if (ssl->buffers.sig.buffer == NULL) {
                        ERROR_OUT(MEMORY_E, exit_scke);
                    }

                    c16toa((word16)esSz, args->output);
                    args->output += OPAQUE16_LEN;
                    XMEMCPY(args->output, ssl->arrays->client_identity, esSz);
                    args->output += esSz;
                    args->length = args->encSz - esSz - OPAQUE16_LEN;
                    args->encSz = esSz + OPAQUE16_LEN;

                    ret = AllocKey(ssl, DYNAMIC_TYPE_DH,
                                            (void**)&ssl->buffers.serverDH_Key);
                    if (ret != 0) {
                        goto exit_scke;
                    }

                    #if !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST) && \
                        !defined(WOLFSSL_OLD_PRIME_CHECK)
                    if (ssl->options.dhDoKeyTest &&
                        !ssl->options.dhKeyTested)
                    {
                        ret = wc_DhSetCheckKey(ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length,
                            ssl->buffers.serverDH_G.buffer,
                            ssl->buffers.serverDH_G.length,
                            NULL, 0, 0, ssl->rng);
                        if (ret != 0) {
                            goto exit_scke;
                        }
                        ssl->options.dhKeyTested = 1;
                    }
                    else
                    #endif
                    {
                        ret = wc_DhSetKey(ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length,
                            ssl->buffers.serverDH_G.buffer,
                            ssl->buffers.serverDH_G.length);
                        if (ret != 0) {
                            goto exit_scke;
                        }
                    }

                    /* for DH, encSecret is Yc, agree is pre-master */
                    ret = DhGenKeyPair(ssl, ssl->buffers.serverDH_Key,
                            ssl->buffers.sig.buffer,
                            (word32*)&ssl->buffers.sig.length,
                            args->output + OPAQUE16_LEN, &args->length);
                    break;
                }
            #endif /* !NO_DH && !NO_PSK */
            #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                case ecdhe_psk_kea:
                {
                    word32 esSz = 0;
                    args->output = args->encSecret;

                    /* Send PSK client identity */
                    ssl->arrays->psk_keySz = ssl->options.client_psk_cb(ssl,
                         ssl->arrays->server_hint, ssl->arrays->client_identity,
                         MAX_PSK_ID_LEN, ssl->arrays->psk_key, MAX_PSK_KEY_LEN);
                    if (ssl->arrays->psk_keySz == 0 ||
                                     ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN) {
                        ERROR_OUT(PSK_KEY_ERROR, exit_scke);
                    }
                    ssl->arrays->client_identity[MAX_PSK_ID_LEN] = '\0'; /* null term */
                    esSz = (word32)XSTRLEN(ssl->arrays->client_identity);
                    if (esSz > MAX_PSK_ID_LEN) {
                        ERROR_OUT(CLIENT_ID_ERROR, exit_scke);
                    }
                    /* CLIENT: Pre-shared Key for peer authentication. */
                    ssl->options.peerAuthGood = 1;

                    /* place size and identity in output buffer sz:identity */
                    c16toa((word16)esSz, args->output);
                    args->output += OPAQUE16_LEN;
                    XMEMCPY(args->output, ssl->arrays->client_identity, esSz);
                    args->output += esSz;
                    args->encSz = esSz + OPAQUE16_LEN;

                    /* length is used for public key size */
                    args->length = MAX_ENCRYPT_SZ;

                    /* Create shared ECC key leaving room at the beginning
                       of buffer for size of shared key. */
                    ssl->arrays->preMasterSz = ENCRYPT_LEN - OPAQUE16_LEN;

                #ifdef HAVE_CURVE25519
                    if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                    #ifdef HAVE_PK_CALLBACKS
                        /* if callback then use it for shared secret */
                        if (ssl->ctx->X25519SharedSecretCb != NULL) {
                            break;
                        }
                    #endif

                        ret = wc_curve25519_export_public_ex(
                                (curve25519_key*)ssl->hsKey,
                                args->output + OPAQUE8_LEN, &args->length,
                                EC25519_LITTLE_ENDIAN);
                        if (ret != 0) {
                            ERROR_OUT(ECC_EXPORT_ERROR, exit_scke);
                        }

                        break;
                    }
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->ecdhCurveOID == ECC_X448_OID) {
                    #ifdef HAVE_PK_CALLBACKS
                        /* if callback then use it for shared secret */
                        if (ssl->ctx->X448SharedSecretCb != NULL) {
                            break;
                        }
                    #endif

                        ret = wc_curve448_export_public_ex(
                                (curve448_key*)ssl->hsKey,
                                args->output + OPAQUE8_LEN, &args->length,
                                EC448_LITTLE_ENDIAN);
                        if (ret != 0) {
                            ERROR_OUT(ECC_EXPORT_ERROR, exit_scke);
                        }

                        break;
                    }
                #endif
                #ifdef HAVE_PK_CALLBACKS
                    /* if callback then use it for shared secret */
                    if (ssl->ctx->EccSharedSecretCb != NULL) {
                        break;
                    }
                #endif

                    /* Place ECC key in output buffer, leaving room for size */
                    PRIVATE_KEY_UNLOCK();
                    ret = wc_ecc_export_x963((ecc_key*)ssl->hsKey,
                                    args->output + OPAQUE8_LEN, &args->length);
                    PRIVATE_KEY_LOCK();
                    if (ret != 0) {
                        ERROR_OUT(ECC_EXPORT_ERROR, exit_scke);
                    }

                    break;
                }
            #endif /* (HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448) && !NO_PSK */
            #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                case ecc_diffie_hellman_kea:
                {
                    ssl->arrays->preMasterSz = ENCRYPT_LEN;

                #ifdef HAVE_CURVE25519
                    if (ssl->hsType == DYNAMIC_TYPE_CURVE25519) {
                    #ifdef HAVE_PK_CALLBACKS
                        /* if callback then use it for shared secret */
                        if (ssl->ctx->X25519SharedSecretCb != NULL) {
                            break;
                        }
                    #endif

                        ret = wc_curve25519_export_public_ex(
                                (curve25519_key*)ssl->hsKey,
                                args->encSecret + OPAQUE8_LEN, &args->encSz,
                                EC25519_LITTLE_ENDIAN);
                        if (ret != 0) {
                            ERROR_OUT(ECC_EXPORT_ERROR, exit_scke);
                        }

                        break;
                    }
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->hsType == DYNAMIC_TYPE_CURVE448) {
                    #ifdef HAVE_PK_CALLBACKS
                        /* if callback then use it for shared secret */
                        if (ssl->ctx->X448SharedSecretCb != NULL) {
                            break;
                        }
                    #endif

                        ret = wc_curve448_export_public_ex(
                                (curve448_key*)ssl->hsKey,
                                args->encSecret + OPAQUE8_LEN, &args->encSz,
                                EC448_LITTLE_ENDIAN);
                        if (ret != 0) {
                            ERROR_OUT(ECC_EXPORT_ERROR, exit_scke);
                        }

                        break;
                    }
                #endif
                #if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
                #ifdef HAVE_PK_CALLBACKS
                    /* if callback then use it for shared secret */
                    if (ssl->ctx->EccSharedSecretCb != NULL) {
                        break;
                    }
                #endif

                    /* Place ECC key in buffer, leaving room for size */
                    PRIVATE_KEY_UNLOCK();
                    ret = wc_ecc_export_x963((ecc_key*)ssl->hsKey,
                                args->encSecret + OPAQUE8_LEN, &args->encSz);
                    PRIVATE_KEY_LOCK();
                    if (ret != 0) {
                        ERROR_OUT(ECC_EXPORT_ERROR, exit_scke);
                    }
                #endif /* HAVE_ECC */
                    break;
                }
            #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */
        FALL_THROUGH;

        case TLS_ASYNC_DO:
        {
            switch(ssl->specs.kea)
            {
            #ifndef NO_RSA
                case rsa_kea:
                {
                        ret = RsaEnc(ssl,
                            ssl->arrays->preMasterSecret, SECRET_LEN,
                            args->encSecret, &args->encSz,
                            ssl->peerRsaKey,
                        #if defined(HAVE_PK_CALLBACKS)
                            &ssl->buffers.peerRsaKey
                        #else
                            NULL
                        #endif
                        );

                    break;
                }
            #endif /* !NO_RSA */
            #ifndef NO_DH
                case diffie_hellman_kea:
                {
                    ret = DhAgree(ssl, ssl->buffers.serverDH_Key,
                        ssl->buffers.sig.buffer, ssl->buffers.sig.length,
                        ssl->buffers.serverDH_Pub.buffer,
                        ssl->buffers.serverDH_Pub.length,
                        ssl->arrays->preMasterSecret,
                        &ssl->arrays->preMasterSz,
                        ssl->buffers.serverDH_P.buffer,
                        ssl->buffers.serverDH_P.length);
                    break;
                }
            #endif /* !NO_DH */
            #ifndef NO_PSK
                case psk_kea:
                {
                    break;
                }
            #endif /* !NO_PSK */
            #if !defined(NO_DH) && !defined(NO_PSK)
                case dhe_psk_kea:
                {
                    ret = DhAgree(ssl, ssl->buffers.serverDH_Key,
                        ssl->buffers.sig.buffer, ssl->buffers.sig.length,
                        ssl->buffers.serverDH_Pub.buffer,
                        ssl->buffers.serverDH_Pub.length,
                        ssl->arrays->preMasterSecret + OPAQUE16_LEN,
                        &ssl->arrays->preMasterSz,
                        ssl->buffers.serverDH_P.buffer,
                        ssl->buffers.serverDH_P.length);
                    break;
                }
            #endif /* !NO_DH && !NO_PSK */
            #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                case ecdhe_psk_kea:
                {
                #ifdef HAVE_CURVE25519
                    if (ssl->peerX25519KeyPresent) {
                        ret = X25519SharedSecret(ssl,
                            (curve25519_key*)ssl->hsKey, ssl->peerX25519Key,
                            args->output + OPAQUE8_LEN, &args->length,
                            ssl->arrays->preMasterSecret + OPAQUE16_LEN,
                            &ssl->arrays->preMasterSz,
                            WOLFSSL_CLIENT_END
                        );
                        if (!ssl->specs.static_ecdh
                        #ifdef WOLFSSL_ASYNC_CRYPT
                            && ret != WC_PENDING_E
                        #endif
                        ) {
                            FreeKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                                   (void**)&ssl->peerX25519Key);
                            ssl->peerX25519KeyPresent = 0;
                        }
                        break;
                    }
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->peerX448KeyPresent) {
                        ret = X448SharedSecret(ssl,
                            (curve448_key*)ssl->hsKey, ssl->peerX448Key,
                            args->output + OPAQUE8_LEN, &args->length,
                            ssl->arrays->preMasterSecret + OPAQUE16_LEN,
                            &ssl->arrays->preMasterSz,
                            WOLFSSL_CLIENT_END
                        );
                        if (!ssl->specs.static_ecdh
                        #ifdef WOLFSSL_ASYNC_CRYPT
                            && ret != WC_PENDING_E
                        #endif
                        ) {
                            FreeKey(ssl, DYNAMIC_TYPE_CURVE448,
                                                     (void**)&ssl->peerX448Key);
                            ssl->peerX448KeyPresent = 0;
                        }
                        break;
                    }
                #endif
                    ret = EccSharedSecret(ssl,
                        (ecc_key*)ssl->hsKey, ssl->peerEccKey,
                        args->output + OPAQUE8_LEN, &args->length,
                        ssl->arrays->preMasterSecret + OPAQUE16_LEN,
                        &ssl->arrays->preMasterSz,
                        WOLFSSL_CLIENT_END
                    );
                #ifdef WOLFSSL_ASYNC_CRYPT
                    if (ret != WC_PENDING_E)
                #endif
                    {
                        FreeKey(ssl, DYNAMIC_TYPE_ECC,
                                                      (void**)&ssl->peerEccKey);
                        ssl->peerEccKeyPresent = 0;
                    }
                    break;
                }
            #endif /* (HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448) && !NO_PSK */
            #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                case ecc_diffie_hellman_kea:
                {
                #ifdef HAVE_ECC
                    ecc_key* peerKey;
                #endif

                #ifdef HAVE_CURVE25519
                    if (ssl->peerX25519KeyPresent) {
                        ret = X25519SharedSecret(ssl,
                            (curve25519_key*)ssl->hsKey, ssl->peerX25519Key,
                            args->encSecret + OPAQUE8_LEN, &args->encSz,
                            ssl->arrays->preMasterSecret,
                            &ssl->arrays->preMasterSz,
                            WOLFSSL_CLIENT_END
                        );
                        if (!ssl->specs.static_ecdh
                        #ifdef WOLFSSL_ASYNC_CRYPT
                            && ret != WC_PENDING_E
                        #endif
                        ) {
                            FreeKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                                   (void**)&ssl->peerX25519Key);
                            ssl->peerX25519KeyPresent = 0;
                        }
                        break;
                    }
                #endif
                #ifdef HAVE_CURVE448
                    if (ssl->peerX448KeyPresent) {
                        ret = X448SharedSecret(ssl,
                            (curve448_key*)ssl->hsKey, ssl->peerX448Key,
                            args->encSecret + OPAQUE8_LEN, &args->encSz,
                            ssl->arrays->preMasterSecret,
                            &ssl->arrays->preMasterSz,
                            WOLFSSL_CLIENT_END
                        );
                        if (!ssl->specs.static_ecdh
                        #ifdef WOLFSSL_ASYNC_CRYPT
                            && ret != WC_PENDING_E
                        #endif
                        ) {
                            FreeKey(ssl, DYNAMIC_TYPE_CURVE448,
                                                     (void**)&ssl->peerX448Key);
                            ssl->peerX448KeyPresent = 0;
                        }
                        break;
                    }
                #endif
                #ifdef HAVE_ECC
                    peerKey = (ssl->specs.static_ecdh) ?
                              ssl->peerEccDsaKey : ssl->peerEccKey;

                    ret = EccSharedSecret(ssl,
                              (ecc_key*)ssl->hsKey, peerKey,
                              args->encSecret + OPAQUE8_LEN, &args->encSz,
                              ssl->arrays->preMasterSecret,
                              &ssl->arrays->preMasterSz,
                              WOLFSSL_CLIENT_END);

                    if (!ssl->specs.static_ecdh
                #ifdef WOLFSSL_ASYNC_CRYPT
                        && ret != WC_PENDING_E
                #endif
                     && !ssl->options.keepResources) {
                        FreeKey(ssl, DYNAMIC_TYPE_ECC,
                                                      (void**)&ssl->peerEccKey);
                        ssl->peerEccKeyPresent = 0;
                    }
                #endif

                    break;
                }
            #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */
        FALL_THROUGH;

        case TLS_ASYNC_VERIFY:
        {
            switch(ssl->specs.kea)
            {
            #ifndef NO_RSA
                case rsa_kea:
                {
                    break;
                }
            #endif /* !NO_RSA */
            #ifndef NO_DH
                case diffie_hellman_kea:
                {
                    break;
                }
            #endif /* !NO_DH */
            #ifndef NO_PSK
                case psk_kea:
                {
                    break;
                }
            #endif /* !NO_PSK */
            #if !defined(NO_DH) && !defined(NO_PSK)
                case dhe_psk_kea:
                {
                    byte* pms = ssl->arrays->preMasterSecret;

                    /* validate args */
                    if (args->output == NULL || args->length == 0) {
                        ERROR_OUT(BAD_FUNC_ARG, exit_scke);
                    }

                    c16toa((word16)args->length, args->output);
                    args->encSz += args->length + OPAQUE16_LEN;
                    c16toa((word16)ssl->arrays->preMasterSz, pms);
                    ssl->arrays->preMasterSz += OPAQUE16_LEN;
                    pms += ssl->arrays->preMasterSz;

                    /* make psk pre master secret */
                    /* length of key + length 0s + length of key + key */
                    c16toa((word16)ssl->arrays->psk_keySz, pms);
                    pms += OPAQUE16_LEN;
                    XMEMCPY(pms, ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                    ssl->arrays->preMasterSz +=
                                         ssl->arrays->psk_keySz + OPAQUE16_LEN;
                    ForceZero(ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                    ssl->arrays->psk_keySz = 0; /* No further need */
                    break;
                }
            #endif /* !NO_DH && !NO_PSK */
            #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                case ecdhe_psk_kea:
                {
                    byte* pms = ssl->arrays->preMasterSecret;

                    /* validate args */
                    if (args->output == NULL || args->length > ENCRYPT_LEN) {
                        ERROR_OUT(BAD_FUNC_ARG, exit_scke);
                    }

                    /* place size of public key in output buffer */
                    *args->output = (byte)args->length;
                    args->encSz += args->length + OPAQUE8_LEN;

                    /* Create pre master secret is the concatenation of
                       eccSize + eccSharedKey + pskSize + pskKey */
                    c16toa((word16)ssl->arrays->preMasterSz, pms);
                    ssl->arrays->preMasterSz += OPAQUE16_LEN;
                    pms += ssl->arrays->preMasterSz;

                    c16toa((word16)ssl->arrays->psk_keySz, pms);
                    pms += OPAQUE16_LEN;
                    XMEMCPY(pms, ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                    ssl->arrays->preMasterSz +=
                                          ssl->arrays->psk_keySz + OPAQUE16_LEN;

                    ForceZero(ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                    ssl->arrays->psk_keySz = 0; /* No further need */
                    break;
                }
            #endif /* (HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448) && !NO_PSK */
            #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                case ecc_diffie_hellman_kea:
                {
                    if (args->encSecret == NULL) {
                        ret = BAD_STATE_E;
                        goto exit_scke;
                    }
                    else {
                        /* place size of public key in buffer */
                        *args->encSecret = (byte)args->encSz;
                        args->encSz += OPAQUE8_LEN;
                    }
                    break;
                }
            #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */
        FALL_THROUGH;

        case TLS_ASYNC_FINALIZE:
        {
            word32 tlsSz = 0;
            word32 idx = 0;

            if (ssl->options.tls || ssl->specs.kea == diffie_hellman_kea) {
                tlsSz = 2;
            }

            if (ssl->specs.kea == ecc_diffie_hellman_kea ||
                ssl->specs.kea == dhe_psk_kea ||
                ssl->specs.kea == ecdhe_psk_kea) { /* always off */
                tlsSz = 0;
            }

            idx = HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
            args->sendSz = args->encSz + tlsSz + idx;

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                idx    += DTLS_HANDSHAKE_EXTRA + DTLS_RECORD_EXTRA;
                args->sendSz += DTLS_HANDSHAKE_EXTRA + DTLS_RECORD_EXTRA;
            }
        #endif

            if (IsEncryptionOn(ssl, 1)) {
                args->sendSz += MAX_MSG_EXTRA;
            }

            /* check for available size */
            if ((ret = CheckAvailableSize(ssl, args->sendSz)) != 0)
                goto exit_scke;

            /* get output buffer */
            args->output = ssl->buffers.outputBuffer.buffer +
                           ssl->buffers.outputBuffer.length;

            AddHeaders(args->output, args->encSz + tlsSz, client_key_exchange, ssl);

            if (tlsSz) {
                c16toa((word16)args->encSz, &args->output[idx]);
                idx += OPAQUE16_LEN;
            }
            XMEMCPY(args->output + idx, args->encSecret, args->encSz);
            idx += args->encSz;

            if (IsEncryptionOn(ssl, 1)) {
                int recordHeaderSz = RECORD_HEADER_SZ;

                if (ssl->options.dtls)
                    recordHeaderSz += DTLS_RECORD_EXTRA;
                args->inputSz = idx - recordHeaderSz; /* buildmsg adds rechdr */
                args->input = (byte*)XMALLOC(args->inputSz, ssl->heap,
                                                       DYNAMIC_TYPE_IN_BUFFER);
                if (args->input == NULL) {
                    ERROR_OUT(MEMORY_E, exit_scke);
                }

                XMEMCPY(args->input, args->output + recordHeaderSz,
                                                                args->inputSz);
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            if (IsEncryptionOn(ssl, 1)) {
            #ifdef WOLFSSL_DTLS
                if (IsDtlsNotSctpMode(ssl) &&
                        (ret = DtlsMsgPoolSave(ssl, args->input, args->inputSz, client_key_exchange)) != 0) {
                    goto exit_scke;
                }
            #endif
                ret = BuildMessage(ssl, args->output, args->sendSz,
                            args->input, args->inputSz, handshake, 1, 0, 0, CUR_ORDER);
                XFREE(args->input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                args->input = NULL; /* make sure its not double free'd on cleanup */

                if (ret >= 0) {
                    args->sendSz = ret;
                    ret = 0;
                }
            }
            else {
            #ifdef WOLFSSL_DTLS
                if (IsDtlsNotSctpMode(ssl)) {
                    if ((ret = DtlsMsgPoolSave(ssl, args->output, args->sendSz, client_key_exchange)) != 0) {
                        goto exit_scke;
                    }
                }
                if (ssl->options.dtls)
                    DtlsSEQIncrement(ssl, CUR_ORDER);
            #endif
                ret = HashOutput(ssl, args->output, args->sendSz, 0);
            }

            if (ret != 0) {
                goto exit_scke;
            }

        #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
            if (ssl->hsInfoOn)
                AddPacketName(ssl, "ClientKeyExchange");
            if (ssl->toInfoOn) {
                ret = AddPacketInfo(ssl, "ClientKeyExchange", handshake,
                         args->output, args->sendSz, WRITE_PROTO, 0, ssl->heap);
                if (ret != 0) {
                    goto exit_scke;
                }
            }
        #endif

            ssl->buffers.outputBuffer.length += args->sendSz;

            if (!ssl->options.groupMessages) {
                ret = SendBuffered(ssl);
            }
            if (ret == 0 || ret == WANT_WRITE) {
                int tmpRet = MakeMasterSecret(ssl);
                if (tmpRet != 0) {
                    ret = tmpRet;   /* save WANT_WRITE unless more serious */
                }
                ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
                ssl->options.buildingMsg = 0;
            }
        #if defined(OPENSSL_EXTRA) && defined(HAVE_SECRET_CALLBACK)
            if (ssl->keyLogCb != NULL) {
                int secretSz = SECRET_LEN;
                ret = ssl->keyLogCb(ssl, ssl->arrays->masterSecret, &secretSz,
                                                                        NULL);
                if (ret != 0 || secretSz != SECRET_LEN)
                    return SESSION_SECRET_CB_E;
            }
        #endif /* OPENSSL_EXTRA && HAVE_SECRET_CALLBACK */
            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_scke:

    WOLFSSL_LEAVE("SendClientKeyExchange", ret);
    WOLFSSL_END(WC_FUNC_CLIENT_KEY_EXCHANGE_SEND);

#ifdef WOLFSSL_ASYNC_IO
    /* Handle async operation */
    if (ret == WC_PENDING_E || ret == WANT_WRITE) {
        if (ssl->options.buildingMsg)
            return ret;
        /* If we have completed all states then we will not enter this function
         * again. We need to do clean up now. */
    }
#endif

    /* No further need for PMS */
    if (ssl->arrays->preMasterSecret != NULL) {
        ForceZero(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);
    }
    ssl->arrays->preMasterSz = 0;

    /* Final cleanup */
#ifdef WOLFSSL_ASYNC_IO
    /* Cleanup async */
    FreeAsyncCtx(ssl, 0);
#else
    FreeSckeArgs(ssl, args);
#endif
    FreeKeyExchange(ssl);

    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(ret);
    }
    return ret;
}

#endif /* !WOLFSSL_NO_TLS12 */

#ifndef NO_CERTS

#ifndef WOLFSSL_NO_TLS12

#ifndef WOLFSSL_NO_CLIENT_AUTH
typedef struct ScvArgs {
    byte*  output; /* not allocated */
#ifndef NO_RSA
    byte*  verifySig;
#endif
    byte*  verify; /* not allocated */
    byte*  input;
    word32 idx;
    word32 extraSz;
    word32 sigSz;
    int    sendSz;
    int    inputSz;
    word16 length;
    byte   sigAlgo;
} ScvArgs;

static void FreeScvArgs(WOLFSSL* ssl, void* pArgs)
{
    ScvArgs* args = (ScvArgs*)pArgs;

    (void)ssl;

#ifndef NO_RSA
    if (args->verifySig) {
        XFREE(args->verifySig, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
        args->verifySig = NULL;
    }
#endif
    if (args->input) {
        XFREE(args->input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
        args->input = NULL;
    }
}

/* handle generation of certificate_verify (15) */
int SendCertificateVerify(WOLFSSL* ssl)
{
    int ret = 0;
#ifdef WOLFSSL_ASYNC_IO
    ScvArgs* args = NULL;
    WOLFSSL_ASSERT_SIZEOF_GE(ssl->async->args, *args);
#else
    ScvArgs  args[1];
#endif

    WOLFSSL_START(WC_FUNC_CERTIFICATE_VERIFY_SEND);
    WOLFSSL_ENTER("SendCertificateVerify");

#ifdef WOLFSSL_ASYNC_IO
    if (ssl->async == NULL) {
        ssl->async = (struct WOLFSSL_ASYNC*)
                XMALLOC(sizeof(struct WOLFSSL_ASYNC), ssl->heap,
                        DYNAMIC_TYPE_ASYNC);
        if (ssl->async == NULL)
            ERROR_OUT(MEMORY_E, exit_scv);
        XMEMSET(ssl->async, 0, sizeof(struct WOLFSSL_ASYNC));
    }
    args = (ScvArgs*)ssl->async->args;
#ifdef WOLFSSL_ASYNC_CRYPT
    /* BuildMessage does its own Pop */
    if (ssl->error != WC_PENDING_E ||
            ssl->options.asyncState != TLS_ASYNC_END)
        ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
    if (ret != WC_NOT_PENDING_E) {
        /* Check for error */
        if (ret < 0)
            goto exit_scv;
    }
    else
#endif
    if (ssl->options.buildingMsg) {
        /* We should be in the sending state. */
        if (ssl->options.asyncState != TLS_ASYNC_END) {
            ret = BAD_STATE_E;
            goto exit_scv;
        }
    }
    else
#endif
    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(ScvArgs));
    #ifdef WOLFSSL_ASYNC_IO
        ssl->async->freeArgs = FreeScvArgs;
    #endif
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
            if (ssl->options.sendVerify == SEND_BLANK_CERT) {
                return 0;  /* sent blank cert, can't verify */
            }

            args->sendSz = MAX_CERT_VERIFY_SZ + MAX_MSG_EXTRA;
            if (IsEncryptionOn(ssl, 1)) {
                args->sendSz += MAX_MSG_EXTRA;
            }

            /* Use tmp buffer */
            args->input = (byte*)XMALLOC(args->sendSz,
                    ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (args->input == NULL)
                ERROR_OUT(MEMORY_E, exit_scv);
            args->output = args->input;

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;

        case TLS_ASYNC_BUILD:
        {
            ret = BuildCertHashes(ssl, &ssl->hsHashes->certHashes);
            if (ret != 0) {
                goto exit_scv;
            }

            if (ssl->buffers.key == NULL) {
            #ifdef HAVE_PK_CALLBACKS
                if (wolfSSL_CTX_IsPrivatePkSet(ssl->ctx))
                    args->length = GetPrivateKeySigSize(ssl);
                else
            #endif
                    ERROR_OUT(NO_PRIVATE_KEY, exit_scv);
            }
            else {
                /* Decode private key. */
                ret = DecodePrivateKey(ssl, &args->length);
                if (ret != 0) {
                    goto exit_scv;
                }
            }

            if (args->length == 0) {
                ERROR_OUT(NO_PRIVATE_KEY, exit_scv);
            }

            /* idx is used to track verify pointer offset to output */
            args->idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
            args->verify = &args->output[RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ];
            args->extraSz = 0;  /* tls 1.2 hash/sig */

            /* build encoded signature buffer */
            ssl->buffers.sig.length = MAX_ENCODED_SIG_SZ;
            ssl->buffers.sig.buffer = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ,
                                        ssl->heap, DYNAMIC_TYPE_SIGNATURE);
            if (ssl->buffers.sig.buffer == NULL) {
                ERROR_OUT(MEMORY_E, exit_scv);
            }

        #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                args->idx += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                args->verify += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
            }
        #endif

    #ifndef NO_OLD_TLS
        #ifndef NO_SHA
            /* old tls default */
            SetDigest(ssl, sha_mac);
        #endif
    #else
        #ifndef NO_SHA256
            /* new tls default */
            SetDigest(ssl, sha256_mac);
        #endif
    #endif /* !NO_OLD_TLS */

            if (ssl->hsType == DYNAMIC_TYPE_RSA) {
        #ifdef WC_RSA_PSS
                if (IsAtLeastTLSv1_2(ssl) &&
                                (ssl->pssAlgo & (1 << ssl->suites->hashAlgo))) {
                    args->sigAlgo = rsa_pss_sa_algo;
                }
                else
        #endif
                    args->sigAlgo = rsa_sa_algo;
            }
            else if (ssl->hsType == DYNAMIC_TYPE_ECC)
                args->sigAlgo = ecc_dsa_sa_algo;
            else if (ssl->hsType == DYNAMIC_TYPE_ED25519)
                args->sigAlgo = ed25519_sa_algo;
            else if (ssl->hsType == DYNAMIC_TYPE_ED448)
                args->sigAlgo = ed448_sa_algo;

            if (IsAtLeastTLSv1_2(ssl)) {
                EncodeSigAlg(ssl->suites->hashAlgo, args->sigAlgo,
                             args->verify);
                args->extraSz = HASH_SIG_SIZE;
                SetDigest(ssl, ssl->suites->hashAlgo);
            }
        #ifndef NO_OLD_TLS
            else {
                /* if old TLS load MD5 and SHA hash as value to sign
                 * MD5 and SHA must be first two buffers in stucture */
                XMEMCPY(ssl->buffers.sig.buffer,
                                (byte*)&ssl->hsHashes->certHashes, FINISHED_SZ);
            }
        #endif

        #ifndef NO_RSA
            if (args->sigAlgo == rsa_sa_algo) {
                ssl->buffers.sig.length = FINISHED_SZ;
                args->sigSz = ENCRYPT_LEN;

                if (IsAtLeastTLSv1_2(ssl)) {
                    ssl->buffers.sig.length = wc_EncodeSignature(
                            ssl->buffers.sig.buffer, ssl->buffers.digest.buffer,
                            ssl->buffers.digest.length,
                            TypeHash(ssl->suites->hashAlgo));
                }

                /* prepend hdr */
                c16toa(args->length, args->verify + args->extraSz);
            }
            #ifdef WC_RSA_PSS
            else if (args->sigAlgo == rsa_pss_sa_algo) {
                XMEMCPY(ssl->buffers.sig.buffer, ssl->buffers.digest.buffer,
                        ssl->buffers.digest.length);
                ssl->buffers.sig.length = ssl->buffers.digest.length;
                args->sigSz = ENCRYPT_LEN;

                /* prepend hdr */
                c16toa(args->length, args->verify + args->extraSz);
            }
            #endif
        #endif /* !NO_RSA */
        #if defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)
            if (args->sigAlgo == ed25519_sa_algo) {
                ret = Ed25519CheckPubKey(ssl);
                if (ret != 0)
                    goto exit_scv;
            }
        #endif /* HAVE_ED25519 && !NO_ED25519_CLIENT_AUTH */
        #if defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)
            if (args->sigAlgo == ed448_sa_algo) {
                ret = Ed448CheckPubKey(ssl);
                if (ret != 0)
                    goto exit_scv;
            }
        #endif /* HAVE_ED448 && !NO_ED448_CLIENT_AUTH */

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */
        FALL_THROUGH;

        case TLS_ASYNC_DO:
        {
        #ifdef HAVE_ECC
            if (ssl->hsType == DYNAMIC_TYPE_ECC) {
                ecc_key* key = (ecc_key*)ssl->hsKey;

                ret = EccSign(ssl,
                    ssl->buffers.digest.buffer, ssl->buffers.digest.length,
                    ssl->buffers.sig.buffer,
                    (word32*)&ssl->buffers.sig.length,
                    key,
            #ifdef HAVE_PK_CALLBACKS
                    ssl->buffers.key
            #else
                    NULL
            #endif
                );
            }
        #endif /* HAVE_ECC */
        #if defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)
           if (ssl->hsType == DYNAMIC_TYPE_ED25519) {
                ed25519_key* key = (ed25519_key*)ssl->hsKey;

                ret = Ed25519Sign(ssl,
                    ssl->hsHashes->messages, ssl->hsHashes->length,
                    ssl->buffers.sig.buffer, (word32*)&ssl->buffers.sig.length,
                    key,
            #ifdef HAVE_PK_CALLBACKS
                    ssl->buffers.key
            #else
                    NULL
            #endif
                );
            }
        #endif /* HAVE_ED25519 && !NO_ED25519_CLIENT_AUTH */
        #if defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)
           if (ssl->hsType == DYNAMIC_TYPE_ED448) {
                ed448_key* key = (ed448_key*)ssl->hsKey;

                ret = Ed448Sign(ssl,
                    ssl->hsHashes->messages, ssl->hsHashes->length,
                    ssl->buffers.sig.buffer, (word32*)&ssl->buffers.sig.length,
                    key,
            #ifdef HAVE_PK_CALLBACKS
                    ssl->buffers.key
            #else
                    NULL
            #endif
                );
            }
        #endif /* HAVE_ED448 && !NO_ED448_CLIENT_AUTH */
        #ifndef NO_RSA
            if (ssl->hsType == DYNAMIC_TYPE_RSA) {
                RsaKey* key = (RsaKey*)ssl->hsKey;

                /* restore verify pointer */
                args->verify = &args->output[args->idx];

                ret = RsaSign(ssl,
                    ssl->buffers.sig.buffer, ssl->buffers.sig.length,
                    args->verify + args->extraSz + VERIFY_HEADER, &args->sigSz,
                    args->sigAlgo, ssl->suites->hashAlgo, key,
                    ssl->buffers.key
                );
            }
        #endif /* !NO_RSA */

            /* Check for error */
            if (ret != 0) {
                goto exit_scv;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */
        FALL_THROUGH;

        case TLS_ASYNC_VERIFY:
        {
            /* restore verify pointer */
            args->verify = &args->output[args->idx];

            switch (ssl->hsType) {
    #if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
        #ifdef HAVE_ECC
                case DYNAMIC_TYPE_ECC:
            #ifdef WOLFSSL_CHECK_SIG_FAULTS
                {
                    ecc_key* key = (ecc_key*)ssl->hsKey;

                    ret = EccVerify(ssl,
                        ssl->buffers.sig.buffer, ssl->buffers.sig.length,
                        ssl->buffers.digest.buffer, ssl->buffers.digest.length,
                        key,
                    #ifdef HAVE_PK_CALLBACKS
                        ssl->buffers.key
                    #else
                        NULL
                    #endif
                    );
                    if (ret != 0) {
                        WOLFSSL_MSG("Failed to verify ECC signature");
                        goto exit_scv;
                    }
                }
                #if defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
                FALL_THROUGH;
                #endif
            #endif /* WOLFSSL_CHECK_SIG_FAULTS */
        #endif /* HAVE_ECC */
        #ifdef HAVE_ED25519
                case DYNAMIC_TYPE_ED25519:
        #endif
        #ifdef HAVE_ED448
                case DYNAMIC_TYPE_ED448:
        #endif
                    args->length = (word16)ssl->buffers.sig.length;
                    /* prepend hdr */
                    c16toa(args->length, args->verify + args->extraSz);
                    XMEMCPY(args->verify + args->extraSz + VERIFY_HEADER,
                            ssl->buffers.sig.buffer, ssl->buffers.sig.length);
                    break;
    #endif /* HAVE_ECC || HAVE_ED25519 || HAVE_ED448 */
            #ifndef NO_RSA
                case DYNAMIC_TYPE_RSA:
                {
                    RsaKey* key = (RsaKey*)ssl->hsKey;

                    if (args->verifySig == NULL) {
                        args->verifySig = (byte*)XMALLOC(args->sigSz, ssl->heap,
                                          DYNAMIC_TYPE_SIGNATURE);
                        if (args->verifySig == NULL) {
                            ERROR_OUT(MEMORY_E, exit_scv);
                        }
                        XMEMCPY(args->verifySig, args->verify + args->extraSz +
                                                    VERIFY_HEADER, args->sigSz);
                    }

                    /* check for signature faults */
                    ret = VerifyRsaSign(ssl,
                        args->verifySig, args->sigSz,
                        ssl->buffers.sig.buffer, ssl->buffers.sig.length,
                        args->sigAlgo, ssl->suites->hashAlgo, key,
                        ssl->buffers.key
                    );

                    /* free temporary buffer now */
                    if (ret != WC_PENDING_E) {
                        XFREE(args->verifySig, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                        args->verifySig = NULL;
                    }
                    break;
                }
            #endif /* !NO_RSA */
                default:
                    break;
            }

            /* Check for error */
            if (ret != 0) {
                goto exit_scv;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */
        FALL_THROUGH;

        case TLS_ASYNC_FINALIZE:
        {
            if (args->output == NULL) {
                ERROR_OUT(BUFFER_ERROR, exit_scv);
            }
            AddHeaders(args->output, (word32)args->length + args->extraSz +
                                        VERIFY_HEADER, certificate_verify, ssl);

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            ret = SendHandshakeMsg(ssl, args->output,
                (word32)args->length + args->extraSz + VERIFY_HEADER,
                certificate_verify, "CertificateVerify");
            if (ret != 0)
                goto exit_scv;

            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_scv:

    WOLFSSL_LEAVE("SendCertificateVerify", ret);
    WOLFSSL_END(WC_FUNC_CERTIFICATE_VERIFY_SEND);

#ifdef WOLFSSL_ASYNC_IO
    /* Handle async operation */
    if (ret == WANT_WRITE
#ifdef WOLFSSL_ASYNC_CRYPT
            || ret == WC_PENDING_E
#endif
            )
        return ret;
#endif /* WOLFSSL_ASYNC_IO */

    /* Digest is not allocated, so do this to prevent free */
    ssl->buffers.digest.buffer = NULL;
    ssl->buffers.digest.length = 0;

    /* Final cleanup */
#ifdef WOLFSSL_ASYNC_IO
    /* Cleanup async */
    FreeAsyncCtx(ssl, 0);
#else
    FreeScvArgs(ssl, args);
#endif
    FreeKeyExchange(ssl);

    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    return ret;
}
#endif /* WOLFSSL_NO_CLIENT_AUTH */

#endif /* WOLFSSL_NO_TLS12 */

#endif /* NO_CERTS */


#ifdef HAVE_SESSION_TICKET
int SetTicket(WOLFSSL* ssl, const byte* ticket, word32 length)
{
    /* Free old dynamic ticket if we already had one */
    if (ssl->session->ticketLenAlloc > 0) {
        XFREE(ssl->session->ticket, ssl->heap, DYNAMIC_TYPE_SESSION_TICK);
        ssl->session->ticket = ssl->session->staticTicket;
        ssl->session->ticketLenAlloc = 0;
    }

    if (length > sizeof(ssl->session->staticTicket)) {
        byte* sessionTicket =
                   (byte*)XMALLOC(length, ssl->heap, DYNAMIC_TYPE_SESSION_TICK);
        if (sessionTicket == NULL)
            return MEMORY_E;
        ssl->session->ticket = sessionTicket;
        ssl->session->ticketLenAlloc = (word16)length;
    }
    ssl->session->ticketLen = (word16)length;

    if (length > 0) {
        XMEMCPY(ssl->session->ticket, ticket, length);
        if (ssl->session_ticket_cb != NULL) {
            ssl->session_ticket_cb(ssl,
                                   ssl->session->ticket, ssl->session->ticketLen,
                                   ssl->session_ticket_ctx);
        }
        /* Create a fake sessionID based on the ticket, this will
         * supersede the existing session cache info. */
        ssl->options.haveSessionId = 1;
#ifdef WOLFSSL_TLS13
        if (ssl->options.tls1_3) {
            XMEMCPY(ssl->session->sessionID,
                                 ssl->session->ticket + length - ID_LEN, ID_LEN);
            ssl->session->sessionIDSz = ID_LEN;
        }
        else
#endif
        {
            XMEMCPY(ssl->arrays->sessionID,
                                 ssl->session->ticket + length - ID_LEN, ID_LEN);
            ssl->arrays->sessionIDSz = ID_LEN;
        }
    }

    return 0;
}

#ifndef WOLFSSL_NO_TLS12

/* handle processing of session_ticket (4) */
static int DoSessionTicket(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
    word32 size)
{
    word32 begin = *inOutIdx;
    word32 lifetime;
    word16 length;
    int    ret;

    if (ssl->expect_session_ticket == 0) {
        WOLFSSL_MSG("Unexpected session ticket");
        WOLFSSL_ERROR_VERBOSE(SESSION_TICKET_EXPECT_E);
        return SESSION_TICKET_EXPECT_E;
    }

    if (OPAQUE32_LEN > size)
        return BUFFER_ERROR;

    ato32(input + *inOutIdx, &lifetime);
    *inOutIdx += OPAQUE32_LEN;

    if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
        return BUFFER_ERROR;

    ato16(input + *inOutIdx, &length);
    *inOutIdx += OPAQUE16_LEN;

    if ((*inOutIdx - begin) + length > size)
        return BUFFER_ERROR;

    if ((ret = SetTicket(ssl, input + *inOutIdx, length)) != 0)
        return ret;
    *inOutIdx += length;
    if (length > 0) {
        ssl->timeout = lifetime;
#ifndef NO_SESSION_CACHE
        AddSession(ssl);
#endif
    }

    if (IsEncryptionOn(ssl, 0)) {
        *inOutIdx += ssl->keys.padSz;
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead)
            *inOutIdx += MacSize(ssl);
    #endif
    }

    ssl->expect_session_ticket = 0;

    return 0;
}

#endif /* !WOLFSSL_NO_TLS12 */

#endif /* HAVE_SESSION_TICKET */

#endif /* NO_WOLFSSL_CLIENT */


#ifndef NO_CERTS

#ifdef WOLF_PRIVATE_KEY_ID
    int GetPrivateKeySigSize(WOLFSSL* ssl)
    {
        int sigSz = 0;

        if (ssl == NULL)
            return 0;

        switch (ssl->buffers.keyType) {
        #ifndef NO_RSA
        #ifdef WC_RSA_PSS
            case rsa_pss_sa_algo:
        #endif
            case rsa_sa_algo:
                sigSz = ssl->buffers.keySz;
                ssl->hsType = DYNAMIC_TYPE_RSA;
                break;
        #endif
        #ifdef HAVE_ECC
            case ecc_dsa_sa_algo:
                sigSz = wc_ecc_sig_size_calc(ssl->buffers.keySz);
                ssl->hsType = DYNAMIC_TYPE_ECC;
                break;
        #endif
        #ifdef HAVE_ED25519
            case ed25519_sa_algo:
                sigSz = ED25519_SIG_SIZE; /* fixed known value */
                ssl->hsType = DYNAMIC_TYPE_ED25519;
                break;
        #endif
        #ifdef HAVE_ED448
            case ed448_sa_algo:
                sigSz = ED448_SIG_SIZE; /* fixed known value */
                ssl->hsType = DYNAMIC_TYPE_ED448;
                break;
        #endif
            default:
                break;
        }
        return sigSz;
    }
#endif /* HAVE_PK_CALLBACKS */

#endif /* NO_CERTS */

#ifdef HAVE_ECC
    /* returns the WOLFSSL_* version of the curve from the OID sum */
    word16 GetCurveByOID(int oidSum) {
        switch(oidSum) {
    #if (defined(HAVE_ECC160) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 160
        #ifndef NO_ECC_SECP
            case ECC_SECP160R1_OID:
                return WOLFSSL_ECC_SECP160R1;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_SECPR2
            case ECC_SECP160R2_OID:
                return WOLFSSL_ECC_SECP160R2;
        #endif /* HAVE_ECC_SECPR2 */
        #ifdef HAVE_ECC_KOBLITZ
            case ECC_SECP160K1_OID:
                return WOLFSSL_ECC_SECP160K1;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
    #if (defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 192
        #ifndef NO_ECC_SECP
            case ECC_SECP192R1_OID:
                return WOLFSSL_ECC_SECP192R1;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case ECC_SECP192K1_OID:
                return WOLFSSL_ECC_SECP192K1;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
    #if (defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 224
        #ifndef NO_ECC_SECP
            case ECC_SECP224R1_OID:
                return WOLFSSL_ECC_SECP224R1;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case ECC_SECP224K1_OID:
                return WOLFSSL_ECC_SECP224K1;
        #endif /* HAVE_ECC_KOBLITZ */
    #endif
    #if (!defined(NO_ECC256)  || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 256
        #ifndef NO_ECC_SECP
            case ECC_SECP256R1_OID:
                return WOLFSSL_ECC_SECP256R1;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_KOBLITZ
            case ECC_SECP256K1_OID:
                return WOLFSSL_ECC_SECP256K1;
        #endif /* HAVE_ECC_KOBLITZ */
        #ifdef HAVE_ECC_BRAINPOOL
            case ECC_BRAINPOOLP256R1_OID:
                return WOLFSSL_ECC_BRAINPOOLP256R1;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
    #if (defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 384
        #ifndef NO_ECC_SECP
            case ECC_SECP384R1_OID:
                return WOLFSSL_ECC_SECP384R1;
        #endif /* !NO_ECC_SECP */
        #ifdef HAVE_ECC_BRAINPOOL
            case ECC_BRAINPOOLP384R1_OID:
                return WOLFSSL_ECC_BRAINPOOLP384R1;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
    #if (defined(HAVE_ECC512) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 512
        #ifdef HAVE_ECC_BRAINPOOL
            case ECC_BRAINPOOLP512R1_OID:
                return WOLFSSL_ECC_BRAINPOOLP512R1;
        #endif /* HAVE_ECC_BRAINPOOL */
    #endif
    #if (defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)) && ECC_MIN_KEY_SZ <= 521
        #ifndef NO_ECC_SECP
            case ECC_SECP521R1_OID:
                return WOLFSSL_ECC_SECP521R1;
        #endif /* !NO_ECC_SECP */
    #endif
            default:
                WOLFSSL_MSG("Curve OID not compiled in or implemented");
                return 0;
        }
    }
#endif /* HAVE_ECC */


#ifndef NO_WOLFSSL_SERVER

#ifndef WOLFSSL_NO_TLS12

    /* handle generation of server_hello (2) */
    int SendServerHello(WOLFSSL* ssl)
    {
        int    ret;
        byte   *output;
        word16 length;
        word32 idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int    sendSz;
        byte   sessIdSz = ID_LEN;
    #if defined(HAVE_TLS_EXTENSIONS) && defined(HAVE_SESSION_TICKET)
        byte   echoId   = 0;  /* ticket echo id flag */
    #endif
        byte   cacheOff = 0;  /* session cache off flag */

        WOLFSSL_START(WC_FUNC_SERVER_HELLO_SEND);
        WOLFSSL_ENTER("SendServerHello");

        length = VERSION_SZ + RAN_LEN
               + ID_LEN + ENUM_LEN
               + SUITE_LEN
               + ENUM_LEN;

#ifdef HAVE_TLS_EXTENSIONS
        ret = TLSX_GetResponseSize(ssl, server_hello, &length);
        if (ret != 0)
            return ret;
    #ifdef HAVE_SESSION_TICKET
        if (ssl->options.useTicket) {
            /* echo session id sz can be 0,32 or bogus len in between */
            sessIdSz = ssl->arrays->sessionIDSz;
            if (sessIdSz > ID_LEN) {
                WOLFSSL_MSG("Bad bogus session id len");
                return BUFFER_ERROR;
            }
            if (!IsAtLeastTLSv1_3(ssl->version))
                length -= (ID_LEN - sessIdSz);  /* adjust ID_LEN assumption */
            echoId = 1;
        }
    #endif /* HAVE_SESSION_TICKET */
#else
        if (ssl->options.haveEMS) {
            length += HELLO_EXT_SZ_SZ + HELLO_EXT_SZ;
        }
#endif

        /* is the session cache off at build or runtime */
#ifdef NO_SESSION_CACHE
        cacheOff = 1;
#else
        if (ssl->options.sessionCacheOff == 1) {
            cacheOff = 1;
        }
#endif

        /* if no session cache don't send a session ID unless we're echoing
         * an ID as part of session tickets */
        if (cacheOff == 1
        #if defined(HAVE_TLS_EXTENSIONS) && defined(HAVE_SESSION_TICKET)
            && echoId == 0
        #endif
            ) {
            length -= ID_LEN;    /* adjust ID_LEN assumption */
            sessIdSz = 0;
        }

        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
        #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            idx    += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
            sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
        }
        #endif /* WOLFSSL_DTLS */

        if (IsEncryptionOn(ssl, 1))
            sendSz += MAX_MSG_EXTRA;

        /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
         * is not advanced yet */
        ssl->options.buildingMsg = 1;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, length, server_hello, ssl);

        /* now write to output */
        /* first version */
        output[idx++] = (byte)ssl->version.major;
        output[idx++] = (byte)ssl->version.minor;

        /* then random and session id */
        if (!ssl->options.resuming) {
            /* generate random part and session id */
            ret = wc_RNG_GenerateBlock(ssl->rng, output + idx,
                RAN_LEN + sizeof(sessIdSz) + sessIdSz);
            if (ret != 0)
                return ret;

#ifdef WOLFSSL_TLS13
            if (TLSv1_3_Capable(ssl)) {
                /* TLS v1.3 capable server downgraded. */
                XMEMCPY(output + idx + RAN_LEN - (TLS13_DOWNGRADE_SZ + 1),
                        tls13Downgrade, TLS13_DOWNGRADE_SZ);
                output[idx + RAN_LEN - 1] = (byte)IsAtLeastTLSv1_2(ssl);
            }
            else
#endif
            if (ssl->ctx->method->version.major == SSLv3_MAJOR &&
                ssl->ctx->method->version.minor == TLSv1_2_MINOR &&
                (wolfSSL_get_options(ssl) & WOLFSSL_OP_NO_TLSv1_2) == 0 &&
                !IsAtLeastTLSv1_2(ssl)) {
                /* TLS v1.2 capable server downgraded. */
                XMEMCPY(output + idx + RAN_LEN - (TLS13_DOWNGRADE_SZ + 1),
                        tls13Downgrade, TLS13_DOWNGRADE_SZ);
                output[idx + RAN_LEN - 1] = 0;
            }

            /* store info in SSL for later */
            XMEMCPY(ssl->arrays->serverRandom, output + idx, RAN_LEN);
            idx += RAN_LEN;
            output[idx++] = sessIdSz;
            XMEMCPY(ssl->arrays->sessionID, output + idx, sessIdSz);
            ssl->arrays->sessionIDSz = sessIdSz;
        }
        else {
            /* If resuming, use info from SSL */
            XMEMCPY(output + idx, ssl->arrays->serverRandom, RAN_LEN);
            idx += RAN_LEN;
            output[idx++] = sessIdSz;
            XMEMCPY(output + idx, ssl->arrays->sessionID, sessIdSz);
        }
        idx += sessIdSz;

#ifdef SHOW_SECRETS
        {
            int j;
            printf("server random: ");
            for (j = 0; j < RAN_LEN; j++)
                printf("%02x", ssl->arrays->serverRandom[j]);
            printf("\n");
        }
#endif

        /* then cipher suite */
        output[idx++] = ssl->options.cipherSuite0;
        output[idx++] = ssl->options.cipherSuite;

        /* then compression */
        if (ssl->options.usingCompression)
            output[idx++] = ZLIB_COMPRESSION;
        else
            output[idx++] = NO_COMPRESSION;

        /* last, extensions */
#ifdef HAVE_TLS_EXTENSIONS
        {
            word16 offset = 0;
            ret = TLSX_WriteResponse(ssl, output + idx, server_hello, &offset);
            if (ret != 0)
                return ret;
            idx += offset;
        }
#else
#ifdef HAVE_EXTENDED_MASTER
        if (ssl->options.haveEMS) {
            c16toa(HELLO_EXT_SZ, output + idx);
            idx += HELLO_EXT_SZ_SZ;

            c16toa(HELLO_EXT_EXTMS, output + idx);
            idx += HELLO_EXT_TYPE_SZ;
            c16toa(0, output + idx);
            /*idx += HELLO_EXT_SZ_SZ;*/
            /* idx is not used after this point. uncomment the line above
             * if adding any more extensions in the future. */
        }
#endif
#endif

        if (IsEncryptionOn(ssl, 1)) {
            byte* input;
            int   inputSz = idx; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls)
                recordHeaderSz += DTLS_RECORD_EXTRA;
            inputSz -= recordHeaderSz;
            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            #ifdef WOLFSSL_DTLS
            if (IsDtlsNotSctpMode(ssl) &&
                    (ret = DtlsMsgPoolSave(ssl, input, inputSz, server_hello)) != 0) {
                XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                return ret;
            }
            #endif
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        } else {
            #ifdef WOLFSSL_DTLS
                if (IsDtlsNotSctpMode(ssl)) {
                    if ((ret = DtlsMsgPoolSave(ssl, output, sendSz, server_hello)) != 0)
                        return ret;
                }
                if (ssl->options.dtls)
                    DtlsSEQIncrement(ssl, CUR_ORDER);
            #endif
            ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0)
                return ret;
        }

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "ServerHello");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "ServerHello", handshake, output, sendSz,
                          WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
    #endif

        ssl->options.serverState = SERVER_HELLO_COMPLETE;
        ssl->options.buildingMsg = 0;
        ssl->buffers.outputBuffer.length += sendSz;

        if (ssl->options.groupMessages)
            ret = 0;
        else
            ret = SendBuffered(ssl);

        WOLFSSL_LEAVE("SendServerHello", ret);
        WOLFSSL_END(WC_FUNC_SERVER_HELLO_SEND);

        return ret;
    }


#if defined(HAVE_ECC)

    static byte SetCurveId(ecc_key* key)
    {
        if (key == NULL || key->dp == NULL) {
            WOLFSSL_MSG("SetCurveId: Invalid key!");
            return 0;
        }

        return (byte)GetCurveByOID(key->dp->oidSum);
    }

#endif /* HAVE_ECC */

    typedef struct SskeArgs {
        byte*  output; /* not allocated */
    #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        byte*  exportBuf;
    #endif
    #ifndef NO_RSA
        byte*  verifySig;
    #endif
        byte*  input;
        word32 idx;
        word32 tmpSigSz;
        word32 length;
        word32 sigSz;
    #if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448) || \
                                                                !defined(NO_RSA)
        word32 sigDataSz;
    #endif
    #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        word32 exportSz;
    #endif
        int    sendSz;
        int    inputSz;
    } SskeArgs;

    static void FreeSskeArgs(WOLFSSL* ssl, void* pArgs)
    {
        SskeArgs* args = (SskeArgs*)pArgs;

        (void)ssl;

    #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
        if (args->exportBuf) {
            XFREE(args->exportBuf, ssl->heap, DYNAMIC_TYPE_DER);
            args->exportBuf = NULL;
        }
    #endif
    #ifndef NO_RSA
        if (args->verifySig) {
            XFREE(args->verifySig, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
            args->verifySig = NULL;
        }
    #endif
        (void)args;
    }

    /* handle generation of server_key_exchange (12) */
    int SendServerKeyExchange(WOLFSSL* ssl)
    {
        int ret = 0;
    #ifdef WOLFSSL_ASYNC_IO
        SskeArgs* args = NULL;
        WOLFSSL_ASSERT_SIZEOF_GE(ssl->async->args, *args);
    #else
        SskeArgs  args[1];
    #endif

        WOLFSSL_START(WC_FUNC_SERVER_KEY_EXCHANGE_SEND);
        WOLFSSL_ENTER("SendServerKeyExchange");

    #ifdef WOLFSSL_ASYNC_IO
        if (ssl->async == NULL) {
            ssl->async = (struct WOLFSSL_ASYNC*)
                    XMALLOC(sizeof(struct WOLFSSL_ASYNC), ssl->heap,
                            DYNAMIC_TYPE_ASYNC);
            if (ssl->async == NULL)
                ERROR_OUT(MEMORY_E, exit_sske);
            XMEMSET(ssl->async, 0, sizeof(struct WOLFSSL_ASYNC));
        }
        args = (SskeArgs*)ssl->async->args;
    #ifdef WOLFSSL_ASYNC_CRYPT
        ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
        if (ret != WC_NOT_PENDING_E) {
            /* Check for error */
            if (ret < 0)
                goto exit_sske;
        }
        else
    #endif
        if (ssl->options.buildingMsg) {
            /* We should be in the sending state. */
            if (ssl->options.asyncState != TLS_ASYNC_END) {
                ret = BAD_STATE_E;
                goto exit_sske;
            }
        }
        else
    #endif
        {
            /* Reset state */
            ret = 0;
            ssl->options.asyncState = TLS_ASYNC_BEGIN;
            XMEMSET(args, 0, sizeof(SskeArgs));
        #ifdef WOLFSSL_ASYNC_IO
            ssl->async->freeArgs = FreeSskeArgs;
        #endif
        }

        switch(ssl->options.asyncState)
        {
            case TLS_ASYNC_BEGIN:
            {
                /* Do some checks / debug msgs */
                switch(ssl->specs.kea)
                {
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                    {
                        WOLFSSL_MSG("Using ephemeral ECDH PSK");
                        break;
                    }
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                #if defined(HAVE_ECC)
                    case ecc_diffie_hellman_kea:
                    {
                        if (ssl->specs.static_ecdh) {
                            WOLFSSL_MSG("Using Static ECDH, not sending "
                                        "ServerKeyExchange");
                            ERROR_OUT(0, exit_sske);
                        }

                        WOLFSSL_MSG("Using ephemeral ECDH");
                        break;
                    }
                #endif /* HAVE_ECC */
                }

                /* Preparing keys */
                switch(ssl->specs.kea)
                {
                #ifndef NO_PSK
                    case psk_kea:
                    {
                        /* Nothing to do in this sub-state */
                        break;
                    }
                #endif /* !NO_PSK */
                #if !defined(NO_DH) && (!defined(NO_PSK) || !defined(NO_RSA) \
                          || (defined(HAVE_ANON) && !defined(WOLFSSL_NO_TLS12)))
                #if !defined(NO_PSK)
                    case dhe_psk_kea:
                #endif
                #if !defined(NO_RSA) || (defined(HAVE_ANON) && \
                                         !defined(WOLFSSL_NO_TLS12))
                    case diffie_hellman_kea:
                #endif
#if (defined(WOLFSSL_TLS13) || defined(HAVE_FFDHE)) && !defined(HAVE_PUBLIC_FFDHE)
                    if (ssl->namedGroup) {
                        word32 pSz = 0;

                        ret = wc_DhGetNamedKeyParamSize(ssl->namedGroup, &pSz,
                                NULL, NULL);
                        if (ret != 0)
                            goto exit_sske;

                        if (ssl->buffers.serverDH_Pub.buffer == NULL) {
                            /* Free'd in SSL_ResourceFree and
                             * FreeHandshakeResources */
                            ssl->buffers.serverDH_Pub.buffer = (byte*)XMALLOC(
                                    pSz, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
                            if (ssl->buffers.serverDH_Pub.buffer == NULL) {
                                ERROR_OUT(MEMORY_E, exit_sske);
                            }
                            ssl->buffers.serverDH_Pub.length = pSz;
                        }
                        ssl->options.dhKeySz =(word16)pSz;

                        pSz = wc_DhGetNamedKeyMinSize(ssl->namedGroup);

                        if (ssl->buffers.serverDH_Priv.buffer == NULL) {
                            /* Free'd in SSL_ResourceFree and
                             * FreeHandshakeResources */
                            ssl->buffers.serverDH_Priv.buffer = (byte*)XMALLOC(
                                    pSz, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                            if (ssl->buffers.serverDH_Priv.buffer == NULL) {
                                ERROR_OUT(MEMORY_E, exit_sske);
                            }
                            ssl->buffers.serverDH_Priv.length = pSz;
                        }

                        ret = AllocKey(ssl, DYNAMIC_TYPE_DH,
                                            (void**)&ssl->buffers.serverDH_Key);
                        if (ret != 0) {
                            goto exit_sske;
                        }

                        ret = wc_DhSetNamedKey(ssl->buffers.serverDH_Key,
                                ssl->namedGroup);
                        if (ret != 0) {
                            goto exit_sske;
                        }
    #if !defined(WOLFSSL_OLD_PRIME_CHECK) && \
        !defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)
                        ssl->options.dhKeyTested = 1;
    #endif

                #ifdef HAVE_SECURE_RENEGOTIATION
                        /* Check that the DH public key buffer is large
                         * enough to hold the key. This may occur on a
                         * renegotiation when the key generated in the
                         * initial handshake is shorter than the key
                         * generated in the renegotiation. */
                        if (ssl->buffers.serverDH_Pub.length <
                                ssl->buffers.serverDH_P.length) {
                            byte* tmp = (byte*)XREALLOC(
                                    ssl->buffers.serverDH_Pub.buffer,
                                    ssl->buffers.serverDH_P.length +
                                        OPAQUE16_LEN,
                                    ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
                            if (tmp == NULL)
                                ERROR_OUT(MEMORY_E, exit_sske);
                            ssl->buffers.serverDH_Pub.buffer = tmp;
                            ssl->buffers.serverDH_Pub.length =
                                ssl->buffers.serverDH_P.length + OPAQUE16_LEN;
                        }
                #endif

                        ret = DhGenKeyPair(ssl, ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_Priv.buffer,
                            (word32*)&ssl->buffers.serverDH_Priv.length,
                            ssl->buffers.serverDH_Pub.buffer,
                            (word32*)&ssl->buffers.serverDH_Pub.length);
                    #ifdef WOLFSSL_CHECK_MEM_ZERO
                        wc_MemZero_Add("DH private key buffer",
                            ssl->buffers.serverDH_Priv.buffer,
                            ssl->buffers.serverDH_Priv.length);
                    #endif
                        break;
                    }
                    else
#endif
                    {
                        /* Allocate DH key buffers and generate key */
                        if (ssl->buffers.serverDH_P.buffer == NULL ||
                            ssl->buffers.serverDH_G.buffer == NULL) {
                            ERROR_OUT(NO_DH_PARAMS, exit_sske);
                        }

                        if (ssl->buffers.serverDH_Pub.buffer == NULL) {
                            /* Free'd in SSL_ResourceFree and FreeHandshakeResources */
                            ssl->buffers.serverDH_Pub.buffer = (byte*)XMALLOC(
                                    ssl->buffers.serverDH_P.length,
                                    ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
                            if (ssl->buffers.serverDH_Pub.buffer == NULL) {
                                ERROR_OUT(MEMORY_E, exit_sske);
                            }
                            ssl->buffers.serverDH_Pub.length =
                                ssl->buffers.serverDH_P.length;
                        }

                        if (ssl->buffers.serverDH_Priv.buffer == NULL) {
                            /* Free'd in SSL_ResourceFree and FreeHandshakeResources */
                            ssl->buffers.serverDH_Priv.buffer = (byte*)XMALLOC(
                                    ssl->buffers.serverDH_P.length,
                                    ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
                            if (ssl->buffers.serverDH_Priv.buffer == NULL) {
                                ERROR_OUT(MEMORY_E, exit_sske);
                            }
                            ssl->buffers.serverDH_Priv.length =
                                ssl->buffers.serverDH_P.length;
                        }

                        ssl->options.dhKeySz =
                                (word16)ssl->buffers.serverDH_P.length;

                        ret = AllocKey(ssl, DYNAMIC_TYPE_DH,
                                            (void**)&ssl->buffers.serverDH_Key);
                        if (ret != 0) {
                            goto exit_sske;
                        }

                        #if !defined(WOLFSSL_OLD_PRIME_CHECK) && \
                            !defined(HAVE_FIPS) && \
                            !defined(HAVE_SELFTEST)
                        if (ssl->options.dhDoKeyTest &&
                            !ssl->options.dhKeyTested)
                        {
                            ret = wc_DhSetCheckKey(
                                ssl->buffers.serverDH_Key,
                                ssl->buffers.serverDH_P.buffer,
                                ssl->buffers.serverDH_P.length,
                                ssl->buffers.serverDH_G.buffer,
                                ssl->buffers.serverDH_G.length,
                                NULL, 0, 0, ssl->rng);
                            if (ret != 0) {
                                goto exit_sske;
                            }
                            ssl->options.dhKeyTested = 1;
                        }
                        else
                        #endif
                        {
                            ret = wc_DhSetKey(ssl->buffers.serverDH_Key,
                                ssl->buffers.serverDH_P.buffer,
                                ssl->buffers.serverDH_P.length,
                                ssl->buffers.serverDH_G.buffer,
                                ssl->buffers.serverDH_G.length);
                            if (ret != 0) {
                                goto exit_sske;
                            }
                        }

                #ifdef HAVE_SECURE_RENEGOTIATION
                        /* Check that the DH public key buffer is large
                         * enough to hold the key. This may occur on a
                         * renegotiation when the key generated in the
                         * initial handshake is shorter than the key
                         * generated in the renegotiation. */
                        if (ssl->buffers.serverDH_Pub.length <
                                ssl->buffers.serverDH_P.length) {
                            byte* tmp = (byte*)XREALLOC(
                                    ssl->buffers.serverDH_Pub.buffer,
                                    ssl->buffers.serverDH_P.length +
                                        OPAQUE16_LEN,
                                    ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
                            if (tmp == NULL)
                                ERROR_OUT(MEMORY_E, exit_sske);
                            ssl->buffers.serverDH_Pub.buffer = tmp;
                            ssl->buffers.serverDH_Pub.length =
                                ssl->buffers.serverDH_P.length + OPAQUE16_LEN;
                        }
                #endif
                        ret = DhGenKeyPair(ssl, ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_Priv.buffer,
                            (word32*)&ssl->buffers.serverDH_Priv.length,
                            ssl->buffers.serverDH_Pub.buffer,
                            (word32*)&ssl->buffers.serverDH_Pub.length);
                    #ifdef WOLFSSL_CHECK_MEM_ZERO
                        wc_MemZero_Add("DH private key buffer",
                            ssl->buffers.serverDH_Priv.buffer,
                            ssl->buffers.serverDH_Priv.length);
                    #endif
                        break;
                    }
                #endif /* !NO_DH && (!NO_PSK || !NO_RSA) */
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                        /* Fall through to create temp ECC key */
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                #if defined(HAVE_ECC) || \
                    ((defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) && \
                     (defined(HAVE_ED25519) || defined(HAVE_ED448) || \
                      !defined(NO_RSA)))
                    case ecc_diffie_hellman_kea:
                    {
                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                            /* need ephemeral key now, create it if missing */
                            if (ssl->eccTempKey == NULL) {
                                /* alloc/init on demand */
                                ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                    (void**)&ssl->eccTempKey);
                                if (ret != 0) {
                                    goto exit_sske;
                                }
                            }

                            if (ssl->eccTempKeyPresent == 0) {
                                ret = X25519MakeKey(ssl,
                                        (curve25519_key*)ssl->eccTempKey, NULL);
                                if (ret == 0 || ret == WC_PENDING_E) {
                                    ssl->eccTempKeyPresent =
                                        DYNAMIC_TYPE_CURVE25519;
                                }
                            }
                            break;
                        }
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID) {
                            /* need ephemeral key now, create it if missing */
                            if (ssl->eccTempKey == NULL) {
                                /* alloc/init on demand */
                                ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE448,
                                    (void**)&ssl->eccTempKey);
                                if (ret != 0) {
                                    goto exit_sske;
                                }
                            }

                            if (ssl->eccTempKeyPresent == 0) {
                                ret = X448MakeKey(ssl,
                                          (curve448_key*)ssl->eccTempKey, NULL);
                                if (ret == 0 || ret == WC_PENDING_E) {
                                    ssl->eccTempKeyPresent =
                                        DYNAMIC_TYPE_CURVE448;
                                }
                            }
                            break;
                        }
                    #endif
                    #ifdef HAVE_ECC
                        /* need ephemeral key now, create it if missing */
                        if (ssl->eccTempKey == NULL) {
                            /* alloc/init on demand */
                            ret = AllocKey(ssl, DYNAMIC_TYPE_ECC,
                                (void**)&ssl->eccTempKey);
                            if (ret != 0) {
                                goto exit_sske;
                            }
                        }

                        if (ssl->eccTempKeyPresent == 0) {
                            ret = EccMakeKey(ssl, ssl->eccTempKey, NULL);
                            if (ret == 0 || ret == WC_PENDING_E) {
                                ssl->eccTempKeyPresent = DYNAMIC_TYPE_ECC;
                            }
                        }
                    #endif
                        break;
                    }
                #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
                    default:
                        /* Skip ServerKeyExchange */
                        goto exit_sske;
                } /* switch(ssl->specs.kea) */

                /* Check for error */
                if (ret != 0) {
                    goto exit_sske;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_BUILD;
            } /* case TLS_ASYNC_BEGIN */
            FALL_THROUGH;

            case TLS_ASYNC_BUILD:
            {
                switch(ssl->specs.kea)
                {
                #ifndef NO_PSK
                    case psk_kea:
                    {
                        args->idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

                        if (ssl->arrays->server_hint[0] == 0) {
                            ERROR_OUT(0, exit_sske); /* don't send */
                        }

                        /* include size part */
                        args->length = (word32)XSTRLEN(ssl->arrays->server_hint);
                        if (args->length > MAX_PSK_ID_LEN) {
                            ERROR_OUT(SERVER_HINT_ERROR, exit_sske);
                        }

                        args->length += HINT_LEN_SZ;
                        args->sendSz = args->length + HANDSHAKE_HEADER_SZ +
                                                            RECORD_HEADER_SZ;

                    #ifdef WOLFSSL_DTLS
                        if (ssl->options.dtls) {
                            args->sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                            args->idx    += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                        }
                    #endif

                        if (IsEncryptionOn(ssl, 1)) {
                            args->sendSz += MAX_MSG_EXTRA;
                        }

                        /* Use tmp buffer */
                        args->input = (byte*)XMALLOC(args->sendSz,
                                ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                        if (args->input == NULL)
                            ERROR_OUT(MEMORY_E, exit_sske);
                        args->output = args->input;

                        AddHeaders(args->output, args->length,
                                                    server_key_exchange, ssl);

                        /* key data */
                        c16toa((word16)(args->length - HINT_LEN_SZ),
                                                      args->output + args->idx);

                        args->idx += HINT_LEN_SZ;
                        XMEMCPY(args->output + args->idx,
                                ssl->arrays->server_hint,
                                args->length - HINT_LEN_SZ);
                        break;
                    }
                #endif /* !NO_PSK */
                #if !defined(NO_DH) && !defined(NO_PSK)
                    case dhe_psk_kea:
                    {
                        word32 hintLen;

                        args->idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
                        args->length = LENGTH_SZ * 3 + /* p, g, pub */
                                 ssl->buffers.serverDH_P.length +
                                 ssl->buffers.serverDH_G.length +
                                 ssl->buffers.serverDH_Pub.length;

                        /* include size part */
                        hintLen = (word32)XSTRLEN(ssl->arrays->server_hint);
                        if (hintLen > MAX_PSK_ID_LEN) {
                            ERROR_OUT(SERVER_HINT_ERROR, exit_sske);
                        }
                        args->length += hintLen + HINT_LEN_SZ;
                        args->sendSz = args->length + HANDSHAKE_HEADER_SZ +
                                                            RECORD_HEADER_SZ;

                    #ifdef WOLFSSL_DTLS
                        if (ssl->options.dtls) {
                            args->sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                            args->idx    += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                        }
                    #endif

                        if (IsEncryptionOn(ssl, 1)) {
                            args->sendSz += MAX_MSG_EXTRA;
                        }

                        /* Use tmp buffer */
                        args->input = (byte*)XMALLOC(args->sendSz,
                                ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                        if (args->input == NULL)
                            ERROR_OUT(MEMORY_E, exit_sske);
                        args->output = args->input;

                        AddHeaders(args->output, args->length,
                                                    server_key_exchange, ssl);

                        /* key data */
                        c16toa((word16)hintLen, args->output + args->idx);
                        args->idx += HINT_LEN_SZ;
                        XMEMCPY(args->output + args->idx,
                                            ssl->arrays->server_hint, hintLen);
                        args->idx += hintLen;

                        /* add p, g, pub */
                        c16toa((word16)ssl->buffers.serverDH_P.length,
                            args->output + args->idx);
                        args->idx += LENGTH_SZ;
                        XMEMCPY(args->output + args->idx,
                                ssl->buffers.serverDH_P.buffer,
                                ssl->buffers.serverDH_P.length);
                        args->idx += ssl->buffers.serverDH_P.length;

                        /*  g */
                        c16toa((word16)ssl->buffers.serverDH_G.length,
                            args->output + args->idx);
                        args->idx += LENGTH_SZ;
                        XMEMCPY(args->output + args->idx,
                                ssl->buffers.serverDH_G.buffer,
                                ssl->buffers.serverDH_G.length);
                        args->idx += ssl->buffers.serverDH_G.length;

                        /*  pub */
                        c16toa((word16)ssl->buffers.serverDH_Pub.length,
                            args->output + args->idx);
                        args->idx += LENGTH_SZ;
                        XMEMCPY(args->output + args->idx,
                                ssl->buffers.serverDH_Pub.buffer,
                                ssl->buffers.serverDH_Pub.length);
                        /* No need to update idx, since sizes are already set */
                        /* args->idx += ssl->buffers.serverDH_Pub.length; */
                        break;
                    }
                #endif /* !defined(NO_DH) && !defined(NO_PSK) */
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                    {
                        word32 hintLen;

                        /* curve type, named curve, length(1) */
                        args->idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
                        args->length = ENUM_LEN + CURVE_LEN + ENUM_LEN;

                        args->exportSz = MAX_EXPORT_ECC_SZ;
                        args->exportBuf = (byte*)XMALLOC(MAX_EXPORT_ECC_SZ,
                                            ssl->heap, DYNAMIC_TYPE_DER);
                        if (args->exportBuf == NULL) {
                            ERROR_OUT(MEMORY_E, exit_sske);
                        }
                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                            if (wc_curve25519_export_public_ex(
                                    (curve25519_key*)ssl->eccTempKey,
                                    args->exportBuf, &args->exportSz,
                                    EC25519_LITTLE_ENDIAN) != 0) {
                                ERROR_OUT(ECC_EXPORT_ERROR, exit_sske);
                            }
                        }
                        else
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID) {
                            if (wc_curve448_export_public_ex(
                                    (curve448_key*)ssl->eccTempKey,
                                    args->exportBuf, &args->exportSz,
                                    EC448_LITTLE_ENDIAN) != 0) {
                                ERROR_OUT(ECC_EXPORT_ERROR, exit_sske);
                            }
                        }
                        else
                    #endif
                        {
                            PRIVATE_KEY_UNLOCK();
                            ret = wc_ecc_export_x963(ssl->eccTempKey,
                                       args->exportBuf, &args->exportSz);
                            PRIVATE_KEY_LOCK();
                            if (ret != 0) {
                                ERROR_OUT(ECC_EXPORT_ERROR, exit_sske);
                            }
                        }
                        args->length += args->exportSz;

                        /* include size part */
                        hintLen = (word32)XSTRLEN(ssl->arrays->server_hint);
                        if (hintLen > MAX_PSK_ID_LEN) {
                            ERROR_OUT(SERVER_HINT_ERROR, exit_sske);
                        }
                        args->length += hintLen + HINT_LEN_SZ;
                        args->sendSz = args->length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

                    #ifdef WOLFSSL_DTLS
                        if (ssl->options.dtls) {
                            args->sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                            args->idx    += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                        }
                    #endif

                        if (IsEncryptionOn(ssl, 1)) {
                            args->sendSz += MAX_MSG_EXTRA;
                        }

                        /* Use tmp buffer */
                        args->input = (byte*)XMALLOC(args->sendSz,
                                ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                        if (args->input == NULL)
                            ERROR_OUT(MEMORY_E, exit_sske);
                        args->output = args->input;

                        /* key data */
                        c16toa((word16)hintLen, args->output + args->idx);
                        args->idx += HINT_LEN_SZ;
                        XMEMCPY(args->output + args->idx,
                                            ssl->arrays->server_hint, hintLen);
                        args->idx += hintLen;

                        /* ECC key exchange data */
                        args->output[args->idx++] = named_curve;
                        args->output[args->idx++] = 0x00;          /* leading zero */
                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID)
                            args->output[args->idx++] = WOLFSSL_ECC_X25519;
                        else
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID)
                            args->output[args->idx++] = WOLFSSL_ECC_X448;
                        else
                    #endif
                        {
                    #ifdef HAVE_ECC
                            args->output[args->idx++] =
                                                    SetCurveId(ssl->eccTempKey);
                    #endif
                        }
                        args->output[args->idx++] = (byte)args->exportSz;
                        XMEMCPY(args->output + args->idx, args->exportBuf,
                                                                args->exportSz);
                        break;
                    }
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                #if defined(HAVE_ECC) || \
                    ((defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)) && \
                     (defined(HAVE_ED25519) || defined(HAVE_ED448) || \
                      !defined(NO_RSA)))
                    case ecc_diffie_hellman_kea:
                    {
                        enum wc_HashType hashType;
                        word32 preSigSz, preSigIdx;

                        /* curve type, named curve, length(1) */
                        args->idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
                        args->length = ENUM_LEN + CURVE_LEN + ENUM_LEN;

                        /* Export temp ECC key and add to length */
                        args->exportSz = MAX_EXPORT_ECC_SZ;
                        args->exportBuf = (byte*)XMALLOC(MAX_EXPORT_ECC_SZ,
                                            ssl->heap, DYNAMIC_TYPE_DER);
                        if (args->exportBuf == NULL) {
                            ERROR_OUT(MEMORY_E, exit_sske);
                        }
                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                            if (wc_curve25519_export_public_ex(
                                        (curve25519_key*)ssl->eccTempKey,
                                        args->exportBuf, &args->exportSz,
                                        EC25519_LITTLE_ENDIAN) != 0) {
                                ERROR_OUT(ECC_EXPORT_ERROR, exit_sske);
                            }
                        }
                        else
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID) {
                            if (wc_curve448_export_public_ex(
                                        (curve448_key*)ssl->eccTempKey,
                                        args->exportBuf, &args->exportSz,
                                        EC448_LITTLE_ENDIAN) != 0) {
                                ERROR_OUT(ECC_EXPORT_ERROR, exit_sske);
                            }
                        }
                        else
                    #endif
                        {
                    #if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
                            PRIVATE_KEY_UNLOCK();
                            ret = wc_ecc_export_x963(ssl->eccTempKey,
                                    args->exportBuf, &args->exportSz);
                            PRIVATE_KEY_LOCK();
                            if (ret != 0) {
                                ERROR_OUT(ECC_EXPORT_ERROR, exit_sske);
                            }
                    #endif
                        }
                        args->length += args->exportSz;

                        preSigSz  = args->length;
                        preSigIdx = args->idx;

                        if (ssl->buffers.key == NULL) {
                        #ifdef HAVE_PK_CALLBACKS
                            if (wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)) {
                                args->tmpSigSz = GetPrivateKeySigSize(ssl);
                                if (args->tmpSigSz == 0) {
                                    ERROR_OUT(NO_PRIVATE_KEY, exit_sske);
                                }
                            }
                            else
                        #endif
                                ERROR_OUT(NO_PRIVATE_KEY, exit_sske);
                        }
                        else {
                            switch(ssl->suites->sigAlgo) {
                        #ifndef NO_RSA
                        #ifdef WC_RSA_PSS
                            case rsa_pss_sa_algo:
                        #endif
                            case rsa_sa_algo:
                            {
                                word16 keySz;

                                ssl->buffers.keyType = rsa_sa_algo;
                                ret = DecodePrivateKey(ssl, &keySz);
                                if (ret != 0) {
                                    goto exit_sske;
                                }

                                args->tmpSigSz = (word32)keySz;
                                break;
                            }
                        #endif /* !NO_RSA */
                        #ifdef HAVE_ECC
                            case ecc_dsa_sa_algo:
                            {
                                word16 keySz;

                                ssl->buffers.keyType = ecc_dsa_sa_algo;
                                ret = DecodePrivateKey(ssl, &keySz);
                                if (ret != 0) {
                                    goto exit_sske;
                                }
                                /* worst case estimate */
                                args->tmpSigSz = keySz;
                                break;
                            }
                        #endif
                        #ifdef HAVE_ED25519
                            case ed25519_sa_algo:
                            {
                                word16 keySz;

                                ssl->buffers.keyType = ed25519_sa_algo;
                                ret = DecodePrivateKey(ssl, &keySz);
                                if (ret != 0) {
                                    goto exit_sske;
                                }

                                /* worst case estimate */
                                args->tmpSigSz = ED25519_SIG_SIZE;
                                break;
                            }
                        #endif /* HAVE_ED25519 */
                        #ifdef HAVE_ED448
                            case ed448_sa_algo:
                            {
                                word16 keySz;

                                ssl->buffers.keyType = ed448_sa_algo;
                                ret = DecodePrivateKey(ssl, &keySz);
                                if (ret != 0) {
                                    goto exit_sske;
                                }

                                /* worst case estimate */
                                args->tmpSigSz = ED448_SIG_SIZE;
                                break;
                            }
                        #endif /* HAVE_ED448 */
                            default:
                                ERROR_OUT(ALGO_ID_E, exit_sske);  /* unsupported type */
                            } /* switch(ssl->specs.sig_algo) */
                        }

                        /* sig length */
                        args->length += LENGTH_SZ;
                        args->length += args->tmpSigSz;

                        if (IsAtLeastTLSv1_2(ssl)) {
                            args->length += HASH_SIG_SIZE;
                        }

                        args->sendSz = args->length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

                    #ifdef WOLFSSL_DTLS
                        if (ssl->options.dtls) {
                            args->sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                            args->idx    += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                            preSigIdx = args->idx;
                        }
                    #endif
                        if (IsEncryptionOn(ssl, 1)) {
                            args->sendSz += MAX_MSG_EXTRA;
                        }

                        /* Use tmp buffer */
                        args->input = (byte*)XMALLOC(args->sendSz,
                                ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                        if (args->input == NULL)
                            ERROR_OUT(MEMORY_E, exit_sske);
                        args->output = args->input;

                        /* record and message headers will be added below, when we're sure
                           of the sig length */

                        /* key exchange data */
                        args->output[args->idx++] = named_curve;
                        args->output[args->idx++] = 0x00;          /* leading zero */
                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID)
                            args->output[args->idx++] = WOLFSSL_ECC_X25519;
                        else
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID)
                            args->output[args->idx++] = WOLFSSL_ECC_X448;
                        else
                    #endif
                        {
                    #ifdef HAVE_ECC
                            args->output[args->idx++] =
                                                    SetCurveId(ssl->eccTempKey);
                    #endif
                        }
                        args->output[args->idx++] = (byte)args->exportSz;
                        XMEMCPY(args->output + args->idx, args->exportBuf, args->exportSz);
                        args->idx += args->exportSz;

                        /* Determine hash type */
                        if (IsAtLeastTLSv1_2(ssl)) {
                            EncodeSigAlg(ssl->suites->hashAlgo,
                                         ssl->suites->sigAlgo,
                                         &args->output[args->idx]);
                            args->idx += 2;

                            hashType = HashAlgoToType(ssl->suites->hashAlgo);
                            if (hashType == WC_HASH_TYPE_NONE) {
                                ERROR_OUT(ALGO_ID_E, exit_sske);
                            }

                        } else {
                            /* only using sha and md5 for rsa */
                        #ifndef NO_OLD_TLS
                            hashType = WC_HASH_TYPE_SHA;
                            if (ssl->suites->sigAlgo == rsa_sa_algo) {
                                hashType = WC_HASH_TYPE_MD5_SHA;
                            }
                        #else
                            ERROR_OUT(ALGO_ID_E, exit_sske);
                        #endif
                        }

                        /* Signature length will be written later, when we're sure what it is */

                    #ifdef HAVE_FUZZER
                        if (ssl->fuzzerCb) {
                            ssl->fuzzerCb(ssl, args->output + preSigIdx,
                                preSigSz, FUZZ_SIGNATURE, ssl->fuzzerCtx);
                        }
                    #endif

                        ret = HashSkeData(ssl, hashType,
                            args->output + preSigIdx, preSigSz,
                            ssl->suites->sigAlgo);
                        if (ret != 0) {
                            goto exit_sske;
                        }

                        args->sigSz = args->tmpSigSz;

                        /* Sign hash to create signature */
                        switch (ssl->suites->sigAlgo)
                        {
                        #ifndef NO_RSA
                            case rsa_sa_algo:
                            {
                                /* For TLS 1.2 re-encode signature */
                                if (IsAtLeastTLSv1_2(ssl)) {
                                    byte* encodedSig = (byte*)XMALLOC(
                                                  MAX_ENCODED_SIG_SZ, ssl->heap,
                                                           DYNAMIC_TYPE_DIGEST);
                                    if (encodedSig == NULL) {
                                        ERROR_OUT(MEMORY_E, exit_sske);
                                    }

                                    ssl->buffers.digest.length =
                                        wc_EncodeSignature(encodedSig,
                                            ssl->buffers.digest.buffer,
                                            ssl->buffers.digest.length,
                                            TypeHash(ssl->suites->hashAlgo));

                                    /* Replace sig buffer with new one */
                                    XFREE(ssl->buffers.digest.buffer, ssl->heap,
                                                           DYNAMIC_TYPE_DIGEST);
                                    ssl->buffers.digest.buffer = encodedSig;
                                }

                                /* write sig size here */
                                c16toa((word16)args->sigSz,
                                    args->output + args->idx);
                                args->idx += LENGTH_SZ;
                                break;
                            }
                        #ifdef WC_RSA_PSS
                            case rsa_pss_sa_algo:
                                /* write sig size here */
                                c16toa((word16)args->sigSz,
                                    args->output + args->idx);
                                args->idx += LENGTH_SZ;
                                break;
                        #endif
                        #endif /* !NO_RSA */
                            case ecc_dsa_sa_algo:
                            {
                                break;
                            }
                        #ifdef  HAVE_ED25519
                            case ed25519_sa_algo:
                                ret = Ed25519CheckPubKey(ssl);
                                if (ret != 0)
                                    goto exit_sske;
                                break;
                        #endif /* HAVE_ED25519 */
                        #ifdef  HAVE_ED448
                            case ed448_sa_algo:
                                ret = Ed448CheckPubKey(ssl);
                                if (ret != 0)
                                    goto exit_sske;
                                break;
                        #endif /* HAVE_ED448 */
                            default:
                                break;
                        } /* switch(ssl->specs.sig_algo) */
                        break;
                    }
                #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
                #if !defined(NO_DH) && (!defined(NO_RSA) || \
                             (defined(HAVE_ANON) && !defined(WOLFSSL_NO_TLS12)))
                    case diffie_hellman_kea:
                    {
                        enum wc_HashType hashType;
                        word32 preSigSz, preSigIdx;

                        args->idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
                        args->length = LENGTH_SZ * 3;  /* p, g, pub */
                        args->length += ssl->buffers.serverDH_P.length +
                                        ssl->buffers.serverDH_G.length +
                                        ssl->buffers.serverDH_Pub.length;

                        preSigIdx = args->idx;
                        preSigSz  = args->length;

                        if (!ssl->options.usingAnon_cipher) {
                            word16 keySz = 0;

                            /* sig length */
                            args->length += LENGTH_SZ;

                            if (ssl->buffers.key == NULL) {
                            #ifdef HAVE_PK_CALLBACKS
                                if (wolfSSL_CTX_IsPrivatePkSet(ssl->ctx))
                                    keySz = (word32)GetPrivateKeySigSize(ssl);
                                else
                            #endif
                                    ERROR_OUT(NO_PRIVATE_KEY, exit_sske);
                            }
                            else
                            {
                                if (ssl->buffers.keyType == 0)
                                    ssl->buffers.keyType = rsa_sa_algo;
                                ret = DecodePrivateKey(ssl, &keySz);
                                if (ret != 0) {
                                    goto exit_sske;
                                }
                            }

                            /* test if keySz has error */
                            if (keySz == 0) {
                                ERROR_OUT(keySz, exit_sske);
                            }

                            args->tmpSigSz = (word32)keySz;
                            args->length += args->tmpSigSz;

                            if (IsAtLeastTLSv1_2(ssl)) {
                                args->length += HASH_SIG_SIZE;
                            }
                        }

                        args->sendSz = args->length + HANDSHAKE_HEADER_SZ +
                                                            RECORD_HEADER_SZ;

                    #ifdef WOLFSSL_DTLS
                        if (ssl->options.dtls) {
                            args->sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                            args->idx    += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
                            preSigIdx = args->idx;
                        }
                    #endif

                        if (IsEncryptionOn(ssl, 1)) {
                            args->sendSz += MAX_MSG_EXTRA;
                        }

                        /* Use tmp buffer */
                        args->input = (byte*)XMALLOC(args->sendSz,
                                ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                        if (args->input == NULL)
                            ERROR_OUT(MEMORY_E, exit_sske);
                        args->output = args->input;

                        AddHeaders(args->output, args->length,
                                                    server_key_exchange, ssl);

                        /* add p, g, pub */
                        c16toa((word16)ssl->buffers.serverDH_P.length,
                                                    args->output + args->idx);
                        args->idx += LENGTH_SZ;
                        XMEMCPY(args->output + args->idx,
                                              ssl->buffers.serverDH_P.buffer,
                                              ssl->buffers.serverDH_P.length);
                        args->idx += ssl->buffers.serverDH_P.length;

                        /*  g */
                        c16toa((word16)ssl->buffers.serverDH_G.length,
                                                    args->output + args->idx);
                        args->idx += LENGTH_SZ;
                        XMEMCPY(args->output + args->idx,
                                              ssl->buffers.serverDH_G.buffer,
                                              ssl->buffers.serverDH_G.length);
                        args->idx += ssl->buffers.serverDH_G.length;

                        /*  pub */
                        c16toa((word16)ssl->buffers.serverDH_Pub.length,
                                                    args->output + args->idx);
                        args->idx += LENGTH_SZ;
                        XMEMCPY(args->output + args->idx,
                                              ssl->buffers.serverDH_Pub.buffer,
                                              ssl->buffers.serverDH_Pub.length);
                        args->idx += ssl->buffers.serverDH_Pub.length;

                    #ifdef HAVE_FUZZER
                        if (ssl->fuzzerCb) {
                            ssl->fuzzerCb(ssl, args->output + preSigIdx,
                                preSigSz, FUZZ_SIGNATURE, ssl->fuzzerCtx);
                        }
                    #endif

                        if (ssl->options.usingAnon_cipher) {
                            break;
                        }

                        /* Determine hash type */
                        if (IsAtLeastTLSv1_2(ssl)) {
                            EncodeSigAlg(ssl->suites->hashAlgo,
                                         ssl->suites->sigAlgo,
                                         &args->output[args->idx]);
                            args->idx += 2;

                            hashType = HashAlgoToType(ssl->suites->hashAlgo);
                            if (hashType == WC_HASH_TYPE_NONE) {
                                ERROR_OUT(ALGO_ID_E, exit_sske);
                            }
                        } else {
                            /* only using sha and md5 for rsa */
                        #ifndef NO_OLD_TLS
                            hashType = WC_HASH_TYPE_SHA;
                            if (ssl->suites->sigAlgo == rsa_sa_algo) {
                                hashType = WC_HASH_TYPE_MD5_SHA;
                            }
                        #else
                            ERROR_OUT(ALGO_ID_E, exit_sske);
                        #endif
                        }

                        /* signature size */
                        c16toa((word16)args->tmpSigSz, args->output + args->idx);
                        args->idx += LENGTH_SZ;

                        ret = HashSkeData(ssl, hashType,
                            args->output + preSigIdx, preSigSz,
                            ssl->suites->sigAlgo);
                        if (ret != 0) {
                            goto exit_sske;
                        }

                        args->sigSz = args->tmpSigSz;

                        /* Sign hash to create signature */
                        switch (ssl->suites->sigAlgo)
                        {
                        #ifndef NO_RSA
                            case rsa_sa_algo:
                            {
                                /* For TLS 1.2 re-encode signature */
                                if (IsAtLeastTLSv1_2(ssl)) {
                                    byte* encodedSig = (byte*)XMALLOC(
                                                  MAX_ENCODED_SIG_SZ, ssl->heap,
                                                           DYNAMIC_TYPE_DIGEST);
                                    if (encodedSig == NULL) {
                                        ERROR_OUT(MEMORY_E, exit_sske);
                                    }

                                    ssl->buffers.digest.length =
                                        wc_EncodeSignature(encodedSig,
                                            ssl->buffers.digest.buffer,
                                            ssl->buffers.digest.length,
                                            TypeHash(ssl->suites->hashAlgo));

                                    /* Replace sig buffer with new one */
                                    XFREE(ssl->buffers.digest.buffer, ssl->heap,
                                                           DYNAMIC_TYPE_DIGEST);
                                    ssl->buffers.digest.buffer = encodedSig;
                                }
                                break;
                            }
                        #endif /* NO_RSA */
                            default:
                                break;
                        } /* switch (ssl->suites->sigAlgo) */
                        break;
                    }
                #endif /* !defined(NO_DH) && !defined(NO_RSA) */
                    default:
                        break;
                } /* switch(ssl->specs.kea) */

                /* Check for error */
                if (ret != 0) {
                    goto exit_sske;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_DO;
            } /* case TLS_ASYNC_BUILD */
            FALL_THROUGH;

            case TLS_ASYNC_DO:
            {
                switch(ssl->specs.kea)
                {
                #ifndef NO_PSK
                    case psk_kea:
                    {
                        break;
                    }
                #endif /* !NO_PSK */
                #if !defined(NO_DH) && !defined(NO_PSK)
                    case dhe_psk_kea:
                    {
                        break;
                    }
                #endif /* !defined(NO_DH) && !defined(NO_PSK) */
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                    {
                        break;
                    }
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                #if defined(HAVE_ECC)  || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                    case ecc_diffie_hellman_kea:
                    {
                        /* Sign hash to create signature */
                        switch (ssl->suites->sigAlgo)
                        {
                        #ifndef NO_RSA
                        #ifdef WC_RSA_PSS
                            case rsa_pss_sa_algo:
                        #endif
                            case rsa_sa_algo:
                            {
                                RsaKey* key = (RsaKey*)ssl->hsKey;

                                ret = RsaSign(ssl,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    args->output + args->idx,
                                    &args->sigSz,
                                    ssl->suites->sigAlgo, ssl->suites->hashAlgo,
                                    key,
                                    ssl->buffers.key
                                );
                                break;
                            }
                        #endif /* !NO_RSA */
                        #ifdef HAVE_ECC
                            case ecc_dsa_sa_algo:
                            {
                                ecc_key* key = (ecc_key*)ssl->hsKey;

                                ret = EccSign(ssl,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    args->output + LENGTH_SZ + args->idx,
                                    &args->sigSz,
                                    key,
                            #ifdef HAVE_PK_CALLBACKS
                                    ssl->buffers.key
                            #else
                                    NULL
                            #endif
                                );
                                break;
                            }
                        #endif /* HAVE_ECC */
                        #ifdef HAVE_ED25519
                            case ed25519_sa_algo:
                            {
                                ed25519_key* key = (ed25519_key*)ssl->hsKey;

                                ret = Ed25519Sign(ssl,
                                    ssl->buffers.sig.buffer,
                                    ssl->buffers.sig.length,
                                    args->output + LENGTH_SZ + args->idx,
                                    &args->sigSz,
                                    key,
                            #ifdef HAVE_PK_CALLBACKS
                                    ssl->buffers.key
                            #else
                                    NULL
                            #endif
                                );
                                break;
                            }
                        #endif
                        #ifdef HAVE_ED448
                            case ed448_sa_algo:
                            {
                                ed448_key* key = (ed448_key*)ssl->hsKey;

                                ret = Ed448Sign(ssl,
                                    ssl->buffers.sig.buffer,
                                    ssl->buffers.sig.length,
                                    args->output + LENGTH_SZ + args->idx,
                                    &args->sigSz,
                                    key,
                            #ifdef HAVE_PK_CALLBACKS
                                    ssl->buffers.key
                            #else
                                    NULL
                            #endif
                                );
                                break;
                            }
                        #endif
                            default:
                                ERROR_OUT(ALGO_ID_E, exit_sske);
                        } /* switch(ssl->specs.sig_algo) */
                        break;
                    }
                #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
                #if !defined(NO_DH) && !defined(NO_RSA)
                    case diffie_hellman_kea:
                    {
                        /* Sign hash to create signature */
                        switch (ssl->suites->sigAlgo)
                        {
                        #ifndef NO_RSA
                        #ifdef WC_RSA_PSS
                            case rsa_pss_sa_algo:
                        #endif
                            case rsa_sa_algo:
                            {
                                RsaKey* key = (RsaKey*)ssl->hsKey;

                                if (ssl->options.usingAnon_cipher) {
                                    break;
                                }

                                ret = RsaSign(ssl,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    args->output + args->idx,
                                    &args->sigSz,
                                    ssl->suites->sigAlgo, ssl->suites->hashAlgo,
                                    key,
                                    ssl->buffers.key
                                );
                                break;
                            }
                        #endif /* NO_RSA */
                            default:
                                break;
                        } /* switch (ssl->suites->sigAlgo) */

                        break;
                    }
                #endif /* !defined(NO_DH) && !defined(NO_RSA) */
                    default:
                        break;
                } /* switch(ssl->specs.kea) */

                /* Check for error */
                if (ret != 0) {
                    goto exit_sske;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_VERIFY;
            } /* case TLS_ASYNC_DO */
            FALL_THROUGH;

            case TLS_ASYNC_VERIFY:
            {
                switch(ssl->specs.kea)
                {
                #ifndef NO_PSK
                    case psk_kea:
                    {
                        /* Nothing to do in this sub-state */
                        break;
                    }
                #endif /* !NO_PSK */
                #if !defined(NO_DH) && !defined(NO_PSK)
                    case dhe_psk_kea:
                    {
                        /* Nothing to do in this sub-state */
                        break;
                    }
                #endif /* !defined(NO_DH) && !defined(NO_PSK) */
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) ||  \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                    {
                        /* Nothing to do in this sub-state */
                        break;
                    }
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                    case ecc_diffie_hellman_kea:
                    {
                        switch(ssl->suites->sigAlgo)
                        {
                        #ifndef NO_RSA
                        #ifdef WC_RSA_PSS
                            case rsa_pss_sa_algo:
                        #endif
                            case rsa_sa_algo:
                            {
                                RsaKey* key = (RsaKey*)ssl->hsKey;

                                if (args->verifySig == NULL) {
                                    if (args->sigSz == 0) {
                                        ERROR_OUT(BAD_COND_E, exit_sske);
                                    }
                                    args->verifySig = (byte*)XMALLOC(
                                                    args->sigSz, ssl->heap,
                                                    DYNAMIC_TYPE_SIGNATURE);
                                    if (!args->verifySig) {
                                        ERROR_OUT(MEMORY_E, exit_sske);
                                    }
                                    XMEMCPY(args->verifySig,
                                        args->output + args->idx, args->sigSz);
                                }

                                /* check for signature faults */
                                ret = VerifyRsaSign(ssl,
                                    args->verifySig, args->sigSz,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    ssl->suites->sigAlgo, ssl->suites->hashAlgo,
                                    key, ssl->buffers.key
                                );
                                break;
                            }
                        #endif
                            case ecc_dsa_sa_algo:
                        #ifdef WOLFSSL_CHECK_SIG_FAULTS
                            {
                                ecc_key* key = (ecc_key*)ssl->hsKey;

                                ret = EccVerify(ssl,
                                    args->output + LENGTH_SZ + args->idx,
                                    args->sigSz,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    key,
                                #ifdef HAVE_PK_CALLBACKS
                                    ssl->buffers.key
                                #else
                                    NULL
                                #endif
                                );
                                if (ret != 0) {
                                    WOLFSSL_MSG(
                                        "Failed to verify ECC signature");
                                    goto exit_sske;
                                }
                            }
                            #if defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                            FALL_THROUGH;
                            #endif
                        #endif /*  WOLFSSL_CHECK_SIG_FAULTS */
                        #ifdef HAVE_ED25519
                            case ed25519_sa_algo:
                        #endif
                        #ifdef HAVE_ED448
                            case ed448_sa_algo:
                        #endif
                            {
                                /* Now that we know the real sig size, write it. */
                                c16toa((word16)args->sigSz,
                                                    args->output + args->idx);

                                /* And adjust length and sendSz from estimates */
                                args->length += args->sigSz - args->tmpSigSz;
                                args->sendSz += args->sigSz - args->tmpSigSz;
                                break;
                            }
                            default:
                                ERROR_OUT(ALGO_ID_E, exit_sske);  /* unsupported type */
                        } /* switch(ssl->specs.sig_algo) */
                        break;
                    }
                #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
                #if !defined(NO_DH) && !defined(NO_RSA)
                    case diffie_hellman_kea:
                    {
                        switch (ssl->suites->sigAlgo)
                        {
                        #ifndef NO_RSA
                        #ifndef WC_RSA_PSS
                            case rsa_pss_sa_algo:
                        #endif
                            case rsa_sa_algo:
                            {
                                RsaKey* key = (RsaKey*)ssl->hsKey;

                                if (ssl->options.usingAnon_cipher) {
                                    break;
                                }

                                if (args->verifySig == NULL) {
                                    if (args->sigSz == 0) {
                                        ERROR_OUT(BAD_COND_E, exit_sske);
                                    }
                                    args->verifySig = (byte*)XMALLOC(
                                                      args->sigSz, ssl->heap,
                                                      DYNAMIC_TYPE_SIGNATURE);
                                    if (!args->verifySig) {
                                        ERROR_OUT(MEMORY_E, exit_sske);
                                    }
                                    XMEMCPY(args->verifySig,
                                        args->output + args->idx, args->sigSz);
                                }

                                /* check for signature faults */
                                ret = VerifyRsaSign(ssl,
                                    args->verifySig, args->sigSz,
                                    ssl->buffers.digest.buffer,
                                    ssl->buffers.digest.length,
                                    ssl->suites->sigAlgo, ssl->suites->hashAlgo,
                                    key, ssl->buffers.key
                                );
                                break;
                            }
                        #endif
                        } /* switch (ssl->suites->sigAlgo) */
                        break;
                    }
                #endif /* !defined(NO_DH) && !defined(NO_RSA) */
                    default:
                        break;
                } /* switch(ssl->specs.kea) */

                /* Check for error */
                if (ret != 0) {
                    goto exit_sske;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_FINALIZE;
            } /* case TLS_ASYNC_VERIFY */
            FALL_THROUGH;

            case TLS_ASYNC_FINALIZE:
            {
            #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                if (ssl->specs.kea == ecdhe_psk_kea ||
                    ssl->specs.kea == ecc_diffie_hellman_kea) {
                    /* Check output to make sure it was set */
                    if (args->output) {
                        AddHeaders(args->output, args->length,
                                                    server_key_exchange, ssl);
                    }
                    else {
                        ERROR_OUT(BUFFER_ERROR, exit_sske);
                    }
                }
            #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_END;
            } /* case TLS_ASYNC_FINALIZE */
            FALL_THROUGH;

            case TLS_ASYNC_END:
            {
                ret = SendHandshakeMsg(ssl, args->output, args->length,
                        server_key_exchange, "ServerKeyExchange");
                if (ret != 0)
                    goto exit_sske;
                ssl->options.serverState = SERVER_KEYEXCHANGE_COMPLETE;
                break;
            }
            default:
                ret = INPUT_CASE_ERROR;
        } /* switch(ssl->options.asyncState) */

    exit_sske:

        WOLFSSL_LEAVE("SendServerKeyExchange", ret);
        WOLFSSL_END(WC_FUNC_SERVER_KEY_EXCHANGE_SEND);

    #ifdef WOLFSSL_ASYNC_IO
        /* Handle async operation */
        if (ret == WANT_WRITE
        #ifdef WOLFSSL_ASYNC_CRYPT
                || ret == WC_PENDING_E
        #endif
                )
            return ret;
    #endif /* WOLFSSL_ASYNC_IO */

        /* Final cleanup */
        if (
        #ifdef WOLFSSL_ASYNC_IO
            args != NULL &&
        #endif
            args->input != NULL) {
            XFREE(args->input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            args->input = NULL;
        }
    #ifdef WOLFSSL_ASYNC_IO
        /* Cleanup async */
        FreeAsyncCtx(ssl, 0);
    #else
        FreeSskeArgs(ssl, args);
    #endif
        FreeKeyExchange(ssl);

        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(ret);
        }

        return ret;
    }

#if defined(HAVE_SERVER_RENEGOTIATION_INFO) || defined(HAVE_FALLBACK_SCSV) || \
                                                            defined(OPENSSL_ALL)

    /* search suites for specific one, idx on success, negative on error */
    static int FindSuite(Suites* suites, byte first, byte second)
    {
        int i;

        if (suites == NULL || suites->suiteSz == 0) {
            WOLFSSL_MSG("Suites pointer error or suiteSz 0");
            return SUITES_ERROR;
        }

        for (i = 0; i < suites->suiteSz-1; i += SUITE_LEN) {
            if (suites->suites[i]   == first &&
                suites->suites[i+1] == second )
                return i;
        }

        return MATCH_SUITE_ERROR;
    }

#endif

#endif /* !WOLFSSL_NO_TLS12 */


//////////////////////////////

    /* Make sure server cert/key are valid for this suite, true on success
     * Returns 1 for valid server suite or 0 if not found
     * For asynchronous this can return WC_PENDING_E
     */
    static int VerifyServerSuite(WOLFSSL* ssl, word16 idx)
    {
    #ifndef NO_PSK
        int  havePSK = ssl->options.havePSK;
    #endif
        byte first;
        byte second;

        WOLFSSL_ENTER("VerifyServerSuite");

        if (ssl->suites == NULL) {
            WOLFSSL_MSG("Suites pointer error");
            return 0;
        }

        first   = ssl->suites->suites[idx];
        second  = ssl->suites->suites[idx+1];

        if (CipherRequires(first, second, REQUIRES_RSA)) {
            WOLFSSL_MSG("Requires RSA");
            if (ssl->options.haveRSA == 0) {
                WOLFSSL_MSG("Don't have RSA");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_DHE)) {
            WOLFSSL_MSG("Requires DHE");
            if (ssl->options.haveDH == 0) {
                WOLFSSL_MSG("Don't have DHE");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_ECC)) {
            WOLFSSL_MSG("Requires ECC");
            if (ssl->options.haveECC == 0) {
                WOLFSSL_MSG("Don't have ECC");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_ECC_STATIC)) {
            WOLFSSL_MSG("Requires static ECC");
            if (ssl->options.haveStaticECC == 0) {
                WOLFSSL_MSG("Don't have static ECC");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_PSK)) {
            WOLFSSL_MSG("Requires PSK");
        #ifndef NO_PSK
            if (havePSK == 0)
        #endif
            {
                WOLFSSL_MSG("Don't have PSK");
                return 0;
            }
        }

        if (CipherRequires(first, second, REQUIRES_RSA_SIG)) {
            WOLFSSL_MSG("Requires RSA Signature");
            if (ssl->options.side == WOLFSSL_SERVER_END &&
                                           ssl->options.haveECDSAsig == 1) {
                WOLFSSL_MSG("Don't have RSA Signature");
                return 0;
            }
        }

#if !defined(WOLFSSL_OLDTLS_AEAD_CIPHERSUITES)
        if (CipherRequires(first, second, REQUIRES_AEAD)) {
            WOLFSSL_MSG("Requires AEAD");
            if (ssl->version.major == SSLv3_MAJOR &&
                                           ssl->version.minor < TLSv1_2_MINOR) {
                WOLFSSL_MSG("Version of SSL does not support AEAD ciphers");
                return 0;
            }

        }
#endif

#if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                       defined(HAVE_CURVE448)) && defined(HAVE_SUPPORTED_CURVES)
        if (!TLSX_ValidateSupportedCurves(ssl, first, second)) {
            WOLFSSL_MSG("Don't have matching curves");
            return 0;
        }
#endif

#ifdef WOLFSSL_TLS13
        if (IsAtLeastTLSv1_3(ssl->version) &&
                                      ssl->options.side == WOLFSSL_SERVER_END) {
    #ifdef HAVE_SUPPORTED_CURVES
            int doHelloRetry = 0;
            /* Try to establish a key share. */
            int ret = TLSX_KeyShare_Establish(ssl, &doHelloRetry);

            if (ret == MEMORY_E) {
                WOLFSSL_MSG("TLSX_KeyShare_Establish() failed in "
                            "VerifyServerSuite() with MEMORY_E");
                return 0;
            }
            if (doHelloRetry) {
                ssl->options.serverState = SERVER_HELLO_RETRY_REQUEST_COMPLETE;
            }
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E)
                return ret;
        #endif
            if (!doHelloRetry && ret != 0) {
                return 0; /* not found */
            }
    #endif /* HAVE_SUPPORTED_CURVES */
        }
        else if (first == TLS13_BYTE || (first == ECC_BYTE &&
                (second == TLS_SHA256_SHA256 || second == TLS_SHA384_SHA384))) {
            /* Can't negotiate TLS 1.3 cipher suites with lower protocol
             * version. */
            return 0;
        }
#endif /* WOLFSSL_TLS13 */

        return 1;
    }

    static int CompareSuites(WOLFSSL* ssl, Suites* peerSuites, word16 i,
                             word16 j)
    {
        if (ssl->suites->suites[i]   == peerSuites->suites[j] &&
            ssl->suites->suites[i+1] == peerSuites->suites[j+1] ) {

            int ret = VerifyServerSuite(ssl, i);
            if (ret < 0) {
                return ret;
            }
            if (ret) {
                WOLFSSL_MSG("Verified suite validity");
                ssl->options.cipherSuite0 = ssl->suites->suites[i];
                ssl->options.cipherSuite  = ssl->suites->suites[i+1];
                ret = SetCipherSpecs(ssl);
                if (ret == 0) {
                    ret = PickHashSigAlgo(ssl, peerSuites->hashSigAlgo,
                                                     peerSuites->hashSigAlgoSz);
                }
                return ret;
            }
            else {
                WOLFSSL_MSG("Could not verify suite validity, continue");
            }
        }

        return MATCH_SUITE_ERROR;
    }

    int MatchSuite(WOLFSSL* ssl, Suites* peerSuites)
    {
        int ret;
        word16 i, j;

        WOLFSSL_ENTER("MatchSuite");

        /* & 0x1 equivalent % 2 */
        if (peerSuites->suiteSz == 0 || peerSuites->suiteSz & 0x1)
            return BUFFER_ERROR;

        if (ssl->suites == NULL)
            return SUITES_ERROR;

        if (!ssl->options.useClientOrder) {
            /* Server order */
            for (i = 0; i < ssl->suites->suiteSz; i += 2) {
                for (j = 0; j < peerSuites->suiteSz; j += 2) {
                    ret = CompareSuites(ssl, peerSuites, i, j);
                    if (ret != MATCH_SUITE_ERROR)
                        return ret;
                }
            }
        }
        else {
            /* Client order */
            for (j = 0; j < peerSuites->suiteSz; j += 2) {
                for (i = 0; i < ssl->suites->suiteSz; i += 2) {
                    ret = CompareSuites(ssl, peerSuites, i, j);
                    if (ret != MATCH_SUITE_ERROR)
                        return ret;
                }
            }
        }

        WOLFSSL_ERROR_VERBOSE(MATCH_SUITE_ERROR);
        return MATCH_SUITE_ERROR;
    }

#ifdef OLD_HELLO_ALLOWED

    /* process old style client hello, deprecate? */
    int ProcessOldClientHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                              word32 inSz, word16 sz)
    {
        word32          idx = *inOutIdx;
        word16          sessionSz;
        word16          randomSz;
        word16          i, j;
        ProtocolVersion pv;
        Suites          clSuites;
        int ret = -1;

        (void)inSz;
        WOLFSSL_MSG("Got old format client hello");
#ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "ClientHello");
        if (ssl->toInfoOn)
            AddLateName("ClientHello", &ssl->timeoutInfo);
#endif

        /* manually hash input since different format */
#ifndef NO_OLD_TLS
#ifndef NO_MD5
        wc_Md5Update(&ssl->hsHashes->hashMd5, input + idx, sz);
#endif
#ifndef NO_SHA
        wc_ShaUpdate(&ssl->hsHashes->hashSha, input + idx, sz);
#endif
#endif
#ifndef NO_SHA256
        if (IsAtLeastTLSv1_2(ssl)) {
            int shaRet = wc_Sha256Update(&ssl->hsHashes->hashSha256,
                                         input + idx, sz);
            if (shaRet != 0)
                return shaRet;
        }
#endif

        /* does this value mean client_hello? */
        idx++;

        /* version */
        pv.major = input[idx++];
        pv.minor = input[idx++];
        ssl->chVersion = pv;  /* store */

        if (ssl->version.minor > pv.minor) {
            byte haveRSA = 0;
            byte havePSK = 0;
            int  keySz   = 0;

            if (!ssl->options.downgrade) {
                WOLFSSL_MSG("Client trying to connect with lesser version");
                return VERSION_ERROR;
            }
            if (pv.minor < ssl->options.minDowngrade) {
                WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
                return VERSION_ERROR;
            }
            if (pv.minor == SSLv3_MINOR) {
                /* turn off tls */
                WOLFSSL_MSG("\tdowngrading to SSLv3");
                ssl->options.tls    = 0;
                ssl->options.tls1_1 = 0;
                ssl->version.minor  = SSLv3_MINOR;
            }
            else if (pv.minor == TLSv1_MINOR) {
                WOLFSSL_MSG("\tdowngrading to TLSv1");
                /* turn off tls 1.1+ */
                ssl->options.tls1_1 = 0;
                ssl->version.minor  = TLSv1_MINOR;
            }
            else if (pv.minor == TLSv1_1_MINOR) {
                WOLFSSL_MSG("\tdowngrading to TLSv1.1");
                ssl->version.minor  = TLSv1_1_MINOR;
            }
            else if (pv.minor == TLSv1_2_MINOR) {
                WOLFSSL_MSG("    downgrading to TLSv1.2");
                ssl->version.minor  = TLSv1_2_MINOR;
            }
#ifndef NO_RSA
            haveRSA = 1;
#endif
#ifndef NO_PSK
            havePSK = ssl->options.havePSK;
#endif
#ifndef NO_CERTS
            keySz = ssl->buffers.keySz;
#endif

            InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK,
                       ssl->options.haveDH, ssl->options.haveECDSAsig,
                       ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
                       ssl->options.haveFalconSig,
                       ssl->options.haveDilithiumSig, ssl->options.haveAnon,
                       TRUE, ssl->options.side);
        }

        /* suite size */
        ato16(&input[idx], &clSuites.suiteSz);
        idx += OPAQUE16_LEN;

        if (clSuites.suiteSz > WOLFSSL_MAX_SUITE_SZ)
            return BUFFER_ERROR;
        /* Make sure the suiteSz is a multiple of 3. (Old Client Hello) */
        if (clSuites.suiteSz % 3 != 0)
            return BUFFER_ERROR;
        clSuites.hashSigAlgoSz = 0;

        /* session size */
        ato16(&input[idx], &sessionSz);
        idx += OPAQUE16_LEN;

        if (sessionSz > ID_LEN)
            return BUFFER_ERROR;

        /* random size */
        ato16(&input[idx], &randomSz);
        idx += OPAQUE16_LEN;

        if (randomSz > RAN_LEN)
            return BUFFER_ERROR;

        /* suites */
        for (i = 0, j = 0; i < clSuites.suiteSz; i += 3) {
            byte first = input[idx++];
            if (!first) { /* implicit: skip sslv2 type */
                XMEMCPY(&clSuites.suites[j], &input[idx], SUITE_LEN);
                j += SUITE_LEN;
            }
            idx += SUITE_LEN;
        }
        clSuites.suiteSz = j;

        /* session id */
        if (sessionSz) {
            XMEMCPY(ssl->arrays->sessionID, input + idx, sessionSz);
            ssl->arrays->sessionIDSz = (byte)sessionSz;
            idx += sessionSz;
            ssl->options.resuming = 1;
        }

        /* random */
        if (randomSz < RAN_LEN)
            XMEMSET(ssl->arrays->clientRandom, 0, RAN_LEN - randomSz);
        XMEMCPY(&ssl->arrays->clientRandom[RAN_LEN - randomSz], input + idx,
               randomSz);
        idx += randomSz;

        if (ssl->options.usingCompression)
            ssl->options.usingCompression = 0;  /* turn off */

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;
        ssl->cbmode = SSL_CB_MODE_WRITE;
        *inOutIdx = idx;

        ssl->options.haveSessionId = 1;
        /* DoClientHello uses same resume code */
        if (ssl->options.resuming) {  /* let's try */
            WOLFSSL_SESSION* session;
        #ifdef HAVE_SESSION_TICKET
            if (ssl->options.useTicket == 1) {
                session = ssl->session;
            }
            else
        #endif
            {
                session = wolfSSL_GetSession(ssl, ssl->arrays->masterSecret, 1);
            }
            if (!session) {
                WOLFSSL_MSG("Session lookup for resume failed");
                ssl->options.resuming = 0;
            } else {
                if (MatchSuite(ssl, &clSuites) < 0) {
                    WOLFSSL_MSG("Unsupported cipher suite, OldClientHello");
                    return UNSUPPORTED_SUITE;
                }

                ret = wc_RNG_GenerateBlock(ssl->rng, ssl->arrays->serverRandom,
                                                                       RAN_LEN);
                if (ret != 0)
                    return ret;

                #ifdef NO_OLD_TLS
                    ret = DeriveTlsKeys(ssl);
                #else
                    #ifndef NO_TLS
                        if (ssl->options.tls)
                            ret = DeriveTlsKeys(ssl);
                    #endif
                        if (!ssl->options.tls)
                            ret = DeriveKeys(ssl);
                #endif
                /* SERVER: peer auth based on session secret. */
                ssl->options.peerAuthGood = (ret == 0);
                ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;

                return ret;
            }
        }

        ret = MatchSuite(ssl, &clSuites);
        if (ret != 0)return ret;
        return SanityCheckMsgReceived(ssl, client_hello);
    }

#endif /* OLD_HELLO_ALLOWED */

#ifndef WOLFSSL_NO_TLS12

    /**
     *  Handles session resumption.
     *  Session tickets are checked for validity based on the time each ticket
     *  was created, timeout value and the current time. If the tickets are
     *  judged expired, falls back to full-handshake. If you want disable this
     *  session ticket validation check in TLS1.2 and below, define
     *  WOLFSSL_NO_TICKET_EXPIRE.
     */
    int HandleTlsResumption(WOLFSSL* ssl, int bogusID, Suites* clSuites)
    {
        int ret = 0;
        WOLFSSL_SESSION* session;
        (void)bogusID;
    #ifdef HAVE_SESSION_TICKET
        if (ssl->options.useTicket == 1) {
            session = ssl->session;
        }
        else if (bogusID == 1 && ssl->options.rejectTicket == 0) {
            WOLFSSL_MSG("Bogus session ID without session ticket");
            return BUFFER_ERROR;
        }
        else
    #endif
        {
            session = wolfSSL_GetSession(ssl, ssl->arrays->masterSecret, 1);
        }
        if (!session) {
            WOLFSSL_MSG("Session lookup for resume failed");
            ssl->options.resuming = 0;
            return ret;
        }
#if defined(HAVE_SESSION_TICKET) && !defined(WOLFSSL_NO_TICKET_EXPIRE) && \
                                    !defined(NO_ASN_TIME)
        /* check if the ticket is valid */
        if (LowResTimer() > session->bornOn + ssl->timeout) {
            WOLFSSL_MSG("Expired session ticket, fall back to full handshake.");
            ssl->options.resuming = 0;
        }
#endif /* HAVE_SESSION_TICKET && !WOLFSSL_NO_TICKET_EXPIRE && !NO_ASN_TIME */

        else if (session->haveEMS != ssl->options.haveEMS) {
            /* RFC 7627, 5.3, server-side */
            /* if old sess didn't have EMS, but new does, full handshake */
            if (!session->haveEMS && ssl->options.haveEMS) {
                WOLFSSL_MSG("Attempting to resume a session that didn't "
                            "use EMS with a new session with EMS. Do full "
                            "handshake.");
                ssl->options.resuming = 0;
            }
            /* if old sess used EMS, but new doesn't, MUST abort */
            else if (session->haveEMS && !ssl->options.haveEMS) {
                WOLFSSL_MSG("Trying to resume a session with EMS without "
                            "using EMS");
            #ifdef WOLFSSL_EXTRA_ALERTS
                SendAlert(ssl, alert_fatal, handshake_failure);
            #endif
                ret = EXT_MASTER_SECRET_NEEDED_E;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
        }
        else {
        #ifndef NO_RESUME_SUITE_CHECK
            int j;

            /* Check client suites include the one in session */
            for (j = 0; j < clSuites->suiteSz; j += 2) {
                if (clSuites->suites[j] == session->cipherSuite0 &&
                                clSuites->suites[j+1] == session->cipherSuite) {
                    break;
                }
            }
            if (j == clSuites->suiteSz) {
                WOLFSSL_MSG("Prev session's cipher suite not in ClientHello");
            #ifdef WOLFSSL_EXTRA_ALERTS
                SendAlert(ssl, alert_fatal, illegal_parameter);
            #endif
                ret = UNSUPPORTED_SUITE;
                WOLFSSL_ERROR_VERBOSE(ret);
            }
        #endif

            if (ret == 0 && ssl->options.resuming) {
                /* for resumption use the cipher suite from session */
                ssl->options.cipherSuite0 = session->cipherSuite0;
                ssl->options.cipherSuite =  session->cipherSuite;
                ret = SetCipherSpecs(ssl);
                if (ret == 0) {
                    ret = PickHashSigAlgo(ssl, clSuites->hashSigAlgo,
                                               clSuites->hashSigAlgoSz);
                }
            }
            else if (ret == 0) {
                if (MatchSuite(ssl, clSuites) < 0) {
                    WOLFSSL_MSG("Unsupported cipher suite, ClientHello");
                    ret = UNSUPPORTED_SUITE;
                    WOLFSSL_ERROR_VERBOSE(ret);
                }
            }
            if (ret == 0) {
                ret = wc_RNG_GenerateBlock(ssl->rng,
                                           ssl->arrays->serverRandom, RAN_LEN);
            }
            if (ret == 0) {
                #ifdef NO_OLD_TLS
                    ret = DeriveTlsKeys(ssl);
                #else
                    #ifndef NO_TLS
                        if (ssl->options.tls)
                            ret = DeriveTlsKeys(ssl);
                    #endif
                        if (!ssl->options.tls)
                            ret = DeriveKeys(ssl);
                #endif
                /* SERVER: peer auth based on session secret. */
                ssl->options.peerAuthGood = (ret == 0);
                ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
            }
        }


        return ret;
    }


    /* handle processing of client_hello (1) */
    int DoClientHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                             word32 helloSz)
    {
        byte            b;
        byte            bogusID = 0;   /* flag for a bogus session id */
        ProtocolVersion pv;
#ifdef WOLFSSL_SMALL_STACK
        Suites*         clSuites = NULL;
#else
        Suites          clSuites[1];
#endif
        word32          i = *inOutIdx;
        word32          begin = i;
        int             ret = 0;
        byte            lesserVersion;

        WOLFSSL_START(WC_FUNC_CLIENT_HELLO_DO);
        WOLFSSL_ENTER("DoClientHello");

#ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName(ssl, "ClientHello");
        if (ssl->toInfoOn) AddLateName("ClientHello", &ssl->timeoutInfo);
#endif
        /* do not change state in the SSL object before the next region of code
         * to be able to statelessly compute a DTLS cookie */
#ifdef WOLFSSL_DTLS
        if (IsDtlsNotSctpMode(ssl) && IsDtlsNotSrtpMode(ssl) && !IsSCR(ssl)) {
            byte process = 0;
            ret = DoClientHelloStateless(ssl, input, inOutIdx, helloSz,
                &process);
            if (ret != 0 || !process) {
                *inOutIdx += helloSz;
                DtlsResetState(ssl);
                return ret;
            }
        }
#endif /* WOLFSSL_DTLS */

        /* protocol version, random and session id length check */
        if (OPAQUE16_LEN + RAN_LEN + OPAQUE8_LEN > helloSz)
            return BUFFER_ERROR;

        /* protocol version */
        XMEMCPY(&pv, input + i, OPAQUE16_LEN);
        ssl->chVersion = pv;   /* store */
#ifdef WOLFSSL_DTLS
        if (IsDtlsNotSctpMode(ssl) && IsDtlsNotSrtpMode(ssl) && !IsSCR(ssl)) {
            if (((ssl->keys.dtls_sequence_number_hi == ssl->keys.curSeq_hi &&
                  ssl->keys.dtls_sequence_number_lo < ssl->keys.curSeq_lo) ||
                 (ssl->keys.dtls_sequence_number_hi < ssl->keys.curSeq_hi))) {
                /* We should continue with the same sequence number as the
                 * Client Hello if available. */
                ssl->keys.dtls_sequence_number_hi = ssl->keys.curSeq_hi;
                ssl->keys.dtls_sequence_number_lo = ssl->keys.curSeq_lo;
            }
            /* We should continue with the same handshake number as the
             * Client Hello. */
            ssl->keys.dtls_handshake_number =
                    ssl->keys.dtls_peer_handshake_number;
        }
#endif /* WOLFSSL_DTLS */
        i += OPAQUE16_LEN;

        /* Legacy protocol version cannot negotiate TLS 1.3 or higher. */
        if (pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_3_MINOR)
            pv.minor = TLSv1_2_MINOR;

        lesserVersion = !ssl->options.dtls && ssl->version.minor > pv.minor;
        lesserVersion |= ssl->options.dtls && ssl->version.minor < pv.minor;

        if (lesserVersion) {
            byte   belowMinDowngrade;
            word16 haveRSA = 0;
            word16 havePSK = 0;
            int    keySz   = 0;

            if (!ssl->options.downgrade) {
                WOLFSSL_MSG("Client trying to connect with lesser version");
#if defined(WOLFSSL_EXTRA_ALERTS) ||  defined(OPENSSL_EXTRA)
                SendAlert(ssl, alert_fatal, handshake_failure);
#endif
                ret = VERSION_ERROR;
                goto out;
            }

            belowMinDowngrade = pv.minor < ssl->options.minDowngrade;

            /* DTLS versions increase backwards (-1,-2,-3) ecc  */
            if (ssl->options.dtls)
                belowMinDowngrade = ssl->options.dtls
                    && pv.minor > ssl->options.minDowngrade;

            if (belowMinDowngrade) {
                WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
#if defined(WOLFSSL_EXTRA_ALERTS) ||  defined(OPENSSL_EXTRA)
                SendAlert(ssl, alert_fatal, handshake_failure);
#endif
                ret = VERSION_ERROR;
                goto out;
            }

            if (!ssl->options.dtls) {
                if (pv.minor == SSLv3_MINOR) {
                    /* turn off tls */
                    WOLFSSL_MSG("\tdowngrading to SSLv3");
                    ssl->options.tls    = 0;
                    ssl->options.tls1_1 = 0;
                    ssl->version.minor  = SSLv3_MINOR;
                }
                else if (pv.minor == TLSv1_MINOR) {
                    /* turn off tls 1.1+ */
                    WOLFSSL_MSG("\tdowngrading to TLSv1");
                    ssl->options.tls1_1 = 0;
                    ssl->version.minor  = TLSv1_MINOR;
                }
                else if (pv.minor == TLSv1_1_MINOR) {
                    WOLFSSL_MSG("\tdowngrading to TLSv1.1");
                    ssl->version.minor  = TLSv1_1_MINOR;
                }
                else if (pv.minor == TLSv1_2_MINOR) {
                    WOLFSSL_MSG("    downgrading to TLSv1.2");
                    ssl->version.minor  = TLSv1_2_MINOR;
                }
            }
            else {
                if (pv.minor == DTLSv1_2_MINOR) {
                    WOLFSSL_MSG("\tDowngrading to DTLSv1.2");
                    ssl->options.tls1_3 = 0;
                    ssl->version.minor = DTLSv1_2_MINOR;
                }
                else if (pv.minor == DTLS_MINOR) {
                    WOLFSSL_MSG("\tDowngrading to DTLSv1.0");
                    ssl->options.tls1_3 = 0;
                    ssl->version.minor = DTLS_MINOR;
                }
            }
#ifndef NO_RSA
            haveRSA = 1;
#endif
#ifndef NO_PSK
            havePSK = ssl->options.havePSK;
#endif
#ifndef NO_CERTS
            keySz = ssl->buffers.keySz;
#endif
            InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK,
                       ssl->options.haveDH, ssl->options.haveECDSAsig,
                       ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
                       ssl->options.haveFalconSig,
                       ssl->options.haveDilithiumSig, ssl->options.haveAnon,
                       TRUE, ssl->options.side);
        }

        /* check if option is set to not allow the current version
         * set from either wolfSSL_set_options or wolfSSL_CTX_set_options */
        if (!ssl->options.dtls && ssl->options.downgrade &&
            ssl->options.mask > 0) {

            int reset = 0;

            if (ssl->version.minor == TLSv1_2_MINOR &&
               (ssl->options.mask & WOLFSSL_OP_NO_TLSv1_2) ==
                WOLFSSL_OP_NO_TLSv1_2) {
                WOLFSSL_MSG("\tOption set to not allow TLSv1.2, Downgrading");
                ssl->version.minor = TLSv1_1_MINOR;
                reset = 1;
            }

            if (ssl->version.minor == TLSv1_1_MINOR &&
               (ssl->options.mask & WOLFSSL_OP_NO_TLSv1_1) ==
                WOLFSSL_OP_NO_TLSv1_1) {
                WOLFSSL_MSG("\tOption set to not allow TLSv1.1, Downgrading");
                ssl->options.tls1_1 = 0;
                ssl->version.minor = TLSv1_MINOR;
                reset = 1;
            }

            if (ssl->version.minor == TLSv1_MINOR &&
               (ssl->options.mask & WOLFSSL_OP_NO_TLSv1) ==
                WOLFSSL_OP_NO_TLSv1) {
                WOLFSSL_MSG("\tOption set to not allow TLSv1, Downgrading");
                ssl->options.tls    = 0;
                ssl->options.tls1_1 = 0;
                ssl->version.minor = SSLv3_MINOR;
                reset = 1;
            }

            if (ssl->version.minor == SSLv3_MINOR &&
               (ssl->options.mask & WOLFSSL_OP_NO_SSLv3) ==
                WOLFSSL_OP_NO_SSLv3) {
                WOLFSSL_MSG("\tError, option set to not allow SSLv3");
                ret = VERSION_ERROR;
                goto out;
            }

            if (ssl->version.minor < ssl->options.minDowngrade) {
                WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
                ret = VERSION_ERROR;
                goto out;
            }

            if (reset) {
                word16 haveRSA = 0;
                word16 havePSK = 0;
                int    keySz   = 0;

            #ifndef NO_RSA
                haveRSA = 1;
            #endif
            #ifndef NO_PSK
                havePSK = ssl->options.havePSK;
            #endif
            #ifndef NO_CERTS
                keySz = ssl->buffers.keySz;
            #endif

                /* reset cipher suites to account for TLS version change */
                InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK,
                           ssl->options.haveDH, ssl->options.haveECDSAsig,
                           ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
                           ssl->options.haveFalconSig,
                           ssl->options.haveDilithiumSig, ssl->options.haveAnon,
                           TRUE, ssl->options.side);
            }
        }

        /* random */
        XMEMCPY(ssl->arrays->clientRandom, input + i, RAN_LEN);
        i += RAN_LEN;

#ifdef SHOW_SECRETS
        {
            int j;
            printf("client random: ");
            for (j = 0; j < RAN_LEN; j++)
                printf("%02x", ssl->arrays->clientRandom[j]);
            printf("\n");
        }
#endif

        /* session id */
        b = input[i++];

#ifdef HAVE_SESSION_TICKET
        if (b > 0 && b < ID_LEN) {
            bogusID = 1;
            WOLFSSL_MSG("Client sent bogus session id, let's allow for echo");
        }
#endif

        if (b == ID_LEN || bogusID) {
            if ((i - begin) + b > helloSz) {
                ret = BUFFER_ERROR;
                goto out;
            }

            XMEMCPY(ssl->arrays->sessionID, input + i, b);
            ssl->arrays->sessionIDSz = b;
            i += b;
            ssl->options.resuming = 1; /* client wants to resume */
            WOLFSSL_MSG("Client wants to resume session");
        }
        else if (b) {
            WOLFSSL_MSG("Invalid session ID size");
            ret = BUFFER_ERROR; /* session ID nor 0 neither 32 bytes long */
            goto out;
        }

#ifdef WOLFSSL_DTLS
            /* cookie */
            if (ssl->options.dtls) {
                word8 peerCookieSz;
                if ((i - begin) + OPAQUE8_LEN > helloSz) {
                    ret = BUFFER_ERROR;
                    goto out;
                }

                peerCookieSz = input[i++];

                if (peerCookieSz) {
                    if (peerCookieSz > MAX_COOKIE_LEN) {
                        ret = BUFFER_ERROR;
                        goto out;
                    }

                    if ((i - begin) + peerCookieSz > helloSz) {
                        ret = BUFFER_ERROR;
                        goto out;
                    }

                    i += peerCookieSz;
                }
            }
#endif /* WOLFSSL_DTLS */

        /* suites */
        if ((i - begin) + OPAQUE16_LEN > helloSz) {
            ret = BUFFER_ERROR;
            goto out;
        }

#ifdef WOLFSSL_SMALL_STACK
        clSuites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
                                       DYNAMIC_TYPE_SUITES);
        if (clSuites == NULL) {
            ret = MEMORY_E;
            goto out;
        }
#endif
        XMEMSET(clSuites, 0, sizeof(Suites));
        ato16(&input[i], &clSuites->suiteSz);
        i += OPAQUE16_LEN;

        /* Cipher suite lists are always multiples of two in length. */
        if (clSuites->suiteSz % 2 != 0) {
            ret = BUFFER_ERROR;
            goto out;
        }

        /* suites and compression length check */
        if ((i - begin) + clSuites->suiteSz + OPAQUE8_LEN > helloSz) {
            ret = BUFFER_ERROR;
            goto out;
        }

        if (clSuites->suiteSz > WOLFSSL_MAX_SUITE_SZ) {
            ret = BUFFER_ERROR;
            goto out;
        }

        XMEMCPY(clSuites->suites, input + i, clSuites->suiteSz);

#ifdef HAVE_SERVER_RENEGOTIATION_INFO
        /* check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV suite */
        if (FindSuite(clSuites, 0, TLS_EMPTY_RENEGOTIATION_INFO_SCSV) >= 0) {
            TLSX* extension;

            /* check for TLS_EMPTY_RENEGOTIATION_INFO_SCSV suite */
            ret = TLSX_AddEmptyRenegotiationInfo(&ssl->extensions, ssl->heap);
            if (ret != WOLFSSL_SUCCESS)
                goto out;

            extension = TLSX_Find(ssl->extensions, TLSX_RENEGOTIATION_INFO);
            if (extension) {
                ssl->secure_renegotiation =
                                          (SecureRenegotiation*)extension->data;
                ssl->secure_renegotiation->enabled = 1;
            }
        }
#endif /* HAVE_SERVER_RENEGOTIATION_INFO */
#if defined(HAVE_FALLBACK_SCSV) || defined(OPENSSL_ALL)
        /* check for TLS_FALLBACK_SCSV suite */
        if (FindSuite(clSuites, TLS_FALLBACK_SCSV, 0) >= 0) {
            WOLFSSL_MSG("Found Fallback SCSV");
            if (ssl->ctx->method->version.minor > pv.minor) {
                WOLFSSL_MSG("Client trying to connect with lesser version");
                SendAlert(ssl, alert_fatal, inappropriate_fallback);
                ret = VERSION_ERROR;
                goto out;
            }
        }
#endif

        i += clSuites->suiteSz;
        clSuites->hashSigAlgoSz = 0;

        /* compression length */
        b = input[i++];

        if ((i - begin) + b > helloSz) {
            ret = BUFFER_ERROR;
            goto out;
        }

        if (b == 0) {
            WOLFSSL_MSG("No compression types in list");
#ifdef WOLFSSL_EXTRA_ALERTS
            SendAlert(ssl, alert_fatal, decode_error);
#endif
            ret = COMPRESSION_ERROR;
            goto out;
        }

        {
            /* compression match types */
            int matchNo = 0;
            int matchZlib = 0;

            while (b--) {
                byte comp = input[i++];

                if (comp == NO_COMPRESSION) {
                    matchNo = 1;
                }
                if (comp == ZLIB_COMPRESSION) {
                    matchZlib = 1;
                }
            }

            if (ssl->options.usingCompression == 0 && matchNo) {
                WOLFSSL_MSG("Matched No Compression");
            } else if (ssl->options.usingCompression && matchZlib) {
                WOLFSSL_MSG("Matched zlib Compression");
            } else if (ssl->options.usingCompression && matchNo) {
                WOLFSSL_MSG("Could only match no compression, turning off");
                ssl->options.usingCompression = 0;  /* turn off */
            } else {
                WOLFSSL_MSG("Could not match compression");
#ifdef WOLFSSL_EXTRA_ALERTS
                SendAlert(ssl, alert_fatal, illegal_parameter);
#endif
                ret = COMPRESSION_ERROR;
                goto out;
            }
        }

        *inOutIdx = i;

        /* tls extensions */
        if ((i - begin) < helloSz) {
#ifdef HAVE_TLS_EXTENSIONS
            if (TLSX_SupportExtensions(ssl))
#else
            if (IsAtLeastTLSv1_2(ssl))
#endif
            {
                /* Process the hello extension. Skip unsupported. */
                word16 totalExtSz;

#ifdef HAVE_TLS_EXTENSIONS
                /* auto populate extensions supported unless user defined */
                if ((ret = TLSX_PopulateExtensions(ssl, 1)) != 0)
                    goto out;
#endif

                if ((i - begin) + OPAQUE16_LEN > helloSz) {
                    ret = BUFFER_ERROR;
                    goto out;
                }

                ato16(&input[i], &totalExtSz);
                i += OPAQUE16_LEN;

                if ((i - begin) + totalExtSz > helloSz) {
                    ret = BUFFER_ERROR;
                    goto out;
                }

#ifdef HAVE_TLS_EXTENSIONS
                /* tls extensions */
                if ((ret = TLSX_Parse(ssl, input + i, totalExtSz, client_hello,
                                                                    clSuites)))
                    goto out;
    #ifdef WOLFSSL_TLS13
                if (TLSX_Find(ssl->extensions,
                                             TLSX_SUPPORTED_VERSIONS) != NULL) {
                    WOLFSSL_MSG(
                            "Client attempting to connect with higher version");
                    ret = VERSION_ERROR;
                    goto out;
                }
    #endif
    #ifdef HAVE_SNI
                if((ret=SNI_Callback(ssl)))
                    goto out;
    #endif
    #ifdef HAVE_ALPN
                if((ret=ALPN_Select(ssl)))
                    goto out;
    #endif

                i += totalExtSz;
#else
                while (totalExtSz) {
                    word16 extId, extSz;

                    if (OPAQUE16_LEN + OPAQUE16_LEN > totalExtSz) {
                        ret = BUFFER_ERROR;
                        goto out;
                    }

                    ato16(&input[i], &extId);
                    i += OPAQUE16_LEN;
                    ato16(&input[i], &extSz);
                    i += OPAQUE16_LEN;

                    if (OPAQUE16_LEN + OPAQUE16_LEN + extSz > totalExtSz) {
                        ret = BUFFER_ERROR;
                        goto out;
                    }

                    if (extId == HELLO_EXT_SIG_ALGO) {
                        word16 hashSigAlgoSz;

                        ato16(&input[i], &hashSigAlgoSz);
                        i += OPAQUE16_LEN;

                        if (OPAQUE16_LEN + hashSigAlgoSz > extSz) {
                            ret = BUFFER_ERROR;
                            goto out;
                        }

                        if (hashSigAlgoSz % 2 != 0) {
                            ret = BUFFER_ERROR;
                            goto out;
                        }

                        clSuites->hashSigAlgoSz = hashSigAlgoSz;
                        if (clSuites->hashSigAlgoSz > WOLFSSL_MAX_SIGALGO) {
                            WOLFSSL_MSG("ClientHello SigAlgo list exceeds max, "
                                                                  "truncating");
                            clSuites->hashSigAlgoSz = WOLFSSL_MAX_SIGALGO;
                        }

                        XMEMCPY(clSuites->hashSigAlgo, &input[i],
                                                      clSuites->hashSigAlgoSz);

                        i += hashSigAlgoSz;
                    }
#ifdef HAVE_EXTENDED_MASTER
                    else if (extId == HELLO_EXT_EXTMS)
                        ssl->options.haveEMS = 1;
#endif
                    else
                        i += extSz;

                    totalExtSz -= OPAQUE16_LEN + OPAQUE16_LEN + extSz;
                }
#endif
                *inOutIdx = i;
            }
            else
                *inOutIdx = begin + helloSz; /* skip extensions */
        }

#ifdef WOLFSSL_DTLS_CID
        if (ssl->options.useDtlsCID)
            DtlsCIDOnExtensionsParsed(ssl);
#endif /* WOLFSSL_DTLS_CID */

        ssl->options.clientState   = CLIENT_HELLO_COMPLETE;
        ssl->options.haveSessionId = 1;

        /* ProcessOld uses same resume code */
        if (ssl->options.resuming) {
            ret = HandleTlsResumption(ssl, bogusID, clSuites);
            if (ret != 0)
                goto out;

#if defined(HAVE_TLS_EXTENSIONS) && defined(HAVE_ENCRYPT_THEN_MAC) && \
    !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.encThenMac && ssl->specs.cipher_type == block) {
                ret = TLSX_EncryptThenMac_Respond(ssl);
                if (ret != 0)
                    goto out;
            }
            else
                ssl->options.encThenMac = 0;
#endif
            if (ssl->options.clientState == CLIENT_KEYEXCHANGE_COMPLETE) {
                WOLFSSL_LEAVE("DoClientHello", ret);
                WOLFSSL_END(WC_FUNC_CLIENT_HELLO_DO);

                goto out;
            }
        }


#if defined(HAVE_TLS_EXTENSIONS) && defined(HAVE_DH_DEFAULT_PARAMS)
    #if defined(HAVE_FFDHE) && defined(HAVE_SUPPORTED_CURVES)
        if (TLSX_Find(ssl->extensions, TLSX_SUPPORTED_GROUPS) != NULL) {
            /* Set FFDHE parameters or clear DHE parameters if FFDH parameters
             * present and no matches in the server's list. */
            ret = TLSX_SupportedFFDHE_Set(ssl);
            if (ret != 0)
                goto out;
        }
    #endif
#endif

#ifdef OPENSSL_EXTRA
        /* Give user last chance to provide a cert for cipher selection */
        if (ret == 0 && ssl->ctx->certSetupCb != NULL)
            ret = CertSetupCbWrapper(ssl);
#endif
        if (ret == 0)
            ret = MatchSuite(ssl, clSuites);

#ifdef WOLFSSL_EXTRA_ALERTS
        if (ret == BUFFER_ERROR)
            SendAlert(ssl, alert_fatal, decode_error);
        else if (ret < 0)
            SendAlert(ssl, alert_fatal, handshake_failure);
#endif
#if defined(HAVE_TLS_EXTENSIONS) && defined(HAVE_ENCRYPT_THEN_MAC) && \
    !defined(WOLFSSL_AEAD_ONLY)
        if (ret == 0 && ssl->options.encThenMac &&
                                              ssl->specs.cipher_type == block) {
            ret = TLSX_EncryptThenMac_Respond(ssl);
        }
        else
            ssl->options.encThenMac = 0;
#endif

#ifdef WOLFSSL_DTLS
        if (ret == 0 && ssl->options.dtls)
            DtlsMsgPoolReset(ssl);
#endif

    out:

#ifdef WOLFSSL_SMALL_STACK
        if (clSuites != NULL)
            XFREE(clSuites, ssl->heap, DYNAMIC_TYPE_SUITES);
#endif
        WOLFSSL_LEAVE("DoClientHello", ret);
        WOLFSSL_END(WC_FUNC_CLIENT_HELLO_DO);

        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(ret);
        }

        return ret;
    }


#if (!defined(NO_RSA) || defined(HAVE_ECC) || defined(HAVE_ED25519) || \
                        defined(HAVE_ED448)) && !defined(WOLFSSL_NO_CLIENT_AUTH)

    typedef struct DcvArgs {
        byte*  output; /* not allocated */
        word32 sendSz;
        word16 sz;
        word32 sigSz;
        word32 idx;
        word32 begin;
        byte   hashAlgo;
        byte   sigAlgo;
    } DcvArgs;

    static void FreeDcvArgs(WOLFSSL* ssl, void* pArgs)
    {
        DcvArgs* args = (DcvArgs*)pArgs;

        (void)ssl;
        (void)args;
    }

    /* handle processing of certificate_verify (15) */
    static int DoCertificateVerify(WOLFSSL* ssl, byte* input,
                                word32* inOutIdx, word32 size)
    {
        int ret = 0;
    #ifdef WOLFSSL_ASYNC_CRYPT
        DcvArgs* args = NULL;
        WOLFSSL_ASSERT_SIZEOF_GE(ssl->async->args, *args);
    #else
        DcvArgs  args[1];
    #endif

        WOLFSSL_START(WC_FUNC_CERTIFICATE_VERIFY_DO);
        WOLFSSL_ENTER("DoCertificateVerify");

    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ssl->async == NULL) {
            ssl->async = (struct WOLFSSL_ASYNC*)
                    XMALLOC(sizeof(struct WOLFSSL_ASYNC), ssl->heap,
                            DYNAMIC_TYPE_ASYNC);
            if (ssl->async == NULL)
                ERROR_OUT(MEMORY_E, exit_dcv);
        }
        args = (DcvArgs*)ssl->async->args;

        ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
        if (ret != WC_NOT_PENDING_E) {
            /* Check for error */
            if (ret < 0)
                goto exit_dcv;
        }
        else
    #endif
        {
            /* Reset state */
            ret = 0;
            ssl->options.asyncState = TLS_ASYNC_BEGIN;
            XMEMSET(args, 0, sizeof(DcvArgs));
            args->hashAlgo = sha_mac;
            args->sigAlgo = anonymous_sa_algo;
            args->idx = *inOutIdx;
            args->begin = *inOutIdx;
        #ifdef WOLFSSL_ASYNC_CRYPT
            ssl->async->freeArgs = FreeDcvArgs;
        #endif
        }

        switch(ssl->options.asyncState)
        {
            case TLS_ASYNC_BEGIN:
            {
            #ifdef WOLFSSL_CALLBACKS
                if (ssl->hsInfoOn)
                    AddPacketName(ssl, "CertificateVerify");
                if (ssl->toInfoOn)
                    AddLateName("CertificateVerify", &ssl->timeoutInfo);
            #endif

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_BUILD;
            } /* case TLS_ASYNC_BEGIN */
            FALL_THROUGH;

            case TLS_ASYNC_BUILD:
            {
                if (IsAtLeastTLSv1_2(ssl)) {
                    if ((args->idx - args->begin) + ENUM_LEN + ENUM_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dcv);
                    }

                    DecodeSigAlg(&input[args->idx], &args->hashAlgo,
                                 &args->sigAlgo);
                    args->idx += 2;
                }
            #ifndef NO_RSA
                else if (ssl->peerRsaKey != NULL && ssl->peerRsaKeyPresent != 0)
                    args->sigAlgo = rsa_sa_algo;
            #endif
            #ifdef HAVE_ECC
                else if (ssl->peerEccDsaKeyPresent)
                    args->sigAlgo = ecc_dsa_sa_algo;
            #endif
            #if defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)
                else if (ssl->peerEd25519KeyPresent)
                    args->sigAlgo = ed25519_sa_algo;
            #endif /* HAVE_ED25519 && !NO_ED25519_CLIENT_AUTH */
            #if defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)
                else if (ssl->peerEd448KeyPresent)
                    args->sigAlgo = ed448_sa_algo;
            #endif /* HAVE_ED448 && !NO_ED448_CLIENT_AUTH */

                if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                    ERROR_OUT(BUFFER_ERROR, exit_dcv);
                }

                ato16(input + args->idx, &args->sz);
                args->idx += OPAQUE16_LEN;

                if ((args->idx - args->begin) + args->sz > size ||
                                                    args->sz > ENCRYPT_LEN) {
                    ERROR_OUT(BUFFER_ERROR, exit_dcv);
                }

            #ifdef HAVE_ECC
                if (ssl->peerEccDsaKeyPresent) {

                    WOLFSSL_MSG("Doing ECC peer cert verify");

                /* make sure a default is defined */
                #if !defined(NO_SHA)
                    SetDigest(ssl, sha_mac);
                #elif !defined(NO_SHA256)
                    SetDigest(ssl, sha256_mac);
                #elif defined(WOLFSSL_SHA384)
                    SetDigest(ssl, sha384_mac);
                #elif defined(WOLFSSL_SHA512)
                    SetDigest(ssl, sha512_mac);
                #else
                    #error No digest enabled for ECC sig verify
                #endif

                    if (IsAtLeastTLSv1_2(ssl)) {
                        if (args->sigAlgo != ecc_dsa_sa_algo) {
                            WOLFSSL_MSG("Oops, peer sent ECC key but not in verify");
                        }

                        SetDigest(ssl, args->hashAlgo);
                    }
                }
            #endif /* HAVE_ECC */
            #if defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)
                if (ssl->peerEd25519KeyPresent) {
                    WOLFSSL_MSG("Doing ED25519 peer cert verify");
                    if (IsAtLeastTLSv1_2(ssl) &&
                                             args->sigAlgo != ed25519_sa_algo) {
                        WOLFSSL_MSG(
                               "Oops, peer sent ED25519 key but not in verify");
                    }
                }
            #endif /* HAVE_ED25519 && !NO_ED25519_CLIENT_AUTH */
            #if defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)
                if (ssl->peerEd448KeyPresent) {
                    WOLFSSL_MSG("Doing ED448 peer cert verify");
                    if (IsAtLeastTLSv1_2(ssl) &&
                                               args->sigAlgo != ed448_sa_algo) {
                        WOLFSSL_MSG(
                                 "Oops, peer sent ED448 key but not in verify");
                    }
                }
            #endif /* HAVE_ED448 && !NO_ED448_CLIENT_AUTH */

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_DO;
            } /* case TLS_ASYNC_BUILD */
            FALL_THROUGH;

            case TLS_ASYNC_DO:
            {
            #ifndef NO_RSA
                if (ssl->peerRsaKey != NULL && ssl->peerRsaKeyPresent != 0) {
                    WOLFSSL_MSG("Doing RSA peer cert verify");

                    ret = RsaVerify(ssl,
                        input + args->idx,
                        args->sz,
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
                        if (args->sigAlgo == rsa_sa_algo)
                            args->sendSz = ret;
                        else {
                            args->sigSz = ret;
                            args->sendSz = ssl->buffers.digest.length;
                        }
                        ret = 0;
                    }
                }
            #endif /* !NO_RSA */
            #ifdef HAVE_ECC
                if (ssl->peerEccDsaKeyPresent) {
                    WOLFSSL_MSG("Doing ECC peer cert verify");

                    ret = EccVerify(ssl,
                        input + args->idx, args->sz,
                        ssl->buffers.digest.buffer, ssl->buffers.digest.length,
                        ssl->peerEccDsaKey,
                    #ifdef HAVE_PK_CALLBACKS
                        &ssl->buffers.peerEccDsaKey
                    #else
                        NULL
                    #endif
                    );
                    /* SERVER: Data verified with certificate's public key. */
                    ssl->options.peerAuthGood = ssl->options.havePeerCert &&
                                                (ret == 0);
                }
            #endif /* HAVE_ECC */
            #if defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)
                if (ssl->peerEd25519KeyPresent) {
                    WOLFSSL_MSG("Doing Ed25519 peer cert verify");

                    ret = Ed25519Verify(ssl,
                        input + args->idx, args->sz,
                        ssl->hsHashes->messages, ssl->hsHashes->prevLen,
                        ssl->peerEd25519Key,
                    #ifdef HAVE_PK_CALLBACKS
                        &ssl->buffers.peerEd25519Key
                    #else
                        NULL
                    #endif
                    );
                    /* SERVER: Data verified with certificate's public key. */
                    ssl->options.peerAuthGood = ssl->options.havePeerCert &&
                                                (ret == 0);
                }
            #endif /* HAVE_ED25519 && !NO_ED25519_CLIENT_AUTH */
            #if defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)
                if (ssl->peerEd448KeyPresent) {
                    WOLFSSL_MSG("Doing Ed448 peer cert verify");

                    ret = Ed448Verify(ssl,
                        input + args->idx, args->sz,
                        ssl->hsHashes->messages, ssl->hsHashes->prevLen,
                        ssl->peerEd448Key,
                    #ifdef HAVE_PK_CALLBACKS
                        &ssl->buffers.peerEd448Key
                    #else
                        NULL
                    #endif
                    );
                    /* SERVER: Data verified with certificate's public key. */
                    ssl->options.peerAuthGood = ssl->options.havePeerCert &&
                                                (ret == 0);
                }
            #endif /* HAVE_ED448 && !NO_ED448_CLIENT_AUTH */

            #ifdef WOLFSSL_ASYNC_CRYPT
                /* handle async pending */
                if (ret == WC_PENDING_E)
                    goto exit_dcv;
            #endif

                /* Check for error */
                if (ret != 0) {
                    ret = SIG_VERIFY_E;
                    goto exit_dcv;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_VERIFY;
            } /* case TLS_ASYNC_DO */
            FALL_THROUGH;

            case TLS_ASYNC_VERIFY:
            {
            #ifndef NO_RSA
                if (ssl->peerRsaKey != NULL && ssl->peerRsaKeyPresent != 0) {
                    if (IsAtLeastTLSv1_2(ssl)) {
                    #ifdef WC_RSA_PSS
                        if (args->sigAlgo == rsa_pss_sa_algo) {
                            SetDigest(ssl, args->hashAlgo);

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
                                            HashAlgoToType(args->hashAlgo), -1,
                                            mp_count_bits(&ssl->peerRsaKey->n));
                        #endif
                            if (ret != 0) {
                                ret = SIG_VERIFY_E;
                                goto exit_dcv;
                            }
                        }
                        else
                    #endif
                        {
                        #ifndef WOLFSSL_SMALL_STACK
                            byte  encodedSig[MAX_ENCODED_SIG_SZ];
                        #else
                            byte* encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ,
                                             ssl->heap, DYNAMIC_TYPE_SIGNATURE);
                            if (encodedSig == NULL) {
                                ERROR_OUT(MEMORY_E, exit_dcv);
                            }
                        #endif

                            if (args->sigAlgo != rsa_sa_algo) {
                                WOLFSSL_MSG("Oops, peer sent RSA key but not "
                                            "in verify");
                            }

                            SetDigest(ssl, args->hashAlgo);

                            args->sigSz = wc_EncodeSignature(encodedSig,
                                ssl->buffers.digest.buffer,
                                ssl->buffers.digest.length,
                                TypeHash(args->hashAlgo));

                            if (args->sendSz != args->sigSz || !args->output ||
                                XMEMCMP(args->output, encodedSig,
                                   min(args->sigSz, MAX_ENCODED_SIG_SZ)) != 0) {
                                ret = VERIFY_CERT_ERROR;
                            }

                        #ifdef WOLFSSL_SMALL_STACK
                            XFREE(encodedSig, ssl->heap,
                                  DYNAMIC_TYPE_SIGNATURE);
                        #endif
                        }
                    }
                    else {
                        if (args->sendSz != FINISHED_SZ || !args->output ||
                            XMEMCMP(args->output,
                                &ssl->hsHashes->certHashes, FINISHED_SZ) != 0) {
                            ret = VERIFY_CERT_ERROR;
                        }
                    }
                    if (ret == 0) {
                        /* SERVER: Data verified with cert's public key. */
                        ssl->options.peerAuthGood = ssl->options.havePeerCert &&
                                                    (ret == 0);
                    }
                }
            #endif /* !NO_RSA */
                if (ret != 0)
                    break;

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

                ssl->options.havePeerVerify = 1;

                /* Set final index */
                args->idx += args->sz;
                *inOutIdx = args->idx;

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_END;
            } /* case TLS_ASYNC_FINALIZE */
            FALL_THROUGH;

            case TLS_ASYNC_END:
            {
                break;
            }
            default:
                ret = INPUT_CASE_ERROR;
        } /* switch(ssl->options.asyncState) */

    exit_dcv:

        WOLFSSL_LEAVE("DoCertificateVerify", ret);
        WOLFSSL_END(WC_FUNC_CERTIFICATE_VERIFY_DO);

    #ifdef WOLFSSL_ASYNC_CRYPT
        /* Handle async operation */
        if (ret == WC_PENDING_E) {
            /* Mark message as not received so it can process again */
            ssl->msgsReceived.got_certificate_verify = 0;

            return ret;
        }
    #endif /* WOLFSSL_ASYNC_CRYPT */
    #ifdef WOLFSSL_EXTRA_ALERTS
        if (ret == BUFFER_ERROR)
            SendAlert(ssl, alert_fatal, decode_error);
        else if (ret == SIG_VERIFY_E)
            SendAlert(ssl, alert_fatal, decrypt_error);
        else if (ret != 0)
            SendAlert(ssl, alert_fatal, bad_certificate);
    #endif
        /* Digest is not allocated, so do this to prevent free */
        ssl->buffers.digest.buffer = NULL;
        ssl->buffers.digest.length = 0;

    #ifdef WOLFSSL_ASYNC_CRYPT
        /* Cleanup async */
        FreeAsyncCtx(ssl, 0);
    #else
        FreeDcvArgs(ssl, args);
    #endif
        /* Final cleanup */
        FreeKeyExchange(ssl);

        if (ret != 0) {
            WOLFSSL_ERROR_VERBOSE(ret);
        }

        return ret;
    }

#endif /* (!NO_RSA || ECC || ED25519 || ED448) && !WOLFSSL_NO_CLIENT_AUTH */

    /* handle generation of server_hello_done (14) */
    int SendServerHelloDone(WOLFSSL* ssl)
    {
        byte* output;
        int   sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int   ret;

        WOLFSSL_START(WC_FUNC_SERVER_HELLO_DONE_SEND);
        WOLFSSL_ENTER("SendServerHelloDone");

    #ifdef WOLFSSL_DTLS
        if (ssl->options.dtls)
            sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
    #endif

        if (IsEncryptionOn(ssl, 1))
            sendSz += MAX_MSG_EXTRA;

        /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
         * is not advanced yet */
        ssl->options.buildingMsg = 1;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, 0, server_hello_done, ssl);

        if (IsEncryptionOn(ssl, 1)) {
            byte* input;
            int   inputSz = HANDSHAKE_HEADER_SZ; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls) {
                recordHeaderSz += DTLS_RECORD_EXTRA;
                inputSz += DTLS_HANDSHAKE_EXTRA;
            }

            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            #ifdef WOLFSSL_DTLS
            if (IsDtlsNotSctpMode(ssl) &&
                    (ret = DtlsMsgPoolSave(ssl, input, inputSz, server_hello_done)) != 0) {
                XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                return ret;
            }
            #endif
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        } else {
            #ifdef WOLFSSL_DTLS
                if (IsDtlsNotSctpMode(ssl)) {
                    if ((ret = DtlsMsgPoolSave(ssl, output, sendSz, server_hello_done)) != 0)
                        return ret;
                }
                if (ssl->options.dtls)
                    DtlsSEQIncrement(ssl, CUR_ORDER);
            #endif
            ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0)
                return ret;
        }

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "ServerHelloDone");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "ServerHelloDone", handshake, output,
                    sendSz, WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
    #endif
        ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
        ssl->options.buildingMsg = 0;

        ssl->buffers.outputBuffer.length += sendSz;

        ret = SendBuffered(ssl);

        WOLFSSL_LEAVE("SendServerHelloDone", ret);
        WOLFSSL_END(WC_FUNC_SERVER_HELLO_DONE_SEND);

        return ret;
    }

#endif /* !WOLFSSL_NO_TLS12 */

#ifdef HAVE_SESSION_TICKET

    /* create a new session ticket, 0 on success */
    int CreateTicket(WOLFSSL* ssl)
    {
        InternalTicket* it;
        ExternalTicket* et;
        int encLen;
        int ret;
        int error;
        word32 itHash = 0;
        byte zeros[WOLFSSL_TICKET_MAC_SZ];   /* biggest cmp size */

        WOLFSSL_ASSERT_SIZEOF_GE(ssl->session->staticTicket, *et);
        WOLFSSL_ASSERT_SIZEOF_GE(et->enc_ticket, *it);

        if (ssl->session->ticket != ssl->session->staticTicket) {
            /* Always use the static ticket buffer */
            XFREE(ssl->session->ticket, NULL, DYNAMIC_TYPE_SESSION_TICK);
            ssl->session->ticket = ssl->session->staticTicket;
            ssl->session->ticketLenAlloc = 0;
        }

        et = (ExternalTicket*)ssl->session->ticket;
        it = (InternalTicket*)et->enc_ticket;

    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ssl->error != WC_PENDING_E)
    #endif
        {
            XMEMSET(et, 0, sizeof(*et));
        }

        /* build internal */
        it->pv.major = ssl->version.major;
        it->pv.minor = ssl->version.minor;

        it->suite[0] = ssl->options.cipherSuite0;
        it->suite[1] = ssl->options.cipherSuite;

    #ifdef WOLFSSL_EARLY_DATA
        c32toa(ssl->options.maxEarlyDataSz, it->maxEarlyDataSz);
    #endif

        if (!ssl->options.tls1_3) {
            XMEMCPY(it->msecret, ssl->arrays->masterSecret, SECRET_LEN);
#ifndef NO_ASN_TIME
            c32toa(LowResTimer(), it->timestamp);
#endif
            it->haveEMS = (byte) ssl->options.haveEMS;
        }
        else {
#ifdef WOLFSSL_TLS13
        #ifdef WOLFSSL_32BIT_MILLI_TIME
            word32 now = TimeNowInMilliseconds();
        #else
            sword64 now = TimeNowInMilliseconds();
        #endif
            if (now == 0) {
                ret = GETTIME_ERROR;
                goto error;
            }

            /* Client adds to ticket age to obfuscate. */
            ret = wc_RNG_GenerateBlock(ssl->rng, it->ageAdd,
                                       sizeof(it->ageAdd));
            if (ret != 0) {
                ret = BAD_TICKET_ENCRYPT;
                goto error;
            }
            ato32(it->ageAdd, &ssl->session->ticketAdd);
            c16toa(ssl->session->namedGroup, it->namedGroup);
        #ifdef WOLFSSL_32BIT_MILLI_TIME
            c32toa(now, it->timestamp);
        #else
            c32toa((word32)(now >> 32), it->timestamp);
            c32toa((word32)now        , it->timestamp + OPAQUE32_LEN);
        #endif
            /* Resumption master secret. */
            XMEMCPY(it->msecret, ssl->session->masterSecret, SECRET_LEN);
            if (ssl->session->ticketNonce.len > MAX_TICKET_NONCE_STATIC_SZ) {
                WOLFSSL_MSG("Bad ticket nonce value");
                ret = BAD_TICKET_MSG_SZ;
                goto error;
            }
            XMEMCPY(it->ticketNonce, ssl->session->ticketNonce.data,
                ssl->session->ticketNonce.len);
            it->ticketNonceLen = ssl->session->ticketNonce.len;
#endif
        }

#ifdef WOLFSSL_TICKET_HAVE_ID
        {
            const byte* id = NULL;
            byte idSz = 0;
            if (ssl->session->haveAltSessionID) {
                id = ssl->session->altSessionID;
                idSz = ID_LEN;
            }
            else if (!IsAtLeastTLSv1_3(ssl->version) && ssl->arrays != NULL) {
                id = ssl->arrays->sessionID;
                idSz = ssl->arrays->sessionIDSz;
            }
            else {
                id = ssl->session->sessionID;
                idSz = ssl->session->sessionIDSz;
            }
            if (idSz == 0) {
                ret = wc_RNG_GenerateBlock(ssl->rng, ssl->session->altSessionID,
                                           ID_LEN);
                if (ret != 0)
                    goto error;
                ssl->session->haveAltSessionID = 1;
                id = ssl->session->altSessionID;
                idSz = ID_LEN;
            }
            /* make sure idSz is not larger than ID_LEN */
            if (idSz > ID_LEN)
                idSz = ID_LEN;
            XMEMCPY(it->id, id, idSz);
        }
#endif

        /* encrypt */
        encLen = WOLFSSL_TICKET_ENC_SZ;  /* max size user can use */
        if (ssl->ctx->ticketEncCb == NULL
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || defined(WOLFSSL_WPAS_SMALL)
                ||
                /* SSL_OP_NO_TICKET turns off tickets in <= 1.2. Forces
                 * "stateful" tickets for 1.3 so just use the regular
                 * stateless ones. */
                (!IsAtLeastTLSv1_3(ssl->version) &&
                        (ssl->options.mask & WOLFSSL_OP_NO_TICKET) != 0)
#endif
                        ) {
            /* Use BAD_TICKET_ENCRYPT to signal missing ticket callback */
            ret = BAD_TICKET_ENCRYPT;
        }
        else {
            itHash = HashObject((byte*)it, sizeof(*it), &error);
            if (error == 0) {
                ret = ssl->ctx->ticketEncCb(ssl, et->key_name, et->iv, et->mac,
                        1, et->enc_ticket, sizeof(InternalTicket), &encLen,
                        ssl->ctx->ticketEncCtx);
            }
            else {
                ret = WOLFSSL_TICKET_RET_FATAL;
            }
        }
        if (ret != WOLFSSL_TICKET_RET_OK) {
#ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E) {
                return ret;
            }
#endif
            goto error;
        }
        if (encLen < (int)sizeof(InternalTicket) ||
                encLen > (int)WOLFSSL_TICKET_ENC_SZ) {
            WOLFSSL_MSG("Bad user ticket encrypt size");
            ret = BAD_TICKET_KEY_CB_SZ;
        }

        /* sanity checks on encrypt callback */

        /* internal ticket can't be the same if encrypted */
        if (itHash == HashObject((byte*)it, sizeof(*it), &error) || error != 0)
        {
            WOLFSSL_MSG("User ticket encrypt didn't encrypt or hash failed");
            ret = BAD_TICKET_ENCRYPT;
            goto error;
        }

        XMEMSET(zeros, 0, sizeof(zeros));

        /* name */
        if (XMEMCMP(et->key_name, zeros, WOLFSSL_TICKET_NAME_SZ) == 0) {
            WOLFSSL_MSG("User ticket encrypt didn't set name");
            ret = BAD_TICKET_ENCRYPT;
            goto error;
        }

        /* iv */
        if (XMEMCMP(et->iv, zeros, WOLFSSL_TICKET_IV_SZ) == 0) {
            WOLFSSL_MSG("User ticket encrypt didn't set iv");
            ret = BAD_TICKET_ENCRYPT;
            goto error;
        }

        /* mac */
        if (XMEMCMP(et->mac, zeros, WOLFSSL_TICKET_MAC_SZ) == 0) {
            WOLFSSL_MSG("User ticket encrypt didn't set mac");
            ret = BAD_TICKET_ENCRYPT;
            goto error;
        }

        /* set size */
        c16toa((word16)encLen, et->enc_len);
        if (encLen < (int)WOLFSSL_TICKET_ENC_SZ) {
            /* move mac up since whole enc buffer not used */
            XMEMMOVE(et->enc_ticket + encLen, et->mac,
                    WOLFSSL_TICKET_MAC_SZ);
        }
        ssl->session->ticketLen =
                (word16)(encLen + WOLFSSL_TICKET_FIXED_SZ);

        return ret;
    error:
#ifdef WOLFSSL_CHECK_MEM_ZERO
        /* Ticket has sensitive data in it now. */
        wc_MemZero_Add("Create Ticket internal", it, sizeof(InternalTicket));
#endif
        ForceZero(it, sizeof(*it));
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(it, sizeof(InternalTicket));
#endif
        WOLFSSL_ERROR_VERBOSE(ret);
        return ret;

    }

    int DoDecryptTicket(WOLFSSL* ssl, const byte* input, word32 len,
        InternalTicket **it)
    {
        ExternalTicket* et;
        int             ret;
        int             outLen;
        word16          inLen;

        WOLFSSL_START(WC_FUNC_TICKET_DO);
        WOLFSSL_ENTER("DoClientTicket");

        if (len > SESSION_TICKET_LEN ||
            len < (word32)(sizeof(InternalTicket) + WOLFSSL_TICKET_FIXED_SZ)) {
            WOLFSSL_ERROR_VERBOSE(BAD_TICKET_MSG_SZ);
            return WOLFSSL_TICKET_RET_REJECT;
        }

        et = (ExternalTicket*)input;

        /* decrypt */
        ato16(et->enc_len, &inLen);
        if (inLen > WOLFSSL_TICKET_ENC_SZ) {
            WOLFSSL_ERROR_VERBOSE(BAD_TICKET_MSG_SZ);
            return WOLFSSL_TICKET_RET_REJECT;
        }
        outLen = (int)inLen;   /* may be reduced by user padding */

        if (ssl->ctx->ticketEncCb == NULL
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER) || defined(WOLFSSL_WPAS_SMALL)
                ||
                /* SSL_OP_NO_TICKET turns off tickets in < 1.2. Forces
                 * "stateful" tickets for 1.3 so just use the regular
                 * stateless ones. */
                (!IsAtLeastTLSv1_3(ssl->version) &&
                        (ssl->options.mask & WOLFSSL_OP_NO_TICKET) != 0)
#endif
                        ) {
            /* Use BAD_TICKET_ENCRYPT to signal missing ticket callback */
            WOLFSSL_ERROR_VERBOSE(BAD_TICKET_ENCRYPT);
            ret = WOLFSSL_TICKET_RET_REJECT;
        }
        else {
            ret = ssl->ctx->ticketEncCb(ssl, et->key_name, et->iv,
                                    et->enc_ticket + inLen, 0,
                                    et->enc_ticket, inLen, &outLen,
                                    ssl->ctx->ticketEncCtx);
        }
        if (ret != WOLFSSL_TICKET_RET_OK) {
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E) {
                return ret;
            }
        #endif /* WOLFSSL_ASYNC_CRYPT */
            if (ret != WOLFSSL_TICKET_RET_CREATE) {
                WOLFSSL_ERROR_VERBOSE(BAD_TICKET_KEY_CB_SZ);
                return WOLFSSL_TICKET_RET_REJECT;
            }
        }
        if (outLen > (int)inLen || outLen < (int)sizeof(InternalTicket)) {
            WOLFSSL_MSG("Bad user ticket decrypt len");
            WOLFSSL_ERROR_VERBOSE(BAD_TICKET_KEY_CB_SZ);
            return BAD_TICKET_KEY_CB_SZ;
        }
        *it = (InternalTicket*)et->enc_ticket;
        return 0;
    }

    /* Parse ticket sent by client, returns callback return value */
    int DoClientTicket(WOLFSSL* ssl, const byte* input, word32 len)
    {
        InternalTicket* it;
        int             ret;

        WOLFSSL_START(WC_FUNC_TICKET_DO);
        WOLFSSL_ENTER("DoClientTicket");

        ret = DoDecryptTicket(ssl, input, len, &it);
        if (ret != 0)
            return ret;
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        /* Internal ticket successfully decrypted. */
        wc_MemZero_Add("Do Client Ticket internal", it, sizeof(InternalTicket));
    #endif

        /* get master secret */
        if (ret == WOLFSSL_TICKET_RET_OK || ret == WOLFSSL_TICKET_RET_CREATE) {
            if (ssl->version.minor < it->pv.minor) {
                WOLFSSL_MSG("Ticket has greater version");
                ret = VERSION_ERROR;
                goto error;
            }
            else if (ssl->version.minor > it->pv.minor) {
                if (IsAtLeastTLSv1_3(it->pv) != IsAtLeastTLSv1_3(ssl->version)) {
                    WOLFSSL_MSG("Tickets cannot be shared between "
                                               "TLS 1.3 and TLS 1.2 and lower");
                    ret = VERSION_ERROR;
                    goto error;
                }

                if (!ssl->options.downgrade) {
                    WOLFSSL_MSG("Ticket has lesser version");
                    ret = VERSION_ERROR;
                    goto error;
                }

                WOLFSSL_MSG("Downgrading protocol due to ticket");

                if (it->pv.minor < ssl->options.minDowngrade) {
                    WOLFSSL_MSG("Ticket has lesser version than allowed");
                    ret = VERSION_ERROR;
                    goto error;
                }
                ssl->version.minor = it->pv.minor;
            }

#ifdef WOLFSSL_TICKET_HAVE_ID
            {
                ssl->session->haveAltSessionID = 1;
                XMEMCPY(ssl->session->altSessionID, it->id, ID_LEN);
                if (wolfSSL_GetSession(ssl, NULL, 1) != NULL) {
                    WOLFSSL_MSG("Found session matching the session id"
                                " found in the ticket");
                }
                else {
                    WOLFSSL_MSG("Can't find session matching the session id"
                                " found in the ticket");
                }
            }
#endif

            if (!IsAtLeastTLSv1_3(ssl->version)) {
                XMEMCPY(ssl->arrays->masterSecret, it->msecret, SECRET_LEN);
                /* Copy the haveExtendedMasterSecret property from the ticket to
                 * the saved session, so the property may be checked later. */
                ssl->session->haveEMS = it->haveEMS;
                ato32((const byte*)&it->timestamp, &ssl->session->bornOn);
            #ifndef NO_RESUME_SUITE_CHECK
                ssl->session->cipherSuite0 = it->suite[0];
                ssl->session->cipherSuite = it->suite[1];
            #endif
            }
            else {
#ifdef WOLFSSL_TLS13
                /* Restore information to renegotiate. */
            #ifdef WOLFSSL_32BIT_MILLI_TIME
                ato32(it->timestamp, &ssl->session->ticketSeen);
            #else
                word32 seenHi, seenLo;

                ato32(it->timestamp               , &seenHi);
                ato32(it->timestamp + OPAQUE32_LEN, &seenLo);
                ssl->session->ticketSeen = ((sword64)seenHi << 32) + seenLo;
            #endif
                ato32(it->ageAdd, &ssl->session->ticketAdd);
                ssl->session->cipherSuite0 = it->suite[0];
                ssl->session->cipherSuite = it->suite[1];
    #ifdef WOLFSSL_EARLY_DATA
                ato32(it->maxEarlyDataSz, &ssl->session->maxEarlyDataSz);
    #endif
                /* Resumption master secret. */
                XMEMCPY(ssl->session->masterSecret, it->msecret, SECRET_LEN);
                if (it->ticketNonceLen > MAX_TICKET_NONCE_STATIC_SZ) {
                    WOLFSSL_MSG("Unsupported ticketNonce len in ticket");
                    return BAD_TICKET_ENCRYPT;
                }
#if defined(WOLFSSL_TICKET_NONCE_MALLOC) &&                                    \
    (!defined(HAVE_FIPS) || (defined(FIPS_VERSION_GE) && FIPS_VERSION_GE(5,3)))
                if (ssl->session->ticketNonce.data
                       != ssl->session->ticketNonce.dataStatic) {
                    XFREE(ssl->session->ticketNonce.data, ssl->heap,
                        DYNAMIC_TYPE_SESSION_TICK);
                    ssl->session->ticketNonce.data =
                        ssl->session->ticketNonce.dataStatic;
                }
#endif /* defined(WOLFSSL_TICKET_NONCE_MALLOC) && FIPS_VERSION_GE(5,3) */
                XMEMCPY(ssl->session->ticketNonce.data, it->ticketNonce,
                    it->ticketNonceLen);
                ssl->session->ticketNonce.len = it->ticketNonceLen;
                ato16(it->namedGroup, &ssl->session->namedGroup);
#endif
            }
        }

        ForceZero(it, sizeof(*it));
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(it, sizeof(InternalTicket));
#endif

        WOLFSSL_LEAVE("DoClientTicket", ret);
        WOLFSSL_END(WC_FUNC_TICKET_DO);

        return ret;

error:
        ForceZero(it, sizeof(*it));
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Check(it, sizeof(InternalTicket));
#endif
        WOLFSSL_ERROR_VERBOSE(ret);
        return WOLFSSL_TICKET_RET_REJECT;
    }


    /* send Session Ticket */
    int SendTicket(WOLFSSL* ssl)
    {
        byte*              output;
        int                ret;
        int                sendSz;
        word32             length = SESSION_HINT_SZ + LENGTH_SZ;
        word32             idx    = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

        WOLFSSL_START(WC_FUNC_TICKET_SEND);
        WOLFSSL_ENTER("SendTicket");

        if (ssl->options.createTicket) {
            ret = CreateTicket(ssl);
            if (ret != 0)
                return ret;
        }

        length += ssl->session->ticketLen;
        sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

        if (!ssl->options.dtls) {
            if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone)
                sendSz += MAX_MSG_EXTRA;
        }
        else {
        #ifdef WOLFSSL_DTLS
            sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
            idx    += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;
        #endif
        }

        if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone)
            sendSz += cipherExtraData(ssl);

        /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
         * is not advanced yet */
        ssl->options.buildingMsg = 1;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, length, session_ticket, ssl);

        /* hint */
        c32toa(ssl->ctx->ticketHint, output + idx);
        idx += SESSION_HINT_SZ;

        /* length */
        c16toa(ssl->session->ticketLen, output + idx);
        idx += LENGTH_SZ;

        /* ticket */
        XMEMCPY(output + idx, ssl->session->ticket, ssl->session->ticketLen);
        idx += ssl->session->ticketLen;

        if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone) {
            byte* input;
            int   inputSz = idx; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls)
                recordHeaderSz += DTLS_RECORD_EXTRA;
            inputSz -= recordHeaderSz;
            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        }
        else {
            #ifdef WOLFSSL_DTLS
            if (ssl->options.dtls) {
                if ((ret = DtlsMsgPoolSave(ssl, output, sendSz, session_ticket)) != 0)
                    return ret;

                DtlsSEQIncrement(ssl, CUR_ORDER);
            }
            #endif
            ret = HashOutput(ssl, output, sendSz, 0);
            if (ret != 0)
                return ret;
        }

        ssl->buffers.outputBuffer.length += sendSz;
        ssl->options.buildingMsg = 0;

        if (!ssl->options.groupMessages)
            ret = SendBuffered(ssl);

        WOLFSSL_LEAVE("SendTicket", ret);
        WOLFSSL_END(WC_FUNC_TICKET_SEND);

        return ret;
    }

#ifndef WOLFSSL_NO_DEF_TICKET_ENC_CB

/* Initialize the context for session ticket encryption.
 *
 * @param [in]  ctx     SSL context.
 * @param [in]  keyCtx  Context for session ticket encryption.
 * @return  0 on success.
 * @return  BAD_MUTEX_E when initializing mutex fails.
 */
static int TicketEncCbCtx_Init(WOLFSSL_CTX* ctx, TicketEncCbCtx* keyCtx)
{
    int ret = 0;

    XMEMSET(keyCtx, 0, sizeof(*keyCtx));
    keyCtx->ctx = ctx;

#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("TicketEncCbCtx_Init keyCtx->name", keyCtx->name,
        sizeof(keyCtx->name));
    wc_MemZero_Add("TicketEncCbCtx_Init keyCtx->key[0]", keyCtx->key[0],
        sizeof(keyCtx->key[0]));
    wc_MemZero_Add("TicketEncCbCtx_Init keyCtx->key[1]", keyCtx->key[1],
        sizeof(keyCtx->key[1]));
#endif

#ifndef SINGLE_THREADED
    ret = wc_InitMutex(&keyCtx->mutex);
#endif

    return ret;
}

/* Setup the session ticket encryption context for this.
 *
 * Initialize RNG, generate name, generate primary key and set primary key
 * expirary.
 *
 * @param [in]  keyCtx  Context for session ticket encryption.
 * @param [in]  heap    Dynamic memory allocation hint.
 * @param [in]  devId   Device identifier.
 * @return  0 on success.
 * @return  Other value when random number generator fails.
 */
static int TicketEncCbCtx_Setup(TicketEncCbCtx* keyCtx, void* heap, int devId)
{
    int ret;

#ifndef SINGLE_THREADED
    ret = 0;

    /* Check that key wasn't set up while waiting. */
    if (keyCtx->expirary[0] == 0)
#endif
    {
        ret = wc_InitRng_ex(&keyCtx->rng, heap, devId);
        if (ret == 0) {
            ret = wc_RNG_GenerateBlock(&keyCtx->rng, keyCtx->name,
                                       sizeof(keyCtx->name));
        }
        if (ret == 0) {
            /* Mask of the bottom bit - used for index of key. */
            keyCtx->name[WOLFSSL_TICKET_NAME_SZ - 1] &= 0xfe;

            /* Generate initial primary key. */
            ret = wc_RNG_GenerateBlock(&keyCtx->rng, keyCtx->key[0],
                                       WOLFSSL_TICKET_KEY_SZ);
        }
        if (ret == 0) {
            keyCtx->expirary[0] = LowResTimer() + WOLFSSL_TICKET_KEY_LIFETIME;
        }
    }

    return ret;
}
/* Free the context for session ticket encryption.
 *
 * Zeroize keys and name.
 *
 * @param [in]  keyCtx  Context for session ticket encryption.
 */
static void TicketEncCbCtx_Free(TicketEncCbCtx* keyCtx)
{
    /* Zeroize sensitive data. */
    ForceZero(keyCtx->name, sizeof(keyCtx->name));
    ForceZero(keyCtx->key[0], sizeof(keyCtx->key[0]));
    ForceZero(keyCtx->key[1], sizeof(keyCtx->key[1]));

#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(keyCtx->name, sizeof(keyCtx->name));
    wc_MemZero_Check(keyCtx->key[0], sizeof(keyCtx->key[0]));
    wc_MemZero_Check(keyCtx->key[1], sizeof(keyCtx->key[1]));
#endif

#ifndef SINGLE_THREADED
    wc_FreeMutex(&keyCtx->mutex);
#endif
    wc_FreeRng(&keyCtx->rng);
}

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && \
    !defined(WOLFSSL_TICKET_ENC_AES128_GCM) && \
    !defined(WOLFSSL_TICKET_ENC_AES256_GCM)
/* Ticket encryption/decryption implementation.
 *
 * @param [in]   key     Key for encryption/decryption.
 * @param [in]   keyLen  Length of key in bytes.
 * @param [in]   iv      IV/Nonce for encryption/decryption.
 * @param [in]   aad     Additional authentication data.
 * @param [in]   aadSz   Length of additional authentication data.
 * @param [in]   in      Data to encrypt/decrypt.
 * @param [in]   inLen   Length of encrypted data.
 * @param [out]  out     Resulting data from encrypt/decrypt.
 * @param [out]  outLen  Size of resulting data.
 * @param [in]   tag     Authentication tag for encrypted data.
 * @param [in]   heap    Dynamic memory allocation data hint.
 * @param [in]   enc     1 when encrypting, 0 when decrypting.
 * @return  0 on success.
 * @return  Other value when encryption/decryption fails.
 */
static int TicketEncDec(byte* key, int keyLen, byte* iv, byte* aad, int aadSz,
                        byte* in, int inLen, byte* out, int* outLen, byte* tag,
                        void* heap, int enc)
{
    int ret;

    (void)keyLen;
    (void)heap;

    if (enc) {
        ret = wc_ChaCha20Poly1305_Encrypt(key, iv, aad, aadSz, in, inLen, out,
                                          tag);
    }
    else {
        ret = wc_ChaCha20Poly1305_Decrypt(key, iv, aad, aadSz, in, inLen, tag,
                                          out);
    }

    *outLen = inLen;

    return ret;
}
#elif defined(HAVE_AESGCM)
/* Ticket encryption/decryption implementation.
 *
 * @param [in]   key     Key for encryption/decryption.
 * @param [in]   keyLen  Length of key in bytes.
 * @param [in]   iv      IV/Nonce for encryption/decryption.
 * @param [in]   aad     Additional authentication data.
 * @param [in]   aadSz   Length of additional authentication data.
 * @param [in]   in      Data to encrypt/decrypt.
 * @param [in]   inLen   Length of encrypted data.
 * @param [out]  out     Resulting data from encrypt/decrypt.
 * @param [out]  outLen  Size of resulting data.
 * @param [in]   tag     Authentication tag for encrypted data.
 * @param [in]   heap    Dynamic memory allocation data hint.
 * @param [in]   enc     1 when encrypting, 0 when decrypting.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  Other value when encryption/decryption fails.
 */
static int TicketEncDec(byte* key, int keyLen, byte* iv, byte* aad, int aadSz,
                        byte* in, int inLen, byte* out, int* outLen, byte* tag,
                        void* heap, int enc)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes;
#else
    Aes aes[1];
#endif

    (void)heap;

#ifdef WOLFSSL_SMALL_STACK
    aes = (Aes*)XMALLOC(sizeof(Aes), heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (aes == NULL)
        return MEMORY_E;
#endif

    if (enc) {
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(aes, key, keyLen);
        }
        if (ret == 0) {
            ret = wc_AesGcmEncrypt(aes, in, out, inLen, iv, GCM_NONCE_MID_SZ,
                                   tag, AES_BLOCK_SIZE, aad, aadSz);
        }
        wc_AesFree(aes);
    }
    else {
        ret = wc_AesInit(aes, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_AesGcmSetKey(aes, key, keyLen);
        }
        if (ret == 0) {
            ret = wc_AesGcmDecrypt(aes, in, out, inLen, iv, GCM_NONCE_MID_SZ,
                                   tag, AES_BLOCK_SIZE, aad, aadSz);
        }
        wc_AesFree(aes);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(aes, heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    *outLen = inLen;

    return ret;
}
#else
    #error "No encryption algorithm available for default ticket encryption."
#endif

/* Choose a key to use for encryption.
 *
 * Generate a new key if the current ones are expired.
 * If the secondary key has not been used and the primary key has expired then
 * generate a new primary key.
 *
 * @param [in]   Ticket encryption callback context.
 * @param [in]   Session ticket lifetime.
 * @param [out]  Index of key to use for encryption.
 * @return  0 on success.
 * @return  Other value when random number generation fails.
 */
static int TicketEncCbCtx_ChooseKey(TicketEncCbCtx* keyCtx, int ticketHint,
                                    int* keyIdx)
{
    int ret = 0;

    /* Get new current time as lock may have taken some time. */
    word32 now = LowResTimer();

    /* Check expirary of primary key for encrypt. */
    if (keyCtx->expirary[0] >= now + ticketHint) {
        *keyIdx = 0;
    }
    /* Check expirary of primary key for encrypt. */
    else if (keyCtx->expirary[1] >= now + ticketHint) {
        *keyIdx = 1;
    }
    /* No key available to use. */
    else {
        int genKey;

        /* Generate which ever key is expired for decrypt - primary first. */
        if (keyCtx->expirary[0] < now) {
            genKey = 0;
        }
        else if (keyCtx->expirary[1] < now) {
            genKey = 1;
        }
        /* Timeouts and expirary should not allow this to happen. */
        else {
            return BAD_STATE_E;
        }

        /* Generate the required key */
        ret = wc_RNG_GenerateBlock(&keyCtx->rng, keyCtx->key[genKey],
                                   WOLFSSL_TICKET_KEY_SZ);
        if (ret == 0) {
            keyCtx->expirary[genKey] = now + WOLFSSL_TICKET_KEY_LIFETIME;
            *keyIdx = genKey;
        }
    }

    return ret;
}

/* Default Session Ticket encryption/decryption callback.
 *
 * Use ChaCha20-Poly1305 or AES-GCM to encrypt/decrypt the ticket.
 * Two keys are used:
 *  - When the first expires for encryption, then use the other.
 *  - Don't encrypt with key if the ticket lifetime will go beyond expirary.
 *  - Generate a new primary key when primary key expired for decrypt and
 *    no secondary key is activate for encryption.
 *  - Generate a new secondary key when expired and needed.
 *  - Calculate expirary starting from first encrypted ticket.
 *  - Key name has last bit set to indicate index of key.
 * Keys expire for decryption after ticket key lifetime from the first encrypted
 * ticket.
 * Keys can only be use for encryption while the ticket hint does not exceed
 * the key lifetime.
 * Lifetime of a key must be greater than the lifetime of a ticket. This means
 * that if one ticket is only valid for decryption, then the other will be
 * valid for encryption.
 * AAD = key_name | iv | ticket len (16-bits network order)
 *
 * @param [in]      ssl       SSL connection.
 * @param [in,out]  key_name  Name of key from client.
 *                            Encrypt: name of key returned.
 *                            Decrypt: name from ticket message to check.
 * @param [in]      iv        IV to use in encryption/decryption.
 * @param [in]      mac       MAC for authentication of encrypted data.
 * @param [in]      enc       1 when encrypting ticket, 0 when decrypting.
 * @param [in,out]  ticket    Encrypted/decrypted session ticket bytes.
 * @param [in]      inLen     Length of incoming ticket.
 * @param [out]     outLen    Length of outgoing ticket.
 * @param [in]      userCtx   Context for encryption/decryption of ticket.
 * @return  WOLFSSL_TICKET_RET_OK when successful.
 * @return  WOLFSSL_TICKET_RET_CREATE when successful and a new ticket is to
 *          be created for TLS 1.2 and below.
 * @return  WOLFSSL_TICKET_RET_REJECT when failed to produce valid encrypted or
 *          decrypted ticket.
 * @return  WOLFSSL_TICKET_RET_FATAL when key name does not match.
 */
static int DefTicketEncCb(WOLFSSL* ssl, byte key_name[WOLFSSL_TICKET_NAME_SZ],
                          byte iv[WOLFSSL_TICKET_IV_SZ],
                          byte mac[WOLFSSL_TICKET_MAC_SZ],
                          int enc, byte* ticket, int inLen, int* outLen,
                          void* userCtx)
{
    int ret;
    TicketEncCbCtx* keyCtx = (TicketEncCbCtx*)userCtx;
    WOLFSSL_CTX* ctx = keyCtx->ctx;
    word16 sLen = XHTONS((word16)inLen);
    byte aad[WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ + sizeof(sLen)];
    int  aadSz = WOLFSSL_TICKET_NAME_SZ + WOLFSSL_TICKET_IV_SZ + sizeof(sLen);
    byte* p = aad;
    int keyIdx = 0;

    WOLFSSL_ENTER("DefTicketEncCb");

    /* Check we have setup the RNG, name and primary key. */
    if (keyCtx->expirary[0] == 0) {
#ifndef SINGLE_THREADED
        /* Lock around access to expirary and key - stop initial key being
         * generated twice at the same time. */
        if (wc_LockMutex(&keyCtx->mutex) != 0) {
            WOLFSSL_MSG("Couldn't lock key context mutex");
            return WOLFSSL_TICKET_RET_REJECT;
        }
#endif
        /* Sets expirary of primary key in setup. */
        ret = TicketEncCbCtx_Setup(keyCtx, ssl->ctx->heap, ssl->ctx->devId);
#ifndef SINGLE_THREADED
        wc_UnLockMutex(&keyCtx->mutex);
#endif
        if (ret != 0)
            return ret;
    }

    if (enc) {
        /* Return the name of the key - missing key index. */
        XMEMCPY(key_name, keyCtx->name, WOLFSSL_TICKET_NAME_SZ);

        /* Generate a new IV into buffer to be returned.
         * Don't use the RNG in keyCtx as it's for generating private data. */
        ret = wc_RNG_GenerateBlock(ssl->rng, iv, WOLFSSL_TICKET_IV_SZ);
        if (ret != 0) {
            return WOLFSSL_TICKET_RET_REJECT;
        }
    }
    else {
        /* Mask of last bit that is the key index. */
        byte lastByte = key_name[WOLFSSL_TICKET_NAME_SZ - 1] & 0xfe;

        /* For decryption, see if we know this key - check all but last byte. */
        if (XMEMCMP(key_name, keyCtx->name, WOLFSSL_TICKET_NAME_SZ - 1) != 0) {
            return WOLFSSL_TICKET_RET_FATAL;
        }
        /* Ensure last byte without index bit matches too. */
        if (lastByte != keyCtx->name[WOLFSSL_TICKET_NAME_SZ - 1]) {
            return WOLFSSL_TICKET_RET_FATAL;
        }
    }

    /* Build AAD from: key name, iv, and length of ticket. */
    XMEMCPY(p, keyCtx->name, WOLFSSL_TICKET_NAME_SZ);
    p += WOLFSSL_TICKET_NAME_SZ;
    XMEMCPY(p, iv, WOLFSSL_TICKET_IV_SZ);
    p += WOLFSSL_TICKET_IV_SZ;
    XMEMCPY(p, &sLen, sizeof(sLen));

    /* Encrypt ticket. */
    if (enc) {
        word32 now;

        now = LowResTimer();
        /* As long as encryption expirary isn't imminent - no lock. */
        if (keyCtx->expirary[0] > now + ctx->ticketHint) {
            keyIdx = 0;
        }
        else if (keyCtx->expirary[1] > now + ctx->ticketHint) {
            keyIdx = 1;
        }
        else {
#ifndef SINGLE_THREADED
            /* Lock around access to expirary and key - stop key being generated
             * twice at the same time. */
            if (wc_LockMutex(&keyCtx->mutex) != 0) {
                WOLFSSL_MSG("Couldn't lock key context mutex");
                return WOLFSSL_TICKET_RET_REJECT;
            }
#endif
            ret = TicketEncCbCtx_ChooseKey(keyCtx, ctx->ticketHint, &keyIdx);
#ifndef SINGLE_THREADED
            wc_UnLockMutex(&keyCtx->mutex);
#endif
            if (ret != 0) {
                return WOLFSSL_TICKET_RET_REJECT;
            }
        }
        /* Set the name of the key to the index chosen. */
        key_name[WOLFSSL_TICKET_NAME_SZ - 1] |= keyIdx;
        /* Update AAD too. */
        aad[WOLFSSL_TICKET_NAME_SZ - 1] |= keyIdx;

        /* Encrypt ticket data. */
        ret = TicketEncDec(keyCtx->key[keyIdx], WOLFSSL_TICKET_KEY_SZ, iv, aad,
                           aadSz, ticket, inLen, ticket, outLen, mac, ssl->heap,
                           1);
        if (ret != 0) return WOLFSSL_TICKET_RET_REJECT;
    }
    /* Decrypt ticket. */
    else {
        /* Get index of key from name. */
        keyIdx = key_name[WOLFSSL_TICKET_NAME_SZ - 1] & 0x1;
        /* Update AAD with index. */
        aad[WOLFSSL_TICKET_NAME_SZ - 1] |= keyIdx;

        /* Check expirary */
        if (keyCtx->expirary[keyIdx] <= LowResTimer()) {
            return WOLFSSL_TICKET_RET_REJECT;
        }

        /* Decrypt ticket data. */
        ret = TicketEncDec(keyCtx->key[keyIdx], WOLFSSL_TICKET_KEY_SZ, iv, aad,
                           aadSz, ticket, inLen, ticket, outLen, mac, ssl->heap,
                           0);
        if (ret != 0) {
            return WOLFSSL_TICKET_RET_REJECT;
        }
    }

#ifndef WOLFSSL_TICKET_DECRYPT_NO_CREATE
    if (!IsAtLeastTLSv1_3(ssl->version) && !enc)
        return WOLFSSL_TICKET_RET_CREATE;
#endif
    return WOLFSSL_TICKET_RET_OK;
}

#endif /* !WOLFSSL_NO_DEF_TICKET_ENC_CB */

#endif /* HAVE_SESSION_TICKET */

#ifndef WOLFSSL_NO_TLS12

#if defined(HAVE_SECURE_RENEGOTIATION) && \
    !defined(NO_WOLFSSL_SERVER)

    /* handle generation of server's hello_request (0) */
    int SendHelloRequest(WOLFSSL* ssl)
    {
        byte* output;
        int sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int ret;

        WOLFSSL_START(WC_FUNC_HELLO_REQUEST_SEND);
        WOLFSSL_ENTER("SendHelloRequest");

        if (IsEncryptionOn(ssl, 1))
            sendSz += MAX_MSG_EXTRA;

        if (ssl->options.dtls)
            sendSz += DTLS_RECORD_EXTRA + DTLS_HANDSHAKE_EXTRA;

        /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
         * is not advanced yet */
        ssl->options.buildingMsg = 1;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        AddHeaders(output, 0, hello_request, ssl);

        if (IsEncryptionOn(ssl, 1)) {
            byte* input;
            int   inputSz = HANDSHAKE_HEADER_SZ; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            if (ssl->options.dtls) {
                recordHeaderSz += DTLS_RECORD_EXTRA;
                inputSz += DTLS_HANDSHAKE_EXTRA;
            }

            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            #ifdef WOLFSSL_DTLS
            if (IsDtlsNotSctpMode(ssl) &&
                    (ret = DtlsMsgPoolSave(ssl, input, inputSz, hello_request)) != 0) {
                XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                return ret;
            }
            #endif
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 0, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        }

        ssl->buffers.outputBuffer.length += sendSz;
        ssl->options.buildingMsg = 0;

        ret = SendBuffered(ssl);

        WOLFSSL_LEAVE("SendHelloRequest", ret);
        WOLFSSL_END(WC_FUNC_HELLO_REQUEST_SEND);

        return ret;
    }

#endif /* HAVE_SECURE_RENEGOTIATION && !NO_WOLFSSL_SERVER */

#ifdef WOLFSSL_DTLS
    /* handle generation of DTLS hello_verify_request (3) */
    int SendHelloVerifyRequest(WOLFSSL* ssl,
                               const byte* cookie, byte cookieSz)
    {
        byte* output;
        int   length = VERSION_SZ + ENUM_LEN + cookieSz;
        int   idx    = DTLS_RECORD_HEADER_SZ + DTLS_HANDSHAKE_HEADER_SZ;
        int   sendSz = length + idx;
        int   ret;

        /* are we in scr */
        if (IsEncryptionOn(ssl, 1)) {
            sendSz += MAX_MSG_EXTRA;
        }

        /* reset hashes  */
        ret = InitHandshakeHashes(ssl);
        if (ret != 0)
            return ret;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        /* Hello Verify Request should use the same sequence number
         * as the Client Hello unless we are in renegotiation then
         * don't change numbers */
#ifdef HAVE_SECURE_RENEGOTIATION
        if (!IsSCR(ssl))
#endif
        {
            ssl->keys.dtls_sequence_number_hi = ssl->keys.curSeq_hi;
            ssl->keys.dtls_sequence_number_lo = ssl->keys.curSeq_lo;
        }
        AddHeaders(output, length, hello_verify_request, ssl);

        output[idx++] = DTLS_MAJOR;
        output[idx++] = DTLS_MINOR;

        output[idx++] = cookieSz;
        if (cookie == NULL || cookieSz == 0)
            return COOKIE_ERROR;

        XMEMCPY(output + idx, cookie, cookieSz);

#if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "HelloVerifyRequest");
        if (ssl->toInfoOn) {
            ret = AddPacketInfo(ssl, "HelloVerifyRequest", handshake, output,
                          sendSz, WRITE_PROTO, 0, ssl->heap);
            if (ret != 0)
                return ret;
        }
#endif

        /* are we in scr */
        if (IsEncryptionOn(ssl, 1)) {
            byte* input;
            int   inputSz = DTLS_HANDSHAKE_HEADER_SZ + length; /* build msg adds rec hdr */
            int   recordHeaderSz = DTLS_RECORD_HEADER_SZ;

            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 0, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        }

        ssl->buffers.outputBuffer.length += sendSz;
        DtlsResetState(ssl);

        return SendBuffered(ssl);
    }
#endif /* WOLFSSL_DTLS */

    typedef struct DckeArgs {
        byte*  output; /* not allocated */
        word32 length;
        word32 idx;
        word32 begin;
        word32 sigSz;
    #ifndef NO_RSA
        int    lastErr;
    #endif
    } DckeArgs;

    static void FreeDckeArgs(WOLFSSL* ssl, void* pArgs)
    {
        DckeArgs* args = (DckeArgs*)pArgs;

        (void)ssl;
        (void)args;
    }

    /* handle processing client_key_exchange (16) */
    static int DoClientKeyExchange(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                                                                    word32 size)
    {
        int ret;
    #ifdef WOLFSSL_ASYNC_CRYPT
        DckeArgs* args = NULL;
        WOLFSSL_ASSERT_SIZEOF_GE(ssl->async->args, *args);
    #else
        DckeArgs  args[1];
    #endif

        (void)size;
        (void)input;

        WOLFSSL_START(WC_FUNC_CLIENT_KEY_EXCHANGE_DO);
        WOLFSSL_ENTER("DoClientKeyExchange");

    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ssl->async == NULL) {
            ssl->async = (struct WOLFSSL_ASYNC*)
                    XMALLOC(sizeof(struct WOLFSSL_ASYNC), ssl->heap,
                            DYNAMIC_TYPE_ASYNC);
            if (ssl->async == NULL)
                ERROR_OUT(MEMORY_E, exit_dcke);
        }
        args = (DckeArgs*)ssl->async->args;

        ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
        if (ret != WC_NOT_PENDING_E) {
            /* Check for error */
            if (ret < 0)
                goto exit_dcke;
        }
        else
    #endif /* WOLFSSL_ASYNC_CRYPT */
        {
            /* Reset state */
            ret = 0;
            ssl->options.asyncState = TLS_ASYNC_BEGIN;
            XMEMSET(args, 0, sizeof(DckeArgs));
            args->idx = *inOutIdx;
            args->begin = *inOutIdx;
        #ifdef WOLFSSL_ASYNC_CRYPT
            ssl->async->freeArgs = FreeDckeArgs;
        #endif
        }

        /* Do Client Key Exchange State Machine */
        switch(ssl->options.asyncState)
        {
            case TLS_ASYNC_BEGIN:
            {
                /* Sanity checks */
                /* server side checked in SanityCheckMsgReceived */
                if (ssl->options.clientState < CLIENT_HELLO_COMPLETE) {
                    WOLFSSL_MSG("Client sending keyexchange at wrong time");
                    SendAlert(ssl, alert_fatal, unexpected_message);
                    ERROR_OUT(OUT_OF_ORDER_E, exit_dcke);
                }

            #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
                if (ssl->options.verifyPeer &&
                         (ssl->options.mutualAuth || ssl->options.failNoCert)) {
                    if (!ssl->options.havePeerCert) {
                        WOLFSSL_MSG("client didn't present peer cert");
                        ERROR_OUT(NO_PEER_CERT, exit_dcke);
                    }
                }

                if (ssl->options.verifyPeer && ssl->options.failNoCertxPSK) {
                    if (!ssl->options.havePeerCert &&
                                             !ssl->options.usingPSK_cipher) {
                        WOLFSSL_MSG("client didn't present peer cert");
                        ERROR_OUT(NO_PEER_CERT, exit_dcke);
                    }
                }
            #endif /* !NO_CERTS && !WOLFSSL_NO_CLIENT_AUTH */

            #if defined(WOLFSSL_CALLBACKS)
                if (ssl->hsInfoOn) {
                    AddPacketName(ssl, "ClientKeyExchange");
                }
                if (ssl->toInfoOn) {
                    AddLateName("ClientKeyExchange", &ssl->timeoutInfo);
                }
            #endif

                if (ssl->arrays->preMasterSecret == NULL) {
                    ssl->arrays->preMasterSz = ENCRYPT_LEN;
                    ssl->arrays->preMasterSecret = (byte*)XMALLOC(ENCRYPT_LEN,
                                                ssl->heap, DYNAMIC_TYPE_SECRET);
                    if (ssl->arrays->preMasterSecret == NULL) {
                        ERROR_OUT(MEMORY_E, exit_dcke);
                    }
                    XMEMSET(ssl->arrays->preMasterSecret, 0, ENCRYPT_LEN);
                }

                switch (ssl->specs.kea) {
                #ifndef NO_RSA
                    case rsa_kea:
                    {
                        break;
                    } /* rsa_kea */
                #endif /* !NO_RSA */
                #ifndef NO_PSK
                    case psk_kea:
                    {
                        /* sanity check that PSK server callback has been set */
                        if (ssl->options.server_psk_cb == NULL) {
                           WOLFSSL_MSG("No server PSK callback set");
                           ERROR_OUT(PSK_KEY_ERROR, exit_dcke);
                        }
                        break;
                    }
                #endif /* !NO_PSK */
                #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                    case ecc_diffie_hellman_kea:
                    {
                        break;
                    }
                #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
                #ifndef NO_DH
                    case diffie_hellman_kea:
                    {
                        break;
                    }
                #endif /* !NO_DH */
                #if !defined(NO_DH) && !defined(NO_PSK)
                    case dhe_psk_kea:
                    {
                        /* sanity check that PSK server callback has been set */
                        if (ssl->options.server_psk_cb == NULL) {
                            WOLFSSL_MSG("No server PSK callback set");
                            ERROR_OUT(PSK_KEY_ERROR, exit_dcke);
                        }
                        break;
                    }
                #endif /* !NO_DH && !NO_PSK */
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                    {
                        /* sanity check that PSK server callback has been set */
                        if (ssl->options.server_psk_cb == NULL) {
                            WOLFSSL_MSG("No server PSK callback set");
                            ERROR_OUT(PSK_KEY_ERROR, exit_dcke);
                        }
                        break;
                    }
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                    default:
                        WOLFSSL_MSG("Bad kea type");
                        ret = BAD_KEA_TYPE_E;
                } /* switch (ssl->specs.kea) */

                /* Check for error */
                if (ret != 0) {
                    goto exit_dcke;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_BUILD;
            } /* TLS_ASYNC_BEGIN */
            FALL_THROUGH;

            case TLS_ASYNC_BUILD:
            {
                switch (ssl->specs.kea) {
                #ifndef NO_RSA
                    case rsa_kea:
                    {
                        word16 keySz;

                        ssl->buffers.keyType = rsa_sa_algo;
                        ret = DecodePrivateKey(ssl, &keySz);
                        if (ret != 0) {
                            goto exit_dcke;
                        }
                        args->length = (word32)keySz;
                        ssl->arrays->preMasterSz = SECRET_LEN;

                        if (ssl->options.tls) {
                            word16 check;

                            if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                                ERROR_OUT(BUFFER_ERROR, exit_dcke);
                            }

                            ato16(input + args->idx, &check);
                            args->idx += OPAQUE16_LEN;

                            if ((word32)check != args->length) {
                                WOLFSSL_MSG("RSA explicit size doesn't match");
                        #ifdef WOLFSSL_EXTRA_ALERTS
                                SendAlert(ssl, alert_fatal, bad_record_mac);
                        #endif
                                ERROR_OUT(RSA_PRIVATE_ERROR, exit_dcke);
                            }
                        }

                        if ((args->idx - args->begin) + args->length > size) {
                            WOLFSSL_MSG("RSA message too big");
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        /* pre-load PreMasterSecret with RNG data */
                        ret = wc_RNG_GenerateBlock(ssl->rng,
                            &ssl->arrays->preMasterSecret[VERSION_SZ],
                            SECRET_LEN - VERSION_SZ);
                        if (ret != 0) {
                            goto exit_dcke;
                        }

                        args->output = NULL;
                        break;
                    } /* rsa_kea */
                #endif /* !NO_RSA */
                #ifndef NO_PSK
                    case psk_kea:
                    {
                        byte* pms = ssl->arrays->preMasterSecret;
                        word16 ci_sz;

                        if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        ato16(input + args->idx, &ci_sz);
                        args->idx += OPAQUE16_LEN;

                        if (ci_sz > MAX_PSK_ID_LEN) {
                            ERROR_OUT(CLIENT_ID_ERROR, exit_dcke);
                        }

                        if ((args->idx - args->begin) + ci_sz > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        XMEMCPY(ssl->arrays->client_identity,
                                                    input + args->idx, ci_sz);
                        args->idx += ci_sz;

                        ssl->arrays->client_identity[ci_sz] = '\0'; /* null term */
                        ssl->arrays->psk_keySz = ssl->options.server_psk_cb(ssl,
                            ssl->arrays->client_identity, ssl->arrays->psk_key,
                            MAX_PSK_KEY_LEN);

                        if (ssl->arrays->psk_keySz == 0 ||
                                ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN) {
                            #if defined(WOLFSSL_EXTRA_ALERTS) || \
                                defined(WOLFSSL_PSK_IDENTITY_ALERT)
                                SendAlert(ssl, alert_fatal,
                                        unknown_psk_identity);
                            #endif
                            ERROR_OUT(PSK_KEY_ERROR, exit_dcke);
                        }
                        /* SERVER: Pre-shared Key for peer authentication. */
                        ssl->options.peerAuthGood = 1;

                        /* make psk pre master secret */
                        /* length of key + length 0s + length of key + key */
                        c16toa((word16) ssl->arrays->psk_keySz, pms);
                        pms += OPAQUE16_LEN;

                        XMEMSET(pms, 0, ssl->arrays->psk_keySz);
                        pms += ssl->arrays->psk_keySz;

                        c16toa((word16) ssl->arrays->psk_keySz, pms);
                        pms += OPAQUE16_LEN;

                        XMEMCPY(pms, ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                        ssl->arrays->preMasterSz =
                            (ssl->arrays->psk_keySz * 2) + (OPAQUE16_LEN * 2);
                        break;
                    }
                #endif /* !NO_PSK */
                #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                    case ecc_diffie_hellman_kea:
                    {
                    #ifdef HAVE_ECC
                        ecc_key* private_key = ssl->eccTempKey;

                        /* handle static private key */
                        if (ssl->specs.static_ecdh &&
                                          ssl->ecdhCurveOID != ECC_X25519_OID &&
                                          ssl->ecdhCurveOID != ECC_X448_OID) {
                            word16 keySz;

                            ssl->buffers.keyType = ecc_dsa_sa_algo;
                            ret = DecodePrivateKey(ssl, &keySz);
                            if (ret != 0) {
                                goto exit_dcke;
                            }
                            private_key = (ecc_key*)ssl->hsKey;
                        }
                    #endif

                        /* import peer ECC key */
                        if ((args->idx - args->begin) + OPAQUE8_LEN > size) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                            SendAlert(ssl, alert_fatal, decode_error);
                        #endif
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        args->length = input[args->idx++];

                        if ((args->idx - args->begin) + args->length > size) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                            SendAlert(ssl, alert_fatal, decode_error);
                        #endif
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                        #ifdef HAVE_PK_CALLBACKS
                            /* if callback then use it for shared secret */
                            if (ssl->ctx->X25519SharedSecretCb != NULL) {
                                break;
                            }
                        #endif
                            if (ssl->peerX25519Key == NULL) {
                                /* alloc/init on demand */
                                ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                    (void**)&ssl->peerX25519Key);
                                if (ret != 0) {
                                    goto exit_dcke;
                                }
                            } else if (ssl->peerX25519KeyPresent) {
                                ret = ReuseKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                               ssl->peerX25519Key);
                                ssl->peerX25519KeyPresent = 0;
                                if (ret != 0) {
                                    goto exit_dcke;
                                }
                            }

                            if ((ret = wc_curve25519_check_public(
                                    input + args->idx, args->length,
                                    EC25519_LITTLE_ENDIAN)) != 0) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                                if (ret == BUFFER_E)
                                    SendAlert(ssl, alert_fatal, decode_error);
                                else if (ret == ECC_OUT_OF_RANGE_E)
                                    SendAlert(ssl, alert_fatal, bad_record_mac);
                                else {
                                    SendAlert(ssl, alert_fatal,
                                                             illegal_parameter);
                                }
                        #endif
                                ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                            }

                            if (wc_curve25519_import_public_ex(
                                    input + args->idx, args->length,
                                    ssl->peerX25519Key,
                                    EC25519_LITTLE_ENDIAN)) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                                SendAlert(ssl, alert_fatal, illegal_parameter);
                        #endif
                                ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                            }

                            ssl->arrays->preMasterSz = CURVE25519_KEYSIZE;

                            ssl->peerX25519KeyPresent = 1;

                            break;
                        }
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID) {
                        #ifdef HAVE_PK_CALLBACKS
                            /* if callback then use it for shared secret */
                            if (ssl->ctx->X448SharedSecretCb != NULL) {
                                break;
                            }
                        #endif
                            if (ssl->peerX448Key == NULL) {
                                /* alloc/init on demand */
                                ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE448,
                                    (void**)&ssl->peerX448Key);
                                if (ret != 0) {
                                    goto exit_dcke;
                                }
                            } else if (ssl->peerX448KeyPresent) {
                                ret = ReuseKey(ssl, DYNAMIC_TYPE_CURVE448,
                                               ssl->peerX448Key);
                                ssl->peerX448KeyPresent = 0;
                                if (ret != 0) {
                                    goto exit_dcke;
                                }
                            }

                            if ((ret = wc_curve448_check_public(
                                    input + args->idx, args->length,
                                    EC448_LITTLE_ENDIAN)) != 0) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                                if (ret == BUFFER_E)
                                    SendAlert(ssl, alert_fatal, decode_error);
                                else if (ret == ECC_OUT_OF_RANGE_E)
                                    SendAlert(ssl, alert_fatal, bad_record_mac);
                                else {
                                    SendAlert(ssl, alert_fatal,
                                                             illegal_parameter);
                                }
                        #endif
                                ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                            }

                            if (wc_curve448_import_public_ex(
                                    input + args->idx, args->length,
                                    ssl->peerX448Key,
                                    EC448_LITTLE_ENDIAN)) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                                SendAlert(ssl, alert_fatal, illegal_parameter);
                        #endif
                                ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                            }

                            ssl->arrays->preMasterSz = CURVE448_KEY_SIZE;

                            ssl->peerX448KeyPresent = 1;

                            break;
                        }
                    #endif
                #ifdef HAVE_ECC
                    #ifdef HAVE_PK_CALLBACKS
                        /* if callback then use it for shared secret */
                        if (ssl->ctx->EccSharedSecretCb != NULL) {
                            break;
                        }
                    #endif

                        if (!ssl->specs.static_ecdh &&
                            ssl->eccTempKeyPresent == 0) {
                            WOLFSSL_MSG("Ecc ephemeral key not made correctly");
                            ERROR_OUT(ECC_MAKEKEY_ERROR, exit_dcke);
                        }

                        if (ssl->peerEccKey == NULL) {
                            /* alloc/init on demand */
                            ret = AllocKey(ssl, DYNAMIC_TYPE_ECC,
                                (void**)&ssl->peerEccKey);
                            if (ret != 0) {
                                goto exit_dcke;
                            }
                        } else if (ssl->peerEccKeyPresent) {
                            ret = ReuseKey(ssl, DYNAMIC_TYPE_ECC,
                                           ssl->peerEccKey);
                            ssl->peerEccKeyPresent = 0;
                            if (ret != 0) {
                                goto exit_dcke;
                            }
                        }

                        if (wc_ecc_import_x963_ex(input + args->idx,
                                                  args->length, ssl->peerEccKey,
                                                  private_key->dp->id)) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                            SendAlert(ssl, alert_fatal, illegal_parameter);
                        #endif
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                        }

                        ssl->arrays->preMasterSz = private_key->dp->size;

                        ssl->peerEccKeyPresent = 1;

                    #if defined(WOLFSSL_TLS13) || defined(HAVE_FFDHE)
                        /* client_hello may have sent FFEDH2048, which sets namedGroup,
                            but that is not being used, so clear it */
                        /* resolves issue with server side wolfSSL_get_curve_name */
                        ssl->namedGroup = 0;
                    #endif
                #endif /* HAVE_ECC */

                        break;
                    }
                #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
                #ifndef NO_DH
                    case diffie_hellman_kea:
                    {
                        word16 clientPubSz;

                        if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        ato16(input + args->idx, &clientPubSz);
                        args->idx += OPAQUE16_LEN;

                        if ((args->idx - args->begin) + clientPubSz > size) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                            SendAlert(ssl, alert_fatal, decode_error);
                        #endif
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        args->sigSz = clientPubSz;

                        ret = AllocKey(ssl, DYNAMIC_TYPE_DH,
                                            (void**)&ssl->buffers.serverDH_Key);
                        if (ret != 0) {
                            goto exit_dcke;
                        }

                        ret = wc_DhSetKey(ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length,
                            ssl->buffers.serverDH_G.buffer,
                            ssl->buffers.serverDH_G.length);

                        /* set the max agree result size */
                        ssl->arrays->preMasterSz = ENCRYPT_LEN;
                        break;
                    }
                #endif /* !NO_DH */
                #if !defined(NO_DH) && !defined(NO_PSK)
                    case dhe_psk_kea:
                    {
                        word16 clientSz;

                        /* Read in the PSK hint */
                        if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        ato16(input + args->idx, &clientSz);
                        args->idx += OPAQUE16_LEN;
                        if (clientSz > MAX_PSK_ID_LEN) {
                            ERROR_OUT(CLIENT_ID_ERROR, exit_dcke);
                        }

                        if ((args->idx - args->begin) + clientSz > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        XMEMCPY(ssl->arrays->client_identity, input + args->idx,
                                                                    clientSz);
                        args->idx += clientSz;
                        ssl->arrays->client_identity[clientSz] = '\0'; /* null term */

                        /* Read in the DHE business */
                        if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        ato16(input + args->idx, &clientSz);
                        args->idx += OPAQUE16_LEN;

                        if ((args->idx - args->begin) + clientSz > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        args->sigSz = clientSz;

                        ret = AllocKey(ssl, DYNAMIC_TYPE_DH,
                                            (void**)&ssl->buffers.serverDH_Key);
                        if (ret != 0) {
                            goto exit_dcke;
                        }

                        ret = wc_DhSetKey(ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length,
                            ssl->buffers.serverDH_G.buffer,
                            ssl->buffers.serverDH_G.length);

                        break;
                    }
                #endif /* !NO_DH && !NO_PSK */
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                    {
                        word16 clientSz;

                        /* Read in the PSK hint */
                        if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        ato16(input + args->idx, &clientSz);
                        args->idx += OPAQUE16_LEN;
                        if (clientSz > MAX_PSK_ID_LEN) {
                            ERROR_OUT(CLIENT_ID_ERROR, exit_dcke);
                        }
                        if ((args->idx - args->begin) + clientSz > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        XMEMCPY(ssl->arrays->client_identity,
                                                   input + args->idx, clientSz);
                        args->idx += clientSz;
                        ssl->arrays->client_identity[clientSz] = '\0'; /* null term */

                        /* import peer ECC key */
                        if ((args->idx - args->begin) + OPAQUE8_LEN > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        args->length = input[args->idx++];

                        if ((args->idx - args->begin) + args->length > size) {
                            ERROR_OUT(BUFFER_ERROR, exit_dcke);
                        }

                        args->sigSz = ENCRYPT_LEN - OPAQUE16_LEN;

                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                        #ifdef HAVE_PK_CALLBACKS
                            /* if callback then use it for shared secret */
                            if (ssl->ctx->X25519SharedSecretCb != NULL) {
                                break;
                            }
                        #endif

                            if (ssl->eccTempKeyPresent == 0) {
                                WOLFSSL_MSG(
                                     "X25519 ephemeral key not made correctly");
                                ERROR_OUT(ECC_MAKEKEY_ERROR, exit_dcke);
                            }

                            if (ssl->peerX25519Key == NULL) {
                                /* alloc/init on demand */
                                ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                    (void**)&ssl->peerX25519Key);
                                if (ret != 0) {
                                    goto exit_dcke;
                                }
                            } else if (ssl->peerX25519KeyPresent) {
                                ret = ReuseKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                               ssl->peerX25519Key);
                                ssl->peerX25519KeyPresent = 0;
                                if (ret != 0) {
                                    goto exit_dcke;
                                }
                            }

                            if ((ret = wc_curve25519_check_public(
                                    input + args->idx, args->length,
                                    EC25519_LITTLE_ENDIAN)) != 0) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                                if (ret == BUFFER_E)
                                    SendAlert(ssl, alert_fatal, decode_error);
                                else if (ret == ECC_OUT_OF_RANGE_E)
                                    SendAlert(ssl, alert_fatal, bad_record_mac);
                                else {
                                    SendAlert(ssl, alert_fatal,
                                                             illegal_parameter);
                                }
                        #endif
                                ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                            }

                            if (wc_curve25519_import_public_ex(
                                    input + args->idx, args->length,
                                    ssl->peerX25519Key,
                                    EC25519_LITTLE_ENDIAN)) {
                                ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                            }

                            ssl->peerX25519KeyPresent = 1;

                            break;
                        }
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID) {
                        #ifdef HAVE_PK_CALLBACKS
                            /* if callback then use it for shared secret */
                            if (ssl->ctx->X448SharedSecretCb != NULL) {
                                break;
                            }
                        #endif

                            if (ssl->eccTempKeyPresent == 0) {
                                WOLFSSL_MSG(
                                       "X448 ephemeral key not made correctly");
                                ERROR_OUT(ECC_MAKEKEY_ERROR, exit_dcke);
                            }

                            if (ssl->peerX448Key == NULL) {
                                /* alloc/init on demand */
                                ret = AllocKey(ssl, DYNAMIC_TYPE_CURVE448,
                                    (void**)&ssl->peerX448Key);
                                if (ret != 0) {
                                    goto exit_dcke;
                                }
                            } else if (ssl->peerX448KeyPresent) {
                                ret = ReuseKey(ssl, DYNAMIC_TYPE_CURVE448,
                                               ssl->peerX448Key);
                                ssl->peerX448KeyPresent = 0;
                                if (ret != 0) {
                                    goto exit_dcke;
                                }
                            }

                            if ((ret = wc_curve448_check_public(
                                    input + args->idx, args->length,
                                    EC448_LITTLE_ENDIAN)) != 0) {
                        #ifdef WOLFSSL_EXTRA_ALERTS
                                if (ret == BUFFER_E)
                                    SendAlert(ssl, alert_fatal, decode_error);
                                else if (ret == ECC_OUT_OF_RANGE_E)
                                    SendAlert(ssl, alert_fatal, bad_record_mac);
                                else {
                                    SendAlert(ssl, alert_fatal,
                                                             illegal_parameter);
                                }
                        #endif
                                ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                            }

                            if (wc_curve448_import_public_ex(
                                    input + args->idx, args->length,
                                    ssl->peerX448Key,
                                    EC448_LITTLE_ENDIAN)) {
                                ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                            }

                            ssl->peerX448KeyPresent = 1;

                            break;
                        }
                    #endif
                    #ifdef HAVE_PK_CALLBACKS
                        /* if callback then use it for shared secret */
                        if (ssl->ctx->EccSharedSecretCb != NULL) {
                            break;
                        }
                    #endif

                        if (ssl->eccTempKeyPresent == 0) {
                            WOLFSSL_MSG("Ecc ephemeral key not made correctly");
                            ERROR_OUT(ECC_MAKEKEY_ERROR, exit_dcke);
                        }

                        if (ssl->peerEccKey == NULL) {
                            /* alloc/init on demand */
                            ret = AllocKey(ssl, DYNAMIC_TYPE_ECC,
                                (void**)&ssl->peerEccKey);
                            if (ret != 0) {
                                goto exit_dcke;
                            }
                        }
                        else if (ssl->peerEccKeyPresent) {
                            ret = ReuseKey(ssl, DYNAMIC_TYPE_ECC,
                                           ssl->peerEccKey);
                            ssl->peerEccKeyPresent = 0;
                            if (ret != 0) {
                                goto exit_dcke;
                            }
                        }
                        if (wc_ecc_import_x963_ex(input + args->idx,
                                 args->length, ssl->peerEccKey,
                                 ssl->eccTempKey->dp->id)) {
                            ERROR_OUT(ECC_PEERKEY_ERROR, exit_dcke);
                        }

                        ssl->peerEccKeyPresent = 1;
                        break;
                    }
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                    default:
                        ret = BAD_KEA_TYPE_E;
                } /* switch (ssl->specs.kea) */

                /* Check for error */
                if (ret != 0) {
                    goto exit_dcke;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_DO;
            } /* TLS_ASYNC_BUILD */
            FALL_THROUGH;

            case TLS_ASYNC_DO:
            {
                switch (ssl->specs.kea) {
                #ifndef NO_RSA
                    case rsa_kea:
                    {
                        RsaKey* key = (RsaKey*)ssl->hsKey;

                        ret = RsaDec(ssl,
                            input + args->idx,
                            args->length,
                            &args->output,
                            &args->sigSz,
                            key,
                        #ifdef HAVE_PK_CALLBACKS
                            ssl->buffers.key
                        #else
                            NULL
                        #endif
                        );

                        /*  Errors that can occur here that should be
                         *  indistinguishable:
                         *       RSA_BUFFER_E, RSA_PAD_E and RSA_PRIVATE_ERROR
                         */
                    #ifdef WOLFSSL_ASYNC_CRYPT
                        if (ret == WC_PENDING_E)
                            goto exit_dcke;
                    #endif
                        if (ret == BAD_FUNC_ARG)
                            goto exit_dcke;

                        args->lastErr = ret - (SECRET_LEN - args->sigSz);
                        ret = 0;
                        break;
                    } /* rsa_kea */
                #endif /* !NO_RSA */
                #ifndef NO_PSK
                    case psk_kea:
                    {
                        break;
                    }
                #endif /* !NO_PSK */
                #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                    case ecc_diffie_hellman_kea:
                    {
                        void* private_key = ssl->eccTempKey;
                        (void)private_key;

                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                            ret = X25519SharedSecret(ssl,
                                (curve25519_key*)private_key,
                                ssl->peerX25519Key,
                                input + args->idx, &args->length,
                                ssl->arrays->preMasterSecret,
                                &ssl->arrays->preMasterSz,
                                WOLFSSL_SERVER_END
                            );
                            break;
                        }
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID) {
                            ret = X448SharedSecret(ssl,
                                (curve448_key*)private_key,
                                ssl->peerX448Key,
                                input + args->idx, &args->length,
                                ssl->arrays->preMasterSecret,
                                &ssl->arrays->preMasterSz,
                                WOLFSSL_SERVER_END
                            );
                            break;
                        }
                    #endif
                    #ifdef HAVE_ECC
                        if (ssl->specs.static_ecdh) {
                            private_key = ssl->hsKey;
                        }

                        /* Generate shared secret */
                        ret = EccSharedSecret(ssl,
                            (ecc_key*)private_key, ssl->peerEccKey,
                            input + args->idx, &args->length,
                            ssl->arrays->preMasterSecret,
                            &ssl->arrays->preMasterSz,
                            WOLFSSL_SERVER_END
                        );
                    #ifdef WOLFSSL_ASYNC_CRYPT
                        if (ret != WC_PENDING_E)
                    #endif
                        {
                            FreeKey(ssl, DYNAMIC_TYPE_ECC,
                                                      (void**)&ssl->peerEccKey);
                            ssl->peerEccKeyPresent = 0;
                        }
                    #endif
                        break;
                    }
                #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
                #ifndef NO_DH
                    case diffie_hellman_kea:
                    {
                        ret = DhAgree(ssl, ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_Priv.buffer,
                            ssl->buffers.serverDH_Priv.length,
                            input + args->idx,
                            (word16)args->sigSz,
                            ssl->arrays->preMasterSecret,
                            &ssl->arrays->preMasterSz,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length);
                        break;
                    }
                #endif /* !NO_DH */
                #if !defined(NO_DH) && !defined(NO_PSK)
                    case dhe_psk_kea:
                    {
                        ret = DhAgree(ssl, ssl->buffers.serverDH_Key,
                            ssl->buffers.serverDH_Priv.buffer,
                            ssl->buffers.serverDH_Priv.length,
                            input + args->idx,
                            (word16)args->sigSz,
                            ssl->arrays->preMasterSecret + OPAQUE16_LEN,
                            &ssl->arrays->preMasterSz,
                            ssl->buffers.serverDH_P.buffer,
                            ssl->buffers.serverDH_P.length);
                        break;
                    }
                #endif /* !NO_DH && !NO_PSK */
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                    {
                    #ifdef HAVE_CURVE25519
                        if (ssl->ecdhCurveOID == ECC_X25519_OID) {
                            ret = X25519SharedSecret(ssl,
                                (curve25519_key*)ssl->eccTempKey,
                                ssl->peerX25519Key,
                                input + args->idx, &args->length,
                                ssl->arrays->preMasterSecret + OPAQUE16_LEN,
                                &args->sigSz,
                                WOLFSSL_SERVER_END
                            );
                        #ifdef WOLFSSL_ASYNC_CRYPT
                            if (ret != WC_PENDING_E)
                        #endif
                            {
                                FreeKey(ssl, DYNAMIC_TYPE_CURVE25519,
                                                   (void**)&ssl->peerX25519Key);
                                ssl->peerX25519KeyPresent = 0;
                            }
                            break;
                        }
                    #endif
                    #ifdef HAVE_CURVE448
                        if (ssl->ecdhCurveOID == ECC_X448_OID) {
                            ret = X448SharedSecret(ssl,
                                (curve448_key*)ssl->eccTempKey,
                                ssl->peerX448Key,
                                input + args->idx, &args->length,
                                ssl->arrays->preMasterSecret + OPAQUE16_LEN,
                                &args->sigSz,
                                WOLFSSL_SERVER_END
                            );
                        #ifdef WOLFSSL_ASYNC_CRYPT
                            if (ret != WC_PENDING_E)
                        #endif
                            {
                                FreeKey(ssl, DYNAMIC_TYPE_CURVE448,
                                                     (void**)&ssl->peerX448Key);
                                ssl->peerX448KeyPresent = 0;
                            }
                            break;
                        }
                    #endif
                        /* Generate shared secret */
                        ret = EccSharedSecret(ssl,
                            ssl->eccTempKey, ssl->peerEccKey,
                            input + args->idx, &args->length,
                            ssl->arrays->preMasterSecret + OPAQUE16_LEN,
                            &args->sigSz,
                            WOLFSSL_SERVER_END
                        );
                        if (!ssl->specs.static_ecdh
                    #ifdef WOLFSSL_ASYNC_CRYPT
                            && ret != WC_PENDING_E
                    #endif
                        ) {
                            FreeKey(ssl, DYNAMIC_TYPE_ECC,
                                                      (void**)&ssl->peerEccKey);
                            ssl->peerEccKeyPresent = 0;
                        }
                        break;
                    }
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                    default:
                        ret = BAD_KEA_TYPE_E;
                } /* switch (ssl->specs.kea) */

                /* Check for error */
                if (ret != 0) {
                    goto exit_dcke;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_VERIFY;
            } /* TLS_ASYNC_DO */
            FALL_THROUGH;

            case TLS_ASYNC_VERIFY:
            {
                switch (ssl->specs.kea) {
                #ifndef NO_RSA
                    case rsa_kea:
                    {
                        byte *tmpRsa;
                        byte mask;
                        int i;

                        /* Add the signature length to idx */
                        args->idx += args->length;

                    #ifdef DEBUG_WOLFSSL
                        /* check version (debug warning message only) */
                        if (args->output != NULL) {
                            if (args->output[0] != ssl->chVersion.major ||
                                args->output[1] != ssl->chVersion.minor) {
                                WOLFSSL_MSG("preMasterSecret version mismatch");
                            }
                        }
                    #endif

                        /* RFC5246 7.4.7.1:
                         * Treat incorrectly formatted message blocks and/or
                         * mismatched version numbers in a manner
                         * indistinguishable from correctly formatted RSA blocks
                         */

                        ret = args->lastErr;
                        args->lastErr = 0; /* reset */
                        /* On error 'ret' will be negative */
                        mask = ((unsigned int)ret >>
                                                   ((sizeof(ret) * 8) - 1)) - 1;

                        /* build PreMasterSecret */
                        ssl->arrays->preMasterSecret[0] = ssl->chVersion.major;
                        ssl->arrays->preMasterSecret[1] = ssl->chVersion.minor;

                        tmpRsa = input + args->idx - VERSION_SZ - SECRET_LEN;
                        ctMaskCopy(~mask, (byte*)&args->output, (byte*)&tmpRsa,
                            sizeof(args->output));
                        if (args->output != NULL) {
                            /* Use random secret on error */
                            for (i = VERSION_SZ; i < SECRET_LEN; i++) {
                                ssl->arrays->preMasterSecret[i] =
                                     ctMaskSel(mask, args->output[i],
                                               ssl->arrays->preMasterSecret[i]);
                            }
                        }
                        /* preMasterSecret has RNG and version set
                         * return proper length and ignore error
                         * error will be caught as decryption error
                         */
                        args->sigSz = SECRET_LEN;
                        ret = 0;
                        break;
                    } /* rsa_kea */
                #endif /* !NO_RSA */
                #ifndef NO_PSK
                    case psk_kea:
                    {
                        break;
                    }
                #endif /* !NO_PSK */
                #if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                                          defined(HAVE_CURVE448)
                    case ecc_diffie_hellman_kea:
                    {
                        /* skip past the imported peer key */
                        args->idx += args->length;
                        break;
                    }
                #endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
                #ifndef NO_DH
                    case diffie_hellman_kea:
                    {
                        args->idx += (word16)args->sigSz;
                        break;
                    }
                #endif /* !NO_DH */
                #if !defined(NO_DH) && !defined(NO_PSK)
                    case dhe_psk_kea:
                    {
                        byte* pms = ssl->arrays->preMasterSecret;
                        word16 clientSz = (word16)args->sigSz;

                        args->idx += clientSz;
                        c16toa((word16)ssl->arrays->preMasterSz, pms);
                        ssl->arrays->preMasterSz += OPAQUE16_LEN;
                        pms += ssl->arrays->preMasterSz;

                        /* Use the PSK hint to look up the PSK and add it to the
                         * preMasterSecret here. */
                        ssl->arrays->psk_keySz = ssl->options.server_psk_cb(ssl,
                            ssl->arrays->client_identity, ssl->arrays->psk_key,
                            MAX_PSK_KEY_LEN);

                        if (ssl->arrays->psk_keySz == 0 ||
                                ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN) {
                            #if defined(WOLFSSL_EXTRA_ALERTS) || \
                                defined(WOLFSSL_PSK_IDENTITY_ALERT)
                                SendAlert(ssl, alert_fatal,
                                        unknown_psk_identity);
                            #endif
                            ERROR_OUT(PSK_KEY_ERROR, exit_dcke);
                        }
                        /* SERVER: Pre-shared Key for peer authentication. */
                        ssl->options.peerAuthGood = 1;

                        c16toa((word16) ssl->arrays->psk_keySz, pms);
                        pms += OPAQUE16_LEN;

                        XMEMCPY(pms, ssl->arrays->psk_key,
                                                    ssl->arrays->psk_keySz);
                        ssl->arrays->preMasterSz += ssl->arrays->psk_keySz +
                                                                OPAQUE16_LEN;
                        break;
                    }
                #endif /* !NO_DH && !NO_PSK */
                #if (defined(HAVE_ECC) || defined(HAVE_CURVE25519) || \
                                     defined(HAVE_CURVE448)) && !defined(NO_PSK)
                    case ecdhe_psk_kea:
                    {
                        byte* pms = ssl->arrays->preMasterSecret;
                        word16 clientSz = (word16)args->sigSz;

                        /* skip past the imported peer key */
                        args->idx += args->length;

                        /* Add preMasterSecret */
                        c16toa(clientSz, pms);
                        ssl->arrays->preMasterSz = OPAQUE16_LEN + clientSz;
                        pms += ssl->arrays->preMasterSz;

                        /* Use the PSK hint to look up the PSK and add it to the
                         * preMasterSecret here. */
                        ssl->arrays->psk_keySz = ssl->options.server_psk_cb(ssl,
                            ssl->arrays->client_identity, ssl->arrays->psk_key,
                            MAX_PSK_KEY_LEN);

                        if (ssl->arrays->psk_keySz == 0 ||
                                   ssl->arrays->psk_keySz > MAX_PSK_KEY_LEN) {
                            ERROR_OUT(PSK_KEY_ERROR, exit_dcke);
                        }
                        /* SERVER: Pre-shared Key for peer authentication. */
                        ssl->options.peerAuthGood = 1;

                        c16toa((word16) ssl->arrays->psk_keySz, pms);
                        pms += OPAQUE16_LEN;

                        XMEMCPY(pms, ssl->arrays->psk_key, ssl->arrays->psk_keySz);
                        ssl->arrays->preMasterSz +=
                                      ssl->arrays->psk_keySz + OPAQUE16_LEN;
                        break;
                    }
                #endif /* (HAVE_ECC || CURVE25519 || CURVE448) && !NO_PSK */
                    default:
                        ret = BAD_KEA_TYPE_E;
                } /* switch (ssl->specs.kea) */

                /* Check for error */
                if (ret != 0) {
                    goto exit_dcke;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_FINALIZE;
            } /* TLS_ASYNC_VERIFY */
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

                ret = MakeMasterSecret(ssl);

                /* Check for error */
                if (ret != 0) {
                    goto exit_dcke;
                }

                /* Advance state and proceed */
                ssl->options.asyncState = TLS_ASYNC_END;
            } /* TLS_ASYNC_FINALIZE */
            FALL_THROUGH;

            case TLS_ASYNC_END:
            {
                /* Set final index */
                *inOutIdx = args->idx;

                ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
            #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
                if (ssl->options.verifyPeer) {
                    ret = BuildCertHashes(ssl, &ssl->hsHashes->certHashes);
                }
            #endif
                break;
            } /* TLS_ASYNC_END */
            default:
                ret = INPUT_CASE_ERROR;
        } /* switch(ssl->options.asyncState) */

    exit_dcke:

        WOLFSSL_LEAVE("DoClientKeyExchange", ret);
        WOLFSSL_END(WC_FUNC_CLIENT_KEY_EXCHANGE_DO);
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* Handle async operation */
        if (ret == WC_PENDING_E) {
            /* Mark message as not received so it can process again */
            ssl->msgsReceived.got_client_key_exchange = 0;

            return ret;
        }
        /* Cleanup async */
        FreeAsyncCtx(ssl, 0);
    #else
        FreeDckeArgs(ssl, args);
    #endif /* WOLFSSL_ASYNC_CRYPT */
    #ifdef OPENSSL_ALL
        /* add error ret value to error queue */
        if (ret != 0) {
            WOLFSSL_ERROR(ret);
        }
    #endif


        /* Cleanup PMS */
        if (ssl->arrays->preMasterSecret != NULL) {
            ForceZero(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);
        }
        ssl->arrays->preMasterSz = 0;

        /* Final cleanup */
        FreeKeyExchange(ssl);

        return ret;
    }

#endif /* !WOLFSSL_NO_TLS12 */

#ifdef HAVE_SNI
    int SNI_Callback(WOLFSSL* ssl)
    {
        int ad = 0;
        int sniRet = 0;
        /* Stunnel supports a custom sni callback to switch an SSL's ctx
        * when SNI is received. Call it now if exists */
        if(ssl && ssl->ctx && ssl->ctx->sniRecvCb) {
            WOLFSSL_MSG("Calling custom sni callback");
            sniRet = ssl->ctx->sniRecvCb(ssl, &ad, ssl->ctx->sniRecvCbArg);
            switch (sniRet) {
                case warning_return:
                    WOLFSSL_MSG("Error in custom sni callback. Warning alert");
                    SendAlert(ssl, alert_warning, ad);
                    break;
                case fatal_return:
                    WOLFSSL_MSG("Error in custom sni callback. Fatal alert");
                    SendAlert(ssl, alert_fatal, ad);
                    return FATAL_ERROR;
                case noack_return:
                    WOLFSSL_MSG("Server quietly not acking servername.");
                    break;
                default:
                    break;
            }
        }
        return 0;
    }
#endif /* HAVE_SNI */

#endif /* NO_WOLFSSL_SERVER */

#ifdef WOLFSSL_ASYNC_CRYPT
int wolfSSL_AsyncPop(WOLFSSL* ssl, byte* state)
{
    int ret = 0;
    WC_ASYNC_DEV* asyncDev;
    WOLF_EVENT* event;

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    /* check for pending async */
    asyncDev = ssl->asyncDev;
    if (asyncDev) {
        /* grab event pointer */
        event = &asyncDev->event;

        ret = wolfAsync_EventPop(event, WOLF_EVENT_TYPE_ASYNC_WOLFSSL);
        if (ret != WC_NOT_PENDING_E && ret != WC_PENDING_E) {

            /* advance key share state if doesn't need called again */
            if (state && (asyncDev->event.flags & WC_ASYNC_FLAG_CALL_AGAIN) == 0) {
                (*state)++;
            }

            /* clear event */
            XMEMSET(&asyncDev->event, 0, sizeof(WOLF_EVENT));

            /* clear async dev */
            ssl->asyncDev = NULL;
        }
    }
    else {
        ret = WC_NOT_PENDING_E;
    }

    WOLFSSL_LEAVE("wolfSSL_AsyncPop", ret);

    return ret;
}

int wolfSSL_AsyncInit(WOLFSSL* ssl, WC_ASYNC_DEV* asyncDev, word32 flags)
{
    int ret;
    WOLF_EVENT* event;

    if (ssl == NULL || asyncDev == NULL) {
        return BAD_FUNC_ARG;
    }

    /* grab event pointer */
    event = &asyncDev->event;

    /* init event */
    ret = wolfAsync_EventInit(event, WOLF_EVENT_TYPE_ASYNC_WOLFSSL, ssl, flags);

    WOLFSSL_LEAVE("wolfSSL_AsyncInit", ret);

    return ret;
}

int wolfSSL_AsyncPush(WOLFSSL* ssl, WC_ASYNC_DEV* asyncDev)
{
    int ret;
    WOLF_EVENT* event;

    if (ssl == NULL || asyncDev == NULL) {
        return BAD_FUNC_ARG;
    }

    /* grab event pointer */
    event = &asyncDev->event;

    /* store reference to active async operation */
    ssl->asyncDev = asyncDev;

    /* place event into queue */
    ret = wolfAsync_EventQueuePush(&ssl->ctx->event_queue, event);

    /* success means return WC_PENDING_E */
    if (ret == 0) {
        ret = WC_PENDING_E;
    }

    WOLFSSL_LEAVE("wolfSSL_AsyncPush", ret);

    return ret;
}

#endif /* WOLFSSL_ASYNC_CRYPT */


/**
 * Return the max fragment size. This is essentially the maximum
 * fragment_length available.
 * @param ssl         WOLFSSL object containing ciphersuite information.
 * @param maxFragment The amount of space we want to check is available. This
 *                    is only the fragment length WITHOUT the (D)TLS headers.
 * @return            Max fragment size
 */
int wolfSSL_GetMaxFragSize(WOLFSSL* ssl, int maxFragment)
{
    (void) ssl; /* Avoid compiler warnings */

    if (maxFragment > MAX_RECORD_SIZE) {
        maxFragment = MAX_RECORD_SIZE;
    }

#ifdef HAVE_MAX_FRAGMENT
    if ((ssl->max_fragment != 0) && ((word16)maxFragment > ssl->max_fragment)) {
        maxFragment = ssl->max_fragment;
    }
#endif /* HAVE_MAX_FRAGMENT */
#ifdef WOLFSSL_DTLS
    if (IsDtlsNotSctpMode(ssl)) {
        int outputSz, mtuSz;

        /* Given a input buffer size of maxFragment, how big will the
         * encrypted output be? */
        if (IsEncryptionOn(ssl, 1)) {
            outputSz = BuildMessage(ssl, NULL, 0, NULL,
                    maxFragment + DTLS_HANDSHAKE_HEADER_SZ,
                    application_data, 0, 1, 0, CUR_ORDER);
        }
        else {
            outputSz = maxFragment + DTLS_RECORD_HEADER_SZ +
                    DTLS_HANDSHAKE_HEADER_SZ;
        }

        /* Readjust maxFragment for MTU size. */
        #if defined(WOLFSSL_DTLS_MTU)
            mtuSz = ssl->dtlsMtuSz;
        #else
            mtuSz = MAX_MTU;
        #endif
        maxFragment = ModifyForMTU(ssl, maxFragment, outputSz, mtuSz);
    }
#endif

    return maxFragment;
}

#if defined(WOLFSSL_IOTSAFE) && defined(HAVE_PK_CALLBACKS)

IOTSAFE *wolfSSL_get_iotsafe_ctx(WOLFSSL *ssl)
{
    if (ssl == NULL)
        return NULL;
    return &ssl->iotsafe;

}

int wolfSSL_set_iotsafe_ctx(WOLFSSL *ssl, IOTSAFE *iotsafe)
{
    if ((ssl == NULL) || (iotsafe == NULL))
        return BAD_FUNC_ARG;
    XMEMCPY(&ssl->iotsafe, iotsafe, sizeof(IOTSAFE));
    return 0;
}

#endif

#if defined(OPENSSL_ALL) && !defined(NO_FILESYSTEM) && !defined(NO_WOLFSSL_DIR)
/* create an instance of WOLFSSL_BY_DIR_HASH structure */
WOLFSSL_BY_DIR_HASH* wolfSSL_BY_DIR_HASH_new(void)
{
    WOLFSSL_BY_DIR_HASH* dir_hash;

    WOLFSSL_ENTER("wolfSSL_BY_DIR_HASH_new");

    dir_hash = (WOLFSSL_BY_DIR_HASH*)XMALLOC(sizeof(WOLFSSL_BY_DIR_HASH), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (dir_hash) {
        XMEMSET(dir_hash, 0, sizeof(WOLFSSL_BY_DIR_HASH));
    }
    return dir_hash;
}
/* release a WOLFSSL_BY_DIR_HASH resource */
void wolfSSL_BY_DIR_HASH_free(WOLFSSL_BY_DIR_HASH* dir_hash)
{
    if (dir_hash == NULL)
        return;

    XFREE(dir_hash, NULL, DYNAMIC_TYPE_OPENSSL);
}
/* create an instance of WOLFSSL_STACK for STACK_TYPE_BY_DIR_hash */
WOLFSSL_STACK* wolfSSL_sk_BY_DIR_HASH_new_null(void)
{
    WOLFSSL_STACK* sk = wolfSSL_sk_new_node(NULL);

    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_HASH_new_null");

    if (sk) {
        sk->type = STACK_TYPE_BY_DIR_hash;
    }
    return sk;
}

/* returns value less than 0 on fail to match
 * On a successful match the priority level found is returned
 */
int wolfSSL_sk_BY_DIR_HASH_find(
   WOLF_STACK_OF(WOLFSSL_BY_DIR_HASH)* sk, const WOLFSSL_BY_DIR_HASH* toFind)
{
    WOLFSSL_STACK* next;
    int i, sz;

    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_HASH_find");

    if (sk == NULL || toFind == NULL) {
        return WOLFSSL_FAILURE;
    }

    sz   = wolfSSL_sk_BY_DIR_HASH_num(sk);
    next = sk;
    for (i = 0; i < sz && next != NULL; i++) {
        if (next->data.dir_hash->hash_value == toFind->hash_value) {
            return sz - i; /* reverse because stack pushed highest on first */
        }
        next = next->next;
    }
    return -1;
}
/* return a number of WOLFSSL_BY_DIR_HASH in stack */
int wolfSSL_sk_BY_DIR_HASH_num(const WOLF_STACK_OF(WOLFSSL_BY_DIR_HASH) *sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_HASH_num");

    if (sk == NULL)
        return -1;
    return (int)sk->num;
}
/* return WOLFSSL_BY_DIR_HASH instance at i */
WOLFSSL_BY_DIR_HASH* wolfSSL_sk_BY_DIR_HASH_value(
                        const WOLF_STACK_OF(WOLFSSL_BY_DIR_HASH) *sk, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_HASH_value");

    for (; sk != NULL && i > 0; i--)
        sk = sk->next;

    if (i != 0 || sk == NULL)
        return NULL;
    return sk->data.dir_hash;
}
/* pop WOLFSSL_BY_DIR_HASH instance, and remove its node from stack */
WOLFSSL_BY_DIR_HASH* wolfSSL_sk_BY_DIR_HASH_pop(
                                WOLF_STACK_OF(WOLFSSL_BY_DIR_HASH)* sk)
{
    WOLFSSL_STACK* node;
    WOLFSSL_BY_DIR_HASH* hash;

    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_HASH_pop");

    if (sk == NULL) {
        return NULL;
    }

    node = sk->next;
    hash = sk->data.dir_hash;

    if (node != NULL) { /* update sk and remove node from stack */
        sk->data.dir_hash = node->data.dir_hash;
        sk->next = node->next;
        wolfSSL_sk_free_node(node);
    }
    else { /* last x509 in stack */
        sk->data.dir_hash = NULL;
    }

    if (sk->num > 0) {
        sk->num -= 1;
    }

    return hash;
}
/* release all contents in stack, and then release stack itself. */
/* Second argument is a function pointer to release resouces.    */
/* It calls the function to release resouces when t is passed    */
/* instead of wolfSSL_BY_DIR_HASH_free().                        */
void wolfSSL_sk_BY_DIR_HASH_pop_free(WOLF_STACK_OF(BY_DIR_HASH)* sk,
    void (*f) (WOLFSSL_BY_DIR_HASH*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_HASH_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.dir_hash);
        else
            wolfSSL_BY_DIR_HASH_free(tmp->data.dir_hash);
        tmp->data.dir_hash = NULL;
        XFREE(tmp, NULL, DYNAMIC_TYPE_OPENSSL);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.dir_hash);
        else
            wolfSSL_BY_DIR_HASH_free(sk->data.dir_hash);
        sk->data.dir_hash = NULL;
    }
    XFREE(sk, NULL, DYNAMIC_TYPE_OPENSSL);
}
/* release all contents in stack, and then release stack itself */
void wolfSSL_sk_BY_DIR_HASH_free(WOLF_STACK_OF(WOLFSSL_BY_DIR_HASH) *sk)
{
    wolfSSL_sk_BY_DIR_HASH_pop_free(sk, NULL);
}
/* Adds the WOLFSSL_BY_DIR_HASH to the stack "sk". "sk" takes control of "in" and
 * tries to free it when the stack is free'd.
 *
 * return 1 on success 0 on fail
 */
int wolfSSL_sk_BY_DIR_HASH_push(WOLF_STACK_OF(WOLFSSL_BY_DIR_HASH)* sk,
                                               WOLFSSL_BY_DIR_HASH* in)
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_HASH_push");

    if (sk == NULL || in == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* no previous values in stack */
    if (sk->data.dir_hash == NULL) {
        sk->data.dir_hash = in;
        sk->num += 1;
        return WOLFSSL_SUCCESS;
    }

    /* stack already has value(s) create a new node and add more */
    node = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), NULL,
            DYNAMIC_TYPE_OPENSSL);
    if (node == NULL) {
        WOLFSSL_MSG("Memory error");
        return WOLFSSL_FAILURE;
    }
    XMEMSET(node, 0, sizeof(WOLFSSL_STACK));

    /* push new obj onto head of stack */
    node->data.dir_hash    = sk->data.dir_hash;
    node->next             = sk->next;
    node->type             = sk->type;
    sk->next               = node;
    sk->data.dir_hash      = in;
    sk->num                += 1;

    return WOLFSSL_SUCCESS;
}
/* create an instance of WOLFSSL_BY_DIR_entry structure */
WOLFSSL_BY_DIR_entry* wolfSSL_BY_DIR_entry_new(void)
{
    WOLFSSL_BY_DIR_entry* entry;

    WOLFSSL_ENTER("wolfSSL_BY_DIR_entry_new");

    entry = (WOLFSSL_BY_DIR_entry*)XMALLOC(sizeof(WOLFSSL_BY_DIR_entry), NULL,
        DYNAMIC_TYPE_OPENSSL);

    if (entry) {
        XMEMSET(entry, 0, sizeof(WOLFSSL_BY_DIR_entry));
    }
    return entry;
}
/* release a WOLFSSL_BY_DIR_entry resource */
void wolfSSL_BY_DIR_entry_free(WOLFSSL_BY_DIR_entry* entry)
{
    WOLFSSL_ENTER("wolfSSL_BY_DIR_entry_free");

    if (entry == NULL)
        return;

    if (entry->hashes) {
        wolfSSL_sk_BY_DIR_HASH_free(entry->hashes);
    }

    if (entry->dir_name != NULL) {
        XFREE(entry->dir_name, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    XFREE(entry, NULL, DYNAMIC_TYPE_OPENSSL);
}

WOLFSSL_STACK* wolfSSL_sk_BY_DIR_entry_new_null(void)
{
    WOLFSSL_STACK* sk = wolfSSL_sk_new_node(NULL);

    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_entry_new_null");

    if (sk) {
        sk->type = STACK_TYPE_BY_DIR_entry;
    }
    return sk;
}
/* return a number of WOLFSSL_BY_DIR_entry in stack */
int wolfSSL_sk_BY_DIR_entry_num(const WOLF_STACK_OF(WOLFSSL_BY_DIR_entry) *sk)
{
    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_entry_num");

    if (sk == NULL)
        return -1;
    return (int)sk->num;
}
/* return WOLFSSL_BY_DIR_entry instance at i */
WOLFSSL_BY_DIR_entry* wolfSSL_sk_BY_DIR_entry_value(
                        const WOLF_STACK_OF(WOLFSSL_BY_DIR_entry) *sk, int i)
{
    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_entry_value");

    for (; sk != NULL && i > 0; i--)
        sk = sk->next;

    if (i != 0 || sk == NULL)
        return NULL;
    return sk->data.dir_entry;
}
/* pop WOLFSSL_BY_DIR_entry instance first, and remove its node from stack */
WOLFSSL_BY_DIR_entry* wolfSSL_sk_BY_DIR_entry_pop(
                                WOLF_STACK_OF(WOLFSSL_BY_DIR_entry)* sk)
{
    WOLFSSL_STACK* node;
    WOLFSSL_BY_DIR_entry* entry;

    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_entry_pop");

    if (sk == NULL) {
        return NULL;
    }

    node = sk->next;
    entry = sk->data.dir_entry;

    if (node != NULL) { /* update sk and remove node from stack */
        sk->data.dir_entry = node->data.dir_entry;
        sk->next = node->next;
        wolfSSL_sk_free_node(node);
    }
    else { /* last x509 in stack */
        sk->data.dir_entry = NULL;
    }

    if (sk->num > 0) {
        sk->num -= 1;
    }

    return entry;
}
/* release all contents in stack, and then release stack itself. */
/* Second argument is a function pointer to release resouces.    */
/* It calls the function to release resouces when t is passed    */
/* instead of wolfSSL_BY_DIR_entry_free().                       */
void wolfSSL_sk_BY_DIR_entry_pop_free(WOLF_STACK_OF(WOLFSSL_BY_DIR_entry)* sk,
    void (*f) (WOLFSSL_BY_DIR_entry*))
{
    WOLFSSL_STACK* node;

    WOLFSSL_ENTER("wolfSSL_sk_BY_DIR_entry_pop_free");

    if (sk == NULL) {
        return;
    }

    /* parse through stack freeing each node */
    node = sk->next;
    while (node && sk->num > 1) {
        WOLFSSL_STACK* tmp = node;
        node = node->next;

        if (f)
            f(tmp->data.dir_entry);
        else
            wolfSSL_BY_DIR_entry_free(tmp->data.dir_entry);
        tmp->data.dir_entry = NULL;
        XFREE(tmp, NULL, DYNAMIC_TYPE_OPENSSL);
        sk->num -= 1;
    }

    /* free head of stack */
    if (sk->num == 1) {
        if (f)
            f(sk->data.dir_entry);
        else
            wolfSSL_BY_DIR_entry_free(sk->data.dir_entry);
        sk->data.dir_entry = NULL;
    }
    XFREE(sk, NULL, DYNAMIC_TYPE_OPENSSL);
}
/* release all contents in stack, and then release stack itself */
void wolfSSL_sk_BY_DIR_entry_free(WOLF_STACK_OF(wolfSSL_BY_DIR_entry) *sk)
{
    wolfSSL_sk_BY_DIR_entry_pop_free(sk, NULL);
}

/* Adds the wolfSSL_BY_DIR_entry to the stack "sk". "sk" takes control of "in" and
 * tries to free it when the stack is free'd.
 *
 * return 1 on success 0 on fail
 */
int wolfSSL_sk_BY_DIR_entry_push(WOLF_STACK_OF(WOLFSSL_BY_DIR_entry)* sk,
                                               WOLFSSL_BY_DIR_entry* in)
{
    WOLFSSL_STACK* node;

    if (sk == NULL || in == NULL) {
        return WOLFSSL_FAILURE;
    }

    /* no previous values in stack */
    if (sk->data.dir_entry == NULL) {
        sk->data.dir_entry = in;
        sk->num += 1;
        return WOLFSSL_SUCCESS;
    }

    /* stack already has value(s) create a new node and add more */
    node = (WOLFSSL_STACK*)XMALLOC(sizeof(WOLFSSL_STACK), NULL,
            DYNAMIC_TYPE_OPENSSL);
    if (node == NULL) {
        WOLFSSL_MSG("Memory error");
        return WOLFSSL_FAILURE;
    }
    XMEMSET(node, 0, sizeof(WOLFSSL_STACK));

    /* push new obj onto head of stack */
    node->data.dir_entry    = sk->data.dir_entry;
    node->next              = sk->next;
    node->type              = sk->type;
    sk->next                = node;
    sk->data.dir_entry      = in;
    sk->num                 += 1;

    return WOLFSSL_SUCCESS;
}

#endif /* OPENSSL_ALL */

////////////////////////////////////////////////////////

#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_SET_CIPHER_BYTES)
int SetCipherListFromBytes(WOLFSSL_CTX* ctx, Suites* suites, const byte* list,
                           const int listSz)
{
    int ret = 0;
    int idx = 0;
    int i;

    int haveRSAsig       = 0;
    int haveECDSAsig     = 0;
    int haveFalconSig    = 0;
    int haveDilithiumSig = 0;
    int haveAnon         = 0;

    if (suites == NULL || list == NULL) {
        WOLFSSL_MSG("SetCipherListFromBytes parameter error");
        return 0;
    }

    if ((listSz % 2) != 0) {
        return 0;
    }

    for (i = 0; (i + 1) < listSz; i += 2) {
        const byte firstByte = list[i];
        const byte secondByte = list[i + 1];
        const char* name = NULL;
        int j;

        name = GetCipherNameInternal(firstByte, secondByte);
        if (XSTRCMP(name, "None") == 0) {
            /* bytes don't match any known cipher */
            continue;
        }

    #ifdef WOLFSSL_DTLS
        /* don't allow stream ciphers with DTLS */
        if (ctx->method->version.major == DTLS_MAJOR) {
            if (XSTRSTR(name, "RC4")) {
                WOLFSSL_MSG("Stream ciphers not supported with DTLS");
                continue;
            }
        }
    #endif /* WOLFSSL_DTLS */

        for (j = 0; j < idx; j += 2) {
            if ((suites->suites[j+0] == firstByte) &&
                    (suites->suites[j+1] == secondByte)) {
                break;
            }
        }
        /* Silently drop duplicates from list. */
        if (j != idx) {
            continue;
        }

        if (idx + 1 >= WOLFSSL_MAX_SUITE_SZ) {
            WOLFSSL_MSG("WOLFSSL_MAX_SUITE_SZ set too low");
            return 0; /* suites buffer not large enough, error out */
        }

        suites->suites[idx++] = firstByte;
        suites->suites[idx++] = secondByte;

        /* The suites are either ECDSA, RSA, PSK, or Anon. The RSA
         * suites don't necessarily have RSA in the name. */
    #ifdef WOLFSSL_TLS13
        if (firstByte == TLS13_BYTE || (firstByte == ECC_BYTE &&
                                        (secondByte == TLS_SHA256_SHA256 ||
                                         secondByte == TLS_SHA384_SHA384))) {
        #ifndef NO_RSA
            haveRSAsig = 1;
        #endif
        #if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
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
    #endif /* WOLFSSL_TLS13 */
    #if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
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
    }

    if (ret) {
        int keySz = 0;
    #ifndef NO_CERTS
        keySz = ctx->privateKeySz;
    #endif
        suites->suiteSz = (word16)idx;
        InitSuitesHashSigAlgo(suites, haveECDSAsig, haveRSAsig, haveFalconSig,
                              haveDilithiumSig, haveAnon, 1, keySz);
        suites->setSuites = 1;
    }

    (void)ctx;

    return ret;
}
#endif /* OPENSSL_EXTRA */


#ifdef OPENSSL_EXTRA

struct mac_algs {
    byte alg;
    const char* name;
} mac_names[] = {
#ifndef NO_SHA256
    { sha256_mac, "SHA256" },
#endif
#ifdef WOLFSSL_SHA384
    { sha384_mac, "SHA384" },
#endif
#ifdef WOLFSSL_SHA512
    { sha512_mac, "SHA512" },
#endif
#ifdef WOLFSSL_SHA224
    { sha224_mac, "SHA224" },
#endif
#if !defined(NO_SHA) && (!defined(NO_OLD_TLS) || \
                                                defined(WOLFSSL_ALLOW_TLS_SHA1))
    { sha_mac,    "SHA1" },
#endif
};
#define MAC_NAMES_SZ    (int)(sizeof(mac_names)/sizeof(*mac_names))

/* Convert the hash algorithm string to a TLS MAC algorithm num. */
static byte GetMacAlgFromName(const char* name, int len)
{
    byte alg = no_mac;
    int i;

    for (i = 0; i < MAC_NAMES_SZ; i++) {
        if (((int)XSTRLEN(mac_names[i].name) == len) &&
                                 (XMEMCMP(mac_names[i].name, name, len) == 0)) {
            alg = mac_names[i].alg;
            break;
        }
    }

    return alg;
}

struct sig_algs {
    byte alg;
    const char* name;
} sig_names[] = {
#ifndef NO_RSA
    { rsa_sa_algo,     "RSA" },
#ifdef WC_RSA_PSS
    { rsa_pss_sa_algo, "RSA-PSS" },
    { rsa_pss_sa_algo, "PSS" },
#endif
#endif
#ifdef HAVE_ECC
    { ecc_dsa_sa_algo, "ECDSA" },
#endif
#ifdef HAVE_ED25519
    { ed25519_sa_algo, "ED25519" },
#endif
#ifdef HAVE_ED448
    { ed448_sa_algo,   "ED448" },
#endif
#ifndef NO_DSA
    { dsa_sa_algo,     "DSA" },
#endif
};
#define SIG_NAMES_SZ    (int)(sizeof(sig_names)/sizeof(*sig_names))

/* Convert the signature algorithm string to a TLS signature algorithm num. */
static byte GetSigAlgFromName(const char* name, int len)
{
    byte alg = anonymous_sa_algo;
    int i;

    for (i = 0; i < SIG_NAMES_SZ; i++) {
        if (((int)XSTRLEN(sig_names[i].name) == len) &&
                                 (XMEMCMP(sig_names[i].name, name, len) == 0)) {
            alg = sig_names[i].alg;
            break;
        }
    }

    return alg;
}

/* Set the hash/signature algorithms that are supported for certificate signing.
 *
 * suites  [in,out]  Cipher suites and signature algorithms.
 * list    [in]      String representing hash/signature algorithms to set.
 * returns  0 on failure.
 *          1 on success.
 */
int SetSuitesHashSigAlgo(Suites* suites, const char* list)
{
    int ret = 1;
    word16 idx = 0;
    const char* s = list;
    byte sig_alg = 0;
    byte mac_alg = no_mac;

    /* Setting is destructive on error. */
    suites->hashSigAlgoSz = 0;

    do {
        if (*list == '+') {
            if (mac_alg != 0) {
                ret = 0;
                break;
            }
            sig_alg = GetSigAlgFromName(s, (int)(list - s));
            if (sig_alg == 0) {
                ret = 0;
                break;
            }
            s = list + 1;
        }
        else if (*list == ':' || *list == '\0') {
            if (sig_alg == 0) {
                /* No signature algorithm set yet.
                 * Ed25519 and Ed448 have implied MAC algorithm.
                 */
                sig_alg = GetSigAlgFromName(s, (int)(list - s));
                if (sig_alg != ed25519_sa_algo && sig_alg != ed448_sa_algo) {
                    ret = 0;
                    break;
                }
            }
            else {
                mac_alg = GetMacAlgFromName(s, (int)(list - s));
                if (mac_alg == 0) {
                    ret = 0;
                    break;
                }
            }
            AddSuiteHashSigAlgo(suites, mac_alg, sig_alg, 0, &idx);
            sig_alg = 0;
            mac_alg = no_mac;
            s = list + 1;
        }

        list++;
    }
    while (*(list-1) != '\0');

    if (s != list && (sig_alg != 0 || mac_alg != 0)) {
        ret = 0;
    }
    else {
        suites->hashSigAlgoSz = idx;
    }

    return ret;
}

#endif /* OPENSSL_EXTRA */

///////////////////////////////////////////////////////////////////////////////////


#ifndef NO_CERTS

void InitX509Name(WOLFSSL_X509_NAME* name, int dynamicFlag, void* heap)
{
    (void)dynamicFlag;

    if (name != NULL) {
        XMEMSET(name, 0, sizeof(WOLFSSL_X509_NAME));
        name->name        = name->staticName;
        name->heap = heap;
        name->dynamicName = 0;
    }
}


void FreeX509Name(WOLFSSL_X509_NAME* name)
{
    if (name != NULL) {
        if (name->dynamicName) {
            XFREE(name->name, name->heap, DYNAMIC_TYPE_SUBJECT_CN);
            name->name = NULL;
        }
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        {
            int i;
            for (i = 0; i < MAX_NAME_ENTRIES; i++) {
                if (name->entry[i].object != NULL)
                    wolfSSL_ASN1_OBJECT_free(name->entry[i].object);
                if (name->entry[i].value != NULL)
                    wolfSSL_ASN1_STRING_free(name->entry[i].value);
                XMEMSET(&name->entry[i], 0, sizeof(WOLFSSL_X509_NAME_ENTRY));
            }
        }
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
#ifdef OPENSSL_ALL
        if (name->entries) {
            wolfSSL_sk_X509_NAME_ENTRY_free(name->entries);
            name->entries = NULL;
        }
#endif
    }
}


/* Initialize wolfSSL X509 type */
void InitX509(WOLFSSL_X509* x509, int dynamicFlag, void* heap)
{
    if (x509 == NULL) {
        WOLFSSL_MSG("Null parameter passed in!");
        return;
    }

    XMEMSET(x509, 0, sizeof(WOLFSSL_X509));

    x509->heap = heap;
    InitX509Name(&x509->issuer, 0, heap);
    InitX509Name(&x509->subject, 0, heap);
    x509->dynamicMemory  = (byte)dynamicFlag;
#if defined(OPENSSL_EXTRA_X509_SMALL) || defined(OPENSSL_EXTRA)
    x509->refCount = 1;
#ifndef SINGLE_THREADED
    (void)wc_InitMutex(&x509->refMutex);
#endif
#endif
}


/* Free wolfSSL X509 type */
void FreeX509(WOLFSSL_X509* x509)
{
    if (x509 == NULL)
        return;

    FreeX509Name(&x509->issuer);
    FreeX509Name(&x509->subject);
    if (x509->pubKey.buffer) {
        XFREE(x509->pubKey.buffer, x509->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        x509->pubKey.buffer = NULL;
    }
    FreeDer(&x509->derCert);
    XFREE(x509->sig.buffer, x509->heap, DYNAMIC_TYPE_SIGNATURE);
    x509->sig.buffer = NULL;
    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
        if (x509->authKeyIdSrc != NULL) {
            XFREE(x509->authKeyIdSrc, x509->heap, DYNAMIC_TYPE_X509_EXT);
        }
        else {
            XFREE(x509->authKeyId, x509->heap, DYNAMIC_TYPE_X509_EXT);
        }
        x509->authKeyIdSrc = NULL;
        x509->authKeyId = NULL;
        XFREE(x509->subjKeyId, x509->heap, DYNAMIC_TYPE_X509_EXT);
        x509->subjKeyId = NULL;
        if (x509->authInfo != NULL) {
            XFREE(x509->authInfo, x509->heap, DYNAMIC_TYPE_X509_EXT);
            x509->authInfo = NULL;
        }
        if (x509->rawCRLInfo != NULL) {
            XFREE(x509->rawCRLInfo, x509->heap, DYNAMIC_TYPE_X509_EXT);
            x509->rawCRLInfo = NULL;
        }
        if (x509->CRLInfo != NULL) {
            XFREE(x509->CRLInfo, x509->heap, DYNAMIC_TYPE_X509_EXT);
            x509->CRLInfo = NULL;
        }
        #if defined(OPENSSL_ALL) || defined(OPENSSL_EXTRA) || \
            defined(WOLFSSL_QT)
        if (x509->authInfoCaIssuer != NULL) {
            XFREE(x509->authInfoCaIssuer, x509->heap, DYNAMIC_TYPE_X509_EXT);
        }
        if (x509->ext_sk != NULL) {
            wolfSSL_sk_X509_EXTENSION_pop_free(x509->ext_sk, NULL);
        }
        if (x509->ext_sk_full != NULL) {
            wolfSSL_sk_X509_EXTENSION_pop_free(x509->ext_sk_full, NULL);
        }
        #endif /* OPENSSL_ALL || WOLFSSL_QT */
        #ifdef OPENSSL_EXTRA
        /* Free serialNumber that was set by wolfSSL_X509_get_serialNumber */
        if (x509->serialNumber != NULL) {
            wolfSSL_ASN1_INTEGER_free(x509->serialNumber);
        }
        #endif
        if (x509->extKeyUsageSrc != NULL) {
            XFREE(x509->extKeyUsageSrc, x509->heap, DYNAMIC_TYPE_X509_EXT);
            x509->extKeyUsageSrc= NULL;
        }
    #endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */
    #if defined(OPENSSL_ALL)
        if (x509->algor.algorithm) {
            wolfSSL_ASN1_OBJECT_free(x509->algor.algorithm);
            x509->algor.algorithm = NULL;
        }
        if (x509->key.algor) {
            wolfSSL_X509_ALGOR_free(x509->key.algor);
            x509->key.algor = NULL;
        }
        if (x509->key.pkey) {
            wolfSSL_EVP_PKEY_free(x509->key.pkey);
            x509->key.pkey = NULL;
        }
        if (x509->subjAltNameSrc != NULL) {
            XFREE(x509->subjAltNameSrc, x509->heap, DYNAMIC_TYPE_X509_EXT);
            x509->subjAltNameSrc= NULL;
        }
    #endif /* OPENSSL_ALL */
    #if defined(WOLFSSL_CERT_REQ) && defined(OPENSSL_ALL)
        if (x509->reqAttributes) {
            wolfSSL_sk_pop_free(x509->reqAttributes, NULL);
        }
    #endif /* WOLFSSL_CERT_REQ */
    if (x509->altNames) {
        FreeAltNames(x509->altNames, x509->heap);
        x509->altNames = NULL;
    }

    #if defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)
    #ifndef SINGLE_THREADED
        wc_FreeMutex(&x509->refMutex);
    #endif
    #endif
}


#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT)
#if !defined(WOLFSSL_NO_TLS12)
/* Encode the signature algorithm into buffer.
 *
 * hashalgo  The hash algorithm.
 * hsType   The signature type.
 * output    The buffer to encode into.
 */
static WC_INLINE void EncodeSigAlg(byte hashAlgo, byte hsType, byte* output)
{
    switch (hsType) {
#ifdef HAVE_ECC
        case ecc_dsa_sa_algo:
            output[0] = hashAlgo;
            output[1] = ecc_dsa_sa_algo;
            break;
#endif
#ifdef HAVE_ED25519
        case ed25519_sa_algo:
            output[0] = ED25519_SA_MAJOR;
            output[1] = ED25519_SA_MINOR;
            (void)hashAlgo;
            break;
#endif
#ifdef HAVE_ED448
        case ed448_sa_algo:
            output[0] = ED448_SA_MAJOR;
            output[1] = ED448_SA_MINOR;
            (void)hashAlgo;
            break;
#endif
#ifndef NO_RSA
        case rsa_sa_algo:
            output[0] = hashAlgo;
            output[1] = rsa_sa_algo;
            break;
    #ifdef WC_RSA_PSS
        /* PSS signatures: 0x080[4-6] */
        case rsa_pss_sa_algo:
            output[0] = rsa_pss_sa_algo;
            output[1] = hashAlgo;
            break;
    #endif
#endif
        default:
            break;
    }
    (void)hashAlgo;
    (void)output;
}
#endif

#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_NO_CLIENT_AUTH)
static void SetDigest(WOLFSSL* ssl, int hashAlgo)
{
    switch (hashAlgo) {
    #ifndef NO_SHA
        case sha_mac:
            ssl->buffers.digest.buffer = ssl->hsHashes->certHashes.sha;
            ssl->buffers.digest.length = WC_SHA_DIGEST_SIZE;
            break;
    #endif /* !NO_SHA */
    #ifndef NO_SHA256
        case sha256_mac:
            ssl->buffers.digest.buffer = ssl->hsHashes->certHashes.sha256;
            ssl->buffers.digest.length = WC_SHA256_DIGEST_SIZE;
            break;
    #endif /* !NO_SHA256 */
    #ifdef WOLFSSL_SHA384
        case sha384_mac:
            ssl->buffers.digest.buffer = ssl->hsHashes->certHashes.sha384;
            ssl->buffers.digest.length = WC_SHA384_DIGEST_SIZE;
            break;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case sha512_mac:
            ssl->buffers.digest.buffer = ssl->hsHashes->certHashes.sha512;
            ssl->buffers.digest.length = WC_SHA512_DIGEST_SIZE;
            break;
    #endif /* WOLFSSL_SHA512 */
        default:
            break;
    } /* switch */
}
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_NO_CLIENT_AUTH */
#endif /* !NO_WOLFSSL_SERVER || !NO_WOLFSSL_CLIENT */
#endif /* !NO_CERTS */

////////////////////////////////////////////////////////////////////////////////////////////////


int InitSSL_Suites(WOLFSSL* ssl)
{
    int keySz = 0;
    byte havePSK = 0;
    byte haveAnon = 0;
    byte haveRSA = 0;
    byte haveMcast = 0;

    (void)haveAnon; /* Squash unused var warnings */
    (void)haveMcast;

    if (!ssl)
        return BAD_FUNC_ARG;

#ifndef NO_RSA
    haveRSA = 1;
#endif
#ifndef NO_PSK
    havePSK = (byte)ssl->options.havePSK;
#endif /* NO_PSK */
#if !defined(NO_CERTS) && !defined(WOLFSSL_SESSION_EXPORT)
#ifdef HAVE_ANON
    haveAnon = (byte)ssl->options.haveAnon;
#endif /* HAVE_ANON*/
#ifdef WOLFSSL_MULTICAST
    haveMcast = (byte)ssl->options.haveMcast;
#endif /* WOLFSSL_MULTICAST */
#endif /* !NO_CERTS && !WOLFSSL_SESSION_EXPORT */

#ifdef WOLFSSL_EARLY_DATA
    if (ssl->options.side == WOLFSSL_SERVER_END)
        ssl->options.maxEarlyDataSz = ssl->ctx->maxEarlyDataSz;
#endif
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
    ssl->options.cacheMessages = ssl->options.side == WOLFSSL_SERVER_END ||
                                      ssl->buffers.keyType == ed25519_sa_algo ||
                                      ssl->buffers.keyType == ed448_sa_algo;
#endif

#ifndef NO_CERTS
    keySz = ssl->buffers.keySz;
#endif

    /* make sure server has DH parms, and add PSK if there */
    if (ssl->options.side == WOLFSSL_SERVER_END) {
        InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK,
                   ssl->options.haveDH, ssl->options.haveECDSAsig,
                   ssl->options.haveECC, TRUE, ssl->options.haveStaticECC,
                   ssl->options.haveFalconSig, ssl->options.haveDilithiumSig,
                   ssl->options.haveAnon, TRUE, ssl->options.side);
    }
    else {
        InitSuites(ssl->suites, ssl->version, keySz, haveRSA, havePSK, TRUE,
                   ssl->options.haveECDSAsig, ssl->options.haveECC, TRUE,
                   ssl->options.haveStaticECC, ssl->options.haveFalconSig,
                   ssl->options.haveDilithiumSig, ssl->options.haveAnon, TRUE,
                   ssl->options.side);
    }

#if !defined(NO_CERTS) && !defined(WOLFSSL_SESSION_EXPORT)
    /* make sure server has cert and key unless using PSK, Anon, or
     * Multicast. This should be true even if just switching ssl ctx */
    if (ssl->options.side == WOLFSSL_SERVER_END &&
            !havePSK && !haveAnon && !haveMcast) {

        /* server certificate must be loaded */
        if (!ssl->buffers.certificate || !ssl->buffers.certificate->buffer) {
            WOLFSSL_MSG("Server missing certificate");
            WOLFSSL_ERROR_VERBOSE(NO_PRIVATE_KEY);
            return NO_PRIVATE_KEY;
        }

        if (!ssl->buffers.key || !ssl->buffers.key->buffer) {
            /* allow no private key if using existing key */
        #ifdef WOLF_PRIVATE_KEY_ID
            if (ssl->devId != INVALID_DEVID
            #ifdef HAVE_PK_CALLBACKS
                || wolfSSL_CTX_IsPrivatePkSet(ssl->ctx)
            #endif
            ) {
                WOLFSSL_MSG("Allowing no server private key (external)");
            }
            else
        #endif
            {
                WOLFSSL_MSG("Server missing private key");
                WOLFSSL_ERROR_VERBOSE(NO_PRIVATE_KEY);
                return NO_PRIVATE_KEY;
            }
        }
    }
#endif

    return WOLFSSL_SUCCESS;
}

/* returns new reference count. Arg incr positive=up or negative=down */
int SSL_CTX_RefCount(WOLFSSL_CTX* ctx, int incr)
{
    int refCount;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    if (wc_LockMutex(&ctx->countMutex) != 0) {
        WOLFSSL_MSG("Couldn't lock CTX count mutex");
        WOLFSSL_ERROR_VERBOSE(BAD_MUTEX_E);
        return BAD_MUTEX_E;
    }

    ctx->refCount += incr;
    /* make sure refCount is never negative */
    if (ctx->refCount < 0) {
        ctx->refCount = 0;
    }
    refCount = ctx->refCount;

    wc_UnLockMutex(&ctx->countMutex);

    return refCount;
}

/* This function inherits a WOLFSSL_CTX's fields into an SSL object.
   It is used during initialization and to switch an ssl's CTX with
   wolfSSL_Set_SSL_CTX.  Requires ssl->suites alloc and ssl-arrays with PSK
   unless writeDup is on.

   ssl      object to initialize
   ctx      parent factory
   writeDup flag indicating this is a write dup only

   WOLFSSL_SUCCESS return value on success */
int SetSSL_CTX(WOLFSSL* ssl, WOLFSSL_CTX* ctx, int writeDup)
{
    int ret;
    byte newSSL;

    WOLFSSL_ENTER("SetSSL_CTX");
    if (!ssl || !ctx)
        return BAD_FUNC_ARG;

#ifndef SINGLE_THREADED
    if (ssl->suites == NULL && !writeDup)
        return BAD_FUNC_ARG;
#endif

    newSSL = ssl->ctx == NULL; /* Assign after null check */

#ifndef NO_PSK
    if (ctx->server_hint[0] && ssl->arrays == NULL && !writeDup) {
        return BAD_FUNC_ARG;  /* needed for copy below */
    }
#endif

    /* decrement previous CTX reference count if exists.
     * This should only happen if switching ctxs!*/
    if (!newSSL) {
        WOLFSSL_MSG("freeing old ctx to decrement reference count. Switching ctx.");
        wolfSSL_CTX_free(ssl->ctx);
    }

    /* increment CTX reference count */
    if ((ret = SSL_CTX_RefCount(ctx, 1)) < 0) {
        return ret;
    }
    ret = WOLFSSL_SUCCESS; /* set default ret */

    ssl->ctx     = ctx; /* only for passing to calls, options could change */
    /* Don't change version on a SSL object that has already started a
     * handshake */
    if (!ssl->msgsReceived.got_client_hello &&
            !ssl->msgsReceived.got_server_hello)
        ssl->version = ctx->method->version;
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    ssl->options.mask = ctx->mask;
    ssl->options.minProto = ctx->minProto;
    ssl->options.maxProto = ctx->maxProto;
#endif
#ifdef OPENSSL_EXTRA
    #ifdef WOLFSSL_TLS13
    if (ssl->version.minor == TLSv1_3_MINOR &&
     (ssl->options.mask & SSL_OP_NO_TLSv1_3) == SSL_OP_NO_TLSv1_3) {
        if (!ctx->method->downgrade) {
            WOLFSSL_MSG("\tInconsistent protocol options. TLS 1.3 set but not "
                        "allowed and downgrading disabled.");
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;
        }
        WOLFSSL_MSG("\tOption set to not allow TLSv1.3, Downgrading");
        ssl->version.minor = TLSv1_2_MINOR;
    }
    #endif
    if (ssl->version.minor == TLSv1_2_MINOR &&
     (ssl->options.mask & SSL_OP_NO_TLSv1_2) == SSL_OP_NO_TLSv1_2) {
        if (!ctx->method->downgrade) {
            WOLFSSL_MSG("\tInconsistent protocol options. TLS 1.2 set but not "
                        "allowed and downgrading disabled.");
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;
        }
        WOLFSSL_MSG("\tOption set to not allow TLSv1.2, Downgrading");
        ssl->version.minor = TLSv1_1_MINOR;
    }
    if (ssl->version.minor == TLSv1_1_MINOR &&
     (ssl->options.mask & SSL_OP_NO_TLSv1_1) == SSL_OP_NO_TLSv1_1) {
        if (!ctx->method->downgrade) {
            WOLFSSL_MSG("\tInconsistent protocol options. TLS 1.1 set but not "
                        "allowed and downgrading disabled.");
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;
        }
        WOLFSSL_MSG("\tOption set to not allow TLSv1.1, Downgrading");
        ssl->options.tls1_1 = 0;
        ssl->version.minor = TLSv1_MINOR;
    }
    if (ssl->version.minor == TLSv1_MINOR &&
        (ssl->options.mask & SSL_OP_NO_TLSv1) == SSL_OP_NO_TLSv1) {
        if (!ctx->method->downgrade) {
            WOLFSSL_MSG("\tInconsistent protocol options. TLS 1 set but not "
                        "allowed and downgrading disabled.");
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;
        }
        WOLFSSL_MSG("\tOption set to not allow TLSv1, Downgrading");
        ssl->options.tls    = 0;
        ssl->options.tls1_1 = 0;
        ssl->version.minor = SSLv3_MINOR;
    }
    if (ssl->version.minor == SSLv3_MINOR &&
        (ssl->options.mask & SSL_OP_NO_SSLv3) == SSL_OP_NO_SSLv3) {
        WOLFSSL_MSG("\tError, option set to not allow SSLv3");
        WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
        return VERSION_ERROR;
    }

    if (ssl->version.minor < ssl->options.minDowngrade) {
        WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
        WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
        return VERSION_ERROR;
    }
#endif

#ifdef HAVE_ECC
    ssl->eccTempKeySz = ctx->eccTempKeySz;
    ssl->ecdhCurveOID = ctx->ecdhCurveOID;
#endif
#if defined(HAVE_ECC) || defined(HAVE_ED25519) || defined(HAVE_ED448)
    ssl->pkCurveOID = ctx->pkCurveOID;
#endif

#ifdef OPENSSL_EXTRA
    ssl->CBIS         = ctx->CBIS;
#endif
    ssl->timeout = ctx->timeout;
    ssl->verifyCallback    = ctx->verifyCallback;
    /* If we are setting the ctx on an already initialized SSL object
     * then we possibly already have a side defined. Don't overwrite unless
     * the context has a well defined role. */
    if (newSSL || ctx->method->side != WOLFSSL_NEITHER_END)
        ssl->options.side      = ctx->method->side;
    ssl->options.downgrade    = ctx->method->downgrade;
    ssl->options.minDowngrade = ctx->minDowngrade;

    ssl->options.haveRSA          = ctx->haveRSA;
    ssl->options.haveDH           = ctx->haveDH;
    ssl->options.haveECDSAsig     = ctx->haveECDSAsig;
    ssl->options.haveECC          = ctx->haveECC;
    ssl->options.haveStaticECC    = ctx->haveStaticECC;
    ssl->options.haveFalconSig    = ctx->haveFalconSig;
    ssl->options.haveDilithiumSig = ctx->haveDilithiumSig;

#ifndef NO_PSK
    ssl->options.havePSK       = ctx->havePSK;
    ssl->options.client_psk_cb = ctx->client_psk_cb;
    ssl->options.server_psk_cb = ctx->server_psk_cb;
    ssl->options.psk_ctx       = ctx->psk_ctx;
#ifdef WOLFSSL_TLS13
    ssl->options.client_psk_cs_cb    = ctx->client_psk_cs_cb;
    ssl->options.client_psk_tls13_cb = ctx->client_psk_tls13_cb;
    ssl->options.server_psk_tls13_cb = ctx->server_psk_tls13_cb;
#endif
#endif /* NO_PSK */
#ifdef WOLFSSL_EARLY_DATA
    if (ssl->options.side == WOLFSSL_SERVER_END)
        ssl->options.maxEarlyDataSz = ctx->maxEarlyDataSz;
#endif

#ifdef HAVE_ANON
    ssl->options.haveAnon = ctx->haveAnon;
#endif
#ifndef NO_DH
    ssl->options.minDhKeySz = ctx->minDhKeySz;
    ssl->options.maxDhKeySz = ctx->maxDhKeySz;
#endif
#ifndef NO_RSA
    ssl->options.minRsaKeySz = ctx->minRsaKeySz;
#endif
#ifdef HAVE_ECC
    ssl->options.minEccKeySz = ctx->minEccKeySz;
#endif
#ifdef HAVE_PQC
#ifdef HAVE_FALCON
    ssl->options.minFalconKeySz = ctx->minFalconKeySz;
#endif /* HAVE_FALCON */
#ifdef HAVE_DILITHIUM
    ssl->options.minDilithiumKeySz = ctx->minDilithiumKeySz;
#endif /* HAVE_DILITHIUM */
#endif /* HAVE_PQC */
#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
    ssl->options.verifyDepth = ctx->verifyDepth;
#endif

    ssl->options.sessionCacheOff      = ctx->sessionCacheOff;
    ssl->options.sessionCacheFlushOff = ctx->sessionCacheFlushOff;
#ifdef HAVE_EXT_CACHE
    ssl->options.internalCacheOff     = ctx->internalCacheOff;
    ssl->options.internalCacheLookupOff = ctx->internalCacheLookupOff;
#endif

    ssl->options.verifyPeer     = ctx->verifyPeer;
    ssl->options.verifyNone     = ctx->verifyNone;
    ssl->options.failNoCert     = ctx->failNoCert;
    ssl->options.failNoCertxPSK = ctx->failNoCertxPSK;
    ssl->options.sendVerify     = ctx->sendVerify;

    ssl->options.partialWrite  = ctx->partialWrite;
    ssl->options.quietShutdown = ctx->quietShutdown;
    ssl->options.groupMessages = ctx->groupMessages;

#ifndef NO_DH
    #if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
        !defined(HAVE_SELFTEST)
        ssl->options.dhKeyTested = ctx->dhKeyTested;
    #endif
    ssl->buffers.serverDH_P = ctx->serverDH_P;
    ssl->buffers.serverDH_G = ctx->serverDH_G;
#endif

#ifndef NO_CERTS
    /* ctx still owns certificate, certChain, key, dh, and cm */
    ssl->buffers.certificate = ctx->certificate;
    ssl->buffers.certChain = ctx->certChain;
#ifdef WOLFSSL_TLS13
    ssl->buffers.certChainCnt = ctx->certChainCnt;
#endif
    ssl->buffers.key      = ctx->privateKey;
    ssl->buffers.keyType  = ctx->privateKeyType;
    ssl->buffers.keyId    = ctx->privateKeyId;
    ssl->buffers.keyLabel = ctx->privateKeyLabel;
    ssl->buffers.keySz    = ctx->privateKeySz;
    ssl->buffers.keyDevId = ctx->privateKeyDevId;
#endif
#if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
    ssl->options.cacheMessages = ssl->options.side == WOLFSSL_SERVER_END ||
                                      ssl->buffers.keyType == ed25519_sa_algo ||
                                      ssl->buffers.keyType == ed448_sa_algo;
#endif


#ifdef WOLFSSL_ASYNC_CRYPT
    ssl->devId = ctx->devId;
#endif

    if (writeDup == 0) {
#ifndef NO_PSK
        if (ctx->server_hint[0]) {   /* set in CTX */
            XSTRNCPY(ssl->arrays->server_hint, ctx->server_hint,
                                    sizeof(ssl->arrays->server_hint));
            ssl->arrays->server_hint[MAX_PSK_ID_LEN] = '\0'; /* null term */
        }
#endif /* NO_PSK */

        if (ctx->suites) {
#ifndef SINGLE_THREADED
            *ssl->suites = *ctx->suites;
#else
            ssl->suites = ctx->suites;
#endif
        }
        else {
            XMEMSET(ssl->suites, 0, sizeof(Suites));
        }

        if (ssl->options.side != WOLFSSL_NEITHER_END) {
            /* Defer initializing suites until accept or connect */
            ret = InitSSL_Suites(ssl);
        }
    }  /* writeDup check */

    if (ctx->mask != 0 && wolfSSL_set_options(ssl, ctx->mask) == 0) {
        WOLFSSL_MSG("wolfSSL_set_options error");
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SESSION_EXPORT
    #ifdef WOLFSSL_DTLS
    ssl->dtls_export = ctx->dtls_export; /* export function for session */
    #endif
#endif

#ifdef WOLFSSL_WOLFSENTRY_HOOKS
    ssl->AcceptFilter = ctx->AcceptFilter;
    ssl->AcceptFilter_arg = ctx->AcceptFilter_arg;
    ssl->ConnectFilter = ctx->ConnectFilter;
    ssl->ConnectFilter_arg = ctx->ConnectFilter_arg;
#endif

#ifdef OPENSSL_EXTRA
    ssl->readAhead = ctx->readAhead;
#endif
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    /* Don't change recv callback if currently using BIO's */
    if (ssl->CBIORecv != BioReceive)
#endif
        ssl->CBIORecv = ctx->CBIORecv;
#if defined(OPENSSL_EXTRA) && !defined(NO_BIO)
    /* Don't change send callback if currently using BIO's */
    if (ssl->CBIOSend != BioSend)
#endif
        ssl->CBIOSend = ctx->CBIOSend;
    ssl->verifyDepth = ctx->verifyDepth;

    return ret;
}

int InitHandshakeHashes(WOLFSSL* ssl)
{
    int ret;

    /* make sure existing handshake hashes are free'd */
    if (ssl->hsHashes != NULL) {
        FreeHandshakeHashes(ssl);
    }

    /* allocate handshake hashes */
    ssl->hsHashes = (HS_Hashes*)XMALLOC(sizeof(HS_Hashes), ssl->heap,
                                                           DYNAMIC_TYPE_HASHES);
    if (ssl->hsHashes == NULL) {
        WOLFSSL_MSG("HS_Hashes Memory error");
        return MEMORY_E;
    }
    XMEMSET(ssl->hsHashes, 0, sizeof(HS_Hashes));

#ifndef NO_OLD_TLS
#ifndef NO_MD5
    ret = wc_InitMd5_ex(&ssl->hsHashes->hashMd5, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
    #ifdef WOLFSSL_HASH_FLAGS
        wc_Md5SetFlags(&ssl->hsHashes->hashMd5, WC_HASH_FLAG_WILLCOPY);
    #endif
#endif
#ifndef NO_SHA
    ret = wc_InitSha_ex(&ssl->hsHashes->hashSha, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
    #ifdef WOLFSSL_HASH_FLAGS
        wc_ShaSetFlags(&ssl->hsHashes->hashSha, WC_HASH_FLAG_WILLCOPY);
    #endif
#endif
#endif /* !NO_OLD_TLS */
#ifndef NO_SHA256
    ret = wc_InitSha256_ex(&ssl->hsHashes->hashSha256, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
    #ifdef WOLFSSL_HASH_FLAGS
        wc_Sha256SetFlags(&ssl->hsHashes->hashSha256, WC_HASH_FLAG_WILLCOPY);
    #endif
#endif
#ifdef WOLFSSL_SHA384
    ret = wc_InitSha384_ex(&ssl->hsHashes->hashSha384, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
    #ifdef WOLFSSL_HASH_FLAGS
        wc_Sha384SetFlags(&ssl->hsHashes->hashSha384, WC_HASH_FLAG_WILLCOPY);
    #endif
#endif
#ifdef WOLFSSL_SHA512
    ret = wc_InitSha512_ex(&ssl->hsHashes->hashSha512, ssl->heap, ssl->devId);
    if (ret != 0)
        return ret;
    #ifdef WOLFSSL_HASH_FLAGS
        wc_Sha512SetFlags(&ssl->hsHashes->hashSha512, WC_HASH_FLAG_WILLCOPY);
    #endif
#endif

    return ret;
}

void FreeHandshakeHashes(WOLFSSL* ssl)
{
    if (ssl->hsHashes) {
#ifndef NO_OLD_TLS
    #ifndef NO_MD5
        wc_Md5Free(&ssl->hsHashes->hashMd5);
    #endif
    #ifndef NO_SHA
        wc_ShaFree(&ssl->hsHashes->hashSha);
    #endif
#endif /* !NO_OLD_TLS */
    #ifndef NO_SHA256
        wc_Sha256Free(&ssl->hsHashes->hashSha256);
    #endif
    #ifdef WOLFSSL_SHA384
        wc_Sha384Free(&ssl->hsHashes->hashSha384);
    #endif
    #ifdef WOLFSSL_SHA512
        wc_Sha512Free(&ssl->hsHashes->hashSha512);
    #endif
    #if (defined(HAVE_ED25519) || defined(HAVE_ED448)) && \
                                                !defined(WOLFSSL_NO_CLIENT_AUTH)
        if (ssl->hsHashes->messages != NULL) {
            ForceZero(ssl->hsHashes->messages, ssl->hsHashes->length);
            XFREE(ssl->hsHashes->messages, ssl->heap, DYNAMIC_TYPE_HASHES);
            ssl->hsHashes->messages = NULL;
         }
    #endif

        XFREE(ssl->hsHashes, ssl->heap, DYNAMIC_TYPE_HASHES);
        ssl->hsHashes = NULL;
    }
}

/* called if user attempts to re-use WOLFSSL object for a new session.
 * For example wolfSSL_clear() is called then wolfSSL_connect or accept */
int ReinitSSL(WOLFSSL* ssl, WOLFSSL_CTX* ctx, int writeDup)
{
    int ret = 0;

    /* arrays */
    if (!writeDup && ssl->arrays == NULL) {
        ssl->arrays = (Arrays*)XMALLOC(sizeof(Arrays), ssl->heap,
                                                           DYNAMIC_TYPE_ARRAYS);
        if (ssl->arrays == NULL) {
            WOLFSSL_MSG("Arrays Memory error");
            return MEMORY_E;
        }
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("SSL Arrays", ssl->arrays, sizeof(*ssl->arrays));
#endif
        XMEMSET(ssl->arrays, 0, sizeof(Arrays));
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_SNIFFER)
        ssl->arrays->preMasterSz = ENCRYPT_LEN;
        ssl->arrays->preMasterSecret = (byte*)XMALLOC(ENCRYPT_LEN, ssl->heap,
            DYNAMIC_TYPE_SECRET);
        if (ssl->arrays->preMasterSecret == NULL) {
            return MEMORY_E;
        }
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("SSL Arrays", ssl->arrays->preMasterSecret, ENCRYPT_LEN);
#endif
        XMEMSET(ssl->arrays->preMasterSecret, 0, ENCRYPT_LEN);
#endif
    }

    /* RNG */
#ifdef SINGLE_THREADED
    if (ssl->rng == NULL) {
        ssl->rng = ctx->rng; /* CTX may have one, if so use it */
    }
#endif
    if (ssl->rng == NULL) {
        ssl->rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), ssl->heap,DYNAMIC_TYPE_RNG);
        if (ssl->rng == NULL) {
            WOLFSSL_MSG("RNG Memory error");
            return MEMORY_E;
        }
        XMEMSET(ssl->rng, 0, sizeof(WC_RNG));
        ssl->options.weOwnRng = 1;

        /* FIPS RNG API does not accept a heap hint */
#ifndef HAVE_FIPS
        if ( (ret = wc_InitRng_ex(ssl->rng, ssl->heap, ssl->devId)) != 0) {
            WOLFSSL_MSG("RNG Init error");
            return ret;
        }
#else
        if ( (ret = wc_InitRng(ssl->rng)) != 0) {
            WOLFSSL_MSG("RNG Init error");
            return ret;
        }
#endif
    }
    (void)ctx;

    return ret;
}

/* init everything to 0, NULL, default values before calling anything that may
   fail so that destructor has a "good" state to cleanup

   ssl      object to initialize
   ctx      parent factory
   writeDup flag indicating this is a write dup only

   0 on success */
int InitSSL(WOLFSSL* ssl, WOLFSSL_CTX* ctx, int writeDup)
{
    int  ret;

    XMEMSET(ssl, 0, sizeof(WOLFSSL));
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("SSL Keys", &ssl->keys, sizeof(ssl->keys));
#ifdef WOLFSSL_TLS13
    wc_MemZero_Add("SSL client secret", &ssl->clientSecret,
        sizeof(ssl->clientSecret));
    wc_MemZero_Add("SSL client secret", &ssl->serverSecret,
        sizeof(ssl->serverSecret));
#endif
#ifdef WOLFSSL_HAVE_TLS_UNIQUE
    wc_MemZero_Add("ClientFinished hash", &ssl->clientFinished,
        TLS_FINISHED_SZ_MAX);
    wc_MemZero_Add("ServerFinished hash", &ssl->serverFinished,
        TLS_FINISHED_SZ_MAX);
#endif
#endif

#if defined(WOLFSSL_STATIC_MEMORY)
    if (ctx->heap != NULL) {
        WOLFSSL_HEAP_HINT* ssl_hint;
        WOLFSSL_HEAP_HINT* ctx_hint;

        /* avoid dereferencing a test value */
    #ifdef WOLFSSL_HEAP_TEST
        if (ctx->heap == (void*)WOLFSSL_HEAP_TEST) {
            ssl->heap = ctx->heap;
        }
        else {
    #endif
        ssl->heap = (WOLFSSL_HEAP_HINT*)XMALLOC(sizeof(WOLFSSL_HEAP_HINT),
                                               ctx->heap, DYNAMIC_TYPE_SSL);
        if (ssl->heap == NULL) {
            return MEMORY_E;
        }
        XMEMSET(ssl->heap, 0, sizeof(WOLFSSL_HEAP_HINT));
        ssl_hint = ((WOLFSSL_HEAP_HINT*)(ssl->heap));
        ctx_hint = ((WOLFSSL_HEAP_HINT*)(ctx->heap));

        /* lock and check IO count / handshake count */
        if (wc_LockMutex(&(ctx_hint->memory->memory_mutex)) != 0) {
            WOLFSSL_MSG("Bad memory_mutex lock");
            XFREE(ssl->heap, ctx->heap, DYNAMIC_TYPE_SSL);
            ssl->heap = NULL; /* free and set to NULL for IO counter */
            WOLFSSL_ERROR_VERBOSE(BAD_MUTEX_E);
            return BAD_MUTEX_E;
        }
        if (ctx_hint->memory->maxHa > 0 &&
                           ctx_hint->memory->maxHa <= ctx_hint->memory->curHa) {
            WOLFSSL_MSG("At max number of handshakes for static memory");
            wc_UnLockMutex(&(ctx_hint->memory->memory_mutex));
            XFREE(ssl->heap, ctx->heap, DYNAMIC_TYPE_SSL);
            ssl->heap = NULL; /* free and set to NULL for IO counter */
            return MEMORY_E;
        }

        if (ctx_hint->memory->maxIO > 0 &&
                           ctx_hint->memory->maxIO <= ctx_hint->memory->curIO) {
            WOLFSSL_MSG("At max number of IO allowed for static memory");
            wc_UnLockMutex(&(ctx_hint->memory->memory_mutex));
            XFREE(ssl->heap, ctx->heap, DYNAMIC_TYPE_SSL);
            ssl->heap = NULL; /* free and set to NULL for IO counter */
            return MEMORY_E;
        }
        ctx_hint->memory->curIO++;
        ctx_hint->memory->curHa++;
        ssl_hint->memory = ctx_hint->memory;
        ssl_hint->haFlag = 1;
        wc_UnLockMutex(&(ctx_hint->memory->memory_mutex));

        /* check if tracking stats */
        if (ctx_hint->memory->flag & WOLFMEM_TRACK_STATS) {
            ssl_hint->stats = (WOLFSSL_MEM_CONN_STATS*)XMALLOC(
               sizeof(WOLFSSL_MEM_CONN_STATS), ctx->heap, DYNAMIC_TYPE_SSL);
            if (ssl_hint->stats == NULL) {
                return MEMORY_E;
            }
            XMEMSET(ssl_hint->stats, 0, sizeof(WOLFSSL_MEM_CONN_STATS));
        }

        /* check if using fixed IO buffers */
        if (ctx_hint->memory->flag & WOLFMEM_IO_POOL_FIXED) {
            if (wc_LockMutex(&(ctx_hint->memory->memory_mutex)) != 0) {
                WOLFSSL_MSG("Bad memory_mutex lock");
                WOLFSSL_ERROR_VERBOSE(BAD_MUTEX_E);
                return BAD_MUTEX_E;
            }
            if (SetFixedIO(ctx_hint->memory, &(ssl_hint->inBuf)) != 1) {
                wc_UnLockMutex(&(ctx_hint->memory->memory_mutex));
                return MEMORY_E;
            }
            if (SetFixedIO(ctx_hint->memory, &(ssl_hint->outBuf)) != 1) {
                wc_UnLockMutex(&(ctx_hint->memory->memory_mutex));
                return MEMORY_E;
            }
            if (ssl_hint->outBuf == NULL || ssl_hint->inBuf == NULL) {
                WOLFSSL_MSG("Not enough memory to create fixed IO buffers");
                wc_UnLockMutex(&(ctx_hint->memory->memory_mutex));
                return MEMORY_E;
            }
            wc_UnLockMutex(&(ctx_hint->memory->memory_mutex));
        }
    #ifdef WOLFSSL_HEAP_TEST
        }
    #endif
    }
    else {
        ssl->heap = ctx->heap;
    }
#else
    ssl->heap = ctx->heap; /* carry over user heap without static memory */
#endif /* WOLFSSL_STATIC_MEMORY */

    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;

    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;

#ifdef KEEP_PEER_CERT
    InitX509(&ssl->peerCert, 0, ssl->heap);
#endif

    ssl->rfd = -1;   /* set to invalid descriptor */
    ssl->wfd = -1;
    ssl->devId = ctx->devId; /* device for async HW (from wolfAsync_DevOpen) */

    /* initialize states */
    ssl->options.serverState = NULL_STATE;
    ssl->options.clientState = NULL_STATE;
    ssl->options.connectState = CONNECT_BEGIN;
    ssl->options.acceptState  = ACCEPT_BEGIN;
    ssl->options.handShakeState  = NULL_STATE;
    ssl->options.processReply = 0 /* doProcessInit */;
    ssl->options.asyncState = TLS_ASYNC_BEGIN;
    ssl->options.buildMsgState = BUILD_MSG_BEGIN;
    ssl->encrypt.state = CIPHER_STATE_BEGIN;
    ssl->decrypt.state = CIPHER_STATE_BEGIN;
#ifndef NO_DH
    #if !defined(WOLFSSL_OLD_PRIME_CHECK) && !defined(HAVE_FIPS) && \
        !defined(HAVE_SELFTEST)
        ssl->options.dhDoKeyTest = 1;
    #endif
#endif

#ifdef WOLFSSL_DTLS
    #ifdef WOLFSSL_SCTP
        ssl->options.dtlsSctp           = ctx->dtlsSctp;
    #endif
    #ifdef WOLFSSL_SRTP
        ssl->dtlsSrtpProfiles           = ctx->dtlsSrtpProfiles;
    #endif
    #if defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)
        ssl->dtlsMtuSz                  = ctx->dtlsMtuSz;
        /* Add some bytes so that we can operate with slight difference
         * in set MTU size on each peer */
        ssl->dtls_expected_rx           = ssl->dtlsMtuSz +
                                            DTLS_MTU_ADDITIONAL_READ_BUFFER;
    #else
        ssl->dtls_expected_rx = MAX_MTU;
    #endif
    ssl->dtls_timeout_init              = DTLS_TIMEOUT_INIT;
    ssl->dtls_timeout_max               = DTLS_TIMEOUT_MAX;
    ssl->dtls_timeout                   = ssl->dtls_timeout_init;

    ssl->buffers.dtlsCtx.rfd            = -1;
    ssl->buffers.dtlsCtx.wfd            = -1;

    ssl->IOCB_ReadCtx  = &ssl->buffers.dtlsCtx;  /* prevent invalid pointer access if not */
    ssl->IOCB_WriteCtx = &ssl->buffers.dtlsCtx;  /* correctly set */
#else
#ifdef HAVE_NETX
    ssl->IOCB_ReadCtx  = &ssl->nxCtx;  /* default NetX IO ctx, same for read */
    ssl->IOCB_WriteCtx = &ssl->nxCtx;  /* and write */
#elif defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP)
    ssl->mnCtx = mynewt_ctx_new();
    if(!ssl->mnCtx) {
        return MEMORY_E;
    }
    ssl->IOCB_ReadCtx  = ssl->mnCtx;  /* default Mynewt IO ctx, same for read */
    ssl->IOCB_WriteCtx = ssl->mnCtx;  /* and write */
#elif defined (WOLFSSL_GNRC)
    ssl->IOCB_ReadCtx = ssl->gnrcCtx;
    ssl->IOCB_WriteCtx = ssl->gnrcCtx;
#else
    ssl->IOCB_ReadCtx  = &ssl->rfd;  /* prevent invalid pointer access if not */
    ssl->IOCB_WriteCtx = &ssl->wfd;  /* correctly set */
#endif
#endif


#ifndef WOLFSSL_AEAD_ONLY
    #ifndef NO_OLD_TLS
        ssl->hmac = SSL_hmac; /* default to SSLv3 */
    #elif !defined(WOLFSSL_NO_TLS12) && !defined(NO_TLS)
      #if !defined(WOLFSSL_RENESAS_SCEPROTECT) && \
          !defined(WOLFSSL_RENESAS_TSIP_TLS)
        ssl->hmac = TLS_hmac;
      #else
        ssl->hmac = Renesas_cmn_TLS_hmac;
      #endif
    #endif
#endif

#if defined(WOLFSSL_OPENVPN) && defined(HAVE_KEYING_MATERIAL)
    /* Save arrays by default for OpenVPN */
    ssl->options.saveArrays = 1;
#endif

    ssl->cipher.ssl = ssl;

#ifdef HAVE_EXTENDED_MASTER
    ssl->options.haveEMS = ctx->haveEMS;
#endif
    ssl->options.useClientOrder = ctx->useClientOrder;
    ssl->options.mutualAuth = ctx->mutualAuth;

#ifdef WOLFSSL_TLS13
    #if defined(HAVE_SESSION_TICKET) && !defined(NO_WOLFSSL_SERVER)
        ssl->options.maxTicketTls13 = ctx->maxTicketTls13;
    #endif
    #ifdef HAVE_SESSION_TICKET
        ssl->options.noTicketTls13  = ctx->noTicketTls13;
    #endif
    ssl->options.noPskDheKe = ctx->noPskDheKe;
    #if defined(WOLFSSL_POST_HANDSHAKE_AUTH)
        ssl->options.postHandshakeAuth = ctx->postHandshakeAuth;
        ssl->options.verifyPostHandshake = ctx->verifyPostHandshake;
    #endif

    if (ctx->numGroups > 0) {
        XMEMCPY(ssl->group, ctx->group, sizeof(*ctx->group) * ctx->numGroups);
        ssl->numGroups = ctx->numGroups;
    }
#endif

#ifdef HAVE_TLS_EXTENSIONS
#ifdef HAVE_MAX_FRAGMENT
    ssl->max_fragment = MAX_RECORD_SIZE;
#endif
#ifdef HAVE_ALPN
    ssl->alpn_peer_requested = NULL;
    ssl->alpn_peer_requested_length = 0;
    #if defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || defined(WOLFSSL_HAPROXY)
        ssl->alpnSelect    = ctx->alpnSelect;
        ssl->alpnSelectArg = ctx->alpnSelectArg;
    #endif
    #if !defined(NO_BIO) && defined(OPENSSL_EXTRA)
        if (ctx->alpn_cli_protos != NULL && ctx->alpn_cli_protos_len > 0) {
            ret = wolfSSL_set_alpn_protos(ssl, ctx->alpn_cli_protos,
                                            ctx->alpn_cli_protos_len);
        #if defined(WOLFSSL_ERROR_CODE_OPENSSL)
            if (ret) {
        #else
            if (!ret) {
        #endif
                WOLFSSL_MSG("failed to set alpn protos to ssl object");
                return ret;
            }
        }
    #endif
#endif
#ifdef HAVE_SUPPORTED_CURVES
    ssl->options.userCurves = ctx->userCurves;
#endif
#endif /* HAVE_TLS_EXTENSIONS */

#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    ssl->options.disallowEncThenMac = ctx->disallowEncThenMac;
#endif

    /* default alert state (none) */
    ssl->alert_history.last_rx.code  = -1;
    ssl->alert_history.last_rx.level = -1;
    ssl->alert_history.last_tx.code  = -1;
    ssl->alert_history.last_tx.level = -1;

#ifdef OPENSSL_EXTRA
    /* copy over application session context ID */
    ssl->sessionCtxSz = ctx->sessionCtxSz;
    XMEMCPY(ssl->sessionCtx, ctx->sessionCtx, ctx->sessionCtxSz);
    ssl->cbioFlag = ctx->cbioFlag;

    ssl->protoMsgCb  = ctx->protoMsgCb;
    ssl->protoMsgCtx = ctx->protoMsgCtx;

    /* follow default behavior of setting toInfoOn similar to
     * wolfSSL_set_msg_callback when the callback is set */
    if (ctx->protoMsgCb != NULL) {
        ssl->toInfoOn = 1;
    }

    ssl->disabledCurves = ctx->disabledCurves;
#endif

    InitCiphers(ssl);
    InitCipherSpecs(&ssl->specs);

    /* all done with init, now can return errors, call other stuff */
    if ((ret = ReinitSSL(ssl, ctx, writeDup)) != 0) {
        return ret;
    }

    if (!writeDup) {
#ifdef OPENSSL_EXTRA
        if ((ssl->param = (WOLFSSL_X509_VERIFY_PARAM*)XMALLOC(
                                    sizeof(WOLFSSL_X509_VERIFY_PARAM),
                                    ssl->heap, DYNAMIC_TYPE_OPENSSL)) == NULL) {
            WOLFSSL_MSG("ssl->param memory error");
            return MEMORY_E;
        }
        XMEMSET(ssl->param, 0, sizeof(WOLFSSL_X509_VERIFY_PARAM));
#endif

#ifdef SINGLE_THREADED
        if (ctx->suites == NULL)
#endif
        {
            /* suites */
            ssl->suites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
                                       DYNAMIC_TYPE_SUITES);
            if (ssl->suites == NULL) {
                WOLFSSL_MSG("Suites Memory error");
                return MEMORY_E;
            }
        #ifdef OPENSSL_ALL
            ssl->suites->stack = NULL;
        #endif
#ifdef SINGLE_THREADED
            ssl->options.ownSuites = 1;
#endif
        }
#ifdef SINGLE_THREADED
        else {
            ssl->options.ownSuites = 0;
        }
#endif
    } /* !writeDup */

    /* Initialize SSL with the appropriate fields from it's ctx */
    /* requires valid arrays and suites unless writeDup ing */
    if ((ret = SetSSL_CTX(ssl, ctx, writeDup)) != WOLFSSL_SUCCESS)
        return ret;

    ssl->options.dtls = ssl->version.major == DTLS_MAJOR;

#ifdef HAVE_WRITE_DUP
    if (writeDup) {
        /* all done */
        return 0;
    }
#endif

    /* hsHashes */
    ret = InitHandshakeHashes(ssl);
    if (ret != 0)
        return ret;

#if defined(WOLFSSL_DTLS) && !defined(NO_WOLFSSL_SERVER)
    if (ssl->options.dtls && ssl->options.side == WOLFSSL_SERVER_END) {
        if (!IsAtLeastTLSv1_3(ssl->version)) {
                ret = wolfSSL_DTLS_SetCookieSecret(ssl, NULL, 0);
                if (ret != 0) {
                    WOLFSSL_MSG("DTLS Cookie Secret error");
                    return ret;
                }
        }
#if defined(WOLFSSL_DTLS13) && defined(WOLFSSL_SEND_HRR_COOKIE)
        else {
            ret = wolfSSL_send_hrr_cookie(ssl, NULL, 0);
            if (ret != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG("DTLS1.3 Cookie secret error");
                return ret;
            }
        }
#endif /* WOLFSSL_DTLS13 && WOLFSSL_SEND_HRR_COOKIE */
    }
#endif /* WOLFSSL_DTLS && !NO_WOLFSSL_SERVER */

#ifdef HAVE_SECRET_CALLBACK
    ssl->sessionSecretCb  = NULL;
    ssl->sessionSecretCtx = NULL;
#ifdef WOLFSSL_TLS13
    ssl->tls13SecretCb  = NULL;
    ssl->tls13SecretCtx = NULL;
#endif
#endif
#if defined(OPENSSL_EXTRA) && defined(HAVE_SECRET_CALLBACK)
    if (ctx->keyLogCb != NULL) {
        ssl->keyLogCb = SessionSecret_callback;
#if defined(WOLFSSL_TLS13)
        ssl->tls13KeyLogCb = SessionSecret_callback_Tls13;
#endif /*WOLFSSL_TLS13*/
    }
#endif /*OPENSSL_EXTRA && HAVE_SECRET_CALLBACK */

    ssl->session = wolfSSL_NewSession(ssl->heap);
    if (ssl->session == NULL) {
        WOLFSSL_MSG("SSL Session Memory error");
        return MEMORY_E;
    }

#ifdef HAVE_SESSION_TICKET
    ssl->options.noTicketTls12 = ctx->noTicketTls12;
#endif

#ifdef WOLFSSL_MULTICAST
    if (ctx->haveMcast) {
        int i;

        ssl->options.haveMcast = 1;
        ssl->options.mcastID = ctx->mcastID;

        /* Force the state to look like handshake has completed. */
        /* Keying material is supplied externally. */
        ssl->options.serverState = SERVER_FINISHED_COMPLETE;
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
        ssl->options.connectState = SECOND_REPLY_DONE;
        ssl->options.acceptState = ACCEPT_THIRD_REPLY_DONE;
        ssl->options.handShakeState = HANDSHAKE_DONE;
        ssl->options.handShakeDone = 1;

        for (i = 0; i < WOLFSSL_DTLS_PEERSEQ_SZ; i++)
            ssl->keys.peerSeq[i].peerId = INVALID_PEER_ID;
    }
#endif

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        int useSecureReneg = ssl->ctx->useSecureReneg;
        /* use secure renegotiation by default (not recommend) */
    #ifdef WOLFSSL_SECURE_RENEGOTIATION_ON_BY_DEFAULT
        useSecureReneg = 1;
    #endif
        if (useSecureReneg) {
            ret = wolfSSL_UseSecureRenegotiation(ssl);
            if (ret != WOLFSSL_SUCCESS)
                return ret;
            }
    }
#endif /* HAVE_SECURE_RENEGOTIATION */


#ifdef WOLFSSL_DTLS13
    /* setup 0 (un-protected) epoch */
    ssl->dtls13Epochs[0].isValid = 1;
    ssl->dtls13Epochs[0].side = ENCRYPT_AND_DECRYPT_SIDE;
    ssl->dtls13EncryptEpoch = &ssl->dtls13Epochs[0];
    ssl->dtls13DecryptEpoch = &ssl->dtls13Epochs[0];
    ssl->options.dtls13SendMoreAcks = WOLFSSL_DTLS13_SEND_MOREACK_DEFAULT;
    ssl->dtls13Rtx.rtxRecordTailPtr = &ssl->dtls13Rtx.rtxRecords;
#endif /* WOLFSSL_DTLS13 */

#ifdef WOLFSSL_QUIC
    if (ctx->quic.method) {
        ret = wolfSSL_set_quic_method(ssl, ctx->quic.method);
        if (ret != WOLFSSL_SUCCESS)
            return ret;
    }
#endif

#if defined(WOLFSSL_MAXQ10XX_TLS)
    ret = wolfSSL_maxq10xx_load_certificate(ssl);
    if (ret != WOLFSSL_SUCCESS)
        return ret;
#endif

    return 0;
}



//////////////////////////// </body>

#undef ERROR_OUT

#endif /* #ifndef WOLFCRYPT_ONLY */
