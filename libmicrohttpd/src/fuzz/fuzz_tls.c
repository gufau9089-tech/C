/*
  This file is part of libmicrohttpd
  Copyright (C) 2026 Christian Grothoff

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library.
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file fuzz/fuzz_tls.c
 * @brief In-process fuzzer for MHD's HTTPS/TLS integration layer.
 * @author Christian Grothoff
 *
 * The target is **MHD's own TLS plumbing**, not GnuTLS.  GnuTLS has its
 * own OSS-Fuzz project and its record parser is not our bug surface, so
 * only a small part of the input budget is spent throwing raw bytes at a
 * TLS socket.  What this harness really exercises is
 *
 *  - the @c MHD_USE_TLS daemon option surface: #MHD_OPTION_HTTPS_MEM_KEY,
 *    #MHD_OPTION_HTTPS_MEM_CERT, #MHD_OPTION_HTTPS_MEM_TRUST,
 *    #MHD_OPTION_HTTPS_MEM_DHPARAMS, #MHD_OPTION_HTTPS_PRIORITIES,
 *    #MHD_OPTION_HTTPS_PRIORITIES_APPEND, #MHD_OPTION_HTTPS_CRED_TYPE,
 *    #MHD_OPTION_HTTPS_KEY_PASSWORD, #MHD_OPTION_TLS_NO_ALPN and the SNI
 *    callback #MHD_OPTION_HTTPS_CERT_CALLBACK -- with malformed PEM
 *    blobs, mismatched key/certificate pairs, bogus priority strings,
 *    credential types MHD does not support, and an SNI callback that
 *    fails or answers with garbage;
 *  - the pre-shared key path: #MHD_OPTION_GNUTLS_PSK_CRED_HANDLER and
 *    @c psk_gnutls_adapter(), which is the one place where MHD takes a
 *    buffer straight from an application callback and hands it to
 *    GnuTLS.  See the "TLS-PSK" note below for why one input bit turns
 *    the whole scenario on rather than four independent ones;
 *  - the handshake state machine of connection_https.c
 *    (#MHD_TLS_CONN_INIT -> HANDSHAKING -> CONNECTED / TLS_FAILED) and
 *    what MHD does when the handshake fails, is abandoned half way, or
 *    the peer disappears while MHD is still in it;
 *  - the transition from the handshake to the ordinary HTTP parser, and
 *    the TLS receive/send adapters and @c gnutls_bye() shutdown path that
 *    the connection uses afterwards.
 *
 * To reach that last group the harness contains a real, in-process GnuTLS
 * *client*.  Both ends of an @c AF_UNIX @c socketpair() are non-blocking
 * and everything runs in one thread: the client's @c gnutls_handshake()
 * is called until it answers @c GNUTLS_E_AGAIN, then the daemon is pumped
 * with MHD_run(), and so on.  No threads, no ports, no TCP stack, and --
 * because the client's handshake timeout is set to
 * @c GNUTLS_INDEFINITE_TIMEOUT -- no wall clock either.
 *
 * Input format (see README):
 *
 *   byte 0   certificate/key pair selector (valid, mismatched, truncated,
 *            garbage, absent, or built from the fuzzer's own bytes)
 *   byte 1   which TLS daemon options to pass at all (bitmask)
 *              0x01 MHD_OPTION_HTTPS_MEM_TRUST
 *              0x02 MHD_OPTION_HTTPS_MEM_DHPARAMS
 *              0x04 MHD_OPTION_HTTPS_CERT_CALLBACK (the SNI callback)
 *              0x08 MHD_OPTION_HTTPS_PRIORITIES[_APPEND]
 *              0x10 MHD_OPTION_HTTPS_CRED_TYPE
 *              0x20 MHD_OPTION_TLS_NO_ALPN
 *              0x40 MHD_OPTION_HTTPS_KEY_PASSWORD
 *              0x80 use _PRIORITIES_APPEND instead of _PRIORITIES
 *   byte 2   priority string selector
 *   byte 3   bits 0-2 credential type (certificate, PSK, anon, SRP, IA,
 *                     and two values GnuTLS does not define)
 *            bits 3-5 SNI callback behaviour
 *            bit  6   trust blob: CA certificate or garbage
 *            bit  7   DH parameters: valid or garbage
 *   byte 4   bits 0-1 client mode
 *                     0 raw bytes, 1 real TLS client,
 *                     2 real client, handshake abandoned half way,
 *                     3 raw bytes shaped like TLS records
 *            bit  2   client sends a server name (SNI)
 *            bit  3   client presents a client certificate
 *            bits 4-5 client priority string selector
 *            bit  6   gnutls_bye() before closing
 *            bit  7   shutdown(SHUT_WR) before closing
 *   byte 5   bits 0-3 MHD_OPTION_CONNECTION_MEMORY_LIMIT selector
 *            bits 4-5 event loop: MHD_run() vs MHD_get_fdset*() +
 *                     MHD_run_from_select*()
 *            bit  6   hand the daemon one more connection at the very
 *                     end and stop it without running the loop again,
 *                     so that a TLS session is torn down for a
 *                     connection MHD never started
 *            bit  7   unused
 *   byte 6   handler behaviour and introspection
 *              bits 0-1 response constructor
 *              bit  2   MHD_get_connection_info() for the TLS members
 *              bit  3   MHD_get_daemon_info()
 *              bit  4   MHD_set_connection_option()
 *              bit  5   answer 403 instead of 200
 *              bit  6   add a response header
 *              bit  7   MHD_quiesce_daemon() before stopping
 *   byte 7   bits 0-2 handshake round budget (client mode 2)
 *            bit  3   pass the HTTPS options to a daemon started *without*
 *                     MHD_USE_TLS
 *            bit  4   MHD_ALLOW_UPGRADE
 *            bits 5-7 extra pump rounds
 *   byte 8   how many bytes of the segment stream are spliced into the
 *            fuzzer-built PEM blobs (see cred_tbl entries 12 and 13)
 *   byte 9   bits 0-2 the server name the client presents, as an index
 *            into a small built-in table; an op 1 segment overrides it.
 *            In the TLS-PSK scenario that same string is also the PSK
 *            identity the client sends, so an op 1 segment gives byte
 *            level control over the @a username that reaches
 *            psk_gnutls_adapter()
 *            bits 3-5 behaviour of the PSK credentials callback
 *            bit  6   the client offers PSK credentials
 *            bit  7   run the TLS-PSK scenario (see below)
 *   byte 10. a sequence of segments, each introduced by a little-endian
 *            16 bit header  (op << 14) | length
 *              op 0  send the payload
 *              op 1  the payload is the server name the *next* client
 *                    connection presents; nothing is sent
 *              op 2  send the payload and pump the daemon extra rounds
 *              op 3  close the connection, open a fresh one (which means
 *                    a fresh handshake), then send
 *
 * All ten configuration bytes are mandatory; a shorter input is
 * rejected.
 *
 * The segment encoding is byte-for-byte the one fuzz_request uses, and
 * `corpus/` is shared by every harness in this directory (see README
 * section 3), so the seeds below deliberately contain **no op 1
 * segment**: fuzz_request reads op 1 as the declared decoded request
 * body of its own body oracle, and would report a spurious finding when
 * it replays a fuzz_tls seed.  That is what byte 9 is for.  Inputs the
 * generator or a mutator produces may use op 1 freely -- they never end
 * up in `corpus/`.
 *
 * TLS-PSK.  Reaching psk_gnutls_adapter() needs four unrelated things to
 * be true at the same time: the daemon's credential type has to be
 * #GNUTLS_CRD_PSK, both ends need a priority string that actually has a
 * PSK key exchange in it ("NORMAL" does not), the daemon needs
 * #MHD_OPTION_GNUTLS_PSK_CRED_HANDLER, and the client has to offer a PSK
 * identity.  Spread over four independent input bits that combination
 * comes up once in a few hundred thousand inputs, and an 8 hour campaign
 * duly left the function at zero coverage.  Bit 7 of byte 9 therefore
 * switches the whole scenario on at once and the remaining PSK bits only
 * choose between its variants.
 *
 * The variants are the branches of psk_gnutls_adapter() itself: the
 * callback is missing, fails, or answers 0 with a key of a workable
 * size, of 4 KiB, of zero size, of one byte less than the
 * @c MHD_PSK_MIN_SIZE the adapter enforces, and of a size that exceeds
 * @c UINT_MAX.  The two undersized ones and #PSK_OK bracket that
 * minimum from both sides -- #PSK_OK is exactly @c MHD_PSK_MIN_SIZE
 * bytes -- which is what makes an off-by-one in the check visible.
 *
 * One behaviour is deliberately *not* offered: answering 0 without
 * writing the two output parameters.  MHD would then read uninitialised
 * memory, but the application has broken the documented contract, so a
 * report from that would be a harness bug rather than an MHD bug.
 *
 * The certificates and keys are the ones from
 * `src/testcurl/https/tls_test_keys.h` (the CA certificate, the
 * CA-signed server certificate with its key, and the self-signed server
 * certificate with its key), reproduced verbatim so that this harness
 * stays a single translation unit.  The DH parameters are RFC 3526
 * group 14, as emitted by `certtool --get-dh-params --sec-param medium`.
 *
 * The whole harness is guarded by #HTTPS_SUPPORT: `contrib/oss-fuzz/
 * build.sh` configures `--disable-https` (that is what makes the
 * MemorySanitizer build possible), and in such a build this file must
 * still compile to a valid, trivially passing fuzz target.
 */

#define FUZZ_HARNESS_NAME "fuzz_tls"
#include "fuzz_common.h"

/* Pulls in MHD_config.h, which is where HTTPS_SUPPORT is defined.  It
   must come before <microhttpd.h>: it also settles FD_SETSIZE. */
#include "mhd_options.h"

#ifdef HTTPS_SUPPORT

#include <microhttpd.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <arpa/inet.h>

/**
 * LeakSanitizer suppressions, compiled into the harness so that they
 * cannot be forgotten on the command line.
 *
 * There is exactly one entry and it is *not* about MHD.  GnuTLS 3.8.9
 * leaks the partially parsed certificate when a PEM certificate blob
 * ends before its "-----END CERTIFICATE-----" line:
 *
 *     gnutls_certificate_allocate_credentials (&cred);
 *     gnutls_certificate_set_x509_key_mem (cred, &truncated_cert,
 *                                          &good_key,
 *                                          GNUTLS_X509_FMT_PEM);
 *        -> GNUTLS_E_BASE64_UNEXPECTED_HEADER_ERROR (-207)
 *     gnutls_certificate_free_credentials (cred);
 *
 * leaks 9672 bytes in 57 allocations with no libmicrohttpd in the
 * picture at all (reproduced with a 40 line program).  MHD passes the
 * blob straight through and frees the credentials on every path, so
 * there is nothing for MHD to fix and nothing for this harness to find;
 * GnuTLS is fuzzed separately by its own OSS-Fuzz project.
 *
 * The suppression matches only allocations made *inside* GnuTLS's
 * certificate parser.  A credential object leaked by MHD itself is a
 * direct leak from gnutls_certificate_allocate_credentials() and is
 * still reported, as is every other MHD allocation.
 */
const char *
__lsan_default_suppressions (void);

const char *
__lsan_default_suppressions (void)
{
  return "leak:gnutls_x509_crt_init\n";
}


#define MAX_SEGMENTS 48
#define MAX_CONNECTIONS 3
#define RESP_BUF_SIZE 16384
#define GEN_BUF_SIZE 4096
#define MAX_SNI_LEN 255
#define FUZZ_PEM_BODY_MAX 1024

/** Number of client priority strings offered to the input. */
#define CLIENT_PRIO_COUNT 4

/**
 * Upper bound on the number of client/server round trips spent on one
 * handshake.  A TLS 1.3 handshake over a socketpair needs a handful; the
 * cap only has to guarantee termination.
 */
#define HANDSHAKE_ROUNDS 64


/* ------------------------------------------------------------------ */
/* Test credentials                                                    */
/* ------------------------------------------------------------------ */

/*
 * Taken verbatim from src/testcurl/https/tls_test_keys.h (the CA
 * certificate, the CA-signed server certificate and its key, and the
 * self-signed server certificate and its key), so that this harness
 * stays a single translation unit.  dh_params_pem is RFC 3526 group 14,
 * as emitted by "certtool --get-dh-params --sec-param medium".
 */

static const char ca_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIGITCCBAmgAwIBAgIBADANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCUlUx\n"
  "DzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwGTW9zY293MRswGQYDVQQKDBJ0ZXN0\n"
  "LWxpYm1pY3JvaHR0cGQxITAfBgkqhkiG9w0BCQEWEm5vYm9keUBleGFtcGxlLm9y\n"
  "ZzEQMA4GA1UEAwwHdGVzdC1DQTAgFw0yMTA0MDcxNzM2MThaGA8yMTIxMDMxNDE3\n"
  "MzYxOFowgYExCzAJBgNVBAYTAlJVMQ8wDQYDVQQIDAZNb3Njb3cxDzANBgNVBAcM\n"
  "Bk1vc2NvdzEbMBkGA1UECgwSdGVzdC1saWJtaWNyb2h0dHBkMSEwHwYJKoZIhvcN\n"
  "AQkBFhJub2JvZHlAZXhhbXBsZS5vcmcxEDAOBgNVBAMMB3Rlc3QtQ0EwggIiMA0G\n"
  "CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDdaWupA4qZjCBNkJoJOm5xnCaizl36\n"
  "ZLUwp4xBL/YfXPWE3LkmAREiVI/YnAb8l6G7CJnz8dTsOJWkNXG6T1KVP5/2RvBI\n"
  "IaaaufRIAl7hEnj1j9E2hQlV2fxF2ZNhz+nqi0LqKV4LJSpclkXADf2FA9HsVRP/\n"
  "B7zYh+DP0fSU8V6bsu8XCeRGshroAPrc8rH8lFEEXpNLNIqQr8yKx6SmdB6hfja6\n"
  "6SQ0++qBhl0aJtn4LHWZohgjBmkIaGFPYIJLgxQ/xyp2Grz2q7lGKJ+zBkBF8iOP\n"
  "t3x+F1hSCBnr/DGYWmjEm5tYm+7pyuriPddXdCc8+qa2LxMZo3EXxLo5YISpPCyw\n"
  "Z7V3YAOZTr3m1C24LiYvPehCq1CTIkhhmqtlVJXU7ISD48cx9y+5Pi34wtbTI/gN\n"
  "x4voyTLAfyavKMmIpxxIRsWldiF2n06HdvCRVdihDQUad10ygTmWf1J/s2ZETAtH\n"
  "QaSd7MD389t6nQFtTIXigsNKnnDPlrtxt7rOLvLQeR0K04Gzrf/scheOanRAfOXH\n"
  "KNBFU7YkDFG8rqizlC65rx9qeXFYXQcHZTuqxK7tgZnSgJat3E70VbTSCsEEG7eR\n"
  "bNX/fChUKAIIpWaiW6HDlKLl6m2y+BzM91umBsKOqTvntMVFBSF9pVYlXK854aIR\n"
  "q8A2Xujd012seQIDAQABo4GfMIGcMAsGA1UdDwQEAwICpDASBgNVHRMBAf8ECDAG\n"
  "AQH/AgEBMB0GA1UdDgQWBBRYdUPApWoxw4U13Rqsjf9AHdbpLDATBgNVHSUEDDAK\n"
  "BggrBgEFBQcDATAkBglghkgBhvhCAQ0EFxYVVGVzdCBsaWJtaWNyb2h0dHBkIENB\n"
  "MB8GA1UdIwQYMBaAFFh1Q8ClajHDhTXdGqyN/0Ad1uksMA0GCSqGSIb3DQEBCwUA\n"
  "A4ICAQBvrrcTKVeI1EYnXo4BQD4oCvf9z1fYQmL21EbHwgjg1nmaPkvStgWAc5p1\n"
  "kKwySrpEMKXfu68X76RccXZyWWIamEjz2OCWYZgjX6d6FpjhLphL8WxXDy5C9eay\n"
  "ixN7+URz2XQoi22wqR+tCPDhrIzcMPyMkx/6gRgcYeDnaFrkdSeSsKsID4plfcIj\n"
  "ISWJDvv+IAgrtsG1NVHnGwpAv0od3A8/4/fR6PPyewaU3aydvjZ7Au8O9DGDjlU9\n"
  "9HdlOkkY6GVJ1pfGZib7cV7lhy0D2kj1g9xZh97YjpoUfppPl9r+6A8gDm0hXlAD\n"
  "TlzNYlwTb681ZEoSd9PiLEY8HETssHlays2dYXdcNwAEp69iIHz8q1Q98Be9LScl\n"
  "WEzgaOT9U7lpIw/MWbELoMsC+Ecs1cVWBIuiIq8aSG2kRr1x3S8yVXbAohAXif2s\n"
  "E6puieM/VJ25iaNhkbLmDkk58QVVmn9NZNv6ETxuSQMp9e0EwbVlj68vzClQ91Y/\n"
  "nmAiGcLFUEwB9G0szv9+vR+oDW4IkvdFZSUbcICd2cnynnwAD395onqS4hEZO1xM\n"
  "Gy5ZldbTMTjgn7fChNopz15ChPBnwFIjhm+S0CyiLRQAowfknRVq2IBkj7/5kOWg\n"
  "4mcxcq76HoQWK/8X/8RFL1eFVAvY7TNHYJ0RS51DMuwCNQictA==\n"
  "-----END CERTIFICATE-----\n";


static const char srv_signed_key_pem[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCff7amw9zNSE+h\n"
  "rOMhBrzbbsJluUP3gmd8nOKY5MUimoPkxmAXfp2L0il+MPZT/ZEmo11q0k6J2jfG\n"
  "UBQ+oZW9ahNZ9gCDjbYlBblo/mqTai+LdeLO3qk53d0zrZKXvCO6sA3uKpG2WR+g\n"
  "+sNKxfYpIHCpanqBU6O+degIV/+WKy3nQ2Fwp7K5HUNj1u0pg0QQ18yf68LTnKFU\n"
  "HFjZmmaaopWki5wKSBieHivzQy6w+04HSTogHHRK/y/UcoJNSG7xnHmoPPo1vLT8\n"
  "CMRIYnSSgU3wJ43XBJ80WxrC2dcoZjV2XZz+XdQwCD4ZrC1ihykcAmiQA+sauNm7\n"
  "dztOMkGzAgMBAAECggEAIbKDzlvXDG/YkxnJqrKXt+yAmak4mNQuNP+YSCEdHSBz\n"
  "+SOILa6MbnvqVETX5grOXdFp7SWdfjZiTj2g6VKOJkSA7iKxHRoVf2DkOTB3J8np\n"
  "XZd8YaRdMGKVV1O2guQ20Dxd1RGdU18k9YfFNsj4Jtw5sTFTzHr1P0n9ybV9xCXp\n"
  "znSxVfRg8U6TcMHoRDJR9EMKQMO4W3OQEmreEPoGt2/+kMuiHjclxLtbwDxKXTLP\n"
  "pD0gdg3ibvlufk/ccKl/yAglDmd0dfW22oS7NgvRKUve7tzDxY1Q6O5v8BCnLFSW\n"
  "D+z4hS1PzooYRXRkM0xYudvPkryPyu+1kEpw3fNsoQKBgQDRfXJo82XQvlX8WPdZ\n"
  "Ts3PfBKKMVu3Wf8J3SYpuvYT816qR3ot6e4Ivv5ZCQkdDwzzBKe2jAv6JddMJIhx\n"
  "pkGHc0KKOodd9HoBewOd8Td++hapJAGaGblhL5beIidLKjXDjLqtgoHRGlv5Cojo\n"
  "zHa7Viel1eOPPcBumhp83oJ+mQKBgQDC6PmdETZdrW3QPm7ZXxRzF1vvpC55wmPg\n"
  "pRfTRM059jzRzAk0QiBgVp3yk2a6Ob3mB2MLfQVDgzGf37h2oO07s5nspSFZTFnM\n"
  "KgSjFy0xVOAVDLe+0VpbmLp1YUTYvdCNowaoTE7++5rpePUDu3BjAifx07/yaSB+\n"
  "W+YPOfOuKwKBgQCGK6g5G5qcJSuBIaHZ6yTZvIdLRu2M8vDral5k3793a6m3uWvB\n"
  "OFAh/eF9ONJDcD5E7zhTLEMHhXDs7YEN+QODMwjs6yuDu27gv97DK5j1lEsrLUpx\n"
  "XgRjAE3KG2m7NF+WzO1K74khWZaKXHrvTvTEaxudlO3X8h7rN3u7ee9uEQKBgQC2\n"
  "wI1zeTUZhsiFTlTPWfgppchdHPs6zUqq0wFQ5Zzr8Pa72+zxY+NJkU2NqinTCNsG\n"
  "ePykQ/gQgk2gUrt595AYv2De40IuoYk9BlTMuql0LNniwsbykwd/BOgnsSlFdEy8\n"
  "0RQn70zOhgmNSg2qDzDklJvxghLi7zE5aV9//V1/ewKBgFRHHZN1a8q/v8AAOeoB\n"
  "ROuXfgDDpxNNUKbzLL5MO5odgZGi61PBZlxffrSOqyZoJkzawXycNtoBP47tcVzT\n"
  "QPq5ZOB3kjHTcN7dRLmPWjji9h4O3eHCX67XaPVMSWiMuNtOZIg2an06+jxGFhLE\n"
  "qdJNJ1DkyUc9dN2cliX4R+rG\n"
  "-----END PRIVATE KEY-----\n";


static const char srv_signed_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIFSzCCAzOgAwIBAgIBBDANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCUlUx\n"
  "DzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwGTW9zY293MRswGQYDVQQKDBJ0ZXN0\n"
  "LWxpYm1pY3JvaHR0cGQxITAfBgkqhkiG9w0BCQEWEm5vYm9keUBleGFtcGxlLm9y\n"
  "ZzEQMA4GA1UEAwwHdGVzdC1DQTAgFw0yMjA0MjAxODQzMDJaGA8yMTIyMDMyNjE4\n"
  "NDMwMlowZTELMAkGA1UEBhMCUlUxDzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwG\n"
  "TW9zY293MRswGQYDVQQKDBJ0ZXN0LWxpYm1pY3JvaHR0cGQxFzAVBgNVBAMMDnRl\n"
  "c3QtbWhkc2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn3+2\n"
  "psPczUhPoazjIQa8227CZblD94JnfJzimOTFIpqD5MZgF36di9IpfjD2U/2RJqNd\n"
  "atJOido3xlAUPqGVvWoTWfYAg422JQW5aP5qk2ovi3Xizt6pOd3dM62Sl7wjurAN\n"
  "7iqRtlkfoPrDSsX2KSBwqWp6gVOjvnXoCFf/list50NhcKeyuR1DY9btKYNEENfM\n"
  "n+vC05yhVBxY2ZpmmqKVpIucCkgYnh4r80MusPtOB0k6IBx0Sv8v1HKCTUhu8Zx5\n"
  "qDz6Nby0/AjESGJ0koFN8CeN1wSfNFsawtnXKGY1dl2c/l3UMAg+GawtYocpHAJo\n"
  "kAPrGrjZu3c7TjJBswIDAQABo4HmMIHjMAsGA1UdDwQEAwIFoDAMBgNVHRMBAf8E\n"
  "AjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMBMDEGA1UdEQQqMCiCDnRlc3QtbWhk\n"
  "c2VydmVyhwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMB0GA1UdDgQWBBQ57Z06WJae\n"
  "8fJIHId4QGx/HsRgDDAoBglghkgBhvhCAQ0EGxYZVGVzdCBsaWJtaWNyb2h0dHBk\n"
  "IHNlcnZlcjARBglghkgBhvhCAQEEBAMCBkAwHwYDVR0jBBgwFoAUWHVDwKVqMcOF\n"
  "Nd0arI3/QB3W6SwwDQYJKoZIhvcNAQELBQADggIBAI7Lggm/XzpugV93H5+KV48x\n"
  "X+Ct8unNmPCSzCaI5hAHGeBBJpvD0KME5oiJ5p2wfCtK5Dt9zzf0S0xYdRKqU8+N\n"
  "aKIvPoU1hFixXLwTte1qOp6TviGvA9Xn2Fc4n36dLt6e9aiqDnqPbJgBwcVO82ll\n"
  "HJxVr3WbrAcQTB3irFUMqgAke/Cva9Bw79VZgX4ghb5EnejDzuyup4pHGzV10Myv\n"
  "hdg+VWZbAxpCe0S4eKmstZC7mWsFCLeoRTf/9Pk1kQ6+azbTuV/9QOBNfFi8QNyb\n"
  "18jUjmm8sc2HKo8miCGqb2sFqaGD918hfkWmR+fFkzQ3DZQrT+eYbKq2un3k0pMy\n"
  "UySy8SRn1eadfab+GwBVb68I9TrPRMrJsIzysNXMX4iKYl2fFE/RSNnaHtPw0C8y\n"
  "B7memyxPRl+H2xg6UjpoKYh3+8e44/XKm0rNIzXjrwA8f8gnw2TbqmMDkj1YqGnC\n"
  "SCj5A27zUzaf2pT/YsnQXIWOJjVvbEI+YKj34wKWyTrXA093y8YI8T3mal7Kr9YM\n"
  "WiIyPts0/aVeziM0Gunglz+8Rj1VesL52FTurobqusPgM/AME82+qb/qnxuPaCKj\n"
  "OT1qAbIblaRuWqCsid8BzP7ZQiAnAWgMRSUg1gzDwSwRhrYQRRWAyn/Qipzec+27\n"
  "/w0gW9EVWzFhsFeGEssi\n"
  "-----END CERTIFICATE-----\n";


static const char srv_self_signed_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIDJzCCAg+gAwIBAgIUOKf6e6Heee2XA+yF5St3t+fVM40wDQYJKoZIhvcNAQEF\n"
  "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTIyMTAxMDA4MzQ0N1oYDzIxMjIw\n"
  "OTE2MDgzNDQ3WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n"
  "AQUAA4IBDwAwggEKAoIBAQClivgF8Xq0ekQli++0l7Q5JFwJCuLf04Cb1UKIS80U\n"
  "CfphFd1ILJepNw4bWR3OV1sRI1vFiw6LnCz53vOwVNyiZ+sMGi4bDX4AV9Xd+F83\n"
  "xhG8AjOmKTayW0TxSIvt47Qd5S/4fgraxMtvqrRRBen30iKOwX7uNF/4dYb9vdin\n"
  "OldV/e8uzbqSurMGkNDznOeSaNBmdO/7x0VMFZM2hwmHyiiw75/j4BhUlLCcMEvK\n"
  "oN+YHNCNcTt3Qm1vVuiGXmh9QreOV09Gc1SzAltxF2gmI0jzw8r/duz18QXMNsMw\n"
  "El/Ah4+02gR70L7qlgttN1NPU3RJpK/L34J7yg649wHTAgMBAAGjbzBtMB0GA1Ud\n"
  "DgQWBBROVferD+YYcV1YEnFgC0jYm5X9BjAfBgNVHSMEGDAWgBROVferD+YYcV1Y\n"
  "EnFgC0jYm5X9BjAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGCCWxvY2FsaG9z\n"
  "dIcEfwAAATANBgkqhkiG9w0BAQUFAAOCAQEAoRbozsm5xXdNX3VO++s2LMzw5KM9\n"
  "RpIInHNkMJbnyLJFKJ8DF7nTxSGCA38YMkX3tphPNKZXbg+V64Dqr/XpzOVyiinU\n"
  "7hIwyUdSSKKyErZxIWR97lY6Q3SOyPAg8ZElbtvSsSzmd772VE23VTXGDi7AW0PQ\n"
  "hag9N2EEnHURMvID15O+UXyFpDdyUyQIbx3HuswsGDH9xBTm4irLyrZwO0KwKg5a\n"
  "JBeUiPs0SYRRfn9/MoE6VwAnmOCg3LLR6ZPU3hQtTPLHj2Op1g5fey3X3X6lC+JC\n"
  "K6dNZc1zBFPz8KANGUsFYbmoP2bvAAA+6KwCnZZEflUgE7/HFEmQhVOezw==\n"
  "-----END CERTIFICATE-----\n";


static const char srv_self_signed_key_pem[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClivgF8Xq0ekQl\n"
  "i++0l7Q5JFwJCuLf04Cb1UKIS80UCfphFd1ILJepNw4bWR3OV1sRI1vFiw6LnCz5\n"
  "3vOwVNyiZ+sMGi4bDX4AV9Xd+F83xhG8AjOmKTayW0TxSIvt47Qd5S/4fgraxMtv\n"
  "qrRRBen30iKOwX7uNF/4dYb9vdinOldV/e8uzbqSurMGkNDznOeSaNBmdO/7x0VM\n"
  "FZM2hwmHyiiw75/j4BhUlLCcMEvKoN+YHNCNcTt3Qm1vVuiGXmh9QreOV09Gc1Sz\n"
  "AltxF2gmI0jzw8r/duz18QXMNsMwEl/Ah4+02gR70L7qlgttN1NPU3RJpK/L34J7\n"
  "yg649wHTAgMBAAECggEAERbbCtYGakoy7cNX8Ac3Kiz4OVC/4gZWAQBPeX2FwrtS\n"
  "9yHIMbK0x1mxIZ6eBpabBpZlW2vDCSOKuxLKiloAWt2qdJnhR5apesSWhe8leT7/\n"
  "xq5dgZpAlMH6SIRKObknd2yY+qicW0A0licDrVeUcypkueL8xP9wJtiPInOuQXkI\n"
  "QROhB13eStRuRKYwOn5gtwAHJ+J1DFKKiqpBOkrSYf4625StGegJO9+bjK0ei+0W\n"
  "tp6unpiwA/lXTgz6Xim1Z3fzWs4XjFgVKzK5s/6yBJjr8spHX6lv7QsahP4w6HZ/\n"
  "VcRxP6cJNd/otiTEtJXpbxiiyccwXm/AOcOn22P1cQKBgQDAnY/0G/ap/G98pneE\n"
  "suzNXhWOQ8JoL8d66Io8vwTvfiJggfgUcwblI7pPCrSlaZMR7/q6JImE53lZtPk8\n"
  "eI3c9lN0ocr8E7+huDpYdk7cMYj9SuxySsXoMLiMqzHFi+NcIhKMF56kk6a5CFCt\n"
  "yP1Ofy76LVweGE3XvTwpwE7wUQKBgQDcBLyH1cC71s0I0Gz28AyELV9hPhasjAKO\n"
  "12CVbeBVTPd+28uk/3o80wSrTksc6H5ehAA2aTvrb4OhwssWNL+D0fS8YK2cJ3V0\n"
  "FJxGAM266+vC4d/8jRTHJnc+6PP3ix5t6vAt+K2Y0fePtefLqf4ebgXx/ODAj3J2\n"
  "aZKBldjK4wKBgGIRFpTLk/eR/dUyEBHw4x3gdAsdtqJDCUYrlQ4+ly20Q55tLbiD\n"
  "pBQP77CEm9rH+MgeLcKODbIsBB3HRUojet7wTydHpMhY6a1V1ebqPVZgpgWIGwBJ\n"
  "z59bBusf0lRo15Y2Bslq0SurvSvh7um8NjO8D1fytj7gUumvgC0lq0sxAoGBAI1+\n"
  "kkx9IBTtIDER8XGhkTsT/uoHxwcyh5abVmbjIclZ1TUFX2L+Vft17ePJVy8BKfvY\n"
  "wlY7uShBMBNAteDTDXNV/CGFv0DUc4myk4nFjIkwng9XufeuN3WX/Eo+AF/rXSdt\n"
  "VwcJjYLhTWdjoe1tppqlQTeN3HCaEA+s92ZVGvXnAoGAMCXGS6WZl1e5wsHRq0Yy\n"
  "8Ef2Wrk620bBjKHolkTfvgfhlvxeZM1sv1ioZGsOeQ0z7O7wdJhvL0M/WAG+3yQj\n"
  "HSXp81T1vOICPwNYZf8xcvbLKmvj7rHFt6ZAZF2o4EK8ReZTRyA3DUpBCDY+s3FN\n"
  "GmBv0D7N3QP0CT3SzfQrPkc=\n"
  "-----END PRIVATE KEY-----\n";


static const char dh_params_pem[] =
  "-----BEGIN DH PARAMETERS-----\n"
  "MIIBDAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz\n"
  "+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a\n"
  "87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7\n"
  "YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi\n"
  "7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD\n"
  "ssbzSibBsu/6iGtCOGEoXJf//////////wIBAgICAQA=\n"
  "-----END DH PARAMETERS-----\n";

/** A PEM blob whose armour is fine but whose payload is not base64. */
static const char garbage_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "this is not base64 at all, not even close !!!! ????\n"
  "-----END CERTIFICATE-----\n";

static const char garbage_key_pem[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "@@@@ neither is this @@@@\n"
  "-----END PRIVATE KEY-----\n";

/** Correct base64, but the armour never ends. */
static const char truncated_cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIFSzCCAzOgAwIBAgIBBDANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCUlUx\n"
  "DzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwGTW9zY293MRswGQYDVQQKDBJ0ZXN0\n";

static const char truncated_key_pem[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCff7amw9zNSE+h\n";

/** Base64 of a certificate, but with no PEM armour at all. */
static const char no_armour_pem[] =
  "MIIFSzCCAzOgAwIBAgIBBDANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCUlUx\n"
  "DzANBgNVBAgMBk1vc2NvdzEPMA0GA1UEBwwGTW9zY293MRswGQYDVQQKDBJ0ZXN0\n";

static const char garbage_dh_pem[] =
  "-----BEGIN DH PARAMETERS-----\n"
  "not-dh-parameters\n"
  "-----END DH PARAMETERS-----\n";

/**
 * PEM blobs assembled from the fuzzer's own bytes, see cred_tbl entries
 * 12 and 13.  Static so that the pointer handed to MHD stays valid for
 * the whole lifetime of the daemon.
 */
static char fuzz_cert_pem[FUZZ_PEM_BODY_MAX + 128];
static char fuzz_key_pem[FUZZ_PEM_BODY_MAX + 128];


/**
 * A certificate/key pair for #MHD_OPTION_HTTPS_MEM_CERT and
 * #MHD_OPTION_HTTPS_MEM_KEY.  A NULL member means "do not pass the
 * option at all", which is a configuration MHD has to reject cleanly.
 */
struct cred_pair
{
  const char *cert;
  const char *key;
};

static const struct cred_pair cred_tbl[] = {
  { srv_signed_cert_pem, srv_signed_key_pem },        /*  0 valid, CA signed */
  { srv_self_signed_cert_pem, srv_self_signed_key_pem }, /* 1 valid, self signed */
  { srv_signed_cert_pem, srv_self_signed_key_pem },   /*  2 key does not match */
  { srv_self_signed_cert_pem, srv_signed_key_pem },   /*  3 key does not match */
  { srv_signed_cert_pem, NULL },                      /*  4 certificate only */
  { NULL, srv_signed_key_pem },                       /*  5 key only */
  { NULL, NULL },                                     /*  6 neither */
  { "", "" },                                         /*  7 empty strings */
  { truncated_cert_pem, srv_signed_key_pem },         /*  8 truncated armour */
  { srv_signed_cert_pem, truncated_key_pem },         /*  9 truncated armour */
  { garbage_cert_pem, garbage_key_pem },              /* 10 armour, no base64 */
  { no_armour_pem, srv_signed_key_pem },              /* 11 base64, no armour */
  { fuzz_cert_pem, srv_signed_key_pem },              /* 12 PEM from the input */
  { srv_signed_cert_pem, fuzz_key_pem },              /* 13 PEM from the input */
  { fuzz_cert_pem, fuzz_key_pem },                    /* 14 PEM from the input */
  { srv_signed_cert_pem, srv_signed_key_pem }         /* 15 valid (bias) */
};

#define CRED_COUNT (sizeof (cred_tbl) / sizeof (cred_tbl[0]))

/**
 * Priority strings.  The first entries are the ones a real server would
 * use, the rest are what MHD has to reject without falling over.  MHD
 * hands these to gnutls_priority_init() (or appends them to its own
 * base string) and fails daemon startup if GnuTLS does not like them.
 */
static const char *const prio_tbl[] = {
  "NORMAL",
  "NORMAL:-VERS-ALL:+VERS-TLS1.3",
  "NORMAL:-VERS-ALL:+VERS-TLS1.2",
  "SECURE128",
  "PERFORMANCE",
  "@LIBMICROHTTPD",
  "@SYSTEM",
  "NONE",
  "",
  "BOGUS-PRIORITY-STRING",
  "NORMAL:!!!",
  "NORMAL:-VERS-ALL",
  "NORMAL:+ANON-ECDH",
  "NORMAL:%SERVER_PRECEDENCE",
  "SECURE256:-CIPHER-ALL",
  ":::::"
};

#define PRIO_COUNT (sizeof (prio_tbl) / sizeof (prio_tbl[0]))

/** Priority strings offered to the *client* side. */
static const char *const client_prio_tbl[CLIENT_PRIO_COUNT] = {
  "NORMAL",
  "NORMAL:-VERS-ALL:+VERS-TLS1.3",
  "NORMAL:-VERS-ALL:+VERS-TLS1.2",
  "PERFORMANCE"
};

/**
 * Priority strings for the TLS-PSK scenario, used on both ends.
 * "NORMAL" carries no PSK key exchange, so without one of these the
 * ciphersuite is never negotiated, GnuTLS never asks the server for a
 * key, and psk_gnutls_adapter() is never called.  Index is the client
 * priority selector (byte 4, bits 4-5), which the ordinary tables no
 * longer use once the scenario is on.
 *
 * The TLS 1.2 entry has to remove the other key exchanges explicitly.
 * A daemon with #GNUTLS_CRD_PSK has no certificate credentials, so with
 * the certificate key exchanges still in the list the TLS 1.2 handshake
 * dies with "received handshake message out of context" before GnuTLS
 * ever asks for a key.  Under TLS 1.3 the same list is fine, which is
 * what entries 0 and 2 cover.
 */
static const char *const psk_prio_tbl[CLIENT_PRIO_COUNT] = {
  "NORMAL:+ECDHE-PSK:+DHE-PSK:+PSK",
  "NORMAL:-VERS-ALL:+VERS-TLS1.2:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK",
  "NORMAL:-VERS-ALL:+VERS-TLS1.3:+ECDHE-PSK:+DHE-PSK:+PSK",
  "NORMAL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK"
};

/**
 * Credential types.  Only GNUTLS_CRD_CERTIFICATE and GNUTLS_CRD_PSK are
 * accepted by MHD_TLS_init(); everything else must make daemon startup
 * fail rather than reach the MHD_PANIC() in new_connection_prepare_().
 */
static const int cred_type_tbl[] = {
  (int) GNUTLS_CRD_CERTIFICATE,
  (int) GNUTLS_CRD_PSK,
  (int) GNUTLS_CRD_ANON,
  (int) GNUTLS_CRD_SRP,
  (int) GNUTLS_CRD_IA,
  (int) GNUTLS_CRD_CERTIFICATE,
  99,
  -1
};

#define CRED_TYPE_COUNT (sizeof (cred_type_tbl) / sizeof (cred_type_tbl[0]))

/** Index of #GNUTLS_CRD_PSK in #cred_type_tbl. */
#define PSK_CRED_TYPE_IDX 1u

/**
 * The pre-shared key the client uses, and the one #PSK_OK hands back.
 * They match, so that variant completes the handshake and MHD goes on to
 * serve ordinary HTTP over a session with no certificate at all -- which
 * is a different shape again for the connection introspection calls.
 *
 * Its length is exactly the @c MHD_PSK_MIN_SIZE that psk_gnutls_adapter()
 * enforces (16, RFC 4279 section 7.1).  That is not a coincidence and
 * the two have to be kept in step: #PSK_OK and #PSK_ONE_SHORT bracket
 * the check from both sides, and #PSK_ONE_SHORT derives its length from
 * this array.  The minimum is private to daemon.c, so this is a mirror
 * rather than a shared constant; if daemon.c changes, so must this.
 */
static const unsigned char psk_key_bytes[16] = {
  0x9e, 0x1d, 0x4c, 0x7b, 0x30, 0xa5, 0xf2, 0x68,
  0x11, 0xc3, 0x54, 0xd9, 0x87, 0x2a, 0x6f, 0xb0
};

static const size_t mem_limit_tbl[] = {
  0 /* MHD default */, 256, 512, 1024, 1400, 1500, 2048, 4096, 8192, 32768,
  0, 1024, 2048, 4096, 16384, 0
};

#define MEM_LIMIT_COUNT (sizeof (mem_limit_tbl) / sizeof (mem_limit_tbl[0]))

static const char https_key_password[] = "not-the-password";


/* ------------------------------------------------------------------ */
/* Per-iteration configuration                                         */
/* ------------------------------------------------------------------ */

/** Behaviour of the SNI callback, selected by bits 3-5 of byte 3. */
enum sni_behaviour
{
  SNI_ALWAYS_OK = 0,      /**< always answer with the signed pair */
  SNI_FAIL,               /**< always answer -1 */
  SNI_EMPTY,              /**< answer 0 with an empty certificate list */
  SNI_BY_NAME,            /**< look the server name up, -1 if unknown */
  SNI_MISMATCH,           /**< answer with a key that is not the cert's */
  SNI_NO_KEY,             /**< answer 0, certificate but no key */
  SNI_SELF_SIGNED,        /**< always answer with the self-signed pair */
  SNI_BEHAVIOUR_COUNT
};

/**
 * Behaviour of the PSK credentials callback, selected by bits 3-5 of
 * byte 9.  Each entry corresponds to one branch of psk_gnutls_adapter().
 */
enum psk_behaviour
{
  PSK_OK = 0,             /**< the key the client expects; handshake works */
  PSK_FAIL,               /**< the callback answers -1 */
  PSK_EMPTY,              /**< a zero length key: rejected as too short */
  PSK_LONG,               /**< a 4 KiB key */
  PSK_FROM_ID,            /**< key built from the identity the client sent,
                               so its length is attacker-chosen and lands
                               on either side of MHD_PSK_MIN_SIZE */
  PSK_HUGE,               /**< a size above UINT_MAX */
  PSK_NO_HANDLER,         /**< the option is not passed at all */
  /* Appended rather than grouped with PSK_EMPTY on purpose: the seeds
     below encode the behaviour as a literal index, so inserting in the
     middle would silently re-point every one of them. */
  PSK_ONE_SHORT,          /**< MHD_PSK_MIN_SIZE - 1 bytes: the boundary */
  PSK_BEHAVIOUR_COUNT
};

/** Client behaviour, selected by bits 0-1 of byte 4. */
enum client_mode
{
  CLIENT_RAW = 0,         /**< raw bytes straight at the TLS socket */
  CLIENT_TLS,             /**< a real GnuTLS client */
  CLIENT_TLS_ABANDON,     /**< a real client that stops mid-handshake */
  CLIENT_RECORDS          /**< raw bytes shaped like TLS records */
};

struct fuzz_cfg
{
  /* ---- daemon ---- */
  const char *cert;
  const char *key;
  int use_tls;                 /**< set MHD_USE_TLS at all */
  int use_trust;
  int trust_garbage;
  int use_dhparams;
  int dh_garbage;
  int use_sni;
  int use_prio;
  int prio_append;
  unsigned int prio_idx;
  const char *prio_str;        /**< what use_prio actually passes */
  int use_cred_type;
  unsigned int cred_type_idx;
  int no_alpn;
  int key_password;
  int allow_upgrade;
  size_t mem_limit;
  unsigned int loop_mode;

  /* ---- SNI callback ---- */
  enum sni_behaviour sni_mode;

  /* ---- TLS-PSK ---- */
  int psk_scenario;            /**< the whole PSK bundle is on */
  enum psk_behaviour psk_mode;

  /* ---- client ---- */
  enum client_mode mode;
  int client_sni;
  int client_cert;
  int client_psk;              /**< offer PSK credentials */
  unsigned int client_prio_idx;
  int client_bye;
  int client_shut_wr;
  unsigned int hs_budget;      /**< handshake rounds in CLIENT_TLS_ABANDON */
  unsigned int extra_pump;

  /* ---- handler ---- */
  unsigned int resp_kind;
  int conn_info;
  int daemon_info;
  int conn_option;
  int error_reply;
  int resp_header;
  int quiesce;
  int stop_with_queued;        /**< stop with a connection still queued */
};

static struct fuzz_cfg cfg;

/**
 * Server names the client can present.  Which one is used comes from
 * byte 9 of the input; an op 1 segment overrides it.  MHD itself never
 * looks at the name -- GnuTLS parses the extension and the application
 * callback reads it back -- so a fixed table costs no MHD coverage.
 */
static const char *const sni_name_tbl[] = {
  "test-mhdserver",
  "localhost",
  "mhdhost1",
  "nobody.example.org",
  "",
  "example.org",
  "TEST-MHDSERVER",
  "a.very.long.name.that.nobody.has.a.certificate.for.example.org"
};

#define SNI_NAME_COUNT (sizeof (sni_name_tbl) / sizeof (sni_name_tbl[0]))

/** Server name the next client connection presents. */
static char sni_name[MAX_SNI_LEN + 1];
static size_t sni_name_len;

/** Bytes received from the daemon during the current iteration. */
static char resp_buf[RESP_BUF_SIZE];
static size_t resp_len;

/** Statistics, printed at exit with --verbose. */
static unsigned long stat_daemons;
static unsigned long stat_daemons_failed;
static unsigned long stat_connections;
static unsigned long stat_handshakes_ok;
static unsigned long stat_handshakes_failed;
static unsigned long stat_handler_calls;
static unsigned long stat_sni_calls;
static unsigned long stat_psk_calls;
static int stats_registered;


static void
print_stats (void)
{
  if (! fuzz_verbose)
    return;
  fprintf (stderr,
           "%s: daemons=%lu (start failed=%lu) connections=%lu "
           "handshakes ok=%lu failed=%lu handler calls=%lu SNI calls=%lu "
           "PSK calls=%lu\n",
           FUZZ_HARNESS_NAME,
           stat_daemons, stat_daemons_failed, stat_connections,
           stat_handshakes_ok, stat_handshakes_failed, stat_handler_calls,
           stat_sni_calls, stat_psk_calls);
}


/* ------------------------------------------------------------------ */
/* The SNI (certificate retrieve) callback                             */
/* ------------------------------------------------------------------ */

/**
 * Certificates for the SNI callback, parsed once and then kept in these
 * statics for the whole life of the process: they are configuration, not
 * per-iteration state, and re-parsing them on every execution would cost
 * more than everything else the harness does.  They are reachable from
 * globals, so LeakSanitizer does not count them.
 */
struct sni_host
{
  const char *name;
  const char *cert_pem;
  const char *key_pem;
  gnutls_pcert_st pcrt;
  gnutls_privkey_t key;
  int loaded;
};

static struct sni_host sni_hosts[2] = {
  { "test-mhdserver", NULL, NULL, { 0, { NULL, 0 }, 0 }, NULL, 0 },
  { "localhost", NULL, NULL, { 0, { NULL, 0 }, 0 }, NULL, 0 }
};

static int sni_hosts_ready;


/**
 * @return 0 if the certificates are usable
 */
static int
sni_hosts_init (void)
{
  unsigned int i;

  if (0 != sni_hosts_ready)
    return (1 == sni_hosts_ready) ? 0 : -1;
  sni_hosts[0].cert_pem = srv_signed_cert_pem;
  sni_hosts[0].key_pem = srv_signed_key_pem;
  sni_hosts[1].cert_pem = srv_self_signed_cert_pem;
  sni_hosts[1].key_pem = srv_self_signed_key_pem;
  sni_hosts_ready = 1;
  for (i = 0; i < sizeof (sni_hosts) / sizeof (sni_hosts[0]); i++)
  {
    struct sni_host *h = &sni_hosts[i];
    gnutls_datum_t d;

    d.data = (unsigned char *) (intptr_t) h->cert_pem;
    d.size = (unsigned int) strlen (h->cert_pem);
    if (GNUTLS_E_SUCCESS !=
        gnutls_pcert_import_x509_raw (&h->pcrt, &d, GNUTLS_X509_FMT_PEM, 0))
    {
      sni_hosts_ready = -1;
      continue;
    }
    if (GNUTLS_E_SUCCESS != gnutls_privkey_init (&h->key))
    {
      gnutls_pcert_deinit (&h->pcrt);
      sni_hosts_ready = -1;
      continue;
    }
    d.data = (unsigned char *) (intptr_t) h->key_pem;
    d.size = (unsigned int) strlen (h->key_pem);
    if (GNUTLS_E_SUCCESS !=
        gnutls_privkey_import_x509_raw (h->key, &d, GNUTLS_X509_FMT_PEM,
                                        NULL, 0))
    {
      gnutls_privkey_deinit (h->key);
      h->key = NULL;
      gnutls_pcert_deinit (&h->pcrt);
      sni_hosts_ready = -1;
      continue;
    }
    h->loaded = 1;
  }
  return (1 == sni_hosts_ready) ? 0 : -1;
}


/**
 * #MHD_OPTION_HTTPS_CERT_CALLBACK.  Deliberately badly behaved for most
 * of the settings of @e cfg.sni_mode: an application callback that fails
 * or answers with nothing is exactly the case MHD has to survive.
 */
static int
sni_callback (gnutls_session_t session,
              const gnutls_datum_t *req_ca_dn,
              int nreqs,
              const gnutls_pk_algorithm_t *pk_algos,
              int pk_algos_length,
              gnutls_pcert_st **pcert,
              unsigned int *pcert_length,
              gnutls_privkey_t *pkey)
{
  char name[MAX_SNI_LEN + 1];
  size_t name_len = sizeof (name);
  unsigned int type;
  unsigned int i;

  (void) req_ca_dn;
  (void) nreqs;
  (void) pk_algos;
  (void) pk_algos_length;
  stat_sni_calls++;
  if (! sni_hosts[0].loaded)
    return -1;
  switch (cfg.sni_mode)
  {
  case SNI_FAIL:
    return -1;
  case SNI_EMPTY:
    *pcert = NULL;
    *pcert_length = 0;
    *pkey = NULL;
    return 0;
  case SNI_NO_KEY:
    *pcert = &sni_hosts[0].pcrt;
    *pcert_length = 1;
    *pkey = NULL;
    return 0;
  case SNI_MISMATCH:
    if (! sni_hosts[1].loaded)
      return -1;
    *pcert = &sni_hosts[0].pcrt;
    *pcert_length = 1;
    *pkey = sni_hosts[1].key;
    return 0;
  case SNI_SELF_SIGNED:
    if (! sni_hosts[1].loaded)
      return -1;
    *pcert = &sni_hosts[1].pcrt;
    *pcert_length = 1;
    *pkey = sni_hosts[1].key;
    return 0;
  case SNI_BY_NAME:
    if (GNUTLS_E_SUCCESS !=
        gnutls_server_name_get (session, name, &name_len, &type, 0))
      return -1;
    for (i = 0; i < sizeof (sni_hosts) / sizeof (sni_hosts[0]); i++)
      if ( (sni_hosts[i].loaded) &&
           (0 == strncmp (name, sni_hosts[i].name, name_len)) )
      {
        *pcert = &sni_hosts[i].pcrt;
        *pcert_length = 1;
        *pkey = sni_hosts[i].key;
        return 0;
      }
    return -1;
  case SNI_ALWAYS_OK:
  case SNI_BEHAVIOUR_COUNT:
  default:
    break;
  }
  *pcert = &sni_hosts[0].pcrt;
  *pcert_length = 1;
  *pkey = sni_hosts[0].key;
  return 0;
}


/* ------------------------------------------------------------------ */
/* The application                                                     */
/* ------------------------------------------------------------------ */

static const char resp_body[] = "hello world over TLS";


static enum MHD_Result
ahc (void *cls,
     struct MHD_Connection *connection,
     const char *url,
     const char *method,
     const char *version,
     const char *upload_data,
     size_t *upload_data_size,
     void **req_cls)
{
  static int marker;
  struct MHD_Response *r;
  enum MHD_Result ret;

  (void) cls;
  (void) url;
  (void) method;
  (void) version;
  (void) upload_data;
  stat_handler_calls++;
  if (NULL == *req_cls)
  {
    /* first call: MHD only wants to know that we are interested */
    *req_cls = &marker;
    return MHD_YES;
  }
  if (0 != *upload_data_size)
  {
    /* discard the request body */
    *upload_data_size = 0;
    return MHD_YES;
  }
  if (cfg.conn_info)
  {
    /* The TLS-specific members of MHD_ConnectionInfo; all three answer
       NULL on a connection without a session, which is a state this
       harness can produce. */
    (void) MHD_get_connection_info (connection,
                                    MHD_CONNECTION_INFO_CIPHER_ALGO);
    (void) MHD_get_connection_info (connection,
                                    MHD_CONNECTION_INFO_PROTOCOL);
    (void) MHD_get_connection_info (connection,
                                    MHD_CONNECTION_INFO_GNUTLS_SESSION);
    (void) MHD_get_connection_info (connection,
                                    MHD_CONNECTION_INFO_GNUTLS_CLIENT_CERT);
    (void) MHD_get_connection_info (connection,
                                    MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    (void) MHD_get_connection_info (connection,
                                    MHD_CONNECTION_INFO_CONNECTION_FD);
  }
  if (cfg.conn_option)
    (void) MHD_set_connection_option (connection,
                                      MHD_CONNECTION_OPTION_TIMEOUT,
                                      (unsigned int) 0);
  switch (cfg.resp_kind)
  {
  case 1:
    r = MHD_create_response_from_buffer_copy (sizeof (resp_body) - 1,
                                              resp_body);
    break;
  case 2:
    r = MHD_create_response_empty (MHD_RF_NONE);
    break;
  case 3:
    r = MHD_create_response_from_buffer_static (0, "");
    break;
  case 0:
  default:
    r = MHD_create_response_from_buffer_static (sizeof (resp_body) - 1,
                                                resp_body);
    break;
  }
  if (NULL == r)
    return MHD_NO;
  if (cfg.resp_header)
    (void) MHD_add_response_header (r, "X-Fuzz", "tls");
  ret = MHD_queue_response (connection,
                            cfg.error_reply
                            ? MHD_HTTP_FORBIDDEN
                            : MHD_HTTP_OK,
                            r);
  MHD_destroy_response (r);
  return ret;
}


static void
panic_cb (void *cls,
          const char *file,
          unsigned int line,
          const char *reason)
{
  char msg[512];

  (void) cls;
  (void) snprintf (msg, sizeof (msg),
                   "MHD_PANIC() reached at %s:%u: %s",
                   (NULL != file) ? file : "?",
                   line,
                   (NULL != reason) ? reason : "?");
  fuzz_report_finding (msg);
}


/* ------------------------------------------------------------------ */
/* Driving the daemon                                                  */
/* ------------------------------------------------------------------ */

/**
 * Advance the daemon by one cycle, through the event-loop API selected
 * by byte 5 of the input.  The select() timeout is always zero: the
 * harness is single threaded, whatever the daemon is waiting for has
 * already been written into the socketpair, and blocking would only burn
 * wall clock.
 */
static void
run_once (struct MHD_Daemon *d)
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  MHD_socket max_fd = MHD_INVALID_SOCKET;
  struct timeval tv;

  if (0 == cfg.loop_mode)
  {
    (void) MHD_run (d);
    return;
  }
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  if (1 == cfg.loop_mode)
  {
    /* Parenthesised so that the real v1 function is called: microhttpd.h
       also defines MHD_get_fdset as a macro forwarding to
       MHD_get_fdset2.  Same trick for MHD_run_from_select below. */
    if (MHD_YES != (MHD_get_fdset) (d, &rs, &ws, &es, &max_fd))
    {
      (void) MHD_run (d);
      return;
    }
  }
  else
  {
    if (MHD_YES != MHD_get_fdset2 (d, &rs, &ws, &es, &max_fd,
                                   (unsigned int) FD_SETSIZE))
    {
      (void) MHD_run (d);
      return;
    }
  }
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  if (MHD_INVALID_SOCKET != max_fd)
    (void) select ((int) max_fd + 1, &rs, &ws, &es, &tv);
  if (1 == cfg.loop_mode)
    (void) (MHD_run_from_select) (d, &rs, &ws, &es);
  else
    (void) MHD_run_from_select2 (d, &rs, &ws, &es, (unsigned int) FD_SETSIZE);
}


/* ------------------------------------------------------------------ */
/* The PSK credentials callback                                        */
/* ------------------------------------------------------------------ */

#if GNUTLS_VERSION_MAJOR >= 3

/**
 * #MHD_OPTION_GNUTLS_PSK_CRED_HANDLER.  GnuTLS calls
 * psk_gnutls_adapter() with the identity the client sent, and that
 * function calls this; whatever comes back is copied into a
 * gnutls_malloc()ed buffer and handed to GnuTLS, with @a psk freed by
 * MHD on every path.  The buffer therefore has to come from plain
 * malloc() -- see the doxygen on #MHD_PskServerCredentialsCallback.
 *
 * @param cls unused
 * @param connection the connection GnuTLS is handshaking
 * @param username the identity claimed by the client
 * @param[out] psk the key
 * @param[out] psk_size its length
 * @return 0 on success, -1 on error
 */
static int
psk_cred_cb (void *cls,
             const struct MHD_Connection *connection,
             const char *username,
             void **psk,
             size_t *psk_size)
{
  unsigned char *buf;
  size_t len;

  (void) cls;
  (void) connection;
  stat_psk_calls++;

  switch (cfg.psk_mode)
  {
  case PSK_FAIL:
    return -1;
  case PSK_EMPTY:
    len = 0;
    break;
  case PSK_ONE_SHORT:
    /* One byte below the minimum the adapter enforces.  Deliberately
       written in terms of sizeof (psk_key_bytes), which is exactly that
       minimum, so this stays on the boundary if the minimum changes. */
    len = sizeof (psk_key_bytes) - 1;
    break;
  case PSK_LONG:
    len = 4096;
    break;
  case PSK_FROM_ID:
    len = (NULL != username) ? strlen (username) : 0;
    if (len > 1024)
      len = 1024;
    break;
  case PSK_HUGE:
#if SIZE_MAX > UINT_MAX
    /* The size MHD is told about, not the size allocated: the point is
       the "PSK too long" branch, which rejects before reading @a psk.
       MHD still free()s the pointer, so it has to be a real one. */
    buf = (unsigned char *) malloc (1);
    if (NULL == buf)
      return -1;
    buf[0] = 0;
    *psk = buf;
    *psk_size = (size_t) UINT_MAX + 1u;
    return 0;
#else
    len = sizeof (psk_key_bytes);
    break;
#endif
  case PSK_OK:
  case PSK_NO_HANDLER:  /* not reached: the option is not passed at all */
  case PSK_BEHAVIOUR_COUNT:
  default:
    len = sizeof (psk_key_bytes);
    break;
  }

  /* malloc(0) may answer NULL, which would be indistinguishable from
     failure here; always ask for at least one byte and report the length
     separately. */
  buf = (unsigned char *) malloc (0 != len ? len : 1);
  if (NULL == buf)
    return -1;
  if (0 != len)
  {
    size_t i;

    for (i = 0; i < len; i++)
      buf[i] = psk_key_bytes[i % sizeof (psk_key_bytes)];
  }
  else
    buf[0] = 0;
  *psk = buf;
  *psk_size = len;
  return 0;
}


#endif /* GNUTLS_VERSION_MAJOR >= 3 */


/* ------------------------------------------------------------------ */
/* The in-process TLS client                                           */
/* ------------------------------------------------------------------ */

struct tls_client
{
  gnutls_session_t sess;                    /**< NULL in the raw modes */
  gnutls_certificate_credentials_t cred;
  gnutls_psk_client_credentials_t psk;      /**< only in the PSK scenario */
  int fd;                                   /**< our end of the socketpair */
  int hs_done;
  int dead;
};


static void
pump (struct MHD_Daemon *d,
      unsigned int rounds)
{
  unsigned int i;

  for (i = 0; i < rounds; i++)
    run_once (d);
}


/**
 * Read whatever the daemon has produced so far.  In the raw modes this
 * is a plain recv(); with a real client it goes through GnuTLS, which is
 * what actually drives MHD's send path and its TLS shutdown handling.
 */
static void
tc_drain (struct tls_client *tc)
{
  unsigned int i;
  char tmp[4096];

  if (0 > tc->fd)
    return;
  if (NULL == tc->sess)
  {
    for (;;)
    {
      ssize_t n = recv (tc->fd, tmp, sizeof (tmp), MSG_DONTWAIT);

      if (0 >= n)
        break;
      if (resp_len + (size_t) n < RESP_BUF_SIZE)
      {
        memcpy (resp_buf + resp_len, tmp, (size_t) n);
        resp_len += (size_t) n;
      }
    }
    return;
  }
  if (tc->dead || (! tc->hs_done))
    return;
  for (i = 0; i < 8; i++)
  {
    ssize_t n = gnutls_record_recv (tc->sess, tmp, sizeof (tmp));

    if (0 < n)
    {
      if (resp_len + (size_t) n < RESP_BUF_SIZE)
      {
        memcpy (resp_buf + resp_len, tmp, (size_t) n);
        resp_len += (size_t) n;
      }
      continue;
    }
    if (0 == n)
      break;                    /* peer closed the TLS connection */
    if ( (GNUTLS_E_AGAIN == n) ||
         (GNUTLS_E_INTERRUPTED == n) )
      break;
    if (0 != gnutls_error_is_fatal ((int) n))
      tc->dead = 1;
    break;
  }
}


static void
pump_and_drain (struct MHD_Daemon *d,
                struct tls_client *tc,
                unsigned int rounds)
{
  unsigned int i;

  for (i = 0; i < rounds; i++)
  {
    run_once (d);
    tc_drain (tc);
  }
}


/**
 * Let the client and the daemon take turns at the handshake until it
 * completes, fails, or @a rounds is exhausted.  Exhausting @a rounds on
 * purpose (client mode 2) is what leaves MHD's connection parked in
 * #MHD_TLS_CONN_HANDSHAKING.
 */
static void
tc_handshake (struct MHD_Daemon *d,
              struct tls_client *tc,
              unsigned int rounds)
{
  unsigned int i;

  if ( (NULL == tc->sess) ||
       (0 != tc->dead) ||
       (0 != tc->hs_done) )
    return;
  for (i = 0; i < rounds; i++)
  {
    int ret = gnutls_handshake (tc->sess);

    if (GNUTLS_E_SUCCESS == ret)
    {
      tc->hs_done = 1;
      stat_handshakes_ok++;
      return;
    }
    if (0 != gnutls_error_is_fatal (ret))
    {
      tc->dead = 1;
      stat_handshakes_failed++;
      return;
    }
    /* GNUTLS_E_AGAIN / GNUTLS_E_INTERRUPTED / a warning alert: give the
       daemon a chance to answer. */
    run_once (d);
  }
}


/**
 * Open a fresh connection: a socketpair, one end handed to MHD with
 * MHD_add_connection(), the other end ours.  With a real client the
 * GnuTLS session is set up here too, but the handshake itself is driven
 * by tc_handshake().
 *
 * @return 0 on success
 */
static int
tc_open (struct MHD_Daemon *d,
         struct tls_client *tc)
{
  int sv[2];
  struct sockaddr_in sa;
  int fl;
#if GNUTLS_VERSION_NUMBER >= 0x030500
  gnutls_init_flags_t flags;
#else
  unsigned int flags;
#endif

  memset (tc, 0, sizeof (*tc));
  tc->fd = -1;
  if (0 != socketpair (AF_UNIX, SOCK_STREAM, 0, sv))
    return -1;
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (44444);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (MHD_YES != MHD_add_connection (d,
                                     (MHD_socket) sv[1],
                                     (const struct sockaddr *) &sa,
                                     (socklen_t) sizeof (sa)))
  {
    /* MHD has already closed sv[1] in that case */
    (void) close (sv[0]);
    return -1;
  }
  tc->fd = sv[0];
  stat_connections++;
  /* Our end must never block: the daemon is pumped from this very
     thread, so a blocking write would deadlock the process. */
  fl = fcntl (tc->fd, F_GETFL, 0);
  if (0 <= fl)
    (void) fcntl (tc->fd, F_SETFL, fl | O_NONBLOCK);
  if ( (CLIENT_TLS != cfg.mode) &&
       (CLIENT_TLS_ABANDON != cfg.mode) )
    return 0;

  if (GNUTLS_E_SUCCESS !=
      gnutls_certificate_allocate_credentials (&tc->cred))
  {
    tc->cred = NULL;
    tc->dead = 1;
    return 0;
  }
  if (cfg.client_cert)
  {
    gnutls_datum_t c;
    gnutls_datum_t k;

    c.data = (unsigned char *) (intptr_t) srv_self_signed_cert_pem;
    c.size = (unsigned int) strlen (srv_self_signed_cert_pem);
    k.data = (unsigned char *) (intptr_t) srv_self_signed_key_pem;
    k.size = (unsigned int) strlen (srv_self_signed_key_pem);
    (void) gnutls_certificate_set_x509_key_mem (tc->cred, &c, &k,
                                                GNUTLS_X509_FMT_PEM);
  }
  flags = GNUTLS_CLIENT;
#if GNUTLS_VERSION_MAJOR >= 3
  flags |= GNUTLS_NONBLOCK;
#endif
#if GNUTLS_VERSION_NUMBER >= 0x030402
  flags |= GNUTLS_NO_SIGNAL;
#endif
  if (GNUTLS_E_SUCCESS != gnutls_init (&tc->sess, flags))
  {
    tc->sess = NULL;
    tc->dead = 1;
    return 0;
  }
  if (GNUTLS_E_SUCCESS !=
      gnutls_priority_set_direct (tc->sess,
                                  cfg.psk_scenario
                                  ? psk_prio_tbl[cfg.client_prio_idx]
                                  : client_prio_tbl[cfg.client_prio_idx],
                                  NULL))
    (void) gnutls_priority_set_direct (tc->sess, "NORMAL", NULL);
  if (GNUTLS_E_SUCCESS !=
      gnutls_credentials_set (tc->sess, GNUTLS_CRD_CERTIFICATE, tc->cred))
    tc->dead = 1;
  if (cfg.client_psk)
  {
    /* The identity is the same string byte 9 (or an op 1 segment) picked
       for SNI; it is what arrives as @a username in psk_gnutls_adapter().
       A client that offers no PSK credentials at all against a PSK-only
       server is the other half of this: the handshake then fails without
       the adapter ever being asked. */
    gnutls_datum_t k;

    k.data = (unsigned char *) (intptr_t) psk_key_bytes;
    k.size = (unsigned int) sizeof (psk_key_bytes);
    if (GNUTLS_E_SUCCESS !=
        gnutls_psk_allocate_client_credentials (&tc->psk))
      tc->psk = NULL;
    else
    {
      if (GNUTLS_E_SUCCESS !=
          gnutls_psk_set_client_credentials (tc->psk,
                                             sni_name,
                                             &k,
                                             GNUTLS_PSK_KEY_RAW))
        tc->dead = 1;
      else if (GNUTLS_E_SUCCESS !=
               gnutls_credentials_set (tc->sess, GNUTLS_CRD_PSK, tc->psk))
        tc->dead = 1;
    }
  }
  if ( (cfg.client_sni) &&
       (0 != sni_name_len) )
    (void) gnutls_server_name_set (tc->sess,
                                   GNUTLS_NAME_DNS,
                                   sni_name,
                                   sni_name_len);
  gnutls_transport_set_int (tc->sess, tc->fd);
  /* GNUTLS_INDEFINITE_TIMEOUT: the default handshake timeout is a wall
     clock deadline, and this harness must not depend on the clock. */
  gnutls_handshake_set_timeout (tc->sess, 0);
  return 0;
}


static void
tc_send (struct MHD_Daemon *d,
         struct tls_client *tc,
         const uint8_t *buf,
         size_t len)
{
  size_t off = 0;
  unsigned int stall = 0;

  if ( (0 > tc->fd) ||
       (0 == len) )
    return;
  if (NULL == tc->sess)
  {
    while ( (off < len) &&
            (stall < 64) )
    {
      ssize_t s = send (tc->fd, buf + off, len - off, MSG_DONTWAIT);

      if (0 < s)
      {
        off += (size_t) s;
        stall = 0;
        continue;
      }
      stall++;
      pump_and_drain (d, tc, 2);
      if ( (0 > s) &&
           (EAGAIN != errno) &&
           (EWOULDBLOCK != errno) &&
           (EINTR != errno) )
        break;
    }
    return;
  }
  if ( (0 != tc->dead) ||
       (0 == tc->hs_done) )
    return;
  while ( (off < len) &&
          (stall < 64) )
  {
    /* On GNUTLS_E_AGAIN the call has to be repeated with exactly the
       same arguments, which is why @a off is only advanced on success. */
    ssize_t s = gnutls_record_send (tc->sess, buf + off, len - off);

    if (0 < s)
    {
      off += (size_t) s;
      stall = 0;
      continue;
    }
    if ( (GNUTLS_E_AGAIN == s) ||
         (GNUTLS_E_INTERRUPTED == s) )
    {
      stall++;
      pump_and_drain (d, tc, 2);
      continue;
    }
    if (0 != gnutls_error_is_fatal ((int) s))
      tc->dead = 1;
    break;
  }
}


/**
 * Tear the client end down.  Every GnuTLS object is released on every
 * path, including the ones where the session never got off the ground.
 */
static void
tc_close (struct MHD_Daemon *d,
          struct tls_client *tc)
{
  if (NULL != tc->sess)
  {
    if ( (cfg.client_bye) &&
         (0 == tc->dead) &&
         (0 != tc->hs_done) )
    {
      unsigned int i;

      for (i = 0; i < 8; i++)
      {
        int ret = gnutls_bye (tc->sess, GNUTLS_SHUT_WR);

        if ( (GNUTLS_E_AGAIN != ret) &&
             (GNUTLS_E_INTERRUPTED != ret) )
          break;
        run_once (d);
      }
    }
    gnutls_deinit (tc->sess);
    tc->sess = NULL;
  }
  if (NULL != tc->cred)
  {
    gnutls_certificate_free_credentials (tc->cred);
    tc->cred = NULL;
  }
  if (NULL != tc->psk)
  {
    gnutls_psk_free_client_credentials (tc->psk);
    tc->psk = NULL;
  }
  if (0 <= tc->fd)
  {
    if (cfg.client_shut_wr)
      (void) shutdown (tc->fd, SHUT_WR);
    pump (d, 2);
    (void) close (tc->fd);
    tc->fd = -1;
  }
  tc->hs_done = 0;
  tc->dead = 1;
  pump (d, 4);
}


/**
 * Hand the daemon one more connection and do not run the loop again.
 *
 * See the comment at the call site: this is what leaves a fully prepared
 * connection -- GnuTLS session and all -- on the daemon's
 * new_connections list when MHD_stop_daemon() runs.
 *
 * @param d the daemon, about to be stopped
 * @return our end of the socket pair, or -1 if nothing was queued
 */
static int
queue_unprocessed_conn (struct MHD_Daemon *d)
{
  int sv[2];
  struct sockaddr_in sa;

  if (0 != socketpair (AF_UNIX, SOCK_STREAM, 0, sv))
    return -1;
  memset (&sa, 0, sizeof (sa));
  sa.sin_family = AF_INET;
  sa.sin_port = htons (44444);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (MHD_YES != MHD_add_connection (d,
                                     (MHD_socket) sv[1],
                                     (const struct sockaddr *) &sa,
                                     (socklen_t) sizeof (sa)))
  {
    /* MHD has closed sv[1] already. */
    (void) close (sv[0]);
    return -1;
  }
  return sv[0];
}


/**
 * Bring a fresh connection up to the point where payload can be sent.
 */
static void
tc_start (struct MHD_Daemon *d,
          struct tls_client *tc)
{
  if (0 != tc_open (d, tc))
  {
    tc->fd = -1;
    return;
  }
  if (CLIENT_TLS == cfg.mode)
    tc_handshake (d, tc, HANDSHAKE_ROUNDS);
  else if (CLIENT_TLS_ABANDON == cfg.mode)
    tc_handshake (d, tc, cfg.hs_budget);
  else
    pump (d, 1);
}


/* ------------------------------------------------------------------ */
/* PEM blobs assembled from the input                                  */
/* ------------------------------------------------------------------ */

/**
 * Build @a out as "-----BEGIN @a label-----\n<body>\n-----END @a
 * label-----\n", with @a body_len bytes of @a body as the payload.  The
 * result is always NUL terminated, because MHD calls strlen() on it.
 */
static void
build_fuzz_pem (char *out,
                size_t out_size,
                const char *label,
                const uint8_t *body,
                size_t body_len)
{
  size_t o = 0;
  size_t i;
  int n;

  n = snprintf (out, out_size, "-----BEGIN %s-----\n", label);
  if ( (0 > n) ||
       ((size_t) n >= out_size) )
  {
    out[0] = '\0';
    return;
  }
  o = (size_t) n;
  if (body_len > FUZZ_PEM_BODY_MAX)
    body_len = FUZZ_PEM_BODY_MAX;
  for (i = 0; (i < body_len) && (o + 32 < out_size); i++)
  {
    /* Keep the blob a C string; a NUL inside would simply truncate it
       for MHD's strlen(), which is a less interesting shape. */
    out[o++] = (char) ((0 == body[i]) ? 'A' : body[i]);
  }
  n = snprintf (out + o, out_size - o, "\n-----END %s-----\n", label);
  if (0 > n)
    out[o] = '\0';
}


/* ------------------------------------------------------------------ */
/* The fuzz target                                                     */
/* ------------------------------------------------------------------ */

int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  struct MHD_Daemon *d;
  struct MHD_OptionItem opts[12];
  unsigned int nopt = 0;
  unsigned int flags;
  struct tls_client tc;
  size_t pos;
  unsigned int nseg = 0;
  unsigned int nconn = 1;
  int queued_fd = -1;          /**< see queue_unprocessed_conn() */

  /* Must happen before the first write() into the socketpair; see
     fuzz_ignore_sigpipe() in fuzz_common.h for why the process dies
     without it.  Idempotent. */
  fuzz_ignore_sigpipe ();

  /* The ten configuration bytes are mandatory. */
  if (size < 10)
    return 0;

  resp_len = 0;
  memset (&cfg, 0, sizeof (cfg));

  {
    const char *nm = sni_name_tbl[(data[9] & 0x07) % SNI_NAME_COUNT];

    sni_name_len = strlen (nm);
    memcpy (sni_name, nm, sni_name_len + 1);
  }

  cfg.cert = cred_tbl[data[0] % CRED_COUNT].cert;
  cfg.key = cred_tbl[data[0] % CRED_COUNT].key;

  cfg.use_trust = (0 != (data[1] & 0x01));
  cfg.use_dhparams = (0 != (data[1] & 0x02));
  cfg.use_sni = (0 != (data[1] & 0x04));
  cfg.use_prio = (0 != (data[1] & 0x08));
  cfg.use_cred_type = (0 != (data[1] & 0x10));
  cfg.no_alpn = (0 != (data[1] & 0x20));
  cfg.key_password = (0 != (data[1] & 0x40));
  cfg.prio_append = (0 != (data[1] & 0x80));

  cfg.prio_idx = (unsigned int) (data[2] % PRIO_COUNT);

  cfg.cred_type_idx = (unsigned int) (data[3] & 0x07) % CRED_TYPE_COUNT;
  cfg.sni_mode =
    (enum sni_behaviour) (((unsigned int) (data[3] >> 3) & 0x07)
                          % (unsigned int) SNI_BEHAVIOUR_COUNT);
  cfg.trust_garbage = (0 != (data[3] & 0x40));
  cfg.dh_garbage = (0 != (data[3] & 0x80));

  cfg.prio_str = prio_tbl[cfg.prio_idx];

  cfg.mode = (enum client_mode) (data[4] & 0x03);
  cfg.client_sni = (0 != (data[4] & 0x04));
  cfg.client_cert = (0 != (data[4] & 0x08));
  cfg.client_prio_idx = (unsigned int) ((data[4] >> 4) & 0x03);
  cfg.client_bye = (0 != (data[4] & 0x40));
  cfg.client_shut_wr = (0 != (data[4] & 0x80));

  cfg.mem_limit = mem_limit_tbl[(data[5] & 0x0F) % MEM_LIMIT_COUNT];
  cfg.loop_mode = (unsigned int) ((data[5] >> 4) & 0x03);
  cfg.stop_with_queued = (0 != (data[5] & 0x40));

  cfg.resp_kind = (unsigned int) (data[6] & 0x03);
  cfg.conn_info = (0 != (data[6] & 0x04));
  cfg.daemon_info = (0 != (data[6] & 0x08));
  cfg.conn_option = (0 != (data[6] & 0x10));
  cfg.error_reply = (0 != (data[6] & 0x20));
  cfg.resp_header = (0 != (data[6] & 0x40));
  cfg.quiesce = (0 != (data[6] & 0x80));

  cfg.hs_budget = 1u + (unsigned int) (data[7] & 0x07);
  cfg.use_tls = (0 == (data[7] & 0x08));
  cfg.allow_upgrade =
    (0 != (data[7] & 0x10)) &&
    (MHD_YES == MHD_is_feature_supported (MHD_FEATURE_UPGRADE));
  cfg.extra_pump = (unsigned int) ((data[7] >> 5) & 0x07);

  cfg.psk_mode =
    (enum psk_behaviour) (((unsigned int) (data[9] >> 3) & 0x07)
                          % (unsigned int) PSK_BEHAVIOUR_COUNT);
  cfg.client_psk = (0 != (data[9] & 0x40));
#if GNUTLS_VERSION_MAJOR >= 3
  cfg.psk_scenario = (0 != (data[9] & 0x80));
#else
  /* MHD refuses MHD_OPTION_GNUTLS_PSK_CRED_HANDLER outright when it was
     built against GnuTLS 2, so there is nothing to reach there. */
  cfg.psk_scenario = 0;
#endif

  /* The PSK bundle.  Four things have to line up before GnuTLS asks the
     server for a key at all; see the TLS-PSK note at the top of this
     file for why they are not four independent input bits. */
  if (cfg.psk_scenario)
  {
    cfg.use_tls = 1;
    cfg.use_cred_type = 1;
    cfg.cred_type_idx = PSK_CRED_TYPE_IDX;
    cfg.use_prio = 1;
    cfg.prio_append = 0;
    cfg.prio_str = psk_prio_tbl[cfg.client_prio_idx];
    /* Raw bytes never negotiate anything; the abandoning client is kept
       because stopping half way through a PSK handshake is its own
       shape. */
    if ( (CLIENT_TLS != cfg.mode) &&
         (CLIENT_TLS_ABANDON != cfg.mode) )
      cfg.mode = CLIENT_TLS;
  }
  else
    cfg.client_psk = 0;

  /* A real handshake is pointless without a working credential setup on
     our own side; fall back to the raw modes if the SNI certificates
     could not be parsed. */
  if ( (cfg.use_sni) &&
       (0 != sni_hosts_init ()) )
    cfg.use_sni = 0;

  /* The PEM blobs built from the input.  They are only referenced by
     cred_tbl entries 12-14, but filling them unconditionally keeps this
     out of the option assembly below. */
  {
    size_t body = (size_t) data[8] * 4u;

    if (body > size - 10)
      body = size - 10;
    build_fuzz_pem (fuzz_cert_pem, sizeof (fuzz_cert_pem),
                    "CERTIFICATE", data + 10, body);
    build_fuzz_pem (fuzz_key_pem, sizeof (fuzz_key_pem),
                    "PRIVATE KEY", data + 10, body);
  }

  if (0 != cfg.mem_limit)
  {
    opts[nopt].option = MHD_OPTION_CONNECTION_MEMORY_LIMIT;
    opts[nopt].value = (intptr_t) cfg.mem_limit;
    opts[nopt].ptr_value = NULL;
    nopt++;
  }
  if (NULL != cfg.key)
  {
    opts[nopt].option = MHD_OPTION_HTTPS_MEM_KEY;
    opts[nopt].value = 0;
    opts[nopt].ptr_value = (void *) (intptr_t) cfg.key;
    nopt++;
  }
  if (NULL != cfg.cert)
  {
    opts[nopt].option = MHD_OPTION_HTTPS_MEM_CERT;
    opts[nopt].value = 0;
    opts[nopt].ptr_value = (void *) (intptr_t) cfg.cert;
    nopt++;
  }
  if (cfg.key_password)
  {
    opts[nopt].option = MHD_OPTION_HTTPS_KEY_PASSWORD;
    opts[nopt].value = 0;
    opts[nopt].ptr_value = (void *) (intptr_t) https_key_password;
    nopt++;
  }
  if (cfg.use_trust)
  {
    opts[nopt].option = MHD_OPTION_HTTPS_MEM_TRUST;
    opts[nopt].value = 0;
    opts[nopt].ptr_value = (void *) (intptr_t)
                           (cfg.trust_garbage ? garbage_cert_pem
                            : ca_cert_pem);
    nopt++;
  }
  if (cfg.use_dhparams)
  {
    opts[nopt].option = MHD_OPTION_HTTPS_MEM_DHPARAMS;
    opts[nopt].value = 0;
    opts[nopt].ptr_value = (void *) (intptr_t)
                           (cfg.dh_garbage ? garbage_dh_pem : dh_params_pem);
    nopt++;
  }
  if (cfg.use_prio)
  {
    opts[nopt].option = cfg.prio_append
                        ? MHD_OPTION_HTTPS_PRIORITIES_APPEND
                        : MHD_OPTION_HTTPS_PRIORITIES;
    opts[nopt].value = 0;
    opts[nopt].ptr_value = (void *) (intptr_t) cfg.prio_str;
    nopt++;
  }
  if (cfg.use_cred_type)
  {
    opts[nopt].option = MHD_OPTION_HTTPS_CRED_TYPE;
    opts[nopt].value = (intptr_t) cred_type_tbl[cfg.cred_type_idx];
    opts[nopt].ptr_value = NULL;
    nopt++;
  }
  if (cfg.no_alpn)
  {
    opts[nopt].option = MHD_OPTION_TLS_NO_ALPN;
    opts[nopt].value = 1;
    opts[nopt].ptr_value = NULL;
    nopt++;
  }
  opts[nopt].option = MHD_OPTION_END;
  opts[nopt].value = 0;
  opts[nopt].ptr_value = NULL;

  flags = MHD_USE_NO_LISTEN_SOCKET;
  if (cfg.use_tls)
    flags |= MHD_USE_TLS;
  if (fuzz_verbose)
    flags |= MHD_USE_ERROR_LOG;
  if (cfg.allow_upgrade)
    flags |= MHD_ALLOW_UPGRADE;

  MHD_set_panic_func (&panic_cb, NULL);
  /* The callback options go through the varargs rather than through the
     option array: the array's ptr_value is a void *, and a function
     pointer does not portably fit in one.  A NULL callback is exactly
     equivalent to not passing the option -- which is what makes
     PSK_NO_HANDLER (the "PSK not supported by this server" arm of
     psk_gnutls_adapter()) reachable without a second call site.

     MHD_OPTION_GNUTLS_PSK_CRED_HANDLER is the exception: an MHD built
     against GnuTLS 2 rejects it whatever the callback is, and rejecting
     an option fails the whole MHD_start_daemon(), so on such a build the
     option must not be passed at all. */
#if GNUTLS_VERSION_MAJOR >= 3
  d = MHD_start_daemon (flags,
                        0,
                        NULL, NULL,
                        &ahc, NULL,
                        MHD_OPTION_ARRAY, opts,
                        MHD_OPTION_HTTPS_CERT_CALLBACK,
                        cfg.use_sni ? &sni_callback : NULL,
                        MHD_OPTION_GNUTLS_PSK_CRED_HANDLER,
                        (cfg.psk_scenario &&
                         (PSK_NO_HANDLER != cfg.psk_mode))
                        ? &psk_cred_cb : NULL,
                        NULL,
                        MHD_OPTION_END);
#else
  d = MHD_start_daemon (flags,
                        0,
                        NULL, NULL,
                        &ahc, NULL,
                        MHD_OPTION_ARRAY, opts,
                        MHD_OPTION_HTTPS_CERT_CALLBACK,
                        cfg.use_sni ? &sni_callback : NULL,
                        MHD_OPTION_END);
#endif
  if (NULL == d)
  {
    stat_daemons_failed++;
    return 0;
  }
  stat_daemons++;
  if (! stats_registered)
  {
    stats_registered = 1;
    (void) atexit (&print_stats);
  }
  if (cfg.daemon_info)
  {
    (void) MHD_get_daemon_info (d, MHD_DAEMON_INFO_LISTEN_FD);
    (void) MHD_get_daemon_info (d, MHD_DAEMON_INFO_FLAGS);
    (void) MHD_get_daemon_info (d, MHD_DAEMON_INFO_CURRENT_CONNECTIONS);
    (void) MHD_get_daemon_info (d, MHD_DAEMON_INFO_BIND_PORT);
  }

  /* The connection is opened lazily, when the first segment that carries
     wire data is reached, so that a leading op 1 segment can still
     override the server name byte 9 selected. */
  tc.sess = NULL;
  tc.cred = NULL;
  tc.psk = NULL;
  tc.fd = -1;
  tc.hs_done = 0;
  tc.dead = 1;

  pos = 10u;
  while ( (pos + 2 <= size) &&
          (nseg < MAX_SEGMENTS) )
  {
    unsigned int hdr = (unsigned int) data[pos]
                       | ((unsigned int) data[pos + 1] << 8);
    unsigned int op = hdr >> 14;
    size_t slen = (size_t) (hdr & 0x3FFF);

    pos += 2;
    nseg++;
    if (slen > size - pos)
      slen = size - pos;

    if (1 == op)
    {
      /* Server name declaration for the next connection, not wire data. */
      size_t n = slen;

      if (n > MAX_SNI_LEN)
        n = MAX_SNI_LEN;
      memcpy (sni_name, data + pos, n);
      /* GnuTLS wants a plain host name, and an embedded NUL would only
         shorten it behind our back. */
      while ( (0 != n) &&
              ('\0' == sni_name[n - 1]) )
        n--;
      sni_name[n] = '\0';
      sni_name_len = n;
      pos += slen;
      continue;
    }
    if (0 > tc.fd)
    {
      tc_start (d, &tc);
      if (0 > tc.fd)
        break;
    }
    else if ( (3 == op) &&
              (nconn < MAX_CONNECTIONS) )
    {
      tc_close (d, &tc);
      tc_start (d, &tc);
      nconn++;
      if (0 > tc.fd)
        break;
    }
    if (0 != slen)
      tc_send (d, &tc, data + pos, slen);
    pos += slen;
    pump_and_drain (d, &tc, (2 == op) ? (6u + cfg.extra_pump) : 3u);
  }
  if (0 > tc.fd)
    tc_start (d, &tc);
  pump_and_drain (d, &tc, 2u + cfg.extra_pump);
  tc_close (d, &tc);

  if (cfg.quiesce)
    (void) MHD_quiesce_daemon (d);
  /* Last, so that no run can drain the list again.  MHD_add_connection()
     on a thread-safe daemon (the default) only queues the socket, but
     new_connection_prepare_() has already built the GnuTLS session for
     it; stopping before the next run is what makes MHD free that session
     from new_connection_close_() rather than from the ordinary
     connection teardown.  fuzz_eventloop covers the same shape without
     TLS -- see its byte 3 bit 4. */
  if (cfg.stop_with_queued)
    queued_fd = queue_unprocessed_conn (d);
  MHD_stop_daemon (d);
  if (0 <= queued_fd)
    (void) close (queued_fd);
  return 0;
}


/* ------------------------------------------------------------------ */
/* Structure-aware generator                                           */
/* ------------------------------------------------------------------ */

struct sbuf
{
  uint8_t *p;
  size_t len;
  size_t cap;
};


static void
sb_raw (struct sbuf *b,
        const void *v,
        size_t n)
{
  if (b->len + n > b->cap)
    n = b->cap - b->len;
  memcpy (b->p + b->len, v, n);
  b->len += n;
}


static void
sb_str (struct sbuf *b,
        const char *s)
{
  sb_raw (b, s, strlen (s));
}


static void
sb_u32 (struct sbuf *b,
        uint32_t v)
{
  char tmp[16];
  unsigned int n = 0;

  do
  {
    tmp[n++] = (char) ('0' + (v % 10u));
    v /= 10u;
  }
  while ( (0 != v) &&
          (n < sizeof (tmp)) );
  while (0 != n)
  {
    char c = tmp[--n];

    sb_raw (b, &c, 1);
  }
}


enum gen_shape
{
  SHAPE_TLS_HTTP = 0,   /**< good credentials, real handshake, HTTP over TLS */
  SHAPE_RAW_BYTES,      /**< good credentials, junk at the TLS socket */
  SHAPE_ABANDON,        /**< a real client that walks away mid-handshake */
  SHAPE_BAD_CREDS,      /**< mismatched/garbage/absent key or certificate */
  SHAPE_BAD_OPTIONS,    /**< bogus priorities, credential types, no MHD_USE_TLS */
  SHAPE_SNI,            /**< the certificate callback, all behaviours */
  SHAPE_PEM_FUZZ,       /**< PEM blobs built from the generator's own bytes */
  SHAPE_RECORDS,        /**< hand-built TLS records */
  SHAPE_PSK,            /**< the pre-shared key credentials path */
  SHAPE_COUNT
};

static int forced_shape = -1;
static int forced_shape_read;

static const char *const gen_methods[] = {
  "GET", "POST", "HEAD", "PUT", "OPTIONS", "BREW"
};

static const char *const gen_targets[] = {
  "/", "/a", "/index.html", "/a?b=c", "/%41%42", "*", "//"
};

static const char *const gen_versions[] = {
  "HTTP/1.1", "HTTP/1.0", "HTTP/1.2", "HTTP/9.9"
};

static const char *const gen_hdr_names[] = {
  "Host", "User-Agent", "Accept", "Connection", "X-Fuzz", "Cookie",
  "Content-Type", "Expect"
};

static const char *const gen_hdr_values[] = {
  "x", "localhost", "*/*", "keep-alive", "close", "100-continue",
  "text/plain", "a=b"
};


/**
 * A plain HTTP request; over TLS this is what makes MHD leave the
 * handshake state machine and enter the ordinary parser.
 */
static void
gen_http_request (struct fuzz_rng *rng,
                  struct sbuf *b)
{
  unsigned int nh;
  unsigned int i;
  int with_body;

  sb_str (b, gen_methods[fuzz_below (rng, (uint32_t)
                                     (sizeof (gen_methods)
                                      / sizeof (gen_methods[0])))]);
  sb_str (b, " ");
  sb_str (b, gen_targets[fuzz_below (rng, (uint32_t)
                                     (sizeof (gen_targets)
                                      / sizeof (gen_targets[0])))]);
  sb_str (b, " ");
  sb_str (b, gen_versions[fuzz_below (rng, (uint32_t)
                                      (sizeof (gen_versions)
                                       / sizeof (gen_versions[0])))]);
  sb_str (b, "\r\n");
  with_body = fuzz_chance (rng, 3);
  nh = fuzz_below (rng, 4);
  for (i = 0; i < nh; i++)
  {
    sb_str (b, gen_hdr_names[fuzz_below (rng, (uint32_t)
                                         (sizeof (gen_hdr_names)
                                          / sizeof (gen_hdr_names[0])))]);
    sb_str (b, ": ");
    sb_str (b, gen_hdr_values[fuzz_below (rng, (uint32_t)
                                          (sizeof (gen_hdr_values)
                                           / sizeof (gen_hdr_values[0])))]);
    sb_str (b, "\r\n");
  }
  if (with_body)
  {
    unsigned int blen = fuzz_below (rng, 64);

    sb_str (b, "Content-Length: ");
    sb_u32 (b, blen);
    sb_str (b, "\r\n\r\n");
    for (i = 0; i < blen; i++)
    {
      char c = (char) ('a' + (int) fuzz_below (rng, 26));

      sb_raw (b, &c, 1);
    }
    return;
  }
  sb_str (b, "\r\n");
}


/**
 * Something that looks like a TLS record: a content type, a version, a
 * length and a payload.  Most of this lands in GnuTLS's record parser
 * rather than in MHD, which is why the generator spends only one shape
 * on it.
 */
static void
gen_tls_records (struct fuzz_rng *rng,
                 struct sbuf *b)
{
  unsigned int n = 1 + fuzz_below (rng, 4);
  unsigned int i;
  unsigned int j;

  for (i = 0; i < n; i++)
  {
    uint8_t hdr[5];
    unsigned int plen = fuzz_below (rng, 96);
    unsigned int declared = fuzz_chance (rng, 3)
                            ? fuzz_below (rng, 0x4000)
                            : plen;

    hdr[0] = fuzz_chance (rng, 4)
             ? fuzz_byte (rng)
             : (uint8_t) (20 + fuzz_below (rng, 4));
    hdr[1] = 0x03;
    hdr[2] = (uint8_t) fuzz_below (rng, 5);
    hdr[3] = (uint8_t) ((declared >> 8) & 0xFF);
    hdr[4] = (uint8_t) (declared & 0xFF);
    sb_raw (b, hdr, sizeof (hdr));
    for (j = 0; j < plen; j++)
    {
      uint8_t v = fuzz_byte (rng);

      sb_raw (b, &v, 1);
    }
  }
}


/**
 * Number of leading entries of #prio_tbl that GnuTLS accepts.  Beyond
 * that the daemon refuses to start, which is a fine thing to fuzz but a
 * poor way to reach the handshake.
 */
#define PRIO_VALID_COUNT 7


/**
 * Constrain the configuration bytes so that MHD_start_daemon() actually
 * succeeds.  Used by the shapes whose point is what happens *after* the
 * daemon is up; the option surface itself is fuzzed by the shapes that
 * do not call this.
 */
static void
make_daemon_startable (struct fuzz_rng *rng,
                       uint8_t *cfg_bytes)
{
  cfg_bytes[1] &= (uint8_t) ~0x10u;      /* no credential type override */
  cfg_bytes[3] &= (uint8_t) ~0xC0u;      /* valid trust store, valid DH */
  if (0 != (cfg_bytes[1] & 0x08u))
    cfg_bytes[2] = (uint8_t) fuzz_below (rng, PRIO_VALID_COUNT);
  cfg_bytes[7] &= (uint8_t) ~0x08u;      /* keep MHD_USE_TLS */
}


/**
 * Emit one segment with the given op code.
 */
static void
emit_segment (struct sbuf *out,
              unsigned int op,
              const uint8_t *payload,
              size_t len)
{
  unsigned int hv;
  uint8_t hdr[2];

  if (len > 0x3FFF)
    len = 0x3FFF;
  hv = (op << 14) | (unsigned int) len;
  hdr[0] = (uint8_t) (hv & 0xFF);
  hdr[1] = (uint8_t) (hv >> 8);
  sb_raw (out, hdr, 2);
  sb_raw (out, payload, len);
}


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  struct sbuf out;
  struct sbuf rb;
  uint8_t req[GEN_BUF_SIZE];
  uint8_t cfg_bytes[10];
  enum gen_shape shape;
  unsigned int nreq;
  unsigned int i;

  out.p = buf;
  out.len = 0;
  out.cap = cap;

  if (! forced_shape_read)
  {
    const char *e = getenv ("MHD_FUZZ_SHAPE");

    forced_shape_read = 1;
    if (NULL != e)
      forced_shape = atoi (e);
  }
  if (0 <= forced_shape)
    shape = (enum gen_shape) (forced_shape % (int) SHAPE_COUNT);
  else
    shape = (enum gen_shape) fuzz_below (rng, (uint32_t) SHAPE_COUNT);

  for (i = 0; i < sizeof (cfg_bytes); i++)
    cfg_bytes[i] = fuzz_byte (rng);

  /* Byte 0 picks the credentials, byte 4 (bits 0-1) the client, and byte
     1 which options are passed at all; every shape below narrows exactly
     those and leaves the rest of the configuration space random. */
  cfg_bytes[7] &= (uint8_t) ~0x08u;      /* keep MHD_USE_TLS by default */
  switch (shape)
  {
  case SHAPE_TLS_HTTP:
    cfg_bytes[0] = (uint8_t) (fuzz_chance (rng, 2) ? 0 : 1);
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u) | CLIENT_TLS);
    cfg_bytes[1] &= (uint8_t) ~0x04u;    /* no SNI callback */
    make_daemon_startable (rng, cfg_bytes);
    break;
  case SHAPE_RAW_BYTES:
    cfg_bytes[0] = 0;
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u) | CLIENT_RAW);
    make_daemon_startable (rng, cfg_bytes);
    break;
  case SHAPE_ABANDON:
    cfg_bytes[0] = (uint8_t) (fuzz_chance (rng, 2) ? 0 : 1);
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u) | CLIENT_TLS_ABANDON);
    cfg_bytes[7] = (uint8_t) ((cfg_bytes[7] & ~0x07u)
                              + fuzz_below (rng, 6));
    make_daemon_startable (rng, cfg_bytes);
    break;
  case SHAPE_BAD_CREDS:
    /* entries 2-11 of cred_tbl are the broken ones */
    cfg_bytes[0] = (uint8_t) (2 + fuzz_below (rng, 10));
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u)
                              | (fuzz_chance (rng, 2) ? CLIENT_TLS
                                 : CLIENT_RAW));
    break;
  case SHAPE_BAD_OPTIONS:
    cfg_bytes[1] |= 0x18u;               /* priorities + credential type */
    cfg_bytes[2] = (uint8_t) fuzz_below (rng, (uint32_t) PRIO_COUNT);
    cfg_bytes[3] = fuzz_byte (rng);
    if (fuzz_chance (rng, 4))
      cfg_bytes[7] |= 0x08u;             /* HTTPS options, but no MHD_USE_TLS */
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u)
                              | (fuzz_chance (rng, 2) ? CLIENT_TLS
                                 : CLIENT_RAW));
    break;
  case SHAPE_SNI:
    cfg_bytes[0] = (uint8_t) (fuzz_chance (rng, 3) ? 6 : 0);
    cfg_bytes[3] = (uint8_t)
                   ((cfg_bytes[3] & ~0x38u)
                    | (fuzz_below (rng, (uint32_t) SNI_BEHAVIOUR_COUNT) << 3));
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u) | CLIENT_TLS | 0x04u);
    cfg_bytes[9] = (uint8_t) fuzz_below (rng, (uint32_t) SNI_NAME_COUNT);
    make_daemon_startable (rng, cfg_bytes);
    cfg_bytes[1] |= 0x04u;               /* the certificate callback */
    break;
  case SHAPE_PEM_FUZZ:
    cfg_bytes[0] = (uint8_t) (12 + fuzz_below (rng, 3));
    cfg_bytes[8] = (uint8_t) (1 + fuzz_below (rng, 64));
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u)
                              | (fuzz_chance (rng, 2) ? CLIENT_TLS
                                 : CLIENT_RAW));
    break;
  case SHAPE_RECORDS:
    cfg_bytes[0] = 0;
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u) | CLIENT_RECORDS);
    make_daemon_startable (rng, cfg_bytes);
    break;
  case SHAPE_PSK:
    /* The certificate is irrelevant to a PSK handshake but still has to
       let the daemon start, so keep the valid pair. */
    cfg_bytes[0] = 0;
    cfg_bytes[4] = (uint8_t) ((cfg_bytes[4] & ~0x03u)
                              | (fuzz_chance (rng, 5) ? CLIENT_TLS_ABANDON
                                 : CLIENT_TLS));
    cfg_bytes[1] &= (uint8_t) ~0x04u;    /* no SNI callback */
    make_daemon_startable (rng, cfg_bytes);
    cfg_bytes[9] = (uint8_t)
                   (0x80u                                 /* the scenario itself */
                    | (fuzz_chance (rng, 6) ? 0u : 0x40u) /* client PSK */
                    | (uint8_t) (fuzz_below (rng,
                                             (uint32_t) PSK_BEHAVIOUR_COUNT)
                                 << 3)
                    | (uint8_t) fuzz_below (rng, (uint32_t) SNI_NAME_COUNT));
    break;
  case SHAPE_COUNT:
  default:
    break;
  }
  /* Byte 9 already carries a server name; now and then hand the same
     one over as an op 1 segment instead, so that the segment form is
     exercised too.  Generated inputs are never written to corpus/, so
     unlike the seeds they may use op 1 (see the note at the top). */
  sb_raw (&out, cfg_bytes, sizeof (cfg_bytes));
  if (fuzz_chance (rng, 4))
  {
    const char *nm = sni_name_tbl[cfg_bytes[9] & 0x07];

    emit_segment (&out, 1u, (const uint8_t *) nm, strlen (nm));
  }

  nreq = 1u + (fuzz_chance (rng, 4) ? 1u : 0u);
  for (i = 0; i < nreq; i++)
  {
    unsigned int op;

    rb.p = req;
    rb.len = 0;
    rb.cap = sizeof (req);
    switch (shape)
    {
    case SHAPE_RECORDS:
      gen_tls_records (rng, &rb);
      break;
    case SHAPE_RAW_BYTES:
      {
        unsigned int n = 1 + fuzz_below (rng, 256);
        unsigned int j;

        for (j = 0; j < n; j++)
        {
          uint8_t v = fuzz_byte (rng);

          sb_raw (&rb, &v, 1);
        }
        break;
      }
    default:
      gen_http_request (rng, &rb);
      break;
    }
    if (0 != i)
      op = 3u;                           /* a fresh connection */
    else
      op = fuzz_chance (rng, 3) ? 2u : 0u;
    /* Split the payload now and then: MHD's parser is incremental and
       the TLS record boundaries move with the split. */
    if ( (rb.len > 8) &&
         fuzz_chance (rng, 3) )
    {
      size_t cut = 1 + fuzz_below (rng, (uint32_t) (rb.len - 1));

      emit_segment (&out, op, req, cut);
      emit_segment (&out, 2u, req + cut, rb.len - cut);
    }
    else
    {
      emit_segment (&out, op, req, rb.len);
    }
  }
  return out.len;
}


/* ------------------------------------------------------------------ */
/* Built-in seed corpus                                                */
/* ------------------------------------------------------------------ */

struct seed_part
{
  unsigned int op;              /**< 0 send, 1 server name, 2 send+pump, 3 new */
  const char *txt;              /**< NUL terminated payload */
};

struct seed_def
{
  const char *name;
  unsigned char cfg[10];
  struct seed_part parts[4];
};

#define P_END { 0, NULL }

/* The configuration bytes are written out in full so that a seed can be
   read without decoding: see the input format at the top of this file. */
static const struct seed_def seeds[] = {
  /* A complete TLS 1.3 handshake followed by an ordinary request: the
     only shape that reaches the handshake -> HTTP parser transition. */
  { "tls-handshake-get",
    { 0, 0x00, 0, 0, 0x41, 0x00, 0x04, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* The same, but the request arrives in two TLS records. */
  { "tls-handshake-split",
    { 0, 0x00, 0, 0, 0x41, 0x00, 0x04, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHo" },
      { 2, "st: x\r\n\r\n" }, P_END, P_END } },

  /* Keep-alive over TLS: two requests on one session, then gnutls_bye(). */
  { "tls-keepalive",
    { 0, 0x00, 0, 0, 0x41, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 2, "GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" },
      P_END, P_END } },

  /* A second connection, i.e. a second handshake on the same daemon. */
  { "tls-second-connection",
    { 0, 0x00, 0, 0, 0x41, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET /a HTTP/1.1\r\nHost: x\r\n\r\n" },
      { 3, "GET /b HTTP/1.1\r\nHost: x\r\n\r\n" },
      P_END, P_END } },

  /* Plain HTTP at a TLS port: the record layer sees "GET ..." and the
     handshake fails, which is MHD_run_tls_handshake_()'s error arm. */
  { "plain-http-at-tls-port",
    { 0, 0x00, 0, 0, 0x00, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* Nothing at all, then EOF: the connection dies in MHD_TLS_CONN_INIT. */
  { "eof-in-init",
    { 0, 0x00, 0, 0, 0x80, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "" }, P_END, P_END, P_END } },

  /* A real client that walks away after a single handshake round: MHD is
     left in MHD_TLS_CONN_HANDSHAKING when the socket closes. */
  { "abandon-handshake",
    { 0, 0x00, 0, 0, 0x02, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "" }, P_END, P_END, P_END } },

  /* Certificate and key do not belong together. */
  { "mismatched-key",
    { 2, 0x00, 0, 0, 0x01, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* No certificate at all: MHD_start_daemon() has to fail cleanly. */
  { "no-certificate",
    { 6, 0x00, 0, 0, 0x01, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* PEM armour with a payload that is not base64. */
  { "garbage-pem",
    { 10, 0x00, 0, 0, 0x01, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* A priority string GnuTLS rejects (index 9 of prio_tbl). */
  { "bogus-priorities",
    { 0, 0x08, 9, 0, 0x01, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* The same string through MHD_OPTION_HTTPS_PRIORITIES_APPEND. */
  { "bogus-priorities-append",
    { 0, 0x88, 10, 0, 0x01, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* TLS 1.2 only on both ends, with the trust store and a client
     certificate request. */
  { "tls12-with-trust",
    { 0, 0x01, 2, 0, 0x29, 0x00, 0x04, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* Valid Diffie-Hellman parameters (RFC 3526 group 14). */
  { "valid-dhparams",
    { 0, 0x02, 0, 0, 0x21, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* Malformed Diffie-Hellman parameters: MHD_start_daemon() must fail. */
  { "garbage-dhparams",
    { 0, 0x02, 0, 0x80, 0x01, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* A credential type MHD does not support (GNUTLS_CRD_ANON). */
  { "cred-type-anon",
    { 0, 0x10, 0, 0x02, 0x01, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* GNUTLS_CRD_PSK without a PSK callback: the daemon starts, the
     handshake cannot. */
  { "cred-type-psk",
    { 0, 0x10, 0, 0x01, 0x01, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* The TLS-PSK scenario (byte 9 bit 7), one seed per branch of
     psk_gnutls_adapter().  Byte 9 is
       0x80 scenario | 0x40 client offers PSK | behaviour << 3 | identity.
     Byte 4 bits 4-5 pick the PSK priority string, which is what decides
     the protocol version the PSK key exchange runs under. */

  /* The whole path end to end: identity accepted, key matches, handshake
     completes, and MHD then serves plain HTTP over a session that has no
     certificate at all (byte 6 bit 2 reads the TLS members back). */
  { "psk-handshake",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x04, 0x00, 0, 0xC0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* The same over TLS 1.3, where GnuTLS treats the key as an external
     PSK and the exchange has a different shape. */
  { "psk-handshake-tls13",
    { 0, 0x00, 0, 0, 0x21, 0x00, 0x00, 0x00, 0, 0xC0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* The application refuses the identity: the adapter's -1 arm. */
  { "psk-callback-fails",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x00, 0x00, 0, 0xC8 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* Zero length key: the "PSK too short" arm, and the reason MHD never
     reaches gnutls_malloc(0). */
  { "psk-empty-key",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x00, 0x00, 0, 0xD0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* One byte below the minimum -- the other side of the boundary that
     psk-handshake (exactly the minimum) sits on. */
  { "psk-one-byte-short",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x00, 0x00, 0, 0xF8 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* 4 KiB key: the copy into the gnutls_malloc()ed buffer, at a size no
     ciphersuite expects. */
  { "psk-long-key",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x00, 0x00, 0, 0xD8 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* Key length taken from the identity, with the longest identity in the
     table (sni_name_tbl entry 7, 62 characters): the callback then hands
     back a 62 byte key, which no PSK ciphersuite expects. */
  { "psk-key-from-identity",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x00, 0x00, 0, 0xE7 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* A key size above UINT_MAX: the "PSK too long" arm, which has to
     free the application's buffer and fail. */
  { "psk-oversized-key",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x00, 0x00, 0, 0xE8 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* PSK credential type, PSK ciphersuite, but no credentials callback:
     the "PSK not supported by this server" arm. */
  { "psk-no-handler",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x00, 0x00, 0, 0xF0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* A PSK-only server against a client that offers no PSK identity: the
     handshake fails before the adapter is ever asked. */
  { "psk-client-no-creds",
    { 0, 0x00, 0, 0, 0x11, 0x00, 0x00, 0x00, 0, 0x80 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* Byte 5 bit 6: stop the daemon with a connection queued but never
     started, so that its GnuTLS session is freed by
     new_connection_close_() instead of by the ordinary teardown. */
  { "stop-with-queued-connection",
    { 0, 0x00, 0, 0, 0x01, 0x40, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* The SNI callback, answering for the presented name (byte 9 = 0,
     "test-mhdserver").  No op 1 segment here or below: see the note on
     the shared corpus at the top of this file. */
  { "sni-by-name",
    { 6, 0x04, 0, 0x18, 0x05, 0x00, 0x04, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: test-mhdserver\r\n\r\n" },
      P_END, P_END, P_END } },

  /* The SNI callback failing outright. */
  { "sni-callback-fails",
    { 6, 0x04, 0, 0x08, 0x05, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
      P_END, P_END, P_END } },

  /* The SNI callback answering with an empty certificate list. */
  { "sni-callback-empty",
    { 6, 0x04, 0, 0x10, 0x05, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
      P_END, P_END, P_END } },

  /* The SNI callback answering with a key that is not the certificate's
     (byte 9 = 1, "localhost"). */
  { "sni-callback-mismatch",
    { 6, 0x04, 0, 0x20, 0x05, 0x00, 0x00, 0x00, 0, 1 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
      P_END, P_END, P_END } },

  /* The SNI callback answering with a certificate but no key. */
  { "sni-callback-no-key",
    { 6, 0x04, 0, 0x28, 0x05, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
      P_END, P_END, P_END } },

  /* An unknown server name with the by-name callback (byte 9 = 3,
     "nobody.example.org"): no certificate. */
  { "sni-unknown-name",
    { 6, 0x04, 0, 0x18, 0x05, 0x00, 0x00, 0x00, 0, 3 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" },
      P_END, P_END, P_END } },

  /* A PEM blob assembled from the payload below (cred_tbl entry 14). */
  { "fuzzed-pem",
    { 14, 0x00, 0, 0, 0x01, 0x00, 0x00, 0x00, 32, 0 },
    { { 0, "MIIFSzCCAzOgAwIBAgIBBDANBgkqhkiG9w0BAQsFADCBgTELMAkGA1UEBhMCUlUx" },
      P_END, P_END, P_END } },

  /* A truncated TLS record header, then EOF. */
  { "short-record",
    { 0, 0x00, 0, 0, 0x00, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "\x16\x03\x01" }, P_END, P_END, P_END } },

  /* A record that promises far more data than it delivers. */
  { "record-length-lie",
    { 0, 0x00, 0, 0, 0x00, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "\x16\x03\x01\x3f\xff\x01\x02\x03\x04" }, P_END, P_END, P_END } },

  /* The HTTPS options on a daemon started without MHD_USE_TLS. */
  { "no-use-tls-flag",
    { 0, 0x0F, 0, 0, 0x00, 0x00, 0x00, 0x08, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* A tiny connection memory pool with a real TLS session. */
  { "small-pool-tls",
    { 0, 0x00, 0, 0, 0x41, 0x01, 0x00, 0x00, 0, 0 },
    { { 0, "GET /aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa HTTP/1.1\r\n"
        "Host: x\r\nX-Long: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n" },
      P_END, P_END, P_END } },

  /* A request body over TLS, so that the receive adapter is used for
     more than the request line. */
  { "tls-request-body",
    { 0, 0x00, 0, 0, 0x41, 0x00, 0x00, 0x00, 0, 0 },
    { { 0, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n"
        "hello world" },
      P_END, P_END, P_END } },

  /* The external event loop (MHD_get_fdset() + MHD_run_from_select()). */
  { "tls-external-loop",
    { 0, 0x00, 0, 0, 0x41, 0x10, 0x04, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } },

  /* MHD_quiesce_daemon() with a live TLS connection. */
  { "tls-quiesce",
    { 0, 0x00, 0, 0, 0x41, 0x00, 0x80, 0x00, 0, 0 },
    { { 0, "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }, P_END, P_END, P_END } }
};

static uint8_t seed_render_buf[2048];


static size_t
fuzz_seed_count (void)
{
  return sizeof (seeds) / sizeof (seeds[0]);
}


static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len)
{
  const struct seed_def *sd = &seeds[idx];
  struct sbuf b;
  unsigned int i;

  b.p = seed_render_buf;
  b.len = 0;
  b.cap = sizeof (seed_render_buf);
  sb_raw (&b, sd->cfg, sizeof (sd->cfg));
  for (i = 0; i < sizeof (sd->parts) / sizeof (sd->parts[0]); i++)
  {
    if (NULL == sd->parts[i].txt)
      break;
    emit_segment (&b, sd->parts[i].op,
                  (const uint8_t *) sd->parts[i].txt,
                  strlen (sd->parts[i].txt));
  }
  *len = b.len;
  return seed_render_buf;
}


#else  /* ! HTTPS_SUPPORT */

/*
 * MHD was configured without HTTPS (which is what
 * contrib/oss-fuzz/build.sh does for the MemorySanitizer build), so
 * there is no TLS layer to fuzz.  The file still has to produce a valid
 * fuzz target: LLVMFuzzerTestOneInput() must exist unconditionally, or
 * an OSS-Fuzz build of this harness would silently be an empty binary.
 */

int
LLVMFuzzerTestOneInput (const uint8_t *data,
                        size_t size)
{
  fuzz_ignore_sigpipe ();
  (void) data;
  (void) size;
  return 0;
}


static size_t
fuzz_generate (struct fuzz_rng *rng,
               uint8_t *buf,
               size_t cap)
{
  (void) rng;
  if (0 == cap)
    return 0;
  buf[0] = 0;
  return 1;
}


static const uint8_t no_https_seed[] = { 0 };


static size_t
fuzz_seed_count (void)
{
  return 1;
}


static const uint8_t *
fuzz_seed_get (size_t idx,
               size_t *len)
{
  (void) idx;
  *len = sizeof (no_https_seed);
  return no_https_seed;
}


#endif /* ! HTTPS_SUPPORT */

/* end of fuzz_tls.c */
