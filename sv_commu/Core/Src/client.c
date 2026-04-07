// board_auth_client.c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "lwip/netif.h"
#include "lwip/dhcp.h"
#include "lwip/ip4_addr.h"
#include "lwip/timeouts.h"

#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/errno.h"

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pem.h"


extern struct netif gnetif;

// ===== 사용자 설정 =====
#define SERVER_IP     ""   // 서버 IP(핀닝한 IP)
#define SERVER_PORT   ""            // 서버 실행 포트(--port)

static const char ID_STR[]  = "";

// 보드에 탑재된 값(제조 단계에서 탑재됐다고 가정)
static const char M1_HEX[]  = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"; // 32B hex
static const char KID_HEX[] = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"; // 32B hex

// 서버 인증서(또는 CA) PEM을 보드 플래시에 문자열로 탑재
static const char SERVER_CERT_PEM[] =
"-----BEGIN CERTIFICATE-----\n"

"-----END CERTIFICATE-----\n";
// =======================


static void dump_mbed_err(const char* where, int ret)
{
    // mbedtls_strerror()가 프로젝트에 없어서 링크 에러가 나므로 일단 숫자만 출력
    printf("[ERR] %s: -0x%04X (%d)\r\n", where, (unsigned)(-ret), ret);
}

static int hex2bin_fixed(const char* hex, uint8_t* out, size_t out_len)
{
    size_t n = strlen(hex);
    if (n != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        char c1 = hex[2*i], c2 = hex[2*i+1];
        int hi = (c1>='0'&&c1<='9')?c1-'0':(c1>='a'&&c1<='f')?c1-'a'+10:(c1>='A'&&c1<='F')?c1-'A'+10:-1;
        int lo = (c2>='0'&&c2<='9')?c2-'0':(c2>='a'&&c2<='f')?c2-'a'+10:(c2>='A'&&c2<='F')?c2-'A'+10:-1;
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi<<4) | lo);
    }
    return 0;
}

static void bin2hex(const uint8_t* in, size_t in_len, char* out /*2*len+1*/)
{
    static const char* hx = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[2*i]   = hx[(in[i] >> 4) & 0xF];
        out[2*i+1] = hx[in[i] & 0xF];
    }
    out[2*in_len] = '\0';
}

static int wait_dhcp(uint32_t timeout_ms)
{
    uint32_t start = sys_now();
    while ((sys_now() - start) < timeout_ms) {
        if (netif_is_up(&gnetif) && netif_is_link_up(&gnetif) && dhcp_supplied_address(&gnetif)) {
            return 0;
        }
        //sys_check_timeouts();
        // FreeRTOS면 osDelay(50) 추천
        osDelay(50);
    }
    return -1;
}

static int net_connect_timeout(mbedtls_net_context *net,
                               const char *ip_str,
                               uint16_t port,
                               int timeout_ms)
{
    printf("test123\n");

    int fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
    printf("sock fd=%d errno=%d\r\n", fd, errno);
    if (fd < 0) return -errno;


    // non-blocking 설정 (FIONBIO)
    unsigned long mode = 1;
    int ir = lwip_ioctl(fd, FIONBIO, &mode);
   	printf("ioctl ret=%d errno=%d\r\n", ir, errno);
   	printf("test1234\n");
   	if (ir != 0) {
   		int e = errno;
   		lwip_close(fd);
   		return -e;  // 여기서 return이면 test1이 안 찍힘
   	}


    if (lwip_ioctl(fd, FIONBIO, &mode) != 0) {
        int e = errno;
        lwip_close(fd);
        return -e;
    }
    printf("test1\n");
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = lwip_htons(port);
    sa.sin_addr.s_addr = ipaddr_addr(ip_str);

    int r = lwip_connect(fd, (struct sockaddr*)&sa, sizeof(sa));
    if (r == 0) {
        // 즉시 연결 성공
        goto ok;
    }

    if (errno != EINPROGRESS) {
        int e = errno;
        lwip_close(fd);
        return -e;
    }
    printf("test2\n");
    // select로 connect 완료/실패 대기
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(fd, &wfds);

    struct timeval tv;
    tv.tv_sec  = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    r = lwip_select(fd + 1, NULL, &wfds, NULL, &tv);
    if (r == 0) { lwip_close(fd); return -ETIMEDOUT; }
    if (r < 0)  { int e = errno; lwip_close(fd); return -e; }

    // connect 결과 확인
    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    lwip_getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
    if (soerr != 0) { lwip_close(fd); return -soerr; }

ok:
    // 다시 blocking으로 (mbedTLS send/recv용)
    mode = 0;
    lwip_ioctl(fd, FIONBIO, &mode);

    // recv/send timeout도 같이(선택)
    struct timeval tv2 = { .tv_sec = 5, .tv_usec = 0 };
    lwip_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    lwip_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv2, sizeof(tv2));

    net->fd = fd;
    return 0;
}


// 서버가 요청 1개 처리 후 connection close 하므로 "POST 1회당 TLS 연결 1회"로 구현
static int tls_http_post_once(const char* path,
                              const char* json_body,
                              char* resp_buf, size_t resp_cap)
{
    int ret = 0;

    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;
    mbedtls_x509_crt cacert;

    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);
    mbedtls_x509_crt_init(&cacert);

    const char* pers = "stm32-auth";

    if ((ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                                     (const unsigned char*)pers, strlen(pers))) != 0) {
        dump_mbed_err("ctr_drbg_seed", ret); goto out;
    }

    // 서버 인증서(또는 CA) 탑재분을 신뢰 체인으로 등록
    if ((ret = mbedtls_x509_crt_parse(&cacert,
                                     (const unsigned char*)SERVER_CERT_PEM,
                                     sizeof(SERVER_CERT_PEM))) < 0) {
        dump_mbed_err("x509_crt_parse", ret); goto out;
    }

    printf("[TLS] tcp connect %s:%s...\r\n", SERVER_IP, SERVER_PORT);
    /*if ((ret = mbedtls_net_connect(&net, SERVER_IP, SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        dump_mbed_err("net_connect", ret); goto out;
    }*/

    printf("[TLS] tcp connect %s:%s...\r\n", SERVER_IP, SERVER_PORT);
    ret = net_connect_timeout(&net, SERVER_IP, (uint16_t)atoi(SERVER_PORT), 5000);
    if (ret != 0) {
        printf("[ERR] connect ret=%d\r\n", ret);   // -ETIMEDOUT, -ECONNREFUSED 등
        goto out;
    }
    // 윗부분
    printf("[TLS] tcp connect OK\r\n");

    printf("[TLS] ssl_setup...\r\n");
    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        dump_mbed_err("ssl_config_defaults", ret); goto out;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr);

    // 인증서 “핀닝”에 가까운 방식: 서버/CA 인증서를 직접 넣고 VERIFY_REQUIRED
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

    // TLS 1.3만 허용 (mbedTLS TLS1.3이 활성화된 빌드여야 함)
    // (TLS 1.3은 보통 (3,4)로 표현됨)
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        dump_mbed_err("ssl_setup", ret); goto out;
    }

    // hostname 검증은 생략(인증서 SAN에 IP가 없으면 실패할 수 있음)
    // 필요하면 mbedtls_ssl_set_hostname(&ssl, SERVER_IP);

    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    printf("[TLS] handshake...\r\n");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            dump_mbed_err("ssl_handshake", ret); goto out;
        }
    }

    // 인증서 검증 결과
    {
        uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
        if (flags != 0) {
            printf("[TLS] verify flags=0x%08lX\r\n", (unsigned long)flags);
            ret = -1; goto out;
        }
    }

    // HTTP POST 작성
    char req_hdr[512];
    int body_len = (int)strlen(json_body);
    int hdr_len = snprintf(req_hdr, sizeof(req_hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, SERVER_IP, body_len);

    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char*)req_hdr, hdr_len)) < 0) {
        dump_mbed_err("ssl_write(hdr)", ret); goto out;
    }
    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char*)json_body, body_len)) < 0) {
        dump_mbed_err("ssl_write(body)", ret); goto out;
    }

    // 응답 읽기(간단히 1~몇번 read로 끝낸다고 가정)
    memset(resp_buf, 0, resp_cap);
    size_t off = 0;
    for (;;) {
        if (off + 1 >= resp_cap) break;
        ret = mbedtls_ssl_read(&ssl, (unsigned char*)resp_buf + off, (int)(resp_cap - 1 - off));
        if (ret == 0) break; // close
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) continue;
            dump_mbed_err("ssl_read", ret); goto out;
        }
        off += (size_t)ret;
    }

    mbedtls_ssl_close_notify(&ssl);
    ret = 0;

out:
    mbedtls_net_free(&net);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    return ret;
}

// HTTP 응답에서 {"ok":true,"r":"..."} 중 r(hex 64 chars)만 추출
static int json_extract_r_hex(const char* http_resp, char r_hex_out[65])
{
    const char* p = strstr(http_resp, "\"r\":\"");
    if (!p) return -1;
    p += 5; // len("\"r\":\"") = 5
    // p points to first hex char
    for (int i = 0; i < 64; i++) {
        char c = p[i];
        int ishex = (c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F');
        if (!ishex) return -1;
        r_hex_out[i] = (char)tolower((unsigned char)c);
    }
    r_hex_out[64] = '\0';
    return 0;
}

static int make_pk_raw_p256(uint8_t* pk_out, size_t pk_cap, size_t* pk_len_out)
{
    int ret = 0;
    mbedtls_ecp_keypair ec;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr;

    mbedtls_ecp_keypair_init(&ec);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr);

    const char* pers = "p256-raw";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr, mbedtls_entropy_func, &entropy,
                                     (const unsigned char*)pers, strlen(pers))) != 0) {
        goto out;
    }

    if ((ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &ec,
                                   mbedtls_ctr_drbg_random, &ctr)) != 0) {
        goto out;
    }

    // 공개키 uncompressed point: 0x04 || X(32) || Y(32) = 65 bytes
    size_t olen = 0;
    if ((ret = mbedtls_ecp_point_write_binary(&ec.grp, &ec.Q,
                                              MBEDTLS_ECP_PF_UNCOMPRESSED,
                                              &olen, pk_out, pk_cap)) != 0) {
        goto out;
    }

    *pk_len_out = olen;  // 보통 65
    ret = 0;

out:
    mbedtls_ecp_keypair_free(&ec);
    mbedtls_ctr_drbg_free(&ctr);
    mbedtls_entropy_free(&entropy);
    return ret;
}

static int hmac_sha256_32(const uint8_t key[32], const uint8_t* msg, size_t msg_len, uint8_t out[32])
{
    const mbedtls_md_info_t* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md) return -1;
    return mbedtls_md_hmac(md, key, 32, msg, msg_len, out);
}

int board_run_auth_sequence(void)
{
    if (wait_dhcp(15000) != 0) {
        printf("[NET] DHCP timeout\r\n");
        return -1;
    }

    printf("[NET] IP=%s GW=%s\r\n",
           ip4addr_ntoa(netif_ip4_addr(&gnetif)),
           ip4addr_ntoa(netif_ip4_gw(&gnetif)));

    // 0) /ping (옵션)
    {
        char resp[512];
        // 서버 코드에 /ping 존재 :contentReference[oaicite:3]{index=3}
        // GET 구현은 생략하고, 필요하면 POST 함수와 같은 방식으로 GET도 구현 가능
        (void)resp;
    }

    uint8_t m1[32], kid[32];
    if (hex2bin_fixed(M1_HEX, m1, 32) != 0) { printf("bad m1\r\n"); return -1; }
    if (hex2bin_fixed(KID_HEX, kid, 32) != 0) { printf("bad kid\r\n"); return -1; }

    // 1) /auth1 : {id,m1} -> r 받기 (서버 로직 그대로)
    printf("[AUTH1] start\r\n");
    char body1[256];
    snprintf(body1, sizeof(body1),
             "{\"id\":\"%s\",\"m1\":\"%s\"}",
             ID_STR, M1_HEX);

    char resp1[1024];
    if (tls_http_post_once("/auth1", body1, resp1, sizeof(resp1)) != 0) {
        printf("[AUTH1] failed\r\n");
        return -1;
    }
    printf("[AUTH1] resp:\r\n%s\r\n", resp1);

    char r_hex[65];
    if (json_extract_r_hex(resp1, r_hex) != 0) {
        printf("[AUTH1] cannot find r\r\n");
        return -1;
    }
    uint8_t r[32];
    if (hex2bin_fixed(r_hex, r, 32) != 0) {
        printf("[AUTH1] bad r hex\r\n");
        return -1;
    }

    // 2) P-256 KeyGen -> pk_der
    // 2) P-256 KeyGen -> pk_raw (uncompressed point: 65 bytes)
    printf("[KeyGen] start\r\n");
    uint8_t pk_raw[80];   // 65바이트면 충분(여유)
    size_t pk_len = 0;
    if (make_pk_raw_p256(pk_raw, sizeof(pk_raw), &pk_len) != 0) {
        printf("[KEYGEN] failed\r\n");
        return -1;
    }

    // msg2 = ID || m1(=m1') || PK_RAW || R
    const uint8_t* idb = (const uint8_t*)ID_STR;
    size_t idlen = strlen(ID_STR);

    size_t msg2_len = idlen + 32 + pk_len + 32;
    uint8_t* msg2 = (uint8_t*)malloc(msg2_len);
    if (!msg2) return -1;

    size_t off = 0;
    memcpy(msg2 + off, idb, idlen);      off += idlen;
    memcpy(msg2 + off, m1, 32);          off += 32;
    memcpy(msg2 + off, pk_raw, pk_len);  off += pk_len;
    memcpy(msg2 + off, r, 32);           off += 32;

    uint8_t m2[32];
    if (hmac_sha256_32(kid, msg2, msg2_len, m2) != 0) {
        free(msg2);
        printf("[M2] hmac failed\r\n");
        return -1;
    }
    free(msg2);

    // pk_hex 만들기 (pk_raw 기준)
    char pk_hex[2*80 + 1];
    if (pk_len * 2 + 1 > sizeof(pk_hex)) { printf("pk too big\r\n"); return -1; }
    bin2hex(pk_raw, pk_len, pk_hex);

    char m2_hex[65];
    bin2hex(m2, 32, m2_hex);

    printf("[AUTH2] start\r\n");
    // 3) /auth2 : {id, pk(hex DER), m2}
    // 서버는 요청 1개 처리 후 close 하므로, 두 번째 TLS 연결을 새로 맺는다. :contentReference[oaicite:7]{index=7}
    char* body2 = (char*)malloc(128 + strlen(pk_hex));
    if (!body2) return -1;
    sprintf(body2, "{\"id\":\"%s\",\"pk\":\"%s\",\"m2\":\"%s\"}", ID_STR, pk_hex, m2_hex);

    char resp2[1024];
    int rc = tls_http_post_once("/auth2", body2, resp2, sizeof(resp2));
    free(body2);

    if (rc != 0) {
        printf("[AUTH2] failed\r\n");
        return -1;
    }
    printf("[AUTH2] resp:\r\n%s\r\n", resp2);

    printf("[DONE] auth sequence complete\r\n");
    return 0;
}
