#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "SAPI.h"
#include "ext/standard/head.h"
#include "zend_compile.h"
#include "modsec.h"
#include "php_waf.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

/* C++ headers for ModSecurity */
#ifdef __cplusplus
extern "C" {
#endif

/* msc_set_request_hostname needs libmodsecurity >= 3.0.13. Older builds
 * lack the symbol so never reference it or waf.so fails to dlopen.
 * SERVER_NAME is derived from Host by libmodsecurity. */

/* ============================================================================
 * Per Process ModSecurity State
 * ============================================================================ */

/* Per-process engine + rules, set in MINIT and torn down in MSHUTDOWN
 * (single-threaded under ZTS), shared read-only across request threads. */
static ModSecurity *g_modsec = NULL;
static RulesSet *g_rules = NULL;
static zend_bool g_modsec_initialized = 0;
/* Transaction-id sequence, atomic under ZTS, plain increment under NTS. */
static unsigned long g_transaction_counter = 0;

/* ============================================================================
 * Log Callback
 * ============================================================================ */

static void modsec_log_callback(void *data, const void *rule_message) {
    (void)data;
    if (rule_message != NULL) {
        const char *msg = (const char *)rule_message;
        php_error(E_WARNING, "waf: ModSecurity: %s", msg);
    }
}

/* ============================================================================
 * HTTP Error Response
 * ============================================================================ */

void waf_send_block_response(int status_code) {
    const char *status_text = "Forbidden";

    switch (status_code) {
        case WAF_HTTP_STATUS_BAD_REQUEST: status_text = "Bad Request"; break;
        case WAF_HTTP_STATUS_FORBIDDEN: status_text = "Forbidden"; break;
        case WAF_HTTP_STATUS_NOT_FOUND: status_text = "Not Found"; break;
        case WAF_HTTP_STATUS_SERVER_ERROR: status_text = "Internal Server Error"; break;
        case 301: status_text = "Moved Permanently"; break;
        case 302: status_text = "Found"; break;
        case 307: status_text = "Temporary Redirect"; break;
        case 308: status_text = "Permanent Redirect"; break;
    }

    /* Emit the full HTTP response via original_ub_write, bypassing the PHP
     * output layer and our hook. While a transaction is active waf_ub_write
     * buffers into response_body so headers would be swallowed. Writing
     * through original_ub_write keeps Status, headers and body ordered for
     * both the request phase block and the RSHUTDOWN block. */
    size_t (*orig_write)(const char *, size_t) = waf_original_ub_write();
    if (orig_write == NULL) {
        orig_write = sapi_module.ub_write;
    }

    char hdr[640];
    int hlen;

    /* Handle redirect if intervention URL is set. */
    if (WAF_G(intervention).url != NULL) {
        char *rhdr = NULL;
        int rlen = spprintf(&rhdr, 0,
                            "Status: %d %s\r\n"
                            "Location: %s\r\n"
                            "Content-Type: text/html; charset=utf-8\r\n"
                            "\r\n",
                            status_code, status_text, WAF_G(intervention).url);
        if (rlen > 0 && rhdr != NULL) {
            orig_write(rhdr, (size_t)rlen);
        }
        efree(rhdr);
        SG(sapi_headers).http_response_code = status_code;
        SG(headers_sent) = 1;
        return;
    }

    /* Build response body. */
    char *body = NULL;
    int blen = spprintf(&body, 0,
             "<!DOCTYPE html>\n<html>\n<head><title>%d %s</title></head>\n"
             "<body>\n<h1>%d %s</h1>\n"
             "<p>Request blocked by ModSecurity Web Application Firewall.</p>\n"
             "<p>Transaction ID: %s</p>\n</body>\n</html>\n",
             status_code, status_text, status_code, status_text,
             WAF_G(transaction_id) ? WAF_G(transaction_id) : "unknown");

    /* Status line and Content Type. */
    hlen = snprintf(hdr, sizeof(hdr),
                    "Status: %d %s\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n",
                    status_code, status_text);
    if (hlen > 0 && (size_t)hlen < sizeof(hdr)) {
        orig_write(hdr, (size_t)hlen);
    }

    /* Optional Transaction ID header. */
    if (WAF_G(transaction_id) != NULL) {
        char txh[256];
        int txl = snprintf(txh, sizeof(txh), "X-Transaction-Id: %s\r\n",
                           WAF_G(transaction_id));
        if (txl > 0 && (size_t)txl < sizeof(txh)) {
            orig_write(txh, (size_t)txl);
        }
    }

    /* Blank line terminates the header section, then the body. */
    orig_write("\r\n", 2);
    if (blen > 0 && body != NULL) {
        orig_write(body, (size_t)blen);
    }
    if (body != NULL) {
        efree(body);
    }

    /* Mark headers sent so shutdown does not emit a second default 200 frame. */
    SG(sapi_headers).http_response_code = status_code;
    SG(headers_sent) = 1;
}

/* ============================================================================
 * Module Lifecycle Functions
 * ============================================================================ */

int waf_modsec_init(void) {
    const char *error = NULL;
    int ret = 0;
    char *seclang_config = NULL;

    if (g_modsec_initialized) return 0;
    if (!WAF_G(enabled)) return 0;

    g_modsec = msc_init();
    if (g_modsec == NULL) {
        php_error(E_WARNING, "waf: Failed to initialize ModSecurity");
        return -1;
    }

    msc_set_connector_info(g_modsec, "PHP waf extension v" PHP_WAF_VERSION);
    msc_set_log_cb(g_modsec, modsec_log_callback);

    g_rules = msc_create_rules_set();
    if (g_rules == NULL) {
        php_error(E_WARNING, "waf: Failed to create ModSecurity rules set");
        msc_cleanup(g_modsec);
        g_modsec = NULL;
        return -1;
    }

    /* SecLang directives with no C API. Inject as an inline snippet before the
     * user rules. Persistent allocs since this runs in MINIT, and spprintf
     * formats with emalloc, so duplicate into a persistent string each step. */
    seclang_config = pestrdup("", 1);
    if (WAF_G(modsec_debug_log) != NULL && WAF_G(modsec_debug_log)[0] != '\0') {
        char *tmp = NULL;
        spprintf(&tmp, 0, "%sSecDebugLog %s\nSecDebugLogLevel %ld\n", seclang_config,
                 WAF_G(modsec_debug_log), (long)WAF_G(modsec_debug_level));
        pefree(seclang_config, 1);
        seclang_config = pestrdup(tmp, 1);
        efree(tmp);
    }
    if (WAF_G(modsec_audit_log) != NULL && WAF_G(modsec_audit_log)[0] != '\0') {
        char *tmp = NULL;
        spprintf(&tmp, 0, "%sSecAuditEngine On\nSecAuditLog %s\n", seclang_config,
                 WAF_G(modsec_audit_log));
        pefree(seclang_config, 1);
        seclang_config = pestrdup(tmp, 1);
        efree(tmp);
        if (WAF_G(modsec_audit_log_parts) != NULL &&
            WAF_G(modsec_audit_log_parts)[0] != '\0') {
            char *tmp2 = NULL;
            spprintf(&tmp2, 0, "%sSecAuditLogParts %s\n", seclang_config,
                     WAF_G(modsec_audit_log_parts));
            pefree(seclang_config, 1);
            seclang_config = pestrdup(tmp2, 1);
            efree(tmp2);
        }
    }

    if (seclang_config != NULL && seclang_config[0] != '\0') {
        ret = msc_rules_add(g_rules, seclang_config, &error);
        if (ret < 0) {
            php_error(E_WARNING, "waf: Failed to configure ModSecurity logging: %s",
                      error ? error : "unknown error");
            pefree(seclang_config, 1);
            msc_rules_cleanup(g_rules);
            msc_cleanup(g_modsec);
            g_rules = NULL;
            g_modsec = NULL;
            return -1;
        }
    }
    pefree(seclang_config, 1);

    if (WAF_G(modsec_rules_file) != NULL && strlen(WAF_G(modsec_rules_file)) > 0) {
        ret = msc_rules_add_file(g_rules, WAF_G(modsec_rules_file), &error);
        if (ret < 0) {
            php_error(E_WARNING, "waf: Failed to load rules from file: %s",
                      error ? error : "unknown error");
            msc_rules_cleanup(g_rules);
            msc_cleanup(g_modsec);
            g_rules = NULL;
            g_modsec = NULL;
            return -1;
        }
    }

    if (WAF_G(modsec_rules_inline) != NULL && strlen(WAF_G(modsec_rules_inline)) > 0) {
        ret = msc_rules_add(g_rules, WAF_G(modsec_rules_inline), &error);
        if (ret < 0) {
            php_error(E_WARNING, "waf: Failed to load inline rules: %s",
                      error ? error : "unknown error");
            msc_rules_cleanup(g_rules);
            msc_cleanup(g_modsec);
            g_rules = NULL;
            g_modsec = NULL;
            return -1;
        }
    }

    g_modsec_initialized = 1;
    php_error(E_NOTICE, "waf: ModSecurity initialized successfully");
    return 0;
}

void waf_modsec_shutdown(void) {
    if (!g_modsec_initialized) return;

    if (g_rules != NULL) {
        msc_rules_cleanup(g_rules);
        g_rules = NULL;
    }
    if (g_modsec != NULL) {
        msc_cleanup(g_modsec);
        g_modsec = NULL;
    }
    g_modsec_initialized = 0;
}

zend_bool waf_modsec_is_enabled(void) {
    return g_modsec_initialized && g_modsec != NULL && g_rules != NULL;
}

/* ============================================================================
 * Transaction Lifecycle Functions
 * ============================================================================ */

static void generate_transaction_id(char *buf, size_t buf_len) {
    struct timeval tv;
    unsigned long seq;
    gettimeofday(&tv, NULL);
#if defined(ZTS)
    /* Under a threaded SAPI use an atomic counter so IDs never collide. */
    seq = __atomic_add_fetch(&g_transaction_counter, 1, __ATOMIC_SEQ_CST);
#else
    seq = ++g_transaction_counter;
#endif
    snprintf(buf, buf_len, "%08lx%08lx%08lx",
             (unsigned long)tv.tv_sec,
             (unsigned long)tv.tv_usec,
             seq);
}

Transaction *waf_modsec_transaction_begin(void) {
    Transaction *transaction = NULL;
    char tx_id[WAF_TRANSACTION_ID_LEN + 1] = {0};

    if (!waf_modsec_is_enabled()) return NULL;

    /* Initialize intervention structure */
    WAF_G(intervention).status = WAF_HTTP_STATUS_OK;
    WAF_G(intervention).pause = 0;
    WAF_G(intervention).url = NULL;
    WAF_G(intervention).log = NULL;
    WAF_G(intervention).disruptive = 0;

    /* Generate or use provided transaction ID */
    if (WAF_G(modsec_transaction_id) != NULL && strlen(WAF_G(modsec_transaction_id)) > 0) {
        snprintf(tx_id, sizeof(tx_id), "%s", WAF_G(modsec_transaction_id));
    } else {
        generate_transaction_id(tx_id, sizeof(tx_id));
    }

    /* Store transaction ID */
    if (WAF_G(transaction_id) != NULL) efree(WAF_G(transaction_id));
    WAF_G(transaction_id) = estrndup(tx_id, strlen(tx_id));

    transaction = msc_new_transaction_with_id(g_modsec, g_rules, tx_id, NULL);
    if (transaction == NULL) {
        php_error(E_WARNING, "waf: Failed to create ModSecurity transaction");
        return NULL;
    }

    WAF_G(modsec_transaction) = transaction;
    return transaction;
}

void waf_modsec_transaction_end(void) {
    Transaction *transaction = WAF_G(modsec_transaction);

    if (transaction != NULL) {
        msc_transaction_cleanup(transaction);
        WAF_G(modsec_transaction) = NULL;
    }

    waf_modsec_intervention_cleanup();

    if (WAF_G(transaction_id) != NULL) {
        efree(WAF_G(transaction_id));
        WAF_G(transaction_id) = NULL;
    }
}

const char *waf_modsec_get_transaction_id(void) {
    return WAF_G(transaction_id);
}

/* ============================================================================
 * Connection Phase (Phase 1)
 * ============================================================================ */

int waf_modsec_process_connection(const char *client_ip, int client_port,
                                  const char *server_ip, int server_port) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_connection(transaction, client_ip, client_port, server_ip, server_port);
}

/* ============================================================================
 * URI Phase (Phase 2)
 * ============================================================================ */

int waf_modsec_process_uri(const char *uri, const char *method,
                           const char *http_version) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_uri(transaction, uri, method, http_version);
}

int waf_modsec_set_hostname(const char *hostname) {
#ifdef HAVE_MSC_SET_REQUEST_HOSTNAME
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL || hostname == NULL) return 0;
    return msc_set_request_hostname(transaction, (const unsigned char *)hostname);
#else
    /* Symbol unavailable on libmodsecurity < 3.0.13, SERVER_NAME comes from Host. */
    (void)hostname;
    return 0;
#endif
}

/* ============================================================================
 * Request Headers Phase (Phase 3)
 * ============================================================================ */

int waf_modsec_add_request_header(const char *name, size_t name_len,
                                  const char *value, size_t value_len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_add_n_request_header(transaction, (const unsigned char *)name,
                                    name_len, (const unsigned char *)value, value_len);
}

int waf_modsec_process_request_headers(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_request_headers(transaction);
}

/* ============================================================================
 * Request Body Phase (Phase 4)
 * ============================================================================ */

int waf_modsec_append_request_body(const unsigned char *body, size_t len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_append_request_body(transaction, body, len);
}

int waf_modsec_process_request_body(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_request_body(transaction);
}

/* ============================================================================
 * Response Headers Phase (Phase 5)
 * ============================================================================ */

int waf_modsec_add_response_header(const char *name, size_t name_len,
                                   const char *value, size_t value_len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_add_n_response_header(transaction, (const unsigned char *)name,
                                     name_len, (const unsigned char *)value, value_len);
}

int waf_modsec_process_response_headers(int status_code, const char *protocol) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_response_headers(transaction, status_code, protocol);
}

int waf_modsec_update_status_code(int status) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_update_status_code(transaction, status);
}

/* ============================================================================
 * Response Body Phase (Phase 4)
 * ============================================================================ */

int waf_modsec_append_response_body(const unsigned char *body, size_t len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_append_response_body(transaction, body, len);
}

int waf_modsec_process_response_body(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_response_body(transaction);
}

const char *waf_modsec_get_response_body(size_t *len) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL || len == NULL) return NULL;
    *len = msc_get_response_body_length(transaction);
    return msc_get_response_body(transaction);
}

/* ============================================================================
 * Logging Phase (Phase 7)
 * ============================================================================ */

int waf_modsec_process_logging(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;
    return msc_process_logging(transaction);
}

/* ============================================================================
 * Intervention Handling
 * ============================================================================ */

int waf_modsec_check_intervention(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    if (transaction == NULL) return 0;

    /* Free previous intervention resources before resetting */
    waf_modsec_intervention_cleanup();

    /* Reset intervention structure */
    WAF_G(intervention).status = WAF_HTTP_STATUS_OK;
    WAF_G(intervention).pause = 0;
    WAF_G(intervention).disruptive = 0;
    WAF_G(intervention).url = NULL;
    WAF_G(intervention).log = NULL;

    if (msc_intervention(transaction, &WAF_G(intervention))) {
        if (WAF_G(intervention).disruptive) {
            return WAF_G(intervention).status > 0
                       ? (int)WAF_G(intervention).status
                       : (int)WAF_G(modsec_block_status);
        }
    }
    return 0;
}

const char *waf_modsec_get_intervention_log(void) {
    return WAF_G(intervention).log;
}

const char *waf_modsec_get_intervention_url(void) {
    return WAF_G(intervention).url;
}

int waf_modsec_get_intervention_status(void) {
    return WAF_G(intervention).status > 0
               ? (int)WAF_G(intervention).status
               : (int)WAF_G(modsec_block_status);
}

void waf_modsec_intervention_cleanup(void) {
    if (WAF_G(intervention).url != NULL) {
        free(WAF_G(intervention).url);
        WAF_G(intervention).url = NULL;
    }
    if (WAF_G(intervention).log != NULL) {
        free(WAF_G(intervention).log);
        WAF_G(intervention).log = NULL;
    }
}

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

const char *waf_get_client_ip(void) {
    zval *server_vars = NULL;
    zval *forwarded_for = NULL;
    zval *remote_addr = NULL;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return "127.0.0.1";
    }

    /* Use X Forwarded For only when trusted, taking the leftmost (original
     * client) entry since the header is client controlled. */
    if (WAF_G(trust_proxy_headers)) {
        forwarded_for = zend_hash_str_find(Z_ARRVAL_P(server_vars), "HTTP_X_FORWARDED_FOR",
                                           sizeof("HTTP_X_FORWARDED_FOR") - 1);
        if (forwarded_for != NULL && Z_TYPE_P(forwarded_for) == IS_STRING &&
            Z_STRLEN_P(forwarded_for) > 0) {
            /* XFF may be "client, proxy1, proxy2" take the first token. */
            const char *xff = Z_STRVAL_P(forwarded_for);
            const char *comma = strchr(xff, ',');
            size_t ip_len = comma != NULL ? (size_t)(comma - xff) : Z_STRLEN_P(forwarded_for);
            /* Trim trailing whitespace. */
            while (ip_len > 0 && (xff[ip_len - 1] == ' ' || xff[ip_len - 1] == '\t')) {
                ip_len--;
            }
            if (ip_len > 0) {
                size_t copy_len = ip_len < sizeof(WAF_G(client_ip)) - 1
                                      ? ip_len
                                      : sizeof(WAF_G(client_ip)) - 1;
                /* NOLINTNEXTLINE(clang analyzer security.insecureAPI.DeprecatedOrUnsafeBufferHandling) */
                memcpy(WAF_G(client_ip), xff, copy_len);
                WAF_G(client_ip)[copy_len] = '\0';
                return WAF_G(client_ip);
            }
        }
    }

    /* Fall back to REMOTE_ADDR */
    remote_addr = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REMOTE_ADDR",
                                     sizeof("REMOTE_ADDR") - 1);
    if (remote_addr != NULL && Z_TYPE_P(remote_addr) == IS_STRING) {
        return Z_STRVAL_P(remote_addr);
    }

    return "127.0.0.1";
}

int waf_get_client_port(void) {
    zval *server_vars = NULL;
    zval *remote_port = NULL;
    long port = 0;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return 0;
    }

    remote_port = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REMOTE_PORT",
                                     sizeof("REMOTE_PORT") - 1);
    if (remote_port != NULL && Z_TYPE_P(remote_port) == IS_STRING) {
        port = strtol(Z_STRVAL_P(remote_port), NULL, 10);
        return (port > 0 && port <= WAF_MAX_PORT_NUMBER) ? (int)port : 0;
    }

    return 0;
}

const char *waf_get_server_ip(void) {
    zval *server_vars = NULL;
    zval *server_addr = NULL;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return "127.0.0.1";
    }

    server_addr = zend_hash_str_find(Z_ARRVAL_P(server_vars), "SERVER_ADDR",
                                     sizeof("SERVER_ADDR") - 1);
    if (server_addr != NULL && Z_TYPE_P(server_addr) == IS_STRING) {
        return Z_STRVAL_P(server_addr);
    }

    return "127.0.0.1";
}

int waf_get_server_port(void) {
    zval *server_vars = NULL;
    zval *server_port = NULL;
    long port = 0;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return WAF_DEFAULT_HTTP_PORT;
    }

    server_port = zend_hash_str_find(Z_ARRVAL_P(server_vars), "SERVER_PORT",
                                     sizeof("SERVER_PORT") - 1);
    if (server_port != NULL && Z_TYPE_P(server_port) == IS_STRING) {
        port = strtol(Z_STRVAL_P(server_port), NULL, 10);
        return (port > 0 && port <= WAF_MAX_PORT_NUMBER) ? (int)port : WAF_DEFAULT_HTTP_PORT;
    }

    return WAF_DEFAULT_HTTP_PORT;
}

const char *waf_get_http_version(void) {
    zval *server_vars = NULL;
    zval *protocol = NULL;

    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
    if (server_vars == NULL || Z_TYPE_P(server_vars) != IS_ARRAY) {
        return "1.1";
    }

    protocol = zend_hash_str_find(Z_ARRVAL_P(server_vars), "SERVER_PROTOCOL",
                                  sizeof("SERVER_PROTOCOL") - 1);
    if (protocol != NULL && Z_TYPE_P(protocol) == IS_STRING) {
        const char *proto = Z_STRVAL_P(protocol);
        if (strncmp(proto, "HTTP/", WAF_HTTP_PREFIX_LEN) == 0) {
            return proto + WAF_HTTP_PREFIX_LEN;
        }
        return proto;
    }

    return "1.1";
}

/* ============================================================================
 * High Level Request Processing
 * ============================================================================ */

int waf_modsec_process_request(void) {
    Transaction *transaction = NULL;
    zval *server_vars = NULL;
    zend_string *key = NULL;
    zval *val = NULL;
    int intervention_status = 0;
    const char *client_ip = NULL;
    int client_port = 0;
    const char *server_ip = NULL;
    const char *request_uri = NULL;
    const char *request_method = NULL;
    const char *http_version = NULL;
    const char *server_name = NULL;
    int server_port = 0;

    if (!waf_modsec_is_enabled()) return 0;

    /* Force the $_SERVER auto global to be populated NOW. Under
     * auto_globals_jit=On $_SERVER is realized lazily on first reference,
     * but waf_execute_ex fires on the first userland opcode BEFORE that
     * reference runs. Reading $_SERVER here otherwise yields a stale/empty
     * symbol table so every request looks like "GET /" from 127.0.0.1 with
     * no User-Agent and rule 1027 false-positives on benign endpoints.
     * zend_is_auto_global_str runs the JIT callback to populate
     * EG(symbol_table) regardless of jit. */
    zend_is_auto_global_str(ZEND_STRL("_SERVER"));

    /* Create transaction */
    transaction = waf_modsec_transaction_begin();
    if (transaction == NULL) return 0;

    /* Get connection info */
    client_ip = waf_get_client_ip();
    client_port = waf_get_client_port();
    server_ip = waf_get_server_ip();
    server_port = waf_get_server_port();

    /* Process connection phase */
    waf_modsec_process_connection(client_ip, client_port, server_ip, server_port);

    /* Get request info from $_SERVER */
    server_vars = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);

    request_uri = "/";
    request_method = "GET";
    http_version = waf_get_http_version();
    server_name = "localhost";

    if (server_vars != NULL && Z_TYPE_P(server_vars) == IS_ARRAY) {
        zval *uri_val = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REQUEST_URI",
                                           sizeof("REQUEST_URI") - 1);
        if (uri_val != NULL && Z_TYPE_P(uri_val) == IS_STRING) {
            request_uri = Z_STRVAL_P(uri_val);
        }

        zval *method_val = zend_hash_str_find(Z_ARRVAL_P(server_vars), "REQUEST_METHOD",
                                              sizeof("REQUEST_METHOD") - 1);
        if (method_val != NULL && Z_TYPE_P(method_val) == IS_STRING) {
            request_method = Z_STRVAL_P(method_val);
        }

        zval *name_val = zend_hash_str_find(Z_ARRVAL_P(server_vars), "SERVER_NAME",
                                            sizeof("SERVER_NAME") - 1);
        if (name_val != NULL && Z_TYPE_P(name_val) == IS_STRING) {
            server_name = Z_STRVAL_P(name_val);
        }
    }

    /* Set hostname */
    waf_modsec_set_hostname(server_name);

    /* Process URI phase */
    waf_modsec_process_uri(request_uri, request_method, http_version);

    /* Add request headers from $_SERVER (HTTP_* entries) */
    if (server_vars != NULL && Z_TYPE_P(server_vars) == IS_ARRAY) {
        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(server_vars), key, val) {
            if (key == NULL) continue;
            if (strncmp(ZSTR_VAL(key), "HTTP_", WAF_HTTP_PREFIX_LEN) != 0) continue;

            /* Convert HTTP_HEADER_NAME to Header Name format */
            const char *header_name = ZSTR_VAL(key) + WAF_HTTP_PREFIX_LEN;
            size_t header_name_len = ZSTR_LEN(key) - WAF_HTTP_PREFIX_LEN;
            char *formatted_name = estrndup(header_name, header_name_len);

            /* Convert underscores to hyphens and proper casing */
            for (size_t i = 0; i < header_name_len; i++) {
                if (formatted_name[i] == '_') {
                    formatted_name[i] = '-';
                } else if (formatted_name[i] >= 'A' && formatted_name[i] <= 'Z') {
                    if (i > 0 && formatted_name[i - 1] != '-') {
                        formatted_name[i] = (char)(formatted_name[i] + WAF_ASCII_UPPERCASE_OFFSET);
                    }
                }
            }

            if (Z_TYPE_P(val) == IS_STRING) {
                waf_modsec_add_request_header(formatted_name, header_name_len,
                                              Z_STRVAL_P(val), Z_STRLEN_P(val));
            }

            efree(formatted_name);
        }
        ZEND_HASH_FOREACH_END();

        /* Forward CONTENT_TYPE/CONTENT_LENGTH only when non empty. PHP FPM
         * always sets them (empty for bodyless GETs) and an empty Content
         * Length trips negated operators like rule 1071 since an empty value
         * fails the positive regex. An absent variable is skipped so mirror
         * that by forwarding only real values. */
        zval *ct = zend_hash_str_find(Z_ARRVAL_P(server_vars), "CONTENT_TYPE",
                                      sizeof("CONTENT_TYPE") - 1);
        if (ct != NULL && Z_TYPE_P(ct) == IS_STRING && Z_STRLEN_P(ct) > 0) {
            waf_modsec_add_request_header("Content-Type", WAF_CONTENT_TYPE_HEADER_LEN,
                                          Z_STRVAL_P(ct), Z_STRLEN_P(ct));
        }

        zval *cl = zend_hash_str_find(Z_ARRVAL_P(server_vars), "CONTENT_LENGTH",
                                      sizeof("CONTENT_LENGTH") - 1);
        if (cl != NULL && Z_TYPE_P(cl) == IS_STRING && Z_STRLEN_P(cl) > 0) {
            waf_modsec_add_request_header("Content-Length", WAF_CONTENT_LENGTH_HEADER_LEN,
                                          Z_STRVAL_P(cl), Z_STRLEN_P(cl));
        }
    }

    /* Process request headers phase */
    waf_modsec_process_request_headers();

    /* Check intervention after headers */
    intervention_status = waf_modsec_check_intervention();
    if (intervention_status > 0) {
        return intervention_status;
    }

    /* Append request body if available */
    if (WAF_G(request_body) != NULL && ZSTR_LEN(WAF_G(request_body)) > 0) {
        waf_modsec_append_request_body(
            (const unsigned char *)ZSTR_VAL(WAF_G(request_body)),
            ZSTR_LEN(WAF_G(request_body)));
    }

    /* Process request body phase */
    waf_modsec_process_request_body();

    /* Check intervention after body */
    intervention_status = waf_modsec_check_intervention();

    return intervention_status;
}

/* Locate the entity body within the buffered response. Under fpm-fcgi the
 * SAPI header frame ("Status: ...\r\n\r\n") is serialized through ub_write
 * ahead of the body, so the buffer holds frame+body, and RESPONSE_BODY rules
 * must inspect only the body. Returns a pointer past the first CRLFCRLF, its
 * length via *body_len, and the frame length via *frame_len (0 if none). */
static const char *waf_response_body_start(const zend_string *buf,
                                           size_t *body_len,
                                           size_t *frame_len) {
    const char *start = ZSTR_VAL(buf);
    size_t total = ZSTR_LEN(buf);
    const char *p = start;
    const char *end = start + total;

    while (p + 4 <= end) {
        if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n') {
            size_t skip = (size_t)(p - start) + 4;
            *frame_len = skip;
            *body_len = total - skip;
            return start + skip;
        }
        p++;
    }

    *frame_len = 0;
    *body_len = total;
    return start;
}

/* Rebuild the SAPI header frame with its Content-Length header updated to
 * new_len. Under fpm-fcgi the frame is "Name: value\r\n" lines terminated by a
 * blank line. A RESPONSE_BODY rewrite changing the body length would leave the
 * app's Content-Length stale (client truncation/hang), so this replaces that
 * one header line. Returns NULL (no change) when there is no Content-Length
 * header (chunked/Close-delimited, where a length change is harmless).
 * Exact-name match (colon at offset 14) so e.g. "Content-Length-Type" isn't
 * touched. */
static zend_string *waf_frame_update_content_length(const char *frame,
                                                     size_t frame_len,
                                                     size_t new_len) {
    smart_str out = {0};
    const char *end = frame + frame_len;
    const char *line_start = frame;
    zend_bool found = 0;

    while (line_start < end) {
        const char *eol = memchr(line_start, '\r', end - line_start);
        if (eol == NULL || eol + 1 >= end || eol[1] != '\n') {
            /* Non-CRLF line, stop and flush the rest verbatim below. */
            break;
        }
        const char *colon = memchr(line_start, ':', eol - line_start);
        if (colon != NULL &&
            (size_t)(colon - line_start) == sizeof("Content-Length") - 1 &&
            strncasecmp(line_start, "Content-Length", sizeof("Content-Length") - 1) == 0) {
            char numbuf[32];
            int nlen = snprintf(numbuf, sizeof(numbuf), "%zu", new_len);
            smart_str_appendl(&out, "Content-Length: ", sizeof("Content-Length: ") - 1);
            smart_str_appendl(&out, numbuf, nlen);
            smart_str_appendl(&out, "\r\n", 2);
            found = 1;
        } else {
            smart_str_appendl(&out, line_start, eol - line_start);
            smart_str_appendl(&out, "\r\n", 2);
        }
        line_start = eol + 2;
    }

    /* Flush any trailing remainder verbatim. */
    if (line_start < end) {
        smart_str_appendl(&out, line_start, end - line_start);
    }

    if (!found) {
        /* No Content-Length header: no frame fixup needed. */
        smart_str_free(&out);
        return NULL;
    }

    smart_str_0(&out);
    return out.s;
}

/* ============================================================================
 * High Level Response Processing
 * ============================================================================ */

int waf_modsec_process_response(void) {
    Transaction *transaction = WAF_G(modsec_transaction);
    int intervention_status = 0;
    int response_code = 0;
    /* msc_process_response_headers expects the full protocol string ("HTTP/1.1"),
     * not just the version number that waf_get_http_version returns. */
    const char *server_protocol = "HTTP/1.1";
    {
        zval *sv = zend_hash_str_find(&EG(symbol_table), "_SERVER", sizeof("_SERVER") - 1);
        if (sv != NULL && Z_TYPE_P(sv) == IS_ARRAY) {
            zval *pv = zend_hash_str_find(Z_ARRVAL_P(sv), "SERVER_PROTOCOL",
                                          sizeof("SERVER_PROTOCOL") - 1);
            if (pv != NULL && Z_TYPE_P(pv) == IS_STRING)
                server_protocol = Z_STRVAL_P(pv);
        }
    }
    sapi_header_struct *h = NULL;
    const char *body_ptr = NULL;
    size_t body_len = 0;
    size_t frame_len = 0;

    if (transaction == NULL) return 0;

    /* Get response code */
    response_code = SG(sapi_headers).http_response_code;
    if (response_code == 0) {
        response_code = WAF_HTTP_STATUS_OK;
    }

    /* Add response headers from SAPI */
    h = zend_llist_get_first(&SG(sapi_headers).headers);
    while (h != NULL) {
        char *colon = strchr(h->header, ':');
        if (colon != NULL) {
            size_t name_len = colon - h->header;
            const char *value = colon + 1;
            while (*value == ' ') value++;

            waf_modsec_add_response_header(h->header, name_len, value, strlen(value));
        }
        h = zend_llist_get_next(&SG(sapi_headers).headers);
    }

    /* Process response headers phase */
    waf_modsec_process_response_headers(response_code, server_protocol);

    /* Check intervention after headers */
    intervention_status = waf_modsec_check_intervention();
    if (intervention_status > 0) {
        /* Defer transaction end and logging to the caller (RSHUTDOWN) so the
         * block response can still read the transaction ID and redirect URL. */
        return intervention_status;
    }

    /* Feed the ENTITY BODY (not the SAPI header frame) to phase 4. Under
     * fpm-fcgi the buffer holds frame+body, so skip past the header frame so
     * RESPONSE_BODY rules inspect only the body. Skipped when body inspection
     * is disabled (modsec_response_body_limit == 0). */
    if (WAF_G(modsec_response_body_limit) != 0 &&
        WAF_G(response_body) != NULL && ZSTR_LEN(WAF_G(response_body)) > 0) {
        body_ptr = waf_response_body_start(WAF_G(response_body), &body_len,
                                           &frame_len);
        if (body_len > 0) {
            waf_modsec_append_response_body((const unsigned char *)body_ptr,
                                            body_len);
        }
    }

    /* Process response body phase */
    if (WAF_G(modsec_response_body_limit) != 0) {
        waf_modsec_process_response_body();
    }

    /* If libmodsecurity rewrote the body, replace the body portion of the buffer
     * (preserving the frame prefix). Skipped on overflow: a rewrite can't be
     * redelivered once the prefix already streamed. If the length changed,
     * update the frame's Content-Length. */
    if (!WAF_G(response_body_sent) && WAF_G(modsec_response_body_limit) != 0 &&
        WAF_G(response_body) != NULL && body_len > 0) {
        size_t new_len = 0;
        const char *new_body = waf_modsec_get_response_body(&new_len);
        if (new_body != NULL && new_len > 0) {
            const char *frame = ZSTR_VAL(WAF_G(response_body));
            size_t use_frame_len = frame_len;
            zend_string *new_frame = NULL;
            if (new_len != body_len) {
                new_frame = waf_frame_update_content_length(frame, frame_len,
                                                             new_len);
                if (new_frame != NULL) {
                    frame = ZSTR_VAL(new_frame);
                    use_frame_len = ZSTR_LEN(new_frame);
                }
            }

            zend_string *replaced = zend_string_alloc(use_frame_len + new_len, 0);
            /* NOLINTNEXTLINE(clang analyzer security.insecureAPI.DeprecatedOrUnsafeBufferHandling) */
            memcpy(ZSTR_VAL(replaced), frame, use_frame_len);
            /* NOLINTNEXTLINE(clang analyzer security.insecureAPI.DeprecatedOrUnsafeBufferHandling) */
            memcpy(ZSTR_VAL(replaced) + use_frame_len, new_body, new_len);
            ZSTR_VAL(replaced)[use_frame_len + new_len] = '\0';
            if (new_frame != NULL) {
                zend_string_release(new_frame);
            }
            zend_string_release(WAF_G(response_body));
            WAF_G(response_body) = replaced;
        }
    }

    /* Check intervention after body */
    intervention_status = waf_modsec_check_intervention();

    /* Note logging + transaction end are deferred to the caller (RSHUTDOWN). */
    return intervention_status;
}

#ifdef __cplusplus
}
#endif
