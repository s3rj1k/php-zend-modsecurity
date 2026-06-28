#ifndef PHP_WAF_H
#define PHP_WAF_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "SAPI.h"
#include "ext/standard/file.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "php.h"
#include "php_ini.h"
#include "zend_exceptions.h"

/* ModSecurity C API */
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"

#define PHP_WAF_VERSION "1.1.0"
#define PHP_WAF_EXTNAME "waf"

ZEND_BEGIN_MODULE_GLOBALS(waf)
/* Main enable/disable flag */
zend_bool enabled;

/* Trust proxy provided client IP (X Forwarded For). Off by default so a
 * client cannot spoof its source IP for IP based rules. */
zend_bool trust_proxy_headers;

/* Request/Response body buffers */
zend_string *request_body;
zend_string *response_body;

/* Per-request scratch buffer for waf_get_client_ip. In request globals (not a
 * function static) so it is per-thread under ZTS. Valid for the request that
 * fills it. */
char client_ip[64];

/* True once the response body buffer has been flushed to the client on
 * overflow (response_body_limit reached). The retained buffer is still fed
 * to ModSecurity for inspection at RSHUTDOWN, but it must not be flushed a
 * second time (the bytes already streamed out, in order, during the request). */
zend_bool response_body_sent;

/* ModSecurity configuration */
char *modsec_rules_file;
char *modsec_rules_inline;
zend_long modsec_block_status;
char *modsec_debug_log;
zend_long modsec_debug_level;
char *modsec_transaction_id;
char *modsec_audit_log;
char *modsec_audit_log_parts;
/* Max request body bytes buffered for inspection. 0 disables it. */
zend_long modsec_request_body_limit;
zend_long modsec_response_body_limit;

/* ModSecurity per request state */
Transaction *modsec_transaction;
ModSecurityIntervention intervention;
zend_bool modsec_processed;

/* Non zero (block status code) once the request was blocked in RINIT. The block
 * page is already sent and the transaction finalized there, so the rest of the
 * request must short circuit without running user code or emitting further
 * output. Kept across the RINIT->execute_ex->RSHUTDOWN path. */
int modsec_blocked;

/* Transaction ID for this request */
char *transaction_id;
ZEND_END_MODULE_GLOBALS(waf)

#ifdef ZTS
#define WAF_G(v) TSRMG(waf_globals_id, zend_waf_globals *, v)
#else
#define WAF_G(v) (waf_globals.v)
extern zend_waf_globals waf_globals;
#endif

extern zend_module_entry waf_module_entry;
#define phpext_waf_ptr &waf_module_entry

/* Request body capture */
zend_string *waf_capture_request_body(void);

/* Global initialization */
void waf_init_globals(zend_waf_globals *globals);

/* Original SAPI output writer (saved before the ub_write hook was installed).
 * Use to write output that must reach the client immediately without buffering
 * for response inspection (e.g. block pages). */
size_t (*waf_original_ub_write(void))(const char *str, size_t str_len);

/* ModSecurity integration functions (from modsec.h) */
int waf_modsec_process_request(void);
int waf_modsec_process_response(void);

#endif
