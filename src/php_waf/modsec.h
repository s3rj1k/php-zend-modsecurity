#ifndef PHP_WAF_MODSEC_H
#define PHP_WAF_MODSEC_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend_smart_str.h"

/* ModSecurity C API */
#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "modsecurity/transaction.h"
#include "modsecurity/debug_log.h"
#include "modsecurity/audit_log.h"

/* ============================================================================
 * Constants
 * ============================================================================ */

/* Max request body size captured for inspection (10MB). Default for the
 * waf.modsec_request_body_limit INI, and 0 disables request body inspection. */
#define WAF_REQUEST_BODY_MAX_SIZE ((size_t)(10 * 1024 * 1024))

/* Max response body size captured for inspection (10MB) */
#define WAF_RESPONSE_BODY_MAX_SIZE ((size_t)(10 * 1024 * 1024))

/* HTTP status code constants */
#define WAF_HTTP_STATUS_OK           200
#define WAF_HTTP_STATUS_BAD_REQUEST  400
#define WAF_HTTP_STATUS_FORBIDDEN    403
#define WAF_HTTP_STATUS_NOT_FOUND    404
#define WAF_HTTP_STATUS_SERVER_ERROR 500

/* HTTP protocol constants */
#define WAF_DEFAULT_HTTP_PORT  80
#define WAF_HTTP_PREFIX_LEN    5
#define WAF_MAX_PORT_NUMBER    65535

/* Header name length constants */
#define WAF_CONTENT_TYPE_HEADER_LEN    12
#define WAF_CONTENT_LENGTH_HEADER_LEN  14

/* ASCII constants */
#define WAF_ASCII_UPPERCASE_OFFSET  32

/* Transaction ID length */
#define WAF_TRANSACTION_ID_LEN  32

/* ============================================================================
 * ModSecurity Module Lifecycle Functions
 * ============================================================================ */

/* Initialize ModSecurity once per process. Returns 0 on success, 1 on failure. */
int waf_modsec_init(void);

/* Shut down ModSecurity once per process. */
void waf_modsec_shutdown(void);

/* Returns 1 if enabled and initialized, 0 otherwise. */
zend_bool waf_modsec_is_enabled(void);

/* ============================================================================
 * Transaction Lifecycle Functions
 * ============================================================================ */

/* Create a transaction for the current request. Returns it or NULL. */
Transaction *waf_modsec_transaction_begin(void);

/* End and clean up the current transaction. */
void waf_modsec_transaction_end(void);

/* Returns the current transaction ID or NULL. */
const char *waf_modsec_get_transaction_id(void);

/* ============================================================================
 * Connection Phase (Phase 1)
 * ============================================================================ */

/* Process the connection phase. Returns 0 on success, non zero on error. */
int waf_modsec_process_connection(const char *client_ip, int client_port,
                                  const char *server_ip, int server_port);

/* ============================================================================
 * URI Phase (Phase 2)
 * ============================================================================ */

/* Process the URI phase once the full request URI is known. */
int waf_modsec_process_uri(const char *uri, const char *method,
                           const char *http_version);

/* Set the request hostname. */
int waf_modsec_set_hostname(const char *hostname);

/* ============================================================================
 * Request Headers Phase (Phase 3)
 * ============================================================================ */

/* Add a request header to the transaction. */
int waf_modsec_add_request_header(const char *name, size_t name_len,
                                  const char *value, size_t value_len);

/* Evaluate rules against the collected request headers. */
int waf_modsec_process_request_headers(void);

/* ============================================================================
 * Request Body Phase (Phase 4)
 * ============================================================================ */

/* Append a request body chunk for streaming processing. */
int waf_modsec_append_request_body(const unsigned char *body, size_t len);

/* Evaluate rules against the request body. */
int waf_modsec_process_request_body(void);

/* ============================================================================
 * Response Headers Phase (Phase 5)
 * ============================================================================ */

/* Add a response header to the transaction. */
int waf_modsec_add_response_header(const char *name, size_t name_len,
                                   const char *value, size_t value_len);

/* Process the response headers phase. */
int waf_modsec_process_response_headers(int status_code, const char *protocol);

/* Update the HTTP status code in the transaction. */
int waf_modsec_update_status_code(int status);

/* ============================================================================
 * Response Body Phase (Phase 4)
 * ============================================================================ */

/* Append a response body chunk. */
int waf_modsec_append_response_body(const unsigned char *body, size_t len);

/* Evaluate rules against the response body. */
int waf_modsec_process_response_body(void);

/* Returns the (possibly modified) response body, or NULL. */
const char *waf_modsec_get_response_body(size_t *len);

/* ============================================================================
 * Logging Phase (Phase 7)
 * ============================================================================ */

/* Run audit logging and final transaction logging. */
int waf_modsec_process_logging(void);

/* ============================================================================
 * Intervention Handling
 * ============================================================================ */

/* Returns 0 if no intervention, or the block status code if disruptive. */
int waf_modsec_check_intervention(void);

/* Returns the intervention log message or NULL. */
const char *waf_modsec_get_intervention_log(void);

/* Returns the intervention redirect URL or NULL. */
const char *waf_modsec_get_intervention_url(void);

/* Returns the intervention status code. */
int waf_modsec_get_intervention_status(void);

/* Free intervention resources. */
void waf_modsec_intervention_cleanup(void);

/* ============================================================================
 * High Level Request/Response Processing
 * ============================================================================ */

/* Run all request phases, checking intervention after each.
 * Returns 0 if allowed, or the block status if blocked. */
int waf_modsec_process_request(void);

/* Run all response phases, checking intervention after each.
 * Returns 0 if allowed, or the block status if blocked. */
int waf_modsec_process_response(void);

/* ============================================================================
 * HTTP Response Helpers
 * ============================================================================ */

/* Emit the HTTP error response for a blocked request. */
void waf_send_block_response(int status_code);

/* ============================================================================
 * Utility Functions
 * ============================================================================ */

/* Returns the client IP from $_SERVER. */
const char *waf_get_client_ip(void);

/* Returns the client port from $_SERVER. */
int waf_get_client_port(void);

/* Returns the server IP from $_SERVER. */
const char *waf_get_server_ip(void);

/* Returns the server port from $_SERVER. */
int waf_get_server_port(void);

/* Returns the HTTP version from $_SERVER (e.g. "1.1"). */
const char *waf_get_http_version(void);

#endif /* PHP_WAF_MODSEC_H */
