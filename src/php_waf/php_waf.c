#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "modsec.h"
#include "php_waf.h"
#include <strings.h>

/* HTTP status constants (local) body size limits live in modsec.h. */
#define HTTP_STATUS_OK 200
#define HTTP_STATUS_FORBIDDEN 403

// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
ZEND_DECLARE_MODULE_GLOBALS(waf)

// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
/* Original execute_ex. Process-global, set in MINIT, restored in MSHUTDOWN
 * (both single-threaded under ZTS), read-only elsewhere. ZTS-safe. */
// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
static void (*original_execute_ex)(zend_execute_data *execute_data) = NULL;

/* Original SAPI ub_write. Same lifecycle as original_execute_ex. ZTS-safe. */
// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
static size_t (*original_ub_write)(const char *str, size_t len) = NULL;

/* Original SAPI read_post. Hooked to tee multipart bodies (see waf_read_post).
 * Same MINIT/MSHUTDOWN lifecycle, ZTS-safe. */
// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
static size_t (*original_read_post)(char *buffer, size_t count_bytes) = NULL;

/* Accessor for original ub_write so modsec.c can emit output that must reach
 * the client immediately, bypassing the response body buffer. */
size_t (*waf_original_ub_write(void))(const char *str, size_t str_len) {
  return original_ub_write;
}

/* SAPI ub_write hook buffering the response prefix for ModSecurity inspection.
 *
 * Buffers the first modsec_response_body_limit bytes (default 10MB) for
 * inspection at RSHUTDOWN. On overflow the buffer is flushed to the client (to
 * keep output ordered) but retained for inspection, and response_body_sent
 * guards a double flush. Bytes beyond the limit stream straight through (only the
 * leading prefix is inspected, to bound memory). A limit of 0 disables response
 * body inspection entirely. */
static size_t waf_ub_write(const char *str, size_t len) {
  /* Blocked in RINIT, block page already sent, transaction finalized. Discard
   * further output (FPM's "No input file specified." for missing scripts,
   * auto_prepend output, stray warnings) so it doesn't append to the block. */
  if (WAF_G(modsec_blocked)) {
    return len;
  }

  /* Buffer the response prefix for inspection at RSHUTDOWN when the WAF is
   * enabled and body inspection is on.
   *
   * NOT gated on waf_modsec_is_enabled() or an active transaction. sapi_activate
   * reads POST data before RINIT, so a malformed multipart body raises an
   * E_WARNING through ub_write before the transaction exists. If streamed it
   * would trigger a default 200 header frame and then precede a later block's
   * Status header, corrupting the status line (the block's "Status: 403" lands
   * in the body and the client sees 200). Buffering it lets the block path
   * discard it. Keying the gate on waf_modsec_is_enabled() breaks this on builds
   * where the flag is not yet true at sapi_activate time, leaking the warning. */
  if (WAF_G(enabled) && WAF_G(modsec_response_body_limit) != 0) {

    /* Buffer already flushed on overflow, pass everything through directly.
     * The retained prefix is inspected at RSHUTDOWN but not redelivered. */
    if (WAF_G(response_body_sent)) {
      return original_ub_write(str, len);
    }

    size_t current_len = WAF_G(response_body) ? ZSTR_LEN(WAF_G(response_body)) : 0;
    size_t max_size = (size_t)WAF_G(modsec_response_body_limit);

    if (current_len < max_size) {
      size_t remaining = max_size - current_len;
      size_t to_buffer = (len < remaining) ? len : remaining;

      /* Buffer this chunk for inspection up to max_size */
      if (WAF_G(response_body) == NULL) {
        WAF_G(response_body) = zend_string_init(str, to_buffer, 0);
      } else {
        WAF_G(response_body) =
            zend_string_extend(WAF_G(response_body), current_len + to_buffer, 0);
        /* NOLINTNEXTLINE(clang analyzer security.insecureAPI.DeprecatedOrUnsafeBufferHandling) */
        memcpy(ZSTR_VAL(WAF_G(response_body)) + current_len, str, to_buffer);
        ZSTR_VAL(WAF_G(response_body))[current_len + to_buffer] = '\0';
      }

      if (to_buffer < len) {
        /* Buffer now full, flush the inspected prefix to the client to keep
         * output ordered, RETAIN it for ModSecurity inspection at RSHUTDOWN
         * (response_body_sent guards the double flush), then pass the overflow
         * tail through directly. Return len, not the tail write result: the
         * to_buffer prefix bytes are already accounted for in the flush above. */
        original_ub_write(ZSTR_VAL(WAF_G(response_body)),
                          ZSTR_LEN(WAF_G(response_body)));
        WAF_G(response_body_sent) = 1;
        original_ub_write(str + to_buffer, len - to_buffer);
        return len;
      }
      return len;
    }

    /* Buffer exactly full from a prior chunk (no overflow yet), flush it, mark
     * sent, and pass this chunk through. */
    original_ub_write(ZSTR_VAL(WAF_G(response_body)),
                      ZSTR_LEN(WAF_G(response_body)));
    WAF_G(response_body_sent) = 1;
    return original_ub_write(str, len);
  }

  /* Send the output via the original ub_write */
  return original_ub_write(str, len);
}

/* SAPI read_post hook teeing multipart bodies for ModSecurity.
 *
 * php://input is empty for multipart/form-data because rfc1867 consumes the
 * body straight from the post reader into $_FILES, never into
 * SG(request_info).request_body. Teeing the raw bytes here lets the request
 * body phase inspect it. Tee'd only for multipart (non-multipart is already
 * in php://input), driven in RINIT so it never fires during the
 * sapi_deactivate drain (which would allocate after RSHUTDOWN freed it). */
static size_t waf_read_post(char *buffer, size_t count_bytes) {
  /* Defensive NULL check: FPM always provides a read_post handler, but guard
   * the deref to avoid a SIGSEGV if the pointer is somehow unset. */
  if (original_read_post == NULL) {
    return 0;
  }

  size_t n = original_read_post(buffer, count_bytes);
  if (n == 0) {
    return n;
  }

  if (!WAF_G(enabled)) {
    return n;
  }

  /* Tee only multipart POST bodies. rfc1867 consumes them during
   * sapi_activate (before RINIT), so php://input is empty afterwards and the
   * hook is the only capture path. Other bodies stay in php://input, which
   * waf_capture_request_body reads in RINIT, and teeing those here would
   * allocate a duplicate the caller overwrites (leak). */
  const char *ct = SG(request_info).content_type;
  const char *rm = SG(request_info).request_method;
  if (ct == NULL || strncasecmp(ct, "multipart/form-data", 19) != 0) {
    return n;
  }
  if (rm == NULL || strcmp(rm, "POST") != 0) {
    return n;
  }

  size_t current_len = WAF_G(request_body) ? ZSTR_LEN(WAF_G(request_body)) : 0;
  size_t max_size = (size_t)WAF_G(modsec_request_body_limit);
  if (max_size == 0 || current_len >= max_size) {
    return n;
  }

  size_t remaining = max_size - current_len;
  size_t to_buffer = (n < remaining) ? n : remaining;

  if (WAF_G(request_body) == NULL) {
    WAF_G(request_body) = zend_string_init(buffer, to_buffer, 0);
  } else {
    WAF_G(request_body) =
        zend_string_extend(WAF_G(request_body), current_len + to_buffer, 0);
    /* NOLINTNEXTLINE(clang analyzer security.insecureAPI.DeprecatedOrUnsafeBufferHandling) */
    memcpy(ZSTR_VAL(WAF_G(request_body)) + current_len, buffer, to_buffer);
    ZSTR_VAL(WAF_G(request_body))[current_len + to_buffer] = '\0';
  }

  return n;
}

/* execute_ex hook. Request inspection runs in RINIT (before FPM resolves the
 * script) so path rules fire even for non-existent URIs. This hook bails out
 * here when RINIT already blocked (modsec_blocked). execute_ex runs inside
 * php_execute_script's zend_try, so zend_bailout() is safe here (unlike RINIT,
 * where it lands in php_request_startup's zend_try, returns FAILURE, and FPM
 * kills the worker). The inspection block below is a no-op fallback. RINIT
 * sets modsec_processed, so the guard is always false. */
static void waf_execute_ex(zend_execute_data *execute_data) {
  /* Blocked in RINIT, block page already sent. Bail out at this safe point. */
  if (WAF_G(modsec_blocked)) {
    zend_bailout();
  }

  int modsec_intervention = 0;

  /* Process once per request, for user space code only */
  if (!WAF_G(modsec_processed) && execute_data->func &&
      ZEND_USER_CODE(execute_data->func->type)) {

    WAF_G(modsec_processed) = 1;

    /* Run ModSecurity request phases now that $_SERVER is available */
    if (waf_modsec_is_enabled()) {
      modsec_intervention = waf_modsec_process_request();
      if (modsec_intervention > 0) {
        /* Blocked by ModSecurity, drop buffered body (e.g. auto_prepend_file
         * output), send the error response, then end the transaction. */
        if (WAF_G(response_body)) {
          zend_string_release(WAF_G(response_body));
          WAF_G(response_body) = NULL;
        }
        waf_send_block_response(modsec_intervention);

        /* Reflect the block status into the transaction so the audit log
         * reports the final code, not the app's original. */
        waf_modsec_update_status_code(modsec_intervention);

        /* Cleanup transaction */
        waf_modsec_process_logging();
        waf_modsec_transaction_end();

        /* Bail out back to the main loop */
        zend_bailout();
      }
    }
  }

  /* Call the original execute_ex */
  original_execute_ex(execute_data);
}

PHP_INI_BEGIN()
STD_PHP_INI_BOOLEAN("waf.enabled", "0", PHP_INI_SYSTEM, OnUpdateBool, enabled,
                    zend_waf_globals, waf_globals)
STD_PHP_INI_BOOLEAN("waf.trust_proxy_headers", "0", PHP_INI_SYSTEM, OnUpdateBool,
                    trust_proxy_headers, zend_waf_globals, waf_globals)
/* ModSecurity INI entries */
STD_PHP_INI_ENTRY("waf.modsec_rules_file", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_rules_file, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_rules_inline", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_rules_inline, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_block_status", "403", PHP_INI_SYSTEM,
                  OnUpdateLongGEZero, modsec_block_status, zend_waf_globals,
                  waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_debug_log", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_debug_log, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_debug_level", "0", PHP_INI_SYSTEM,
                  OnUpdateLongGEZero, modsec_debug_level, zend_waf_globals,
                  waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_transaction_id", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_transaction_id, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_audit_log", "", PHP_INI_SYSTEM, OnUpdateString,
                  modsec_audit_log, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_audit_log_parts", "ABCFHZ", PHP_INI_SYSTEM,
                  OnUpdateString, modsec_audit_log_parts, zend_waf_globals, waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_response_body_limit", "10485760", PHP_INI_SYSTEM,
                  OnUpdateLongGEZero, modsec_response_body_limit, zend_waf_globals,
                  waf_globals)
STD_PHP_INI_ENTRY("waf.modsec_request_body_limit", "10485760", PHP_INI_SYSTEM,
                  OnUpdateLongGEZero, modsec_request_body_limit, zend_waf_globals,
                  waf_globals)
PHP_INI_END()

void waf_init_globals(zend_waf_globals *globals) {
  globals->enabled = 0;
  globals->trust_proxy_headers = 0;
  globals->request_body = NULL;
  globals->response_body = NULL;
  globals->response_body_sent = 0;

  /* ModSecurity globals */
  globals->modsec_rules_file = NULL;
  globals->modsec_rules_inline = NULL;
  globals->modsec_block_status = HTTP_STATUS_FORBIDDEN;
  globals->modsec_debug_log = NULL;
  globals->modsec_debug_level = 0;
  globals->modsec_transaction_id = NULL;
  globals->modsec_audit_log = NULL;
  globals->modsec_audit_log_parts = NULL;
  globals->modsec_request_body_limit = WAF_REQUEST_BODY_MAX_SIZE;
  globals->modsec_response_body_limit = WAF_RESPONSE_BODY_MAX_SIZE;
  globals->modsec_transaction = NULL;
  globals->modsec_processed = 0;
  globals->modsec_blocked = 0;
  globals->transaction_id = NULL;

  /* Initialize intervention */
  globals->intervention.status = HTTP_STATUS_OK;
  globals->intervention.pause = 0;
  globals->intervention.url = NULL;
  globals->intervention.log = NULL;
  globals->intervention.disruptive = 0;
}

/* Capture the request body from php://input for inspection.
 *
 * Covers every body except multipart POST (teed by waf_read_post during
 * sapi_activate, since rfc1867 consumes them out from under php://input).
 * For non-POST methods (PUT/PATCH/...) php://input reads just in time through
 * the SAPI read_post hook, so the body is also left in
 * SG(request_info).request_body for the application. */
zend_string *waf_capture_request_body(void) {
  /* Already captured by the read_post hook, keep it. */
  if (WAF_G(request_body) != NULL) {
    return WAF_G(request_body);
  }

  php_stream *stream = php_stream_open_wrapper("php://input", "rb", REPORT_ERRORS, NULL);
  if (stream == NULL) {
    return zend_string_init("", 0, 0);
  }

  /* Read up to the request body inspection limit. 0 disables inspection
   * (php_stream_copy_to_mem returns empty for maxlen 0). */
  zend_string *content =
      php_stream_copy_to_mem(stream, (size_t)WAF_G(modsec_request_body_limit), 0);
  php_stream_close(stream);

  /* If the hook teed a body during this read, prefer it and discard the
   * duplicate (covers POST multipart with enable_post_data_reading=Off). */
  if (WAF_G(request_body) != NULL) {
    if (content != NULL) {
      zend_string_release(content);
    }
    return WAF_G(request_body);
  }

  if (content == NULL) {
    return zend_string_init("", 0, 0);
  }
  return content;
}

// NOLINTNEXTLINE(bugprone easily swappable parameters)
PHP_MINIT_FUNCTION(waf) {
  (void)type;
  (void)module_number;

  ZEND_INIT_MODULE_GLOBALS(waf, waf_init_globals, NULL);
  REGISTER_INI_ENTRIES();

  /* Under SAPIs other than PHP-FPM the extension loads as a registered no-op
   * so that tooling (php -m, php -i) and CI can verify the .so is valid and
   * INI directives are present without a fatal error. The SAPI hooks and
   * ModSecurity engine are only installed under fpm-fcgi, where the per-request
   * RINIT/RSHUTDOWN lifecycle and per-request memory isolation are guaranteed. */
  if (strcmp(sapi_module.name, "fpm-fcgi") != 0) {
    return SUCCESS;
  }

  /* Initialize ModSecurity */
  waf_modsec_init();

  /* Hook execute_ex to process ModSecurity after $_SERVER is populated */
  if (original_execute_ex == NULL) {
    original_execute_ex = zend_execute_ex;
    zend_execute_ex = waf_execute_ex;
  }

  /* Hook SAPI ub_write to capture response body for ModSecurity */
  if (original_ub_write == NULL) {
    original_ub_write = sapi_module.ub_write;
    sapi_module.ub_write = waf_ub_write;
  }

  /* Hook SAPI read_post to tee multipart request bodies for ModSecurity */
  if (original_read_post == NULL) {
    original_read_post = sapi_module.read_post;
    sapi_module.read_post = waf_read_post;
  }

  return SUCCESS;
}

// NOLINTNEXTLINE(bugprone easily swappable parameters)
PHP_MSHUTDOWN_FUNCTION(waf) {
  (void)type;
  (void)module_number;

  /* Restore original execute_ex */
  if (original_execute_ex != NULL) {
    zend_execute_ex = original_execute_ex;
    original_execute_ex = NULL;
  }

  /* Restore original SAPI ub_write */
  if (original_ub_write != NULL) {
    sapi_module.ub_write = original_ub_write;
    original_ub_write = NULL;
  }

  /* Restore original SAPI read_post */
  if (original_read_post != NULL) {
    sapi_module.read_post = original_read_post;
    original_read_post = NULL;
  }

  /* Cleanup ModSecurity */
  waf_modsec_shutdown();

  UNREGISTER_INI_ENTRIES();
  return SUCCESS;
}

// NOLINTNEXTLINE(bugprone easily swappable parameters)
PHP_RINIT_FUNCTION(waf) {
  (void)type;
  (void)module_number;

#if defined(ZTS) && defined(COMPILE_DL_WAF)
  ZEND_TSRMLS_CACHE_UPDATE();
#endif

  if (!WAF_G(enabled)) {
    return SUCCESS;
  }

  /* Release any response body buffered BEFORE RINIT. sapi_activate (which runs
   * before module RINITs) reads POST data and a malformed multipart body emits
   * an E_WARNING through ub_write that waf_ub_write buffers into response_body.
   * Nulling the pointer without releasing would leak that zend_string every
   * request. The buffered bytes are not meaningful response output (they are a
   * startup warning) and are intentionally dropped here. A later WAF block
   * re discards response_body, and the allow path flushes only post RINIT
   * output. */
  if (WAF_G(response_body) != NULL) {
    zend_string_release(WAF_G(response_body));
  }
  /* NOTE: WAF_G(request_body) is intentionally NOT cleared here. For a
   * multipart POST it was already teed by waf_read_post during sapi_activate
   * (before RINIT), and clearing would discard it (leak + lost inspection). The
   * prior RSHUTDOWN released any previous value. */
  WAF_G(response_body) = NULL;
  WAF_G(response_body_sent) = 0;
  WAF_G(modsec_transaction) = NULL;
  WAF_G(modsec_processed) = 0;
  WAF_G(modsec_blocked) = 0;
  WAF_G(transaction_id) = NULL;

  /* Initialize intervention for this request */
  WAF_G(intervention).status = HTTP_STATUS_OK;
  WAF_G(intervention).pause = 0;
  WAF_G(intervention).url = NULL;
  WAF_G(intervention).log = NULL;
  WAF_G(intervention).disruptive = 0;

  /* Capture the request body. Multipart POST is already teed by waf_read_post
   * during sapi_activate (before RINIT), and everything else is read from
   * php://input here. */
  if (WAF_G(request_body) == NULL) {
    WAF_G(request_body) = waf_capture_request_body();
  }

  /* Run request phases here, before FPM resolves SCRIPT_FILENAME. execute_ex
   * fires only during php_execute_script (after php_fopen_primary_script), so a
   * non-existent script (/admin, /.env, ...) would 404 before it ran, bypassing
   * path rules. $_SERVER is populated by sapi_activate (before RINIT), forced
   * by zend_is_auto_global_str under auto_globals_jit.
   *
   * On a block, send the response and finalize the transaction here, but do NOT
   * zend_bailout(). RINIT runs inside php_request_startup()'s zend_try, so a
   * bailout returns FAILURE and FPM kills the worker (exit 70) per blocked
   * request. Set modsec_blocked and return SUCCESS, and the request
   * short-circuits on it (execute_ex bails at the safe php_execute_script
   * zend_try, ub_write discards output, RSHUTDOWN skips reprocessing). */
  WAF_G(modsec_processed) = 1;
  if (waf_modsec_is_enabled()) {
    int modsec_intervention = waf_modsec_process_request();
    if (modsec_intervention > 0) {
      /* Drop any output captured before the block. This covers both sinks,
       * response_body (our ub_write buffer, holding e.g. the "Missing boundary
       * in multipart/form-data" warning teed during sapi_activate) and PHP's own
       * output handler stack (when output_buffering is on, the warning lands
       * there instead of ub_write). Discarding both guarantees the block page
       * is the first and only thing sent, so no stale 200 header frame is
       * committed ahead of the block's "Status: <code>" line. */
      if (WAF_G(response_body)) {
        zend_string_release(WAF_G(response_body));
        WAF_G(response_body) = NULL;
      }
      php_output_discard_all();
      /* Reset SAPI header state, a warning may have forced an implicit header
       * send. Clearing headers_sent lets waf_send_block_response emit a clean
       * Status frame as the first output. */
      SG(headers_sent) = 0;
      SG(sapi_headers).http_response_code = modsec_intervention;

      waf_send_block_response(modsec_intervention);
      waf_modsec_update_status_code(modsec_intervention);
      waf_modsec_process_logging();
      waf_modsec_transaction_end();

      WAF_G(modsec_blocked) = modsec_intervention;
      /* Block page already delivered, suppress later output and RSHUTDOWN reflush. */
      WAF_G(response_body_sent) = 1;
      return SUCCESS;
    }
  }

  return SUCCESS;
}

// NOLINTNEXTLINE(bugprone easily swappable parameters)
PHP_RSHUTDOWN_FUNCTION(waf) {
  (void)type;
  (void)module_number;

  int modsec_intervention = 0;

  if (!WAF_G(enabled)) {
    return SUCCESS;
  }

  /* Process ModSecurity response phases */
  if (waf_modsec_is_enabled() && WAF_G(modsec_transaction) != NULL) {
    modsec_intervention = waf_modsec_process_response();
    if (modsec_intervention > 0) {
      /* Response blocked. Emit the block page only if the body hasn't already
       * streamed on overflow (response_body_sent). The status line and partial
       * body are then committed, and a second Status frame would corrupt the
       * response. Real mod_security avoids this with SecResponseBodyLimitAction
       * Reject, but we can't retroactively block, so just audit log here. */
      if (WAF_G(response_body)) {
        zend_string_release(WAF_G(response_body));
        WAF_G(response_body) = NULL;
      }
      if (!WAF_G(response_body_sent)) {
        waf_send_block_response(modsec_intervention);
      }
      /* Reflect the block status into the audit log. */
      waf_modsec_update_status_code(modsec_intervention);
      waf_modsec_process_logging();
      waf_modsec_transaction_end();
    } else {
      /* Response allowed, flush the buffered (possibly rewritten) body,
       * sending headers first since ub_write buffering suppressed the implicit
       * send. Skip the flush if the buffer was already streamed to the client
       * on overflow (response_body_sent). The bytes already went out, in order,
       * so only inspection (done in waf_modsec_process_response) is needed. */
      if (!WAF_G(response_body_sent) &&
          WAF_G(response_body) != NULL && ZSTR_LEN(WAF_G(response_body)) > 0) {
        sapi_send_headers();
        original_ub_write(ZSTR_VAL(WAF_G(response_body)),
                          ZSTR_LEN(WAF_G(response_body)));
      }
      waf_modsec_process_logging();
      waf_modsec_transaction_end();
    }
  } else {
    /* No transaction, send the buffered response body, unless it was already
     * streamed to the client on overflow. */
    if (!WAF_G(response_body_sent) &&
        WAF_G(response_body) != NULL && ZSTR_LEN(WAF_G(response_body)) > 0) {
      sapi_send_headers();
      original_ub_write(ZSTR_VAL(WAF_G(response_body)),
                        ZSTR_LEN(WAF_G(response_body)));
    }
  }

  if (WAF_G(request_body)) {
    zend_string_release(WAF_G(request_body));
    WAF_G(request_body) = NULL;
  }

  if (WAF_G(response_body)) {
    zend_string_release(WAF_G(response_body));
    WAF_G(response_body) = NULL;
  }

  if (WAF_G(transaction_id)) {
    efree(WAF_G(transaction_id));
    WAF_G(transaction_id) = NULL;
  }

  /* Reset per request flags before the next request. sapi_activate (which may
   * emit the multipart warning through ub_write) runs before RINIT, so any flag
   * left set here persists into the next request's sapi_activate. In particular
   * response_body_sent must be 0 or the warning streams directly and commits a
   * 200 header frame ahead of the block, instead of being buffered for the
   * block path to discard. */
  WAF_G(modsec_blocked) = 0;
  WAF_G(response_body_sent) = 0;

  return SUCCESS;
}

PHP_MINFO_FUNCTION(waf) {
  php_info_print_table_start();
  php_info_print_table_header(2, "waf support", "enabled");
  php_info_print_table_row(2, "Version", PHP_WAF_VERSION);
  php_info_print_table_end();

  DISPLAY_INI_ENTRIES();
}

static const zend_function_entry waf_functions[] = {PHP_FE_END};

// NOLINTNEXTLINE(cppcoreguidelines avoid non const global variables)
zend_module_entry waf_module_entry = {
    STANDARD_MODULE_HEADER, PHP_WAF_EXTNAME,
    waf_functions,          PHP_MINIT(waf),
    PHP_MSHUTDOWN(waf),     PHP_RINIT(waf),
    PHP_RSHUTDOWN(waf),     PHP_MINFO(waf),
    PHP_WAF_VERSION,        STANDARD_MODULE_PROPERTIES};

#ifdef COMPILE_DL_WAF
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(waf)
#endif
