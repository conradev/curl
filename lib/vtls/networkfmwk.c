/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "networkfmwk.h"

#ifdef USE_NETWORKFMWK

#include "urldata.h"
#include "cfilters.h"
#include "vtls.h"
#include "vtls_int.h"
#include "sendf.h"
#include "connect.h"
#include "strerror.h"
#include "select.h"
#include "multiif.h"
#include "curl_printf.h"
#include <Network/Network.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>

/* The last #include file should be: */
#include "curl_memory.h"
#include "memdebug.h"

struct network_ssl_backend_data {
  nw_connection_t connection;
  dispatch_queue_t queue;
  bool done;
  bool connected;
  CURLcode error;
};

static dispatch_queue_t network_queue;

static CURLcode code_from_error(nw_error_t error)
{
  nw_error_domain_t domain;
  CURLcode result;

  result = CURLE_OK;
  if(error == nil) {
    return result;
  }

  domain = nw_error_get_error_domain(error);
  switch(domain) {
    case nw_error_domain_posix:
      result = CURLE_WRITE_ERROR;
      break;
    case nw_error_domain_dns:
      result = CURLE_COULDNT_RESOLVE_HOST;
      break;
    case nw_error_domain_tls:
      result = CURLE_SSL_CONNECT_ERROR;
      break;
    case nw_error_domain_invalid:
    default:
      result = CURLE_COULDNT_CONNECT;
      break;
  }
  return result;
}

static int network_init(void)
{
  network_queue = dispatch_queue_create("se.haxx.curl", DISPATCH_QUEUE_SERIAL);
  return 1;
}

static void network_cleanup(void)
{
  dispatch_release(network_queue);
}

static size_t network_version(char *buffer, size_t size)
{
  CFStringRef path;
  CFURLRef url;
  CFStringRef string;
  CFBundleRef bundle;
  char version[15];
  size_t len = -1;
  CFStringEncoding encoding;

  path = CFSTR("/System/Library/Frameworks/Network.framework");
  url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                      path, kCFURLPOSIXPathStyle, true);
  bundle = CFBundleCreate(kCFAllocatorDefault, url);
  CFRelease(url);

  if(!bundle) {
    return len;
  }

  string = CFBundleGetValueForInfoDictionaryKey(bundle,
                                                kCFBundleVersionKey);
  if(!string) {
    goto out;
  }

  encoding = kCFStringEncodingUTF8;
  if(!CFStringGetCString(string, version, sizeof(version), encoding)) {
    goto out;
  }

  len = msnprintf(buffer, size, "Network/%s", version);
out:
  CFRelease(bundle);
  return len;
}

static CURLcode network_connect_start(struct Curl_cfilter *cf,
                                      bool *done)
{
  char port[20];
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  struct ssl_primary_config *conn_config;
  nw_endpoint_t endpoint;
  nw_parameters_t parameters;
  nw_parameters_configure_protocol_block_t configure_tls;
  nw_parameters_configure_protocol_block_t configure_tcp;
  dispatch_semaphore_t semaphore;
  nw_connection_state_changed_handler_t handler;
  nw_connection_state_changed_handler_t conn_handler;

  backend->error = CURLE_OK;
  backend->queue = network_queue;

  msnprintf(port, sizeof(port), "%i", connssl->peer.port);
  endpoint = nw_endpoint_create_host(connssl->peer.hostname, port);

  conn_config = Curl_ssl_cf_get_primary_config(cf);
  configure_tls = ^(nw_protocol_options_t tls_options) {
    sec_protocol_options_t sec_options;
    sec_protocol_verify_t verify_block;

    if(!conn_config->verifypeer) {
      sec_options = nw_tls_copy_sec_protocol_options(tls_options);
      verify_block = ^(sec_protocol_metadata_t UNUSED_PARAM metadata,
                       sec_trust_t UNUSED_PARAM trust_ref,
                       sec_protocol_verify_complete_t complete) {
                        complete(true);
                      };
      sec_protocol_options_set_verify_block(sec_options,
                                            verify_block,
                                            backend->queue);
    }
  };
  configure_tcp = NW_PARAMETERS_DEFAULT_CONFIGURATION;
  parameters = nw_parameters_create_secure_tcp(configure_tls, configure_tcp);
  backend->connection = nw_connection_create(endpoint, parameters);
  nw_connection_set_queue(backend->connection, backend->queue);

  handler = ^(nw_connection_state_t state UNUSED_PARAM, nw_error_t error) {
    if(error) {
      backend->error = code_from_error(error);
    }
  };

  semaphore = dispatch_semaphore_create(0);
  conn_handler = ^(nw_connection_state_t state, nw_error_t error) {
    handler(state, error);
    switch(state) {
      case nw_connection_state_preparing:
        connssl->state = ssl_connection_negotiating;
        connssl->connecting_state = ssl_connect_2;
        break;

      case nw_connection_state_ready:
      case nw_connection_state_waiting:
      case nw_connection_state_invalid:
      case nw_connection_state_failed:
      default:
        backend->done = true;
        connssl->connecting_state = ssl_connect_done;
        connssl->state = ssl_connection_complete;
        *done = true;
        dispatch_semaphore_signal(semaphore);
        break;
    }
  };
  nw_connection_set_state_changed_handler(backend->connection, conn_handler);
  nw_connection_start(backend->connection);
  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
  nw_connection_set_state_changed_handler(backend->connection, handler);
  dispatch_release(semaphore);

  return backend->error;
}

static CURLcode network_connect_common(struct Curl_cfilter *cf,
                                       bool *done)
{
  CURLcode result = CURLE_OK;
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;

  if(!backend->connection) {
    result = network_connect_start(cf, done);
    if(result)
      return result;
  }

  if(backend->done) {
    *done = true;
  }

  return backend->error;
}

static CURLcode network_connect_nonblocking(struct Curl_cfilter *cf,
                                            struct Curl_easy *dat UNUSED_PARAM,
                                            bool *done)
{
  return network_connect_common(cf, done);
}

static CURLcode network_connect(struct Curl_cfilter *cf,
                                struct Curl_easy *data UNUSED_PARAM)
{
  CURLcode result;
  bool done = FALSE;

  result = network_connect_common(cf, &done);
  if(result)
    return result;

  DEBUGASSERT(done);

  return CURLE_OK;
}

static ssize_t network_send(struct Curl_cfilter *cf,
                            struct Curl_easy *data UNUSED_PARAM,
                            const void *buf, size_t len, CURLcode *code)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  void *copy;
  dispatch_semaphore_t semaphore;
  dispatch_data_t dispatch_data;
  __block ssize_t bytes_written = -1;
  nw_connection_send_completion_t completion;

  copy = malloc(len);
  memcpy(copy, buf, len);
  dispatch_data = dispatch_data_create(copy, len, backend->queue,
                                       DISPATCH_DATA_DESTRUCTOR_FREE);

  semaphore = dispatch_semaphore_create(0);

  completion = ^(nw_error_t error) {
    if(error) {
      *code = CURLE_SEND_ERROR;
    }
    else {
      bytes_written = len;
      *code = CURLE_OK;
    }
    dispatch_semaphore_signal(semaphore);
  };
  nw_connection_send(backend->connection, dispatch_data,
                     NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, completion);

  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
  dispatch_release(semaphore);

  return bytes_written;
}

static CURLcode network_random(struct Curl_easy *data UNUSED_PARAM,
                               unsigned char *entropy, size_t length)
{
  arc4random_buf(entropy, length);
  return CURLE_OK;
}

static CURLcode network_sha256sum(const unsigned char *tmp, /* input */
                                  size_t tmplen,
                                  unsigned char *sha256sum, /* output */
                                  size_t sha256len)
{
  (void)sha256len;
  assert(sha256len >= CURL_SHA256_DIGEST_LENGTH);
  (void)CC_SHA256(tmp, (CC_LONG)tmplen, sha256sum);
  return CURLE_OK;
}

static ssize_t network_recv(struct Curl_cfilter *cf,
                            struct Curl_easy *data UNUSED_PARAM,
                            char *buf,
                            size_t len,
                            CURLcode *err)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  dispatch_semaphore_t semaphore;
  nw_connection_receive_completion_t completion;
  __block ssize_t bytes_read = -1;

  semaphore = dispatch_semaphore_create(0);
  completion = ^(dispatch_data_t content,
                 nw_content_context_t context UNUSED_PARAM,
                 bool is_complete UNUSED_PARAM,
                 nw_error_t error) {
    dispatch_data_applier_t applier;
    size_t size;

    if(error) {
      *err = CURLE_RECV_ERROR;
      dispatch_semaphore_signal(semaphore);
      return;
    }

    if(!content) {
      bytes_read = 0; /* EOF */
      *err = CURLE_OK;
      dispatch_semaphore_signal(semaphore);
      return;
    }

    size = dispatch_data_get_size(content);
    if(size > len)
      size = len;

    applier = ^bool(dispatch_data_t region UNUSED_PARAM, size_t offset,
                    const void *buffer, size_t buffer_size) {
      memcpy(buf + offset, buffer, buffer_size);
      return true;
    };
    dispatch_data_apply(content, applier);

    bytes_read = size;
    *err = CURLE_OK;
    dispatch_semaphore_signal(semaphore);
  };

  nw_connection_receive(backend->connection, 1, (uint32_t)len, completion);
  dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
  dispatch_release(semaphore);

  return bytes_read;
}

static CURLcode network_shutdown(struct Curl_cfilter *cf,
                                 struct Curl_easy *data UNUSED_PARAM,
                                 bool send_shutdown UNUSED_PARAM, bool *done)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  dispatch_semaphore_t semaphore;
  nw_connection_state_changed_handler_t handler;
  CURLcode result;

  result = CURLE_OK;

  if(backend->connection) {
    semaphore = dispatch_semaphore_create(0);
    handler = ^(nw_connection_state_t state, nw_error_t error) {
      if(error) {
        backend->error = code_from_error(error);
      }
      switch(state) {
        case nw_connection_state_cancelled:
          *done = true;
          dispatch_semaphore_signal(semaphore);
          break;

        case nw_connection_state_invalid:
        case nw_connection_state_failed:
          backend->error = CURLE_READ_ERROR;
          *done = true;
          dispatch_semaphore_signal(semaphore);
          break;

        default:
          break;
      }
    };
    nw_connection_set_state_changed_handler(backend->connection, handler);
    nw_connection_cancel(backend->connection);
    dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);
    dispatch_release(semaphore);
    result = backend->error;
  }

  return result;
}

static void *network_get_internals(struct ssl_connect_data *connssl,
                                   CURLINFO info UNUSED_PARAM)
{
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  return backend->connection;
}

static void network_close(struct Curl_cfilter *cf UNUSED_PARAM,
                          struct Curl_easy *data UNUSED_PARAM)
{
  struct ssl_connect_data *connssl = cf->ctx;
  struct network_ssl_backend_data *backend =
    (struct network_ssl_backend_data *)connssl->backend;
  if(backend->connection) {
    nw_release(backend->connection);
    backend->connection = NULL;
  }
}

static bool network_data_pending(struct Curl_cfilter *cf UNUSED_PARAM,
                                 const struct Curl_easy *data UNUSED_PARAM)
{
  return FALSE;
}

const struct Curl_ssl Curl_ssl_networkfmwk = {
  { CURLSSLBACKEND_NETWORKFRAMEWORK, "network-framework" }, /* info */

  SSLSUPP_CAINFO_BLOB |
  SSLSUPP_CA_CACHE |
  SSLSUPP_CIPHER_LIST |
  SSLSUPP_TLS13_CIPHERSUITES |
  SSLSUPP_HTTPS_PROXY,                /* supported features */

  sizeof(struct network_ssl_backend_data),

  network_init,              /* init */
  network_cleanup,           /* cleanup */
  network_version,           /* version */
  Curl_none_check_cxn,       /* check */
  network_shutdown,          /* shut_down */
  network_data_pending,      /* data_pending */
  network_random,                      /* random */
  Curl_none_cert_status_request, /* cert_status_request */
  network_connect,           /* connect_blocking */
  network_connect_nonblocking, /* connect_nonblocking */
  Curl_ssl_adjust_pollset,            /* adjust_pollset */
  network_get_internals,      /* get_internals */
  network_close,                      /* close */
  Curl_none_close_all,               /* close_all */
  Curl_none_set_engine,              /* set_engine */
  Curl_none_set_engine_default,      /* set_engine_default */
  Curl_none_engines_list,            /* engines_list */
  Curl_none_false_start,             /* false_start */
  network_sha256sum,                  /* sha256sum */
  NULL,                              /* associate_connection */
  NULL,                              /* disassociate_connection */
  network_recv,             /* recv decrypted data */
  network_send,             /* send data to encrypt */
  NULL                                /* get_channel_binding */
};

#endif /* USE_NETWORKFMWK */
