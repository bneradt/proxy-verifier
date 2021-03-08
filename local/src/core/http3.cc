/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2021, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/http3.h"
#include "core/https.h" // TODO: is this needed anymore?
#include "core/ProxyVerifier.h"

#include <cassert>
#include <fcntl.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <netdb.h>

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"

// TODO:
// ngtcp2/nghttp3 does not have any code examples. The curl implementation might be helpful here:
//
// From curl/lib/quic/
//
//   #ifdef ENABLE_QUIC
//   #ifdef USE_NGTCP2
//   #include "vquic/ngtcp2.h" // <------ Use this
//   #endif
//   #ifdef USE_QUICHE
//   #include "vquic/quiche.h"
//   #endif
//
// Thus, use lib/vquic/ngtcp2.c:
//
// https://github.com/bneradt/curl/blob/72e360e7912e71c9f5d0758a627750667947cc20/lib/vquic/ngtcp2.c

using swoc::Errata;
using swoc::TextView;
using namespace swoc::literals;
using namespace std::literals;
using std::this_thread::sleep_for;

namespace chrono = std::chrono;
using ClockType = std::chrono::system_clock;
using chrono::duration_cast;
using chrono::milliseconds;
using chrono::nanoseconds;

/** The byte used for initialization of structures. */
constexpr auto INITIALIZATION_BYTE = 0x0;

constexpr auto QUIC_MAX_STREAMS = 256 * 1024;
constexpr auto QUIC_MAX_DATA = 1 * 1024 * 1024;
constexpr auto QUIC_IDLE_TIMEOUT = 60s;

constexpr char const *QUIC_CIPHERS = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_"
                                     "POLY1305_SHA256:TLS_AES_128_CCM_SHA256";

constexpr char const *QUIC_GROUPS = "P-256:X25519:P-384:P-521";

int *H3Session::process_exit_code = nullptr;

std::random_device QuicSocket::rd;
std::mt19937 QuicSocket::rng(rd());
std::uniform_int_distribution<int> QuicSocket::uni_id(0, std::numeric_limits<uint8_t>::max());

// --------------------------------------------
// Begin ngtcp2 callbacks.
// --------------------------------------------
static int
cb_recv_crypto_data(
    ngtcp2_conn *tconn,
    ngtcp2_crypto_level crypto_level,
    uint64_t offset,
    const uint8_t *data,
    size_t datalen,
    void *user_data)
{
  (void)offset;
  (void)user_data;

  if (ngtcp2_crypto_read_write_crypto_data(tconn, crypto_level, data, datalen) != 0)
    return NGTCP2_ERR_CRYPTO;

  return 0;
}

static int
cb_handshake_completed(ngtcp2_conn *tconn, void *user_data)
{
  (void)user_data;
  (void)tconn;
  return 0;
}

static int
cb_recv_stream_data(
    ngtcp2_conn *tconn,
    uint32_t flags,
    int64_t stream_id,
    uint64_t offset,
    const uint8_t *buf,
    size_t buflen,
    void *user_data,
    void *stream_user_data)
{
  H3Session *h3_session = (H3Session *)user_data;
  ssize_t nconsumed;
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  (void)offset;
  (void)stream_user_data;

  nconsumed =
      nghttp3_conn_read_stream(h3_session->_quic_socket.h3conn, stream_id, buf, buflen, fin);
  if (nconsumed < 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* number of bytes inside buflen which consists of framing overhead
   * including QPACK HEADERS. In other words, it does not consume payload of
   * DATA frame. */
  ngtcp2_conn_extend_max_stream_offset(tconn, stream_id, nconsumed);
  ngtcp2_conn_extend_max_offset(tconn, nconsumed);

  return 0;
}

static int
cb_acked_stream_data_offset(
    ngtcp2_conn *tconn,
    int64_t stream_id,
    uint64_t offset,
    uint64_t datalen,
    void *user_data,
    void *stream_user_data)
{
  H3Session *h3_session = (H3Session *)user_data;
  int rv;
  (void)stream_id;
  (void)tconn;
  (void)offset;
  (void)datalen;
  (void)stream_user_data;

  rv = nghttp3_conn_add_ack_offset(h3_session->_quic_socket.h3conn, stream_id, datalen);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int
cb_stream_close(
    ngtcp2_conn *tconn,
    int64_t stream_id,
    uint64_t app_error_code,
    void *user_data,
    void *stream_user_data)
{
  H3Session *h3_session = (H3Session *)user_data;
  int rv;
  (void)tconn;
  (void)stream_user_data;
  /* stream is closed... */

  rv = nghttp3_conn_close_stream(h3_session->_quic_socket.h3conn, stream_id, app_error_code);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int
cb_extend_max_local_streams_bidi(ngtcp2_conn *tconn, uint64_t max_streams, void *user_data)
{
  (void)tconn;
  (void)max_streams;
  (void)user_data;

  return 0;
}

static int
cb_get_new_connection_id(
    ngtcp2_conn *tconn,
    ngtcp2_cid *cid,
    uint8_t *token,
    size_t cidlen,
    void *user_data)
{
  (void)tconn;
  (void)user_data;

  QuicSocket::randomly_populate_array(cid->data, cidlen);
  cid->datalen = cidlen;

  QuicSocket::randomly_populate_array(token, NGTCP2_STATELESS_RESET_TOKENLEN);

  return 0;
}

static int
cb_stream_reset(
    ngtcp2_conn *tconn,
    int64_t stream_id,
    uint64_t final_size,
    uint64_t app_error_code,
    void *user_data,
    void *stream_user_data)
{
  H3Session *h3_session = (H3Session *)user_data;
  int rv;
  (void)tconn;
  (void)final_size;
  (void)app_error_code;
  (void)stream_user_data;

  rv = nghttp3_conn_reset_stream(h3_session->_quic_socket.h3conn, stream_id);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static int
cb_extend_max_stream_data(
    ngtcp2_conn *tconn,
    int64_t stream_id,
    uint64_t max_data,
    void *user_data,
    void *stream_user_data)
{
  H3Session *h3_session = (H3Session *)user_data;
  int rv;
  (void)tconn;
  (void)max_data;
  (void)stream_user_data;

  rv = nghttp3_conn_unblock_stream(h3_session->_quic_socket.h3conn, stream_id);
  if (rv != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

static ngtcp2_crypto_level
quic_from_ossl_level(OSSL_ENCRYPTION_LEVEL ossl_level)
{
  switch (ossl_level) {
  case ssl_encryption_initial:
    return NGTCP2_CRYPTO_LEVEL_INITIAL;
  case ssl_encryption_early_data:
    return NGTCP2_CRYPTO_LEVEL_EARLY;
  case ssl_encryption_handshake:
    return NGTCP2_CRYPTO_LEVEL_HANDSHAKE;
  case ssl_encryption_application:
    return NGTCP2_CRYPTO_LEVEL_APPLICATION;
  default:
    assert(0);
    // To silence the compiler complaining about no return from a non-void
    // function.
    return NGTCP2_CRYPTO_LEVEL_EARLY;
  }
}

/// @return 0 on success, 1 on failure.
static int initialize_nghttp3_connection(H3Session *session);

static int
quic_set_encryption_secrets(
    SSL *ssl,
    OSSL_ENCRYPTION_LEVEL ossl_level,
    const uint8_t *rx_secret,
    const uint8_t *tx_secret,
    size_t secretlen)
{
  auto *h3_session = (H3Session *)SSL_get_app_data(ssl);
  auto &qs = h3_session->_quic_socket;
  auto const level = quic_from_ossl_level(ossl_level);

  if (ngtcp2_crypto_derive_and_install_rx_key(
          qs.qconn,
          nullptr,
          nullptr,
          nullptr,
          level,
          rx_secret,
          secretlen) != 0)
    return 0;

  if (ngtcp2_crypto_derive_and_install_tx_key(
          qs.qconn,
          nullptr,
          nullptr,
          nullptr,
          level,
          tx_secret,
          secretlen) != 0)
    return 0;

  if (level == NGTCP2_CRYPTO_LEVEL_APPLICATION) {
    if (initialize_nghttp3_connection(h3_session) != 0) {
      return 0;
    }
  }

  return 1;
}

static int
write_client_handshake(QuicSocket *qs, ngtcp2_crypto_level level, const uint8_t *data, size_t len)
{
  Errata errata;
  QuicHandshake *crypto_data = &qs->crypto_data[level];
  auto *buf = crypto_data->buf;
  if (buf == nullptr) {
    buf = static_cast<char *>(malloc(QuicHandshake::alloclen));
    memset(static_cast<void *>(buf), INITIALIZATION_BYTE, sizeof(buf));
    if (!buf) {
      return 0;
    }
  }

  assert(crypto_data->len + len <= QuicHandshake::alloclen);

  memcpy(&buf[crypto_data->len], data, len);
  crypto_data->len += len;

  int rv = ngtcp2_conn_submit_crypto_data(
      qs->qconn,
      level,
      (uint8_t *)(&buf[crypto_data->len] - len),
      len);
  if (rv != 0) {
    errata.error("write_client_handshake failed");
  }
  assert(0 == rv);

  return 1;
}

static int
quic_add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL ossl_level, const uint8_t *data, size_t len)
{
  auto *h3_session = (H3Session *)SSL_get_app_data(ssl);
  auto &qs = h3_session->_quic_socket;
  auto const level = quic_from_ossl_level(ossl_level);

  return write_client_handshake(&qs, level, data, len);
}

static int
quic_flush_flight(SSL *ssl)
{
  (void)ssl;
  return 1;
}

static int
quic_send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert)
{
  auto *h3_session = (H3Session *)SSL_get_app_data(ssl);
  auto &qs = h3_session->_quic_socket;
  // TODO: comment these out in the parameters.
  (void)level;

  qs.tls_alert = alert;
  return 1;
}

static SSL_QUIC_METHOD ssl_quic_method =
    {quic_set_encryption_secrets, quic_add_handshake_data, quic_flush_flight, quic_send_alert};

static ngtcp2_callbacks client_ngtcp2_callbacks = {
    ngtcp2_crypto_client_initial_cb,
    nullptr, /* recv_client_initial */
    cb_recv_crypto_data,
    cb_handshake_completed,
    nullptr, /* recv_version_negotiation */
    ngtcp2_crypto_encrypt_cb,
    ngtcp2_crypto_decrypt_cb,
    ngtcp2_crypto_hp_mask_cb,
    cb_recv_stream_data,
    nullptr, /* acked_crypto_offset */
    cb_acked_stream_data_offset,
    nullptr, /* stream_open */
    cb_stream_close,
    nullptr, /* recv_stateless_reset */
    ngtcp2_crypto_recv_retry_cb,
    cb_extend_max_local_streams_bidi,
    nullptr, /* extend_max_local_streams_uni */
    nullptr, /* rand  */
    cb_get_new_connection_id,
    nullptr,                     /* remove_connection_id */
    ngtcp2_crypto_update_key_cb, /* update_key */
    nullptr,                     /* path_validation */
    nullptr,                     /* select_preferred_addr */
    cb_stream_reset,
    nullptr, /* extend_max_remote_streams_bidi */
    nullptr, /* extend_max_remote_streams_uni */
    cb_extend_max_stream_data,
    nullptr, /* dcid_status */
    nullptr, /* handshake_confirmed */
    nullptr, /* recv_new_token */
    ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    nullptr /* recv_datagram */
};

// TODO: fill this out when we add server-side code.
#if 0
static ngtcp2_callbacks server_ngtcp2_callbacks = {
  nullptr, /* client_initial */
  ngtcp2_crypto_recv_client_initial_cb, /* recv_client_initial */
  cb_recv_crypto_data,
  cb_handshake_completed,
  nullptr, /* recv_version_negotiation */
  ngtcp2_crypto_encrypt_cb,
  ngtcp2_crypto_decrypt_cb,
  ngtcp2_crypto_hp_mask_cb,
  cb_recv_stream_data,
  nullptr, /* acked_crypto_offset */
  cb_acked_stream_data_offset,
  nullptr, /* stream_open */
  cb_stream_close,
  nullptr, /* recv_stateless_reset */
  ngtcp2_crypto_recv_retry_cb,
  cb_extend_max_local_streams_bidi,
  nullptr, /* extend_max_local_streams_uni */
  nullptr, /* rand  */
  cb_get_new_connection_id,
  nullptr, /* remove_connection_id */
  ngtcp2_crypto_update_key_cb, /* update_key */
  nullptr, /* path_validation */
  nullptr, /* select_preferred_addr */
  cb_stream_reset,
  nullptr, /* extend_max_remote_streams_bidi */
  nullptr, /* extend_max_remote_streams_uni */
  cb_extend_max_stream_data,
  nullptr, /* dcid_status */
  nullptr, /* handshake_confirmed */
  nullptr, /* recv_new_token */
  ngtcp2_crypto_delete_crypto_aead_ctx_cb,
  ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
  nullptr /* recv_datagram */
};
#endif

// --------------------------------------------
// End ngtcp2 callbacks.
// --------------------------------------------

// --------------------------------------------
// Begin nghttp3 callbacks.
// --------------------------------------------

/** Called to populate data frames of a request or response.
 *
 * @return The number of objects populated in vec.
 */
static ssize_t
cb_h3_readfunction(
    nghttp3_conn *conn,
    int64_t stream_id,
    nghttp3_vec *vec,
    size_t veccnt,
    uint32_t *pflags,
    void *user_data,
    void *stream_user_data)
{
  (void)conn;
  (void)stream_id;
  (void)user_data;
  (void)veccnt;

  Errata errata;
  auto *stream_state = reinterpret_cast<H3StreamState*>(stream_user_data);

  if (stream_state->wait_for_continue) {
    errata.diag(R"(Not sending body for "Expect: 100" request.)");
    *pflags = NGHTTP3_DATA_FLAG_EOF;
    return 0;
  }
  // TODO: we won't need offset if things work this way. If things go wonky
  // with larger bodies, then we have to impart a cap and send in chunks. Then
  // the offset will be helpful.
  vec[0].base = (uint8_t*)stream_state->body_to_send + stream_state->send_body_offset;
  vec[0].len = stream_state->send_body_length - stream_state->send_body_offset;
  *pflags = NGHTTP3_DATA_FLAG_EOF;

  return 1;
}

/* this amount of data has now been acked on this stream */
static int
cb_h3_acked_stream_data(
    nghttp3_conn *conn,
    int64_t stream_id,
    size_t datalen,
    void *conn_user_data,
    void *stream_user_data)
{
  (void)conn;
  (void)stream_id;
  (void)conn_user_data;

  Errata errata;
  // TODO: if send cb_h3_readfunction can really just populate base and len
  // like it's doing, this function probably doesn't even need to do what it's
  // doing.
  auto *stream_state = reinterpret_cast<H3StreamState*>(stream_user_data);
  stream_state->send_body_offset += datalen;
  return 0;
}

static int
cb_h3_stream_close(
    nghttp3_conn *conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void *conn_user_data,
    void *stream_user_data)
{
  (void)conn;
  (void)app_error_code;
  (void)stream_user_data;

  Errata errata;

  auto *session = reinterpret_cast<H3Session*>(conn_user_data);
  // TODO: Make sure the stream really can be erased here. Is it's lifetime
  // managed by another holder of the H3StreamState pointer? (If needed.)
  session->_stream_map.erase(stream_id);

  errata.diag("HTTP/3 Stream is closed with id: {}", stream_id);

  /* make sure that ngh3_stream_recv is called again to complete the transfer
     even if there are no more packets to be received from the server. */
  // TODO: this looks important. Probably have to do a receive here?
  //data->state.drain = 1;
  return 0;
}

static int
cb_h3_recv_data(
    nghttp3_conn *conn,
    int64_t stream_id,
    const uint8_t *buf,
    size_t buflen,
    void *conn_user_data,
    void *stream_user_data)
{
  (void)conn;
  (void)conn_user_data;
  auto *stream_state = reinterpret_cast<H3StreamState*>(stream_user_data);

  Errata errata;
  errata.diag(
      "Drained HTTP/3 body for transaction with key: {}, stream id: {} "
      "of {} bytes with content: {}",
      stream_state->key,
      stream_id,
      buflen,
      TextView(reinterpret_cast<char const *>(buf), buflen));

  return 0;
}

static int
cb_h3_deferred_consume(
    nghttp3_conn *conn,
    int64_t stream_id,
    size_t consumed,
    void *conn_user_data,
    void *stream_user_data)
{
  auto *h3_session = (H3Session *)conn_user_data;
  auto &qs = h3_session->_quic_socket;
  (void)conn;
  (void)stream_user_data;
  (void)stream_id;

  ngtcp2_conn_extend_max_stream_offset(qs.qconn, stream_id, consumed);
  ngtcp2_conn_extend_max_offset(qs.qconn, consumed);
  return 0;
}

static int
cb_h3_recv_header(
    nghttp3_conn *conn,
    int64_t stream_id,
    int32_t token,
    nghttp3_rcbuf *name,
    nghttp3_rcbuf *value,
    uint8_t flags,
    void *conn_user_data,
    void *stream_user_data)
{
  (void)conn;
  (void)stream_id;
  (void)token;
  (void)flags;
  (void)conn_user_data;

  auto *stream_state = reinterpret_cast<H3StreamState*>(stream_user_data);
  stream_state->have_received_headers = true;

  TextView name_view = stream_state->register_rcbuf(name);
  TextView value_view = stream_state->register_rcbuf(value);

  assert(stream_state->will_receive_request || stream_state->will_receive_response);
  if (stream_state->will_receive_request) {
    auto &request_headers = stream_state->request_from_client;
    if (name_view == ":method") {
      request_headers->_method = value_view;
    } else if (name_view == ":scheme") {
      request_headers->_scheme = value_view;
    } else if (name_view == ":authority") {
      request_headers->_authority = value_view;
    } else if (name_view == ":path") {
      request_headers->_path = value_view;
    }
    request_headers->_fields_rules->add_field(name_view, value_view);
  } else if (stream_state->will_receive_response) {
    auto &response_headers = stream_state->response_from_server;
    if (name_view == ":status") {
      response_headers->_status = swoc::svtou(value_view);
      response_headers->_status_string = std::string(value_view);
    }
    response_headers->_fields_rules->add_field(name_view, value_view);
    // See if we are expecting a 100 response.
    if (stream_state->wait_for_continue) {
      if (name_view == ":status" && value_view == "100") {
        // We got our 100 Continue. No need to wait for it anymore.
        stream_state->wait_for_continue = false;
      }
    }
  }
  return 0;
}

static int
cb_h3_end_headers(
    nghttp3_conn *conn,
    int64_t stream_id,
    void *conn_user_data,
    void *stream_user_data)
{
  (void)conn;
  (void)stream_id;
  (void)conn_user_data;

  auto *stream_state = reinterpret_cast<H3StreamState*>(stream_user_data);
  Errata errata;
  if (!stream_state->have_received_headers) {
    errata.error("Stream did not receive any headers for key: {}", stream_state->key);
  }
  return 0;
}

static int
cb_h3_send_stop_sending(
    nghttp3_conn *conn,
    int64_t stream_id,
    uint64_t app_error_code,
    void *conn_user_data,
    void *stream_user_data)
{
  (void)conn;
  (void)stream_id;
  (void)app_error_code;
  (void)conn_user_data;
  (void)stream_user_data;
  return 0;
}

static nghttp3_callbacks nghttp3_client_callbacks = {
    cb_h3_acked_stream_data, /* acked_stream_data */
    cb_h3_stream_close,
    cb_h3_recv_data,
    cb_h3_deferred_consume,
    NULL, /* begin_headers */
    cb_h3_recv_header,
    cb_h3_end_headers,
    NULL, /* begin_trailers */
    cb_h3_recv_header,
    NULL, /* end_trailers */
    NULL, /* http_begin_push_promise */
    NULL, /* http_recv_push_promise */
    NULL, /* http_end_push_promise */
    NULL, /* http_cancel_push */
    cb_h3_send_stop_sending,
    NULL, /* push_stream */
    NULL, /* end_stream */
    NULL, /* reset_stream */
};
// --------------------------------------------
// End nghttp3 callbacks.
// --------------------------------------------

constexpr int SUCCEEDED = 0;
constexpr int FAILED = 1;

static int
initialize_nghttp3_connection(H3Session *session)
{
  int rc = 0;
  auto& qs = session->_quic_socket;
  int64_t ctrl_stream_id = 0, qpack_enc_stream_id = 0, qpack_dec_stream_id = 0;

  if (ngtcp2_conn_get_max_local_streams_uni(qs.qconn) < 3) {
    return 1;
  }

  nghttp3_settings_default(&qs.h3settings);

  rc = nghttp3_conn_client_new(
      &qs.h3conn,
      &nghttp3_client_callbacks,
      &qs.h3settings,
      nghttp3_mem_default(),
      session);
  if (rc != 0) {
    return FAILED;
  }

  rc = ngtcp2_conn_open_uni_stream(qs.qconn, &ctrl_stream_id, nullptr);
  if (rc != 0) {
    return FAILED;
  }

  rc = nghttp3_conn_bind_control_stream(qs.h3conn, ctrl_stream_id);
  if (rc != 0) {
    return FAILED;
  }

  rc = ngtcp2_conn_open_uni_stream(qs.qconn, &qpack_enc_stream_id, nullptr);
  if (rc != 0) {
    return FAILED;
  }

  rc = ngtcp2_conn_open_uni_stream(qs.qconn, &qpack_dec_stream_id, nullptr);
  if (rc != 0) {
    return FAILED;
  }

  rc = nghttp3_conn_bind_qpack_streams(qs.h3conn, qpack_enc_stream_id, qpack_dec_stream_id);
  if (rc != 0) {
    return FAILED;
  }

  return SUCCEEDED;
}


static void
quic_settings(QuicSocket &qs, uint64_t stream_buffer_size)
{
  ngtcp2_settings *s = &qs.settings;
  ngtcp2_transport_params *t = &qs.transport_params;
  ngtcp2_settings_default(s);
  ngtcp2_transport_params_default(t);
#ifdef DEBUG_NGTCP2
  s->log_printf = quic_printf;
#else
  s->log_printf = nullptr;
#endif
  auto const current_time = ClockType::now();
  auto const duration_since_epoch = current_time.time_since_epoch();
  s->initial_ts = duration_cast<nanoseconds>(duration_since_epoch).count();
  t->initial_max_stream_data_bidi_local = stream_buffer_size;
  t->initial_max_stream_data_bidi_remote = QUIC_MAX_STREAMS;
  t->initial_max_stream_data_uni = QUIC_MAX_STREAMS;
  t->initial_max_data = QUIC_MAX_DATA;
  t->initial_max_streams_bidi = 1;
  t->initial_max_streams_uni = 3;
  t->max_idle_timeout = duration_cast<milliseconds>(QUIC_IDLE_TIMEOUT).count();
  if (qs.qlogfd != -1) {
    s->qlog.write = nullptr; // TODO: curl has qlog_callback;
  }
}

QuicHandshake::~QuicHandshake()
{
  if (buf != nullptr) {
    free(buf);
    buf = nullptr;
  }
}

QuicSocket::QuicSocket()
{
  memset(&dcid, INITIALIZATION_BYTE, sizeof(dcid));
  memset(&scid, INITIALIZATION_BYTE, sizeof(scid));
  memset(&settings, INITIALIZATION_BYTE, sizeof(settings));
  memset(&transport_params, INITIALIZATION_BYTE, sizeof(transport_params));
  memset(&crypto_data, INITIALIZATION_BYTE, sizeof(crypto_data));
  memset(&local_addr, INITIALIZATION_BYTE, sizeof(local_addr));
  memset(&h3settings, INITIALIZATION_BYTE, sizeof(h3settings));
}

QuicSocket::~QuicSocket()
{
  // TODO: I think they'll be a lot of free'ing to do here. Unless we make
  // extensive use of RAII.
}

// static
void
QuicSocket::randomly_populate_array(uint8_t *array, size_t array_len)
{
  for (auto i = 0u; i < array_len; ++i) {
    array[i] = uni_id(rng);
  }
}

Errata
H3Session::connect_udp_socket(swoc::IPEndpoint const *real_target)
{
  Errata errata;
  int const socket_fd = socket(real_target->family(), SOCK_DGRAM, 0);
  if (0 > socket_fd) {
    errata.error(R"(Failed to open a UDP socket - {})", swoc::bwf::Errno{});
    return errata;
  }
  static constexpr int ONE = 1;
  struct linger l;
  l.l_onoff = 0;
  l.l_linger = 0;
  setsockopt(socket_fd, SOL_SOCKET, SO_LINGER, (char *)&l, sizeof(l));
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &ONE, sizeof(int)) < 0) {
    errata.error(R"(Could not set reuseaddr on socket {} - {}.)", socket_fd, swoc::bwf::Errno{});
    return errata;
  }
  errata.note(this->set_fd(socket_fd));
  if (!errata.is_ok()) {
    return errata;
  }

  // TODO: not sure whether the ngtcp2 connect will clash with this.
  // Connect to the UDP socket so that send and recv work.
  if (-1 == ::connect(socket_fd, &real_target->sa, real_target->size())) {
    errata.error(R"(Failed to connect socket {}: - {})", *real_target, swoc::bwf::Errno{});
    return errata;
  }
  if (0 != ::fcntl(socket_fd, F_SETFL, fcntl(socket_fd, F_GETFL, 0) | O_NONBLOCK)) {
    errata.error(
        R"(Failed to make the client socket non-blocking {}: - {})",
        *real_target,
        swoc::bwf::Errno{});
    return errata;
  }
  this->_endpoint = real_target;
  return errata;
}

Errata
H3Session::do_connect(swoc::IPEndpoint const *real_target)
{
  Errata errata = connect_udp_socket(real_target);
  if (!errata.is_ok()) {
    return errata;
  }

  // A generic UDP socket has been configured and connected. Now finish the
  // connection phase by configuring a QUIC and HTTP/3 connection over this
  // socket.
  errata.note(this->connect());
  return errata;
}

swoc::Rv<int>
H3Session::poll_for_headers(chrono::milliseconds timeout)
{
  if (this->get_a_stream_has_ended()) {
    return 1;
  }
  swoc::Rv<int> zret{-1};
  auto &&[poll_result, poll_errata] = Session::poll_for_data_on_socket(timeout);
  zret.note(std::move(poll_errata));
  if (!zret.is_ok()) {
    return zret;
  } else if (poll_result == 0) {
    return 0;
  } else if (poll_result < 0) {
    // Connection closed.
    close();
    return -1;
  }
  // TODO: replace with the nghttp3 call.
  auto const received_bytes = 0;
  // auto const received_bytes =
  // receive_nghttp2_request(this->get_session(), nullptr, 0, 0, this, timeout);
  if (received_bytes == 0) {
    // The receive timed out.
    return 0;
  }
  if (is_closed()) {
    return -1;
  } else if (this->get_a_stream_has_ended()) {
    return 1;
  } else {
    // The caller will retry.
    return 0;
  }
}

bool
H3Session::get_a_stream_has_ended() const
{
  return !_ended_streams.empty();
}

void
H3Session::set_stream_has_ended(int64_t stream_id)
{
  _ended_streams.push_back(stream_id);
}

swoc::Rv<std::shared_ptr<HttpHeader>>
H3Session::read_and_parse_request(swoc::FixedBufferWriter & /* buffer */)
{
  swoc::Rv<std::shared_ptr<HttpHeader>> zret{nullptr};

  // This function should only be called after poll_for_headers() says there is
  // a finished stream.
  assert(!_ended_streams.empty());
  auto const stream_id = _ended_streams.front();
  _ended_streams.pop_front();
  auto stream_map_iter = _stream_map.find(stream_id);
  if (stream_map_iter == _stream_map.end()) {
    zret.error("Requested request headers for stream id {}, but none are available.", stream_id);
    return zret;
  }
  auto &stream_state = stream_map_iter->second;
  zret = stream_state->request_from_client;
  return zret;
}

swoc::Rv<size_t>
H3Session::drain_body(
    HttpHeader const & /* hdr */,
    size_t /* expected_content_size */,
    TextView /* initial */)
{
  // For HTTP/2, we process entire streams once they are ended. Therefore there
  // is never body to drain.
  return {0};
}

// Complete the TLS handshake (server-side).
Errata
H3Session::accept()
{
  swoc::Errata errata;
  //
  // TODO: call the QUIC API to establish a server-side QUIC connection.
  //

  // Check that the HTTP/3 protocol was negotiated.
  unsigned char const *alpn = nullptr;
  unsigned int alpnlen = 0;
#ifdef OPENSSL_NO_NEXTPROTONEG
  SSL_get0_next_proto_negotiated(this->_ssl, &alpn, &alpnlen);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
  if (alpn == nullptr) {
    SSL_get0_alpn_selected(this->_ssl, &alpn, &alpnlen);
  }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

  if (alpn != nullptr && alpnlen == 2 && memcmp("h3", alpn, 2) == 0) {
    errata.diag(R"(Negotiated ALPN: {}, HTTP/3 is negotiated.)", TextView{(char *)alpn, alpnlen});
  } else {
    errata.error(
        R"(Negotiated ALPN: {}, HTTP/3 failed to negotiate.)",
        (alpn == nullptr) ? "none" : TextView{(char *)alpn, alpnlen});
    return errata;
  }

  this->server_session_init();
  errata.diag("Finished accept using H3Session");
  // TODO Send initial HTTP/3 session frames
  // send_connection_settings();
  // send_nghttp2_data(_session, nullptr, 0, 0, this);
  return errata;
}

// Complete the TLS handshake (client-side).
Errata
H3Session::connect()
{
  swoc::Errata errata;
  //
  // TODO: call the QUIC API to establish a client-side QUIC connection.
  //
  // In curl, see: lib/vquic/ngtcp2.c:Curl_quic_connect()
  //

  errata.note(this->client_session_init());
  if (!errata.is_ok()) {
    errata.error("TLS initialization failed.");
    return errata;
  }

  // TODO Send initial HTTP/3 session frames
  // send_connection_settings();
  // send_nghttp2_data(_session, nullptr, 0, 0, this);
  return errata;
}

Errata
H3Session::run_transactions(
    std::list<Txn> const &txn_list,
    swoc::IPEndpoint const *real_target,
    double rate_multiplier)
{
  Errata errata;

  auto const first_time = ClockType::now();
  for (auto const &txn : txn_list) {
    Errata txn_errata;
    auto const key{txn._req.get_key()};
    if (this->is_closed()) {
      txn_errata.note(this->do_connect(real_target));
      if (!txn_errata.is_ok()) {
        txn_errata.error(R"(Failed to reconnect HTTP/2 key={}.)", key);
        // If we don't have a valid connection, there's no point in continuing.
        break;
      }
    }
    if (rate_multiplier != 0 || txn._user_specified_delay_duration > 0us) {
      std::chrono::duration<double, std::micro> delay_time = 0ms;
      auto current_time = ClockType::now();
      auto next_time = current_time + delay_time;
      if (txn._user_specified_delay_duration > 0us) {
        delay_time = txn._user_specified_delay_duration;
        next_time = current_time + delay_time;
      } else {
        auto const start_offset = txn._start;
        next_time = (rate_multiplier * start_offset) + first_time;
        delay_time = next_time - current_time;
      }
      while (delay_time > 0us) {
        // Make use of our delay time to read any incoming responses.

        // TODO call the nghttp3 function to receive data.
#if 0
        receive_nghttp2_data(
            this->get_session(),
            nullptr,
            0,
            0,
            this,
            duration_cast<milliseconds>(delay_time));
#endif
        current_time = ClockType::now();
        delay_time = next_time - current_time;
        sleep_for(delay_time);
      }
    }
    txn_errata.note(this->run_transaction(txn));
    if (!txn_errata.is_ok()) {
      txn_errata.error(R"(Failed HTTP/2 transaction with key={}.)", key);
    }
    errata.note(std::move(txn_errata));
  }
  // TODO call the nghttp3 function to receive a response.
  // receive_nghttp2_responses(this->get_session(), nullptr, 0, 0, this);
  return errata;
}

Errata
H3Session::run_transaction(Txn const &txn)
{
  Errata errata;
  auto &&[bytes_written, write_errata] = this->write(txn._req);
  errata.note(std::move(write_errata));
  return errata;
}

TextView
H3StreamState::register_rcbuf(nghttp3_rcbuf *rcbuf)
{
  nghttp3_rcbuf_incref(rcbuf);
  _rcbufs_to_free.push_back(rcbuf);
  auto buf = nghttp3_rcbuf_get_buf(rcbuf);
  return TextView(reinterpret_cast<char *>(buf.base), buf.len);
}


H3StreamState::H3StreamState(bool is_client)
  : will_receive_request{is_client}
  , will_receive_response{!is_client}
  , stream_start{ClockType::now()}
  , request_from_client{std::make_shared<HttpHeader>()}
  , response_from_server{std::make_shared<HttpHeader>()}
{
  request_from_client->_is_http3 = true;
  request_from_client->_is_request = true;
  response_from_server->_is_http3 = true;
  response_from_server->_is_response = true;
}

H3StreamState::~H3StreamState()
{
  for (auto rcbuf : _rcbufs_to_free) {
    nghttp3_rcbuf_decref(rcbuf);
  }
}

void
H3StreamState::set_stream_id(int64_t stream_id)
{
  _stream_id = stream_id;
}

int64_t
H3StreamState::get_stream_id() const
{
  return _stream_id;
}

H3Session::H3Session() { }

H3Session::H3Session(TextView const &client_sni, int client_verify_mode)
  : _client_sni{client_sni}
  , _client_verify_mode{client_verify_mode}
{
}

H3Session::~H3Session()
{
  // TODO: add nghttp3_*_del calls here.
}

swoc::Rv<ssize_t> H3Session::read(swoc::MemSpan<char> /* span */)
{
  swoc::Rv<ssize_t> zret{0};
  zret.error("HTTP/3 read() called for the unsupported MemSpan overload.");
  return zret;
}

swoc::Rv<ssize_t> H3Session::write(TextView /* data */)
{
  swoc::Rv<ssize_t> zret{0};
  zret.error("HTTP/3 write() called for the unsupported TextView overload.");
  return zret;
}

nghttp3_nv
H3Session::tv_to_nv(char const *name, TextView v)
{
  nghttp3_nv res;

  res.name = (unsigned char *)name;
  res.namelen = strlen(name);
  res.value = (unsigned char *)v.data();
  res.valuelen = v.length();
  res.flags = NGHTTP3_NV_FLAG_NONE;

  return res;
}

Errata
H3Session::pack_headers(HttpHeader const &hdr, nghttp3_nv *&nv_hdr, int &hdr_count)
{
  Errata errata;

  hdr_count = hdr._fields_rules->_fields.size();

  nv_hdr = reinterpret_cast<nghttp3_nv *>(malloc(sizeof(nghttp3_nv) * hdr_count));

  int offset = 0;
  if (hdr._is_response) {
    nv_hdr[offset++] = tv_to_nv(":status", hdr._status_string);
  } else if (hdr._is_request) {
    // TODO: add error checking and refactor and tolerance for non-required
    // pseudo-headers
    nv_hdr[offset++] = tv_to_nv(":method", hdr._method);
    nv_hdr[offset++] = tv_to_nv(":scheme", hdr._scheme);
    nv_hdr[offset++] = tv_to_nv(":path", hdr._path);
    nv_hdr[offset++] = tv_to_nv(":authority", hdr._authority);
  }
  hdr._fields_rules->add_fields_to_ngnva(nv_hdr + offset);
  return errata;
}

swoc::Rv<ssize_t>
H3Session::write(HttpHeader const &hdr)
{
  swoc::Rv<ssize_t> zret{0};

  auto const key = hdr.get_key();
  H3StreamState *stream_state = nullptr;
  std::shared_ptr<H3StreamState> new_stream_state{nullptr};
  int64_t stream_id = 0;
  if (hdr._is_response) {
    stream_id = hdr._stream_id;
    auto stream_map_iter = _stream_map.find(stream_id);
    if (stream_map_iter == _stream_map.end()) {
      zret.error("Could not find registered stream for stream id: {}", stream_id);
      return zret;
    }
    stream_state = stream_map_iter->second.get();
  } else {
    // Only servers write responses while clients write requests.
    bool const is_client = hdr._is_request;
    new_stream_state = std::make_shared<H3StreamState>(is_client);
    stream_state = new_stream_state.get();

    auto const rc = ngtcp2_conn_open_bidi_stream(_quic_socket.qconn, &stream_id, nullptr);
    if (rc) {
      zret.error("Failed ngtcp2_conn_open_bidi_stream for key: {}", key);
      return zret;
    }
    stream_state->set_stream_id(stream_id);
  }
  stream_state->key = key;

  int num_headers;
  nghttp3_nv *nva = nullptr;
  zret.note(pack_headers(hdr, nva, num_headers));
  if (!zret.is_ok()) {
    zret.error("Failed to pack headers for key: {}", key);
    return zret;
  }

  int submit_result = 0;
  if (hdr._content_size > 0 && (hdr._is_request || !HttpHeader::STATUS_NO_CONTENT[hdr._status])) {
    TextView content;
    if (hdr._content_data) {
      content = TextView{hdr._content_data, hdr._content_size};
    } else {
      // If hdr._content_data is null, then there was no explicit description
      // of the body data via the data node. Instead we'll use our generated
      // HttpHeader::_content.
      content = TextView{HttpHeader::_content.data(), hdr._content_size};
    }
    nghttp3_data_reader data_reader;
    data_reader.read_data = cb_h3_readfunction;
    stream_state->body_to_send = content.data();
    stream_state->send_body_length = content.size();
    stream_state->wait_for_continue = hdr._send_continue;
    if (hdr._is_response) {
      submit_result = nghttp3_conn_submit_response(
          _quic_socket.h3conn,
          stream_id,
          nva,
          num_headers,
          &data_reader);
    } else {
      submit_result = nghttp3_conn_submit_request(
          _quic_socket.h3conn,
          stream_id,
          nva,
          num_headers,
          &data_reader,
          this);
    }
  } else { // Empty body.
    if (hdr._is_response) {
      submit_result = nghttp3_conn_submit_response(
          _quic_socket.h3conn,
          stream_id,
          nva,
          num_headers,
          nullptr);
    } else {
      submit_result = nghttp3_conn_submit_request(
          _quic_socket.h3conn,
          stream_id,
          nva,
          num_headers,
          nullptr,
          this);
    }
  }
  if (hdr._is_response) {
    if (submit_result != 0) {
      zret.error(
          "Submitting an HTTP/3 response with stream id {} failed: {}",
          stream_id,
          submit_result);
    }
  } else {
    if (submit_result != 0) {
      zret.error(
          "Submitting an HTTP/3 request with stream id {} failed: {}",
          stream_id,
          submit_result);
    } else {
      zret.diag("Sent the following HTTP/2 headers for stream id {}:\n{}", stream_id, hdr);
    }
  }
  // TODO: free'ing here is what curl does, but don't we have to read on the
  // socket and send on the socket?
  free(nva);
  return zret;
}

SSL_CTX *H3Session::h3_client_context = nullptr;
SSL_CTX *H3Session::h3_server_context = nullptr;

Errata
H3Session::send_connection_settings()
{
  Errata errata;
  return errata;
}

// static
Errata
H3Session::init(int *process_exit_code)
{
  H3Session::process_exit_code = process_exit_code;
  Errata errata = H3Session::client_init(h3_client_context);
  errata.note(H3Session::server_init(h3_server_context));
  errata.diag("Finished H3Session::init");
  return errata;
}

// static
Errata
H3Session::client_init(SSL_CTX *& /* client_context */)
{
  Errata errata;
  // This will not likely get used since client_session_init does all the heavy lifting.
  return errata;
}

// static
Errata
H3Session::server_init(SSL_CTX *& /* server_context */)
{
  Errata errata;
  // This will not likely get used since server_session_init does all the heavy lifting.
  return errata;
}

Errata
H3Session::client_session_init()
{
  Errata errata;
  _quic_socket.version = NGTCP2_PROTO_VER_MAX;

  SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_method());
  _quic_socket.sslctx = ssl_ctx;
  SSL *ssl = SSL_new(ssl_ctx);
  _quic_socket.ssl = ssl;

  SSL_set_app_data(ssl, this);
  SSL_set_connect_state(ssl);

  auto const *alpn = (const uint8_t *)NGHTTP3_ALPN_H3;
  auto const alpnlen = sizeof(NGHTTP3_ALPN_H3) - 1;
  SSL_set_alpn_protos(ssl, alpn, (int)alpnlen);

  SSL_set_tlsext_host_name(ssl, _client_sni.c_str());

  if (_client_verify_mode != SSL_VERIFY_NONE) {
    errata.diag(
        R"(Setting client H3 verification mode against the proxy to: {}.)",
        _client_verify_mode);
    SSL_set_verify(ssl, _client_verify_mode, nullptr /* No verify_callback is passed */);
  }

  SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);

  SSL_CTX_set_default_verify_paths(ssl_ctx);

  if (SSL_CTX_set_ciphersuites(ssl_ctx, QUIC_CIPHERS) != 1) {
    errata.error("SSL_CTX_set_ciphersuites failed: {}", swoc::bwf::SSLError{});
    return errata;
  }

  if (SSL_CTX_set1_groups_list(ssl_ctx, QUIC_GROUPS) != 1) {
    errata.error("SSL_CTX_set1_groups_list failed: {}", swoc::bwf::SSLError{});
    return errata;
  }

  SSL_CTX_set_quic_method(ssl_ctx, &ssl_quic_method);

  // TODO: consider keylog callbacks.
  // SSL_CTX_set_keylog_callback(ssl_ctx, keylog_callback);

  _quic_socket.dcid.datalen = NGTCP2_MAX_CIDLEN;
  QuicSocket::randomly_populate_array(_quic_socket.dcid.data, _quic_socket.dcid.datalen);

  _quic_socket.scid.datalen = NGTCP2_MAX_CIDLEN;
  QuicSocket::randomly_populate_array(_quic_socket.scid.data, _quic_socket.scid.datalen);

  // TODO Consider quic logging
  //(void)Curl_qlogdir(data, _quic_socket.scid.data, NGTCP2_MAX_CIDLEN, &qfd);
  //_quic_socket.qlogfd = qfd; /* -1 if failure above */
  _quic_socket.qlogfd = -1; // Using -1 to disable quic logging.

  // TODO: CURL seems to pass CURLOPT_BUFFERSIZE for this, if I'm reading the
  // code right. That defaults to 16 kB.
  quic_settings(_quic_socket, MAX_DRAIN_BUFFER_SIZE);

  _quic_socket.local_addrlen = sizeof(_quic_socket.local_addr);
  auto const rv = getsockname(
      this->get_fd(),
      (struct sockaddr *)&_quic_socket.local_addr,
      &_quic_socket.local_addrlen);
  if (rv == -1) {
    errata.error("getsockname failed: {}", swoc::bwf::Errno{});
    return errata;
  }

  ngtcp2_path path;
  memset(&path, INITIALIZATION_BYTE, sizeof(path));
  ngtcp2_addr_init(
      &path.local,
      (struct sockaddr *)&_quic_socket.local_addr,
      _quic_socket.local_addrlen,
      nullptr);
  ngtcp2_addr_init(&path.remote, &this->_endpoint->sa, this->_endpoint->size(), nullptr);

  auto const rc = ngtcp2_conn_client_new(
      &_quic_socket.qconn,
      &_quic_socket.dcid,
      &_quic_socket.scid,
      &path,
      NGTCP2_PROTO_VER_MIN,
      &client_ngtcp2_callbacks,
      &_quic_socket.settings,
      &_quic_socket.transport_params,
      nullptr,
      this /* The user_data in the ngtcp2 callbacks. */);
  if (rc) {
    errata.error("ngtcp2_conn_client_new failed.");
    return errata;
  }

  ngtcp2_conn_set_tls_native_handle(_quic_socket.qconn, _quic_socket.ssl);

  // TODO Set up the HTTP/3 callback methods
  return errata;
}

Errata
H3Session::server_session_init()
{
  Errata errata;
  // TODO: Set up the HTTP/3 callback methods.
  return errata;
}
