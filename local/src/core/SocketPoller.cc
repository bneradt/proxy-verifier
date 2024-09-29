/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/SocketPoller.h"
#include "core/PollTypes.h"
#include "core/http.h"
#include "core/PollManager.h"
#include "core/ProxyVerifier.h"
#include "core/SocketNotifier.h"

#include "swoc/bwf_ex.h"
#include "swoc/bwf_ip.h"
#include "swoc/bwf_std.h"
#include "swoc/Errata.h"

#include <chrono>
#include <mutex>
#include <thread>
#include <unordered_set>

using swoc::Errata;

// Static instantiations.
SocketPoller SocketPoller::_socket_poller; // Our singleton.
std::thread SocketPoller::_poller_thread;
bool SocketPoller::_stop_polling_flag = false;

void
SocketPoller::request_poll(std::weak_ptr<Session> session, short events)
{
  {
    std::lock_guard<std::mutex> lock(_socket_poller._polling_requests_mutex);
    if (auto locked_session = session.lock(); locked_session) {
      auto const fd = locked_session->get_fd();
      _socket_poller._polling_requests.emplace(fd, PollInput{fd, session, events});
    }
  }
  _socket_poller._polling_requests_cv.notify_one();
}

void
SocketPoller::unregister_poll_request(int fd)
{
  {
    std::lock_guard<std::mutex> lock(_socket_poller._polling_requests_mutex);
    _socket_poller._polling_requests.erase(fd);
  } // Unlock the _polling_requests_mutex.
  _socket_poller._poll_fd_manager.remove_fd(fd);
  SocketNotifier::drop_session_notification(fd);
}

void
SocketPoller::unregister_poll_requests(std::vector<PollResult> const &poll_results)
{
  std::lock_guard<std::mutex> lock(_socket_poller._polling_requests_mutex);
  for (auto const &poll_result : poll_results) {
    _socket_poller._polling_requests.erase(poll_result.fd);
  }
}

void
SocketPoller::start_polling_thread()
{
  SocketPoller::_stop_polling_flag = false;
  SocketNotifier::start_notifier_thread();
  _poller_thread = std::thread([]() { SocketPoller::_socket_poller._start_polling(); });
}

void
SocketPoller::stop_polling_thread()
{
  SocketNotifier::stop_notifier_thread();
  SocketPoller::_stop_polling_flag = true;
  _socket_poller._polling_requests_cv.notify_one();
  SocketPoller::_poller_thread.join();
}

SocketPoller::AwaitStatus
SocketPoller::_await_polling_requests()
{
  // Wait for the request_poll producer to add sessions to poll upon.
  std::unique_lock<std::mutex> lock(_polling_requests_mutex);
  _polling_requests_cv.wait(lock, [this]() {
    return !_polling_requests.empty() || SocketPoller::_stop_polling_flag;
  });

  // Either we (1) received poll requests, or (2) we have been asked to stop
  // polling. Handle both cases.
  if (SocketPoller::_stop_polling_flag) {
    return AwaitStatus::STOP_POLLING;
  }

  // We have poll requests to process. Now populate the array of pollfd
  // objects as input to ::poll.
  for (auto const &[_, polling_input] : _polling_requests) {
    _poll_fd_manager.add_fd(polling_input);
  }
  return AwaitStatus::CONTINUE_POLLING;
}

void
SocketPoller::_start_polling()
{
  Errata errata;

  // Declare these out here so there memory isn't reallocated on each iteration.
  std::vector<PollResult> poll_results;
  // default_max_threads is a reasonable approximation. If the user configured
  // more, future emplace_backs will expand the size for us as needed.
  while (!SocketPoller::_stop_polling_flag) {
    // Clear maintains capacity.
    poll_results.clear();

    auto const await_status = _await_polling_requests();
    if (await_status == AwaitStatus::STOP_POLLING) {
      break;
    }

    auto const poll_result = _poll_fd_manager.poll(SocketPoller::_poll_timeout);
    if (poll_result == 0) {
      // Timeout. Simply loop backaround and poll again. Maybe other fd's have
      // been registered.
      continue;
    } else if (poll_result < 0) {
      // Error condition.
      if (errno == EINTR) {
        continue;
      }
      errata.note(S_ERROR, "poll failed: {}", swoc::bwf::Errno{});
      return;
    }

    // Poll succeeded. There are events to process.
    {
      std::lock_guard<std::mutex> lock(_polling_requests_mutex);
      poll_results = _poll_fd_manager.process_poll_events(_polling_requests);
    } // Unlock the _polling_requests_mutex.
    SocketPoller::unregister_poll_requests(poll_results);
    SocketNotifier::notify_sessions(poll_results);
  }
}
