/** @file
 * Common implementation for Proxy Verifier
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/SocketNotifier.h"
#include "core/http.h"

#include <mutex>
#include <thread>

// Static instantiations.
SocketNotifier SocketNotifier::_socket_notifier; // Our singleton.
std::thread SocketNotifier::_notifier_thread;
bool SocketNotifier::_stop_notifier_flag = false;

void
SocketNotifier::notify_sessions(std::vector<PollResult> const &poll_results)
{
  {
    std::lock_guard<std::mutex> lock(_socket_notifier._poll_results_mutex);
    for (auto const &poll_result : poll_results) {
      if (auto session = poll_result.session.lock(); session) {
        _socket_notifier._poll_results.emplace(poll_result.fd, poll_result);
      }
    }
  }
  _socket_notifier._notification_infos_cv.notify_one();
}

void
SocketNotifier::drop_session_notification(int fd)
{
  std::lock_guard<std::mutex> lock(_socket_notifier._poll_results_mutex);
  _socket_notifier._poll_results.erase(fd);
}

void
SocketNotifier::start_notifier_thread()
{
  _stop_notifier_flag = false;
  _notifier_thread = std::thread([]() { SocketNotifier::_socket_notifier._start_notifying(); });
}

void
SocketNotifier::stop_notifier_thread()
{
  _stop_notifier_flag = true;
  _socket_notifier._notification_infos_cv.notify_one();
  _notifier_thread.join();
}

void
SocketNotifier::_start_notifying()
{
  std::vector<std::shared_ptr<Session>> sessions_to_release;
  while (!SocketNotifier::_stop_notifier_flag) {
    // Free the sessions while not holding _poll_results_mutex.
    sessions_to_release.clear();
    std::unique_lock<std::mutex> lock(_poll_results_mutex);
    _notification_infos_cv.wait(lock, [this]() {
      return !_poll_results.empty() || SocketNotifier::_stop_notifier_flag;
    });

    if (SocketNotifier::_stop_notifier_flag) {
      break;
    }

    for (auto &[fd, poll_result] : _poll_results) {
      auto &[_, weak_session, revents] = poll_result;
      if (auto session = weak_session.lock(); session) {
        // If we turn out to be the last holder of this session, we cannot
        // destruct the session while holding the _poll_results_mutex.
        // Otherwise, the Session destructor will call
        // SocketNotifier::drop_session_notification, which will deadlock
        // because it grabs that same mutex. Instead we'll free the sessions on
        // the next iteration of the loop when we call free on the session
        // vector.
        sessions_to_release.push_back(session);
        session->handle_poll_return(revents);
      }
    }
    _poll_results.clear();
  }
}
