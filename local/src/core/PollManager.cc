
/** @file
 * Implements the PollManager class.
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#include "core/PollManager.h"
#include "core/ProxyVerifier.h"
#include "core/http.h"

#include <algorithm>
#include <cassert>
#include <cstring>
#include <unordered_map>



#include <iostream>




#ifdef SUPPORTS_EPOLL
#include <sys/epoll.h>
#else
#include <poll.h>
#endif

/** Help maintain the memory of the "struct pollfd" array for ::poll. */
PollManager::PollManager()
{
  // For the below, default_max_threads is a reasonable approximation to the
  // number of file descriptors we'll need since we don't have access to the
  // ThreadPool instance to call get_max_threads. If the user configured more,
  // future emplace_backs will expand the size for us as needed.
#ifdef SUPPORTS_EPOLL
  _epoll_fd = ::epoll_create(ThreadPool::default_max_threads);
  if (_epoll_fd == -1) {
    // Since these should never happen, let these uncaught exceptions bring
    // down the process and force the dev to update the logic here.
    throw std::runtime_error("Failed to create epoll fd.");
  }
  _epoll_events.reserve(ThreadPool::default_max_threads);
#else
  _poll_fds.reserve(ThreadPool::default_max_threads);
#endif
  _contained_fds.reserve(ThreadPool::default_max_threads);
}

void
PollManager::add_fd(PollInput const &poll_input)
{
  std::lock_guard<std::mutex> lock(_polling_requests_mutex);
  auto spot = _contained_fds.find(poll_input.fd);
  bool const is_new_fd = spot == _contained_fds.end();
  if (!is_new_fd) {
    if (spot->second == poll_input.events) {
      // No change, nothing to do.
      return;
    }
  }
  _contained_fds.emplace(poll_input.fd, poll_input.events);

#ifdef SUPPORTS_EPOLL
  struct epoll_event ev;
  ev.events = poll_input.events;
  ev.data.fd = poll_input.fd;
  int const op = is_new_fd ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
  int epoll_result = ::epoll_ctl(_epoll_fd, op, poll_input.fd, &ev);
  if (epoll_result == -1) {
    switch (errno) {
    case EEXIST:
      // fd is alread in the list, ignore.
      break;
    case EBADF:
      // fd has been closed. Just handle this and move on.
      _contained_fds.erase(poll_input.fd);
      break;
    default:
      // Since these should never happen, let these uncaught exceptions bring
      // down the process and force the dev to update the logic here.
      throw std::runtime_error(std::string("Failed to add fd to epoll: ") + strerror(errno));
    };
  }
#else
  _poll_fds.push_back(pollfd{poll_input.fd, poll_input.events, 0});
#endif
}

void
PollManager::remove_fd(int fd_to_erase)
{
  return this->remove_fds({PollResult(fd_to_erase, {}, 0)});
}

void
PollManager::remove_fds(std::vector<PollResult> const &poll_results)
{
  for (auto const &poll_result : poll_results) {
    std::lock_guard<std::mutex> lock(_polling_requests_mutex);
    if (_contained_fds.find(poll_result.fd) == _contained_fds.end()) {
      // This fd was already removed. Move on.
      continue;
    }
    _contained_fds.erase(poll_result.fd);
#ifdef SUPPORTS_EPOLL
    int epoll_result = ::epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, poll_result.fd, nullptr);
    if (epoll_result == -1 && errno != ENOENT && errno != EBADF) {
      // Since these should never happen, let these uncaught exceptions bring
      // down the process and force the dev to update the logic here.
      throw std::runtime_error(std::string("Failed to remove fd from epoll: ") + strerror(errno));
    }
#endif
  }
#ifndef SUPPORTS_EPOLL
  std::lock_guard<std::mutex> lock(_polling_requests_mutex);
  _poll_fds.erase(
      std::remove_if(
          _poll_fds.begin(),
          _poll_fds.end(),
          [this](struct pollfd const &poll_fd) {
            return _contained_fds.find(poll_fd.fd) == _contained_fds.end();
          }),
      _poll_fds.end());
#endif
}

int
PollManager::poll(std::chrono::milliseconds timeout)
{
  assert(!_just_called_poll);
  this->_just_called_poll = true;
  std::lock_guard<std::mutex> lock(_polling_requests_mutex);
#ifdef SUPPORTS_EPOLL
  if (_epoll_events.size() < _contained_fds.size()) {
    _epoll_events.resize(_contained_fds.size());
  }
  auto const nfds =
      ::epoll_wait(_epoll_fd, _epoll_events.data(), _epoll_events.size(), timeout.count());
  if (nfds > 0) {
    _epoll_events.resize(nfds);
  }
  std::cout << "Polling for " << _contained_fds.size() << " fds, got " << nfds << " events\n";
  return nfds;
#else
  int const nfds = ::poll(_poll_fds.data(), _poll_fds.size(), timeout.count());
  return nfds;
#endif
}

std::vector<PollResult>
PollManager::process_poll_events(std::unordered_map<int, PollInput> const &poll_infos)
{
  assert(_just_called_poll);
  _just_called_poll = false;
  std::vector<PollResult> poll_results;
  std::unique_lock<std::mutex> lock(_polling_requests_mutex);
#ifdef SUPPORTS_EPOLL
  for (auto const &poll_result : _epoll_events) {
    uint32_t const revents = poll_result.events;
    int fd = poll_result.data.fd;
#else
  for (auto const &poll_result : _poll_fds) {
    short const revents = poll_result.revents;
    int fd = poll_result.fd;
#endif

    if (revents == 0) {
      // This fd did not have an event. Move on.
      continue;
    }
    // Make sure that, in the meantime, the session didn't time out and
    // move on and deregister itself.
    auto spot = poll_infos.find(fd);
    if (spot == poll_infos.end()) {
      continue;
    }
    auto session = spot->second.session;
    poll_results.emplace_back(fd, session, revents);
  }
  lock.unlock();
  this->remove_fds(poll_results);
  return poll_results;
}
