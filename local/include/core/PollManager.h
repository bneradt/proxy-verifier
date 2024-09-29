/** @file
 * Manages poll request information for poll interfaces.
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include "core/SocketNotifier.h"
#include "core/PollTypes.h"

#include <chrono>
#include <poll.h>
#include <vector>
#include <unordered_map>

#define SUPPORTS_EPOLL __linux__

#ifdef SUPPORTS_EPOLL
#include <sys/epoll.h>
#else
#include <poll.h>
#endif

/** Encapsulate handling of interfacing with the system's poll interface.
 *
 * This makes the provides a common interface to the rest of the system for
 * polling, regardless of whether poll(2) or epoll(2) is used.
 */
class PollManager
{
public:
  /** Reserve space in our containers in the constructor. */
  PollManager();

  /** Add fd to our set, if it isn't in there already.
   * @param[in] fd The file descriptor to add.
   * @param[in] events The events to poll for on the file descriptor.
   */
  void add_fd(PollInput const &poll_input);

  /** Remove the file descriptor from the polling set.
   *@param[in] fd_to_erase The file descriptor to remove.
   */
  void remove_fd(int fd_to_erase);

  /** Remove the set of file descriptors from the polling set.
   *@param[in] fds_to_erase The file descriptors to remove.
   */
  void remove_fds(std::vector<PollResult> const &fds_to_erase);

  /** Poll on the registered file descriptors.
   * @param[in] timeout The timeout for the poll.
   * @return The return value of ::poll or ::epoll_wait (which conveniently have
   * the same return semantics).
   */
  int poll(std::chrono::milliseconds timeout);

  /** Process the events of the last poll.
   *
   * @param[in] poll_infos Information about the current state of desired poll
   * events. This is used to filter out the poll events to only those that are
   * currently interested.
   * @return The list of poll events that are interesting to the sessions.
   */
  std::vector<PollResult> process_poll_events(std::unordered_map<int, PollInput> const &poll_infos);

private:
  /** Guard the modification of various containers from multi-thread modification. */
  std::mutex _polling_requests_mutex;

#ifndef SUPPORTS_EPOLL
  /// Manage the memory to use for ::poll(2).
  std::vector<struct pollfd> _poll_fds;
#endif

  /// fd -> poll events value.
  std::unordered_map<int, short> _contained_fds;

  /// Ensure that @a poll and @a process_poll_events are alternately called.
  bool _just_called_poll = false;

#ifdef SUPPORTS_EPOLL
  /// The epoll file descriptor.
  int _epoll_fd = -1;

  /// The output data for epoll_wait.
  std::vector<struct epoll_event> _epoll_events;

#endif
};
