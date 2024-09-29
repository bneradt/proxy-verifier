/** @file
 * A structure usefull for communicating poll information.
 *
 * Copyright 2024, Verizon Media
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <memory>

class Session;

/** Information related to a file descriptor being polled upon. */
struct PollInput
{
  PollInput(int fd, std::weak_ptr<Session> session, short events)
    : fd(fd)
    , session(std::move(session))
    , events(events)
  {
  }

  /** The file descriptor interested in polling. */
  int fd = -1;

  /** The HTTP session interested in polling. */
  std::weak_ptr<Session> session;

  /** The input to poll() indicating what events are interesting to @a session. */
  short events = 0;
};

/** Information from poll result.
 *
 * Note that this structure is identical in type to the above, but it names the
 * output event as revents for readability in the context of poll results.
 */
struct PollResult
{
  PollResult(int fd, std::weak_ptr<Session> session, short revents)
    : fd(fd)
    , session(std::move(session))
    , revents(revents)
  {
  }
  /** The file descriptor interested in the poll result. */
  int fd = -1;

  /** The HTTP session interested in the poll result. */
  std::weak_ptr<Session> session;

  /** The poll event for this @a fd. */
  short revents = 0;
};
