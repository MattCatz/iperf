/*
 * iperf, Copyright (c) 2014-2023, The Regents of the University of
 * California, through Lawrence Berkeley National Laboratory (subject
 * to receipt of any required approvals from the U.S. Dept. of
 * Energy).  All rights reserved.
 *
 * If you have questions about your rights to use or distribute this
 * software, please contact Berkeley Lab's Technology Transfer
 * Department at TTD@lbl.gov.
 *
 * NOTICE.  This software is owned by the U.S. Department of Energy.
 * As such, the U.S. Government has been granted for itself and others
 * acting on its behalf a paid-up, nonexclusive, irrevocable,
 * worldwide license in the Software to reproduce, prepare derivative
 * works, and perform publicly and display publicly.  Beginning five
 * (5) years after the date permission to assert copyright is obtained
 * from the U.S. Department of Energy, and subject to any subsequent
 * five (5) year renewals, the U.S. Government is granted for itself
 * and others acting on its behalf a paid-up, nonexclusive,
 * irrevocable, worldwide license in the Software to reproduce,
 * prepare derivative works, distribute copies to the public, perform
 * publicly and display publicly, and to permit others to do so.
 *
 * This code is distributed under a BSD style license, see the LICENSE
 * file for complete information.
 */

#include "iperf_api.h"
#include <setjmp.h>    // for longjmp, jmp_buf, setjmp
#include <signal.h>    // for signal, SIGPIPE, SIG_DFL, SIG_IGN
#include <stdio.h>     // for fprintf, stderr, NULL
#include <stdlib.h>    // for exit
#include <sys/types.h> // for u_int64_t
#include <unistd.h>    // for daemon
struct iperf_test;
static struct iperf_test* test;


static int
run(struct iperf_test* test);

/**************************************************************************/
int
main(int argc, char** argv)
{

  /*
   * Atomics check. We prefer to have atomic types (which is
   * basically on any compiler supporting C11 or better). If we
   * don't have them, we try to approximate the type we need with a
   * regular integer, but complain if they're not lock-free. We only
   * know how to check this on GCC. GCC on CentOS 7 / RHEL 7 is the
   * targeted use case for these check.
   */
#ifndef HAVE_STDATOMIC
#ifdef __GNUC__
  if (!__atomic_always_lock_free(sizeof(u_int64_t), 0)) {
#endif // __GNUC__
    fprintf(stderr,
            "Warning: Cannot guarantee lock-free operation with "
            "64-bit data types\n");
#ifdef __GNUC__
  }
#endif // __GNUC__
#endif // HAVE_STDATOMIC

  test = iperf_new_test();
  if (!test)
    iperf_errexit(NULL, "create new test error - %s", iperf_strerror(i_errno));
  iperf_defaults(test); /* sets defaults */

  if (iperf_parse_arguments(test, argc, argv) < 0) {
    iperf_err(test, "parameter error - %s", iperf_strerror(i_errno));
    fprintf(stderr, "\n");
    usage();
    exit(1);
  }

  if (run(test) < 0)
    iperf_errexit(test, "error - %s", iperf_strerror(i_errno));

  iperf_free_test(test);

  return 0;
}

static void __attribute__((noreturn)) sigend_handler(int sig)
{
  (void)sig;
  iperf_got_sigend(test);
}

/**************************************************************************/
static int
run(struct iperf_test* test)
{
  /* Termination signals. */
  iperf_catch_sigend(sigend_handler);

  /* Ignore SIGPIPE to simplify error handling */
  signal(SIGPIPE, SIG_IGN);

  switch (iperf_get_test_role(test)) {
    case 's':
      if (iperf_get_test_daemon(test)) {
        int rc;
        rc = daemon(1, 0);
        if (rc < 0) {
          i_errno = IEDAEMON;
          iperf_errexit(test, "error - %s", iperf_strerror(i_errno));
        }
      }
      if (iperf_create_pidfile(test) < 0) {
        i_errno = IEPIDFILE;
        iperf_errexit(test, "error - %s", iperf_strerror(i_errno));
      }
      for (;;) {
        int rc;
        rc = iperf_run_server(test);
        if (rc < 0) {
          iperf_err(test, "error - %s", iperf_strerror(i_errno));
          if (iperf_get_test_json_output(test)) {
            if (iperf_json_finish(test) < 0)
              return -1;
          }
          iflush(test);

          if (rc < -1) {
            iperf_errexit(test, "exiting");
          }
        }
        iperf_reset_test(test);
        if (iperf_get_test_one_off(test) && rc != 2) {
          /* Authentication failure doesn't count for 1-off test */
          if (rc < 0 && i_errno == IEAUTHTEST) {
            continue;
          }
          break;
        }
      }
      iperf_delete_pidfile(test);
      break;
    case 'c':
      if (iperf_create_pidfile(test) < 0) {
        i_errno = IEPIDFILE;
        iperf_errexit(test, "error - %s", iperf_strerror(i_errno));
      }
      if (iperf_run_client(test) < 0)
        iperf_errexit(test, "error - %s", iperf_strerror(i_errno));
      iperf_delete_pidfile(test);
      break;
    default:
      usage();
      break;
  }

  iperf_catch_sigend(SIG_DFL);
  signal(SIGPIPE, SIG_DFL);

  return 0;
}
