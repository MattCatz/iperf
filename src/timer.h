/*
 * iperf, Copyright (c) 2014, The Regents of the University of
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
 *
 * Based on timers.h by Jef Poskanzer. Used with permission.
 */

#ifndef __TIMER_H
#define __TIMER_H

#include "iperf_time.h" // for iperf_time
#include <stdint.h>     // for int64_t

/* TimerClientData is an opaque value that tags along with a timer.  The
** client can use it for whatever, and it gets passed to the callback when
** the timer triggers.
*/
typedef union
{
  void* p;
  int i;
  long l;
} TimerClientData;

struct timeval;
extern TimerClientData JunkClientData; /* for use when you don't care */

/* The TimerProc gets called when the timer expires.  It gets passed
** the TimerClientData associated with the timer, and a iperf_time in case
** it wants to schedule another timer.
*/
typedef void
TimerProc(TimerClientData client_data, struct iperf_time* nowP);

/* The Timer struct. */
typedef struct TimerStruct
{
  TimerProc* timer_proc;
  TimerClientData client_data;
  int64_t usecs;
  int periodic;
  struct iperf_time time;
  struct TimerStruct* prev;
  struct TimerStruct* next;
  int hash;
} Timer;

/* Set up a timer, either periodic or one-shot. Returns (Timer*) 0 on errors.
 */
Timer*
tmr_create(struct iperf_time* nowP,
           TimerProc* timer_proc,
           TimerClientData client_data,
           int64_t usecs,
           int periodic);

/* 
** In the case of a pending timer a 1 is returned and timer is updated.
** In the case of no pending timer, 0 is returned and timer is not updated.
*/
int
tmr_timeout(struct iperf_time* nowP, struct timeval* timeout) /* __attribute__((hot)) */;

/* Run the list of timers. Your main program needs to call this every so often,
** or as indicated by tmr_timeout().
*/
void
tmr_run(struct iperf_time* nowP) /* __attribute__((hot)) */;

/* Reset the clock on a timer, to current time plus the original timeout. */
void
tmr_reset(struct iperf_time* nowP, Timer* timer);

/* Deschedule a timer.  Note that non-periodic timers are automatically
** descheduled when they run, so you don't have to call this on them.
*/
void
tmr_cancel(Timer* timer);

/* Clean up the timers package, freeing any unused storage. */
void
tmr_cleanup(void);

/* Cancel all timers and free storage, usually in preparation for exiting. */
void
tmr_destroy(void);

#endif /* __TIMER_H */
