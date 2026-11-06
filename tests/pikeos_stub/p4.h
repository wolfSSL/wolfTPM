/* Minimal stand-in for the PikeOS SDK p4.h, with the SDK's signatures. It lets
 * the transport build and run on a host; it is not used on a PikeOS target. */
#ifndef PIKEOS_STUB_P4_H
#define PIKEOS_STUB_P4_H
typedef int P4_e_t;
typedef unsigned long P4_size_t;
typedef unsigned long long P4_time_t;
#define P4_E_OK 0
#define P4_MSEC(to) ((to) * 1000000ULL)
P4_e_t p4_sleep(P4_time_t timeout);
P4_time_t p4_get_time(void);
#endif
