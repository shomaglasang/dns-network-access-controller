/*INC+*************************************************************************/
/* Filename    : logging.h                                                    */
/*                                                                            */
/* Description : Logging header file.                                         */
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*INC+*************************************************************************/

#ifndef _LOGGING_H
#define _LOGGING_H

/******************************************************************************/
/* Log facilities.                                                            */
/******************************************************************************/
#define LOG_DEF                                   0x0
#define LOG_STDOUT                                0x1
#define LOG_STDERR                                0x2
#define LOG_SYSLOGGER                             0x4

#define PUTS_OUT(l,m...)                          do_log(LOG_STDOUT, l, m)
#define PUTS_ERR(l,m...)                          do_log(LOG_STDERR, l, m)
#define PUTS_SYS(l,m...)                          do_log(LOG_SYSLOGGER, l, m)
#define PUTS_OSYS(l,m...)                         do_log(LOG_STDOUT|LOG_SYSLOGGER, l, m)
#define PUTS_ESYS(l,m...)                         do_log(LOG_STDERR|LOG_SYSLOGGER, l, m)

/******************************************************************************/
/* Forwards decls.                                                            */
/******************************************************************************/
extern void do_log(int fac, int level, char *fmt, ...);

#endif

