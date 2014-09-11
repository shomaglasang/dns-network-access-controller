/*FILE+************************************************************************/
/* Filename    : logging.c                                                    */
/*                                                                            */
/* Description : Logging facility.                                            */
/*                                                                            */
/* Revisions   : 05/10/14  Sho                                                */
/*                         - Creation.                                        */
/*                                                                            */
/*FILE-************************************************************************/

#include <stdarg.h>

#include <common.h>
#include <dnswldcb.h>
#include <logging.h>


/*FUNC+************************************************************************/
/* Function    : do_log                                                       */
/*                                                                            */
/* Description : Log message to destination.                                  */
/*                                                                            */
/* Params      : fac                      - Facility                          */
/*               level                    - Log level                         */
/*               format                   - Message format                    */
/*                                                                            */
/* Returns     : none                                                         */
/*                                                                            */
/*FUNC-************************************************************************/
void do_log(int fac, int level, char *fmt, ...)
{
  va_list args;
  char buf[1023];
  int log_stdout;
  int log_stderr;
  int log_syslog;

  /****************************************************************************/
  /* Filter out debugs, unless needed.                                        */
  /****************************************************************************/
  if ((level == LOG_DEBUG) && (!dnswld.log.is_debug_on))
  {
    return;
  }

  /****************************************************************************/
  /* Format log message.                                                      */
  /****************************************************************************/
  va_start (args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);

  if (fac)
  {
    log_stdout = (fac & LOG_STDOUT) ? TRUE : FALSE;
    log_stderr = (fac & LOG_STDERR) ? TRUE : FALSE;
    log_syslog = (fac & LOG_SYSLOGGER) ? TRUE : FALSE;
  }
  else
  {
    log_stdout = (dnswld.log.facility & LOG_STDOUT) ? TRUE : FALSE;
    log_stderr = (dnswld.log.facility & LOG_STDERR) ? TRUE : FALSE;
    log_syslog = (dnswld.log.facility & LOG_SYSLOGGER) ? TRUE : FALSE;
  }

  /****************************************************************************/
  /* Write to facility.                                                       */
  /****************************************************************************/
  if (log_syslog)
  {
    syslog(level, "%s", buf);
  }

  if (log_stderr)
  {
    fprintf(stderr, "%s\n", buf);
  }

  if (log_stdout)
  {
    fprintf(stdout, "%s\n", buf);
  }
}

