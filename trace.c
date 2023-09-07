#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>

#include "trace.h"

/* Tacacs control flag */
extern int tacacs_ctrl;

/* Output trace log. */
void trace(const char *format, ...)
{
    if (tacacs_ctrl & PAM_TAC_DEBUG == 0) {
        return;
    }

    // convert log to a string because va args resoursive issue:
    // http://www.c-faq.com/varargs/handoff.html
    char logBuffer[MAX_LINE_SIZE];
    va_list args;
    va_start (args, format);
    vsnprintf(logBuffer, sizeof(logBuffer), format, args);
    va_end (args);

    syslog(LOG_INFO, "Audisp-tacplus: %s", logBuffer);
}