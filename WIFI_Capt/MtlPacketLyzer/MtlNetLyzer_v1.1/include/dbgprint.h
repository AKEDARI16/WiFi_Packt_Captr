/*
 * Trace log debugging dbgprint.h
 *
 * This header file may contains logging apis and include libraries
 * Global structures,enums and api's
 *
 */


#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdlib.h>



typedef long osl_time_t;
#define PRINTF_FORMAT(a,b) __attribute__ ((format (printf, (a), (b))))


/*The Log File path points to here*/




/*@Defining Os time structure*/
struct osl_time {
	osl_time_t sec;
	osl_time_t usec;
};

enum {
	 MSG_MSGDUMP, MSG_DEBUG, MSG_INFO, MSG_WARNING, MSG_ERROR
};

extern int log_level;
extern int debug_timestamp;
extern int debug_syslog;



/*
 * The ApI printing the insormation and stored in specific log location file
 * @In params Var_list atgiments 
 *
 */

void dbg_log(int level, const char *fmt, ...);

/* 
 *The ApI printing the time stamp of each estatement of print info
 * @inparams void
 *
 */

void debug_print_timestamp(void);


/*
 * The ApI describes the opening file to pushing the stream buffer into file
 * The debug_close_file describes the file close all the pipes before closing the application
 */


 int debug_open_file(const char *path);
 void debug_close_file(void);


