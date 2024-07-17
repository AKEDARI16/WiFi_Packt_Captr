/**
 * dbg_log - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to stdout, stderr, and/or syslog based on
 * configuration.
 *
 * Note: New line '\n' is added to the end of the text when printing to stdout.
 */

#include "dbgprint.h" /*FIX ME*/


static FILE *debug_tracing_file = NULL;


static FILE *out_file = NULL;
static char *last_path = NULL;


/* Debugging function - conditional printf and  dump. The wrappers can
 * use these for debugging purposes. */



void * osl_memcpy(void *dest, const void *src, size_t n)
{
	char *d = dest;
	const char *s = src;
	while (n--)
		*d++ = *s++;
	return dest;
}

int osl_strcmp(const char *s1, const char *s2)
{
	while (*s1 == *s2) {
		if (*s1 == '\0')
			break;
		s1++;
		s2++;
	}

	return *s1 - *s2;
}

void osl_free(void *ptr)
{
	free(ptr);
}

int osl_memcmp(const void *s1, const void *s2, size_t n)
{
	const unsigned char *p1 = s1, *p2 = s2;

	if (n == 0)
		return 0;

	while (*p1 == *p2) {
		p1++;
		p2++;
		n--;
		if (n == 0)
			return 0;
	}

	return *p1 - *p2;
}

size_t osl_strlen(const char *s)
{
	const char *p = s;
	while (*p)
		p++;
	return p - s;
}


void * osl_malloc(size_t size)
{
	return malloc(size);
}


char * osl_strdup(const char *s)
{
	char *res;
	size_t len;
	if (s == NULL)
		return NULL;
	len = osl_strlen(s);
	res = osl_malloc(len + 1);
	if (res)
		osl_memcpy(res, s, len + 1);
	return res;
}


static int syslog_priority(int level)
{
	switch (level) {
	case MSG_MSGDUMP:
	case MSG_DEBUG:
		return LOG_DEBUG;
	case MSG_INFO:
		return LOG_NOTICE;
	case MSG_WARNING:
		return LOG_WARNING;
	case MSG_ERROR:
		return LOG_ERR;
	}
	return LOG_INFO;
}


int osl_get_time(struct osl_time *t)
{
	int res;
	struct timeval tv;
	res = gettimeofday(&tv, NULL);
	t->sec = tv.tv_sec;
	t->usec = tv.tv_usec;
	return res;
}


/*
 *The function api to print the time in ms.us heading of the each statement
 *The function in params void
 *returns nothing
 */


void debug_print_timestamp(void)
{

	struct osl_time tv;

	if (!debug_timestamp)
		return;

	osl_get_time(&tv);
	if (out_file)
		fprintf(out_file, "%ld.%06u: ", (long) tv.sec,
			(unsigned int) tv.usec);

	if (!out_file && !debug_syslog)
		printf("%ld.%06u: ", (long) tv.sec, (unsigned int) tv.usec);
}

/*
 *It is the functional api to print the information in cap_debug.log file
 *The function in params variable arguments
 *returns nothing
 */

void dbg_log(int level, const char *fmt, ...)
{
	va_list ap;

	if (level >= log_level) {

		if (debug_syslog) {
			va_start(ap, fmt);
			vsyslog(syslog_priority(level), fmt, ap);
			va_end(ap);
		}

		debug_print_timestamp();
		if (out_file) {
			va_start(ap, fmt);
			vfprintf(out_file, fmt, ap);
			fprintf(out_file, "\n");
			va_end(ap);
		}
		if (!debug_syslog && !out_file) {
			va_start(ap, fmt);
			vprintf(fmt, ap);
			printf("\n");
			va_end(ap);
		}
	}

}


/*
 *The API request to open a file in file descriptor using System APIs
 */
int debug_open_file(const char *path)
{

	int out_fd;

	if (!path)
		return 0;

	if (last_path == NULL || osl_strcmp(last_path, path) != 0) {
		/* Save our path to enable re-open */
		osl_free(last_path);
		last_path = osl_strdup(path);
	}

	out_fd = open(path, O_CREAT | O_APPEND | O_WRONLY | O_TRUNC,
		      S_IRWXU | S_IRWXG | S_IRWXO ,0777);
	if (out_fd < 0) {
		dbg_log(MSG_ERROR,
			   "%s: Failed to open output file descriptor, using standard output",
			   __func__);
		return -1;
	}

#ifdef __linux__
	if (fcntl(out_fd, F_SETFD, FD_CLOEXEC) < 0) {
		dbg_log(MSG_DEBUG,
			   "%s: Failed to set FD_CLOEXEC - continue without: %s",
			   __func__, strerror(-1));
	}
#endif /* __linux__ */

	out_file = fdopen(out_fd, "a");
	if (out_file == NULL) {
		dbg_log(MSG_ERROR, "debug_open_file: Failed to open "
			   "output file, using standard output");
		close(out_fd);
		return -1;
	}

	return 0;
}



/*
 *The API request to close a file in file descriptor using System APIs
 *And clears the all the buffers
 */

void debug_close_file(void)
{

	dbg_log(MSG_DEBUG,"Closing function successfullly");
	if (!out_file)
		return;
	fclose(out_file);
	out_file = NULL;
	osl_free(last_path);
	last_path = NULL;
	

}
