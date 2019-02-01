#include "dns.h"

void
log_info(char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void
verbose(char *fmt, ...)
{
	va_list		args;

	if (!VERBOSE)
		return;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);
}

void
log_err(char *fmt, ...)
{
	va_list		args;
	char		*tmp = NULL;
	int			_errno;

	_errno = errno;
	posix_memalign((void **)&tmp, 16, MAXLINE);

	va_start(args, fmt);
	vsprintf(tmp, fmt, args);
	fprintf(stderr, "%s (%s)\n", tmp, strerror(_errno));
	va_end(args);

	free(tmp);
	errno = _errno;
}

void
log_err_quit(char *fmt, ...)
{
	va_list		args;
	char		*tmp = NULL;
	int			_errno;

	_errno = errno;
	posix_memalign((void **)&tmp, 16, MAXLINE);

	va_start(args, fmt);
	vsprintf(tmp, fmt, args);
	fprintf(stderr, "%s (%s)\n", tmp, strerror(_errno));
	va_end(args);

	free(tmp);
	errno = _errno;
	exit(EXIT_FAILURE);
}

void
debug(char *fmt, ...)
{
	va_list		args;

	if (!DEBUG)
		return;
	va_start(args, fmt);
	printf("\e[38;5;9m[debug] \e[m");
	vprintf(fmt, args);
	va_end(args);
}
