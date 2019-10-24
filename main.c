#include "dns.h"

int		DEBUG;
int		VERBOSE;
int		TO_FILE;
int		NO_OPEN;
int		TRACE_PATH;
u16		DNS_PORT;
int		SERVER;
int		host_max;
int		path_max;
char	*inet4_ptr_name;
char	*inet6_ptr_name;
char	*inet4_string;
char	*time_string;
char	*primary_NS;
char	*DNS_SERVER;
char	*TEXT_EDITOR;
char	*HOME_DIR;
char	*b64table;

static int	DO_AXFR = 0;
static char	prog_name[64];

static void __usage(int) __attribute__ ((__noreturn__));
static void __dns_dump_clean(void);
static int __is_inet4_string(char *) __nonnull ((1)) __wur;
static int host_name_ok(char *) __nonnull ((1)) __wur;

static void
__attribute__ ((constructor)) __dns_dump_init(void)
{
	host_max = sysconf(_SC_HOST_NAME_MAX);
	path_max = pathconf("/", _PC_PATH_MAX);
	if (path_max == 0)
		path_max = 1024;
	atexit(__dns_dump_clean);
	TO_FILE = 1;
	NO_OPEN = 0;
	DEBUG = 0;
	VERBOSE = 0;
	DNS_PORT = 53;
	TRACE_PATH = 0;
	SERVER = 0;
	inet4_ptr_name = NULL;
	inet6_ptr_name = NULL;
	inet4_string = NULL;
	primary_NS = NULL;
	DNS_SERVER = NULL;
	time_string = NULL;
	TEXT_EDITOR = NULL;
	HOME_DIR = NULL;

	posix_memalign((void **)&b64table, 16, 128);
	posix_memalign((void **)&inet4_ptr_name, 16, path_max);
	posix_memalign((void **)&inet6_ptr_name, 16, path_max);
	posix_memalign((void **)&inet4_string, 16, INET_ADDRSTRLEN);
	posix_memalign((void **)&primary_NS, 16, host_max);
	posix_memalign((void **)&DNS_SERVER, 16, host_max);
	posix_memalign((void **)&time_string, 16, 64);
	posix_memalign((void **)&TEXT_EDITOR, 16, 64);
	posix_memalign((void **)&HOME_DIR, 16, path_max);
	strncpy(DNS_SERVER, LOCAL_DNS, host_max); // default
	DNS_SERVER[strlen(LOCAL_DNS)] = 0;
	strcpy(TEXT_EDITOR, "xdg-open");
	TEXT_EDITOR[strlen("xdg-open")] = 0;

	strncpy(b64table, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", 65);
	b64table[65] = 0;

	char			*h = NULL;

	h = getenv("HOME");
	strncpy(HOME_DIR, h, strlen(h));
	HOME_DIR[strlen(h)] = 0;
}

void
__dns_dump_clean(void)
{
	if (inet4_ptr_name != NULL) free(inet4_ptr_name);
	if (inet6_ptr_name != NULL) free(inet6_ptr_name);
	if (inet4_string != NULL) free(inet4_string);
	if (primary_NS != NULL) free(primary_NS);
	if (DNS_SERVER != NULL) free(DNS_SERVER);
	if (time_string != NULL) free(time_string);
	if (TEXT_EDITOR != NULL) free(TEXT_EDITOR);
	if (b64table != NULL) free(b64table);
}

int
main(int argc, char *argv[])
{
	static char			c, *host = NULL, *p = NULL, *q = NULL;
	static int			dfd;

	posix_memalign((void **)&host, 16, host_max);

	strncpy(prog_name, argv[0], 64);

	if (strncmp("-h", argv[1], 2) == 0)
		__usage(EXIT_SUCCESS);

	p = q = argv[1];

	while (*q != 0x2f && q < (argv[1] + strlen(argv[1])))
		++q;
	if (*q == 0x2f)
	 { strncpy(host, p, (q - p)); host[(q - p)] = 0; }
	else
	  { strncpy(host, argv[1], strlen(argv[1])); host[strlen(argv[1])] = 0; }

	if (!host_name_ok(host))
	  {
		fprintf(stderr, "\"%s\" is not a valid hostname\n", argv[1]);
		free(host);
		exit(EXIT_FAILURE);
	  }

	opterr = 0;
	while ((c = getopt(argc, argv, "AdS:NhcE:p:vq")) != -1)
	  {
		switch(c)
		  {
			case(0x41):
			DO_AXFR = 1;
			break;
			case(0x45):
			strncpy(TEXT_EDITOR, optarg, strlen(optarg));
			TEXT_EDITOR[strlen(optarg)] = 0;
			break;
			case(0x63):
			NO_OPEN = 1;
			break;
			case(0x64):
			DEBUG = 1;
			break;
			case(0x53):
			if (!__is_inet4_string(optarg))
			  {
				u16		port_save;

				port_save = DNS_PORT;
				DNS_PORT = 53;
				inet4_string = get_inet4_record(optarg);
				strncpy(DNS_SERVER, inet4_string, strlen(inet4_string));
				DNS_SERVER[strlen(inet4_string)] = 0;
				DNS_PORT = port_save;
			  }
			else
			  {
				strncpy(DNS_SERVER, optarg, strlen(optarg));
				DNS_SERVER[strlen(optarg)] = 0;
			  }
			SERVER = 1;
			break;
			case(0x4e):
			TO_FILE = 0;
			break;
			case(0x68):
			__usage(EXIT_SUCCESS);
			break;
			case(0x70):
			DNS_PORT = (u16)atoi(optarg);
			break;
			case(0x76):
			VERBOSE = 1;
			break;
			case(0x71):
			dfd = open("/dev/null", O_RDWR);
			if (STDOUT_FILENO != dfd)
				dup2(dfd, STDOUT_FILENO);
			if (STDERR_FILENO != dfd)
				dup2(dfd, STDERR_FILENO);
			close(dfd);
			break;
			default:
			__usage(EXIT_FAILURE);
		  }
	  }

	if (TO_FILE)
	  {
		check_dump_directory();
	  }

	if (DO_AXFR)
	  {
		int		ret;

		ret = get_axfr_record(host);
		free(host);
		if (ret != 0)
			exit(EXIT_FAILURE);
		exit(EXIT_SUCCESS);
	  }

	fprintf(stdout,
		"Querying \"%s\"\n"
		"Using DNS resolver @ %s\n",
		host,
		DNS_SERVER);

	if (dns_dump(host) != 0)
	  {
		free(host);
		fprintf(stderr, "main() > dns_dump()\n");
		exit(EXIT_FAILURE);
	  }

	free(host);
	exit(EXIT_SUCCESS);
}

void
__usage(int exit_type)
{
	printf(
		"%s <hostname> [options]\n"
		"\n"
		"-A		do an AXFR request (DNS Zone Transfer)\n"
		"		 + send an SOA query to get the primary name server\n"
		"		 + of the host, to which the AXFR request is sent\n"
		"		 + (using TCP)\n"
		"-S		choose DNS server (default is local loopback)\n"
		"-p		choose port number to use (default 53)\n"
		"-N		do not output results to file; print to stdout\n"
		"		 + the default is to create a file in the directory\n"
		"		 + \"${HOME}/DNS_dumps\"\n"
		"-c		do not open the results file when operation complete\n"
		"-E		choose the text editor in which to open the output\n"
		"		 + file (if not printing to stdout). Default behaviour\n"
		"		 + is to exec xdg-open\n"
		"-v		output more messages while processing\n"
		"-d		run in debug mode (outputs diagnostic messages)\n"
		"-q		run in quiet mode\n"
		"		 + diverts stdout and stderr to /dev/null\n"
		"-h		display this informational menu\n",
		prog_name);

	exit(exit_type);
}

int
__is_inet4_string(char *string)
{
	size_t			len;
	int				i;

	len = strlen(string);
	for (i = 0; i < len; ++i)
		if (isalpha(string[i]))
			return(0);

	return(1);
}

int
host_name_ok(char *host)
{
	char		*p = NULL;
	size_t host_len = strlen(host);
	char *e = (host + host_len);
	int			OK, i;

	OK = 1;
	p = host;
	while (p < e)
	{
		if (*p == 0x40)
		  { OK = 0; goto end; }

		for (i = 0x20; i < 0x30; ++i)
		{
			if (*p == 0x2d || *p == 0x2e)
				continue;

			if (*p == i)
			  { OK = 0; goto end; }
		}

		for (i = 0x5b; i < 0x61; ++i)
		{
			if (*p == i)
			  { OK = 0; goto end; }
		}

		for (i = 0x7b; i < 0x80; ++i)
		{
			if (*p == i)
			  { OK = 0; goto end; }
		}
		++p;
	}

	end:
	return(OK);
}
