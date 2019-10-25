#include <openssl/conf.h>
#include <openssl/evp.h>
#include "dns.h"

static int __map_index_to_qtype(int) __wur;
static void __handle_timeout(int);
static void __dump_results(char *) __nonnull ((1));

static sigjmp_buf			__dns_dump_timeout;
static struct sigaction		alarm_act, alarm_oact;

int			IP4_ALLOC_SIZE = 32;
int			IP6_ALLOC_SIZE = 32;
int			MX_ALLOC_SIZE = 32;
int			NS_ALLOC_SIZE = 32;
int			SOA_ALLOC_SIZE = 32;
int			TXT_ALLOC_SIZE = 4;
int			DNSKEY_ALLOC_SIZE = 1;
int			NSEC_ALLOC_SIZE = 1;
int			RRSIG_ALLOC_SIZE = 1;

in_addr_t		*ip4s = NULL;
struct in6_addr		*ip6s = NULL;
Soa_record		*soa_records = NULL;
Mx_record		*mx_records = NULL;
char			**name_servers = NULL;
char			**text_records = NULL;
Dnskey_record	*dnskey_records = NULL;
Nsec_record		*nsec_records = NULL;
Rrsig_record	*rrsig_records = NULL;

int			ip4_cnt;
int			ip6_cnt;
int			mx_cnt;
int			ns_cnt;
int			soa_cnt;
int			txt_cnt;
int			dnskey_cnt;
int			nsec_cnt;
int			rrsig_cnt;

static sigjmp_buf			__timeout, __pipe__;
static struct sigaction		pipe_act, pipe_oact;

static void __dump_axfr_data(char *, char *) __nonnull ((1,2));
static void __handle_timeout__(int);

void
free_record(DNS_RRECORD *record)
{
	if (record != NULL)
	  {
		if (record->name != NULL) { free(record->name); record->name = NULL; }
		if (record->resource != NULL) { free(record->resource); record->resource = NULL; }
		if (record->rdata != NULL) { free(record->rdata); record->rdata = NULL; }
		free(record);
		record = NULL;
	  }
}

void
free_results_memory(void)
{
	int		i;

	if (ip4s != NULL)
	  {
		free(ip4s);
		ip4s = NULL;
	  }

	if (ip6s != NULL)
	  {
		free(ip6s);
		ip6s = NULL;
	  }

	if (mx_records != NULL)
	  {
		for (i = 0; i < mx_cnt; ++i)
	  	  {
			if (mx_records[i].mx_name != NULL) free(mx_records[i].mx_name);
		  }
		free(mx_records);
		mx_records = NULL;
	  }

	if (soa_records != NULL)
	  {
		for (i = 0; i < soa_cnt; ++i)
		  {
			if (soa_records[i].domain != NULL) free(soa_records[i].domain);
			if (soa_records[i].mx_name != NULL) free(soa_records[i].mx_name);
		  }
		free(soa_records);
		soa_records = NULL;
	  }

	if (name_servers != NULL)
	  {
		for (i = 0; i < ns_cnt; ++i)
		  {
			if (name_servers[i] != NULL)
			  {
				free(name_servers[i]);
				name_servers[i] = NULL;
			  }
		  }
		free(name_servers);
		name_servers = NULL;
	  }

	if (text_records != NULL)
	  {
		for (i = 0; i < txt_cnt; ++i)
		  {
			if (text_records[i] != NULL)
			  {
				free(text_records[i]);
				text_records[i] = NULL;
			  }
		  }
		free(text_records);
		text_records = NULL;
	  }

	if (dnskey_records != NULL)
	  {
		for (i = 0; i < dnskey_cnt; ++i)
		  {
			if (dnskey_records[i].public_key != NULL)
			  {
				free(dnskey_records[i].public_key);
				dnskey_records[i].public_key = NULL;
			  }
		  }
		free(dnskey_records);
		dnskey_records = NULL;
	  }

	if (nsec_records != NULL)
	  {
		for (i = 0; i < nsec_cnt; ++i)
		  {
			if (nsec_records[i].next_domain != NULL)
			  {
				free(nsec_records[i].next_domain);
				nsec_records[i].next_domain = NULL;	
			  }
		  }
		free(nsec_records);
		nsec_records = NULL;
	  }

	if (rrsig_records != NULL)
	  {
		for (i = 0; i < rrsig_cnt; ++i)
		  {
			if (rrsig_records[i].signer_name != NULL) { free(rrsig_records[i].signer_name); rrsig_records[i].signer_name = NULL; }
			if (rrsig_records[i].signature != NULL) { free(rrsig_records[i].signature); rrsig_records[i].signature = NULL; }
		  }
		free(rrsig_records);
		rrsig_records = NULL;
	  }
}

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

void
__catch_sigpipe(int signo)
{
	if (signo != SIGPIPE)
		return;

	siglongjmp(__pipe__, 1);
}

void
__handle_timeout__(int signo)
{
	if (signo != SIGALRM)
		return;

	siglongjmp(__timeout, 1);
}

int
get_axfr_record(char *host)
{
	DNS_HEADER				*dns_head = NULL;
	DNS_QUESTION			*dnsq = NULL;
	struct sockaddr_in		dns_server;
	int						dns_socket;
	uc						*buffer = NULL, *p = NULL;
	char					*primary_ns = NULL;
	size_t					len;
	ssize_t					n;
	char					*primary_inet4 = NULL;

	memset(&alarm_act, 0, sizeof(alarm_act));
	memset(&alarm_oact, 0, sizeof(alarm_oact));
	memset(&pipe_act, 0, sizeof(pipe_act));
	memset(&pipe_oact, 0, sizeof(pipe_oact));
	pipe_act.sa_handler = __catch_sigpipe;
	pipe_act.sa_flags = 0;
	sigemptyset(&pipe_act.sa_mask);
	sigaction(SIGPIPE, &pipe_act, &pipe_oact);

	alarm_act.sa_handler = __handle_timeout__;
	alarm_act.sa_flags = 0;
	sigemptyset(&alarm_act.sa_mask);
	sigaction(SIGALRM, &alarm_act, &alarm_oact);

	printf("Doing AXFR request\n");

	// get the primary name server's details
	if (!SERVER)
	  {
		printf("Getting primary name server for \"%s\"\n", host);
		primary_ns = get_primary_ns(host);
		printf("Got primary name server \"%s\"\n", primary_ns);
		primary_inet4 = get_inet4_record(primary_ns);
		strncpy(DNS_SERVER, primary_inet4, strlen(primary_inet4));
		DNS_SERVER[strlen(primary_inet4)] = 0;
	  }

	posix_memalign((void **)&buffer, 16, (DNS_BUFSIZE*4));
	memset(buffer, 0, DNS_BUFSIZE*4);
	p = buffer;

	dns_head = (DNS_HEADER *)p;
	dns_head->ident = htons(getpid());
	dns_head->rd = 1;
	dns_head->cd = 1;
	dns_head->qdcnt = htons(1);

	p += sizeof(DNS_HEADER);
	convert_name(primary_ns, p, &len);
	p += (len + 1);

	dnsq = (DNS_QUESTION *)p;
	dnsq->qtype = htons(QTYPE_AXFR);
	dnsq->qclass = htons(QCLASS_INET);
	p += sizeof(DNS_QUESTION);

	dns_socket = socket(AF_INET, SOCK_STREAM, 0);
	memset(&dns_server, 0, sizeof(dns_server));
	dns_server.sin_port = htons(DNS_PORT);
	dns_server.sin_family = AF_INET;
	inet_pton(AF_INET, DNS_SERVER, &dns_server.sin_addr.s_addr);

	printf("Connecting to %s:%hu\n", DNS_SERVER, DNS_PORT);
	if (sigsetjmp(__timeout, 1) != 0)
	  {
		log_err("Request timed out");
		if (buffer != NULL) { free(buffer); buffer = NULL; }
		return(1);
	  }

	alarm(DNS_TIMEOUT);
	connect(dns_socket, (struct sockaddr *)&dns_server, (socklen_t)sizeof(dns_server));
	alarm(0);
	printf("Connected!\n");

	send(dns_socket, buffer, (p - buffer), 0);
	printf("Sent AXFR request\n");

	if (sigsetjmp(__pipe__, 1) != 0)
	  {
		fprintf(stdout,
			"Caught SIGPIPE (tried to write to socket closed at other end)\n");
		if (buffer != NULL) { free(buffer); buffer = NULL; }
		return(SIGPIPE);
	  }

	alarm(DNS_TIMEOUT);
	n = recv(dns_socket, buffer, DNS_BUFSIZE*4, 0);
	alarm(0);
	if (n == 0)
	  {
		fprintf(stdout,
			"%s @ %s closed TCP socket (refusing connection)\n", primary_ns, primary_inet4);
		if (buffer != NULL) { free(buffer); buffer = NULL; }
		return(1);
	  }
	else if (n < 0)
	  {
		log_err("Error reading from socket!");
		if (buffer != NULL) { free(buffer); buffer = NULL; }
		return(-1);
	  }

	close(dns_socket);
	printf("Parsing AXFR data\n");
	parse_axfr_data(buffer, (size_t)n, host, primary_ns);
	free(buffer);
	return(0);
}

void
parse_axfr_data(uc *data, size_t data_len, char *hostname, char *name_server)
{
	DNS_RDATA			*rdata = NULL;
	int					j;
	uc					*p = NULL;
	u16					qtype;
	char				*eat = NULL; // simply eats unwanted data
	size_t				delta;

	ip4s = calloc(IP4_ALLOC_SIZE, sizeof(in_addr_t));
	ip6s = calloc(IP6_ALLOC_SIZE, sizeof(struct in6_addr));
	mx_records = calloc(MX_ALLOC_SIZE, sizeof(Mx_record));
	name_servers = calloc(NS_ALLOC_SIZE, sizeof(char *));
	text_records = calloc(TXT_ALLOC_SIZE, sizeof(char *));
	dnskey_records = calloc(DNSKEY_ALLOC_SIZE, sizeof(Dnskey_record));
	nsec_records = calloc(NSEC_ALLOC_SIZE, sizeof(Nsec_record));
	rrsig_records = calloc(RRSIG_ALLOC_SIZE, sizeof(Rrsig_record));

	for (j = 0; j < NS_ALLOC_SIZE; ++j)
		name_servers[j] = NULL;
	for (j = 0; j < TXT_ALLOC_SIZE; ++j)
		text_records[j] = NULL;

	eat = calloc(host_max, sizeof(char));

	p = data;
	while (p < (data + data_len))
	  {
		get_name(data, p, (uc *)eat, &delta);
		p += delta;
		rdata = (DNS_RDATA *)p;
		qtype = htons(rdata->type);
		p += sizeof(DNS_RDATA);

		// AT THIS POINT P IS ALREADY POINTING TO THE START OF THE RR DATA
		switch(qtype)
		  {
			case(QTYPE_A):
			++ip4_cnt;
			if (ip4_cnt >= IP4_ALLOC_SIZE)
			  {
				IP4_ALLOC_SIZE *= 2;
				ip4s = realloc(ip4s, (sizeof(in_addr_t) * IP4_ALLOC_SIZE));
			  }
			ip4s[(ip4_cnt-1)] = *((in_addr_t *)p);
			p += sizeof(in_addr_t);
			break;
			case(QTYPE_NS):
			++ns_cnt;
			if (ns_cnt >= NS_ALLOC_SIZE)
			  {
				NS_ALLOC_SIZE *= 2;
				name_servers = realloc(name_servers, (sizeof(char *) * NS_ALLOC_SIZE));
				for (j = ns_cnt-1; j < NS_ALLOC_SIZE; ++j)
					name_servers[j] = NULL;
			  }
			name_servers[(ns_cnt-1)] = calloc(host_max, sizeof(char));
			get_name(data, p, (uc *)name_servers[(ns_cnt-1)], &delta);
			p += delta;
			break;
			case(QTYPE_MX):
			++mx_cnt;
			if (mx_cnt >= MX_ALLOC_SIZE)
			  {
				MX_ALLOC_SIZE *= 2;
				mx_records = realloc(mx_records, (sizeof(Mx_record) * MX_ALLOC_SIZE));
			  }

			mx_records[(mx_cnt-1)].preference = ntohs((*(u16 *)p));
			mx_records[(mx_cnt-1)].mx_name = calloc(host_max, sizeof(char));
			p += sizeof(u16);
			get_name(data, p, mx_records[(mx_cnt-1)].mx_name, &delta);
			p += delta;
			break;
			case(QTYPE_TXT):
			++txt_cnt;
			if (txt_cnt >= TXT_ALLOC_SIZE)
			  {
				TXT_ALLOC_SIZE *= 2;
				text_records = realloc(text_records, (sizeof(char *) * TXT_ALLOC_SIZE));
			  }
			for (j = txt_cnt-1; j < TXT_ALLOC_SIZE; ++j)
				text_records[j] = NULL;
			text_records[(txt_cnt-1)] = calloc(ntohs(rdata->len), sizeof(char *));
			memcpy(text_records[(txt_cnt-1)], p, ntohs(rdata->len));
			break;
			case(QTYPE_AAAA):
			++ip6_cnt;
			if (ip6_cnt >= IP6_ALLOC_SIZE)
			  {
				IP6_ALLOC_SIZE *= 2;
				ip6s = realloc(ip6s, (sizeof(struct in6_addr) * IP6_ALLOC_SIZE));
			  }
			memcpy(&ip6s[(ip6_cnt-1)], p, sizeof(struct in6_addr));
			p += sizeof(struct in6_addr);
			break;
			default:
			// just pass by whatever it is
			p += ntohs(rdata->len);
		  }
	  }

	free(eat);
	__dump_axfr_data(hostname, name_server);
	free_results_memory();
}

void
__dump_axfr_data(char *host, char *ns)
{
	FILE		*fp = NULL;
	int			i, fd;
	char		*tmp = NULL;
	Inet_u		inet_u;
	size_t		len;

	if (TO_FILE)
	  {
		check_dump_directory();
		tmp = calloc(MAXLINE, sizeof(char));
		sprintf(tmp, "%s/DNS_dumps/%s_axfr_data.txt", HOME_DIR, host);
		fd = open(tmp, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU & ~S_IXUSR);
		fp = fdopen(fd, "r+");
		free(tmp);
		tmp = NULL;
	  }

	memset(&inet_u, 0, sizeof(inet_u));
	len = 0;

	fprintf((TO_FILE?fp:stdout),
		"\n"
		"\t\tAXFR Dump for host \"%s\" with primary NS \"%s\", on %s\n"
		"\n",
		host, ns, get_time_string(NULL));
		
	fprintf((TO_FILE?fp:stdout), "\t\t\t\tIPv4s\n");
	for (i = 0; i < ip4_cnt; ++i)
	  {
		fprintf((TO_FILE?fp:stdout),
			"\t\t\t%*.*s => %s\n",
			(int)INET_ADDRSTRLEN, (int)INET_ADDRSTRLEN,
			inet_ntop(AF_INET, &ip4s[i], (char *)inet_u.inet4, INET_ADDRSTRLEN),
			(char *)get_inet4_ptr_record(ip4s[i]));
	  }

	fprintf((TO_FILE?fp:stdout), "\t\t\t\tIPv6s\n");
	for (i = 0; i < ip6_cnt; ++i)
	  {
		fprintf((TO_FILE?fp:stdout),
			"\t\t\t%*.*s => %s\n",
			(int)INET6_ADDRSTRLEN, (int)INET6_ADDRSTRLEN,
			inet_ntop(AF_INET6, &ip6s[i], (char *)inet_u.inet6, INET6_ADDRSTRLEN),
			(char *)get_inet6_ptr_record(ip6s[i]));
	  }

	len = 0;
	for (i = 0; i < mx_cnt; ++i)
		if (strlen((char *)mx_records[i].mx_name) > len)
			len = strlen((char *)mx_records[i].mx_name);

	fprintf((TO_FILE?fp:stdout), "\t\t\t\tMail Exchanges\n");
	for (i = 0; i < mx_cnt; ++i)
	  {
		fprintf((TO_FILE?fp:stdout),
			"\t\t\t%*.*s (%hu)\n",
			(int)len, (int)len,
			(char *)mx_records[i].mx_name,
			mx_records[i].preference);
	  }

	len = 0;
	for (i = 0; i < ns_cnt; ++i)
		if (strlen((char *)name_servers[i]) > len)
			len = strlen((char *)name_servers[i]);

	fprintf((TO_FILE?fp:stdout), "\t\t\t\tName Servers\n");
	for (i = 0; i < ns_cnt; ++i)
	  {
		fprintf((TO_FILE?fp:stdout),
			"\t\t\t%*.*s => %s\n",
			(int)len, (int)len,
			name_servers[i],
			get_inet4_record(name_servers[i]));
	  }
}

uc *
convert_name(char *name, uc *caller_buf, size_t *len)
{
	uc 		*p = NULL, *q = NULL;
	size_t	l;

	sprintf((char *)caller_buf, ".%s.", (char *)name);
	q = caller_buf;
	l = strlen((char *)caller_buf);

	while (1)
	  {
		p = q;
		if (q == (caller_buf + (l - 1)))
			break;
		++q;
		while (*q != 0x2e && q < (caller_buf + l))
			++q;
		*p = ((q - p)-1);
	  }

	debug("caller buf is @ %p: pointer 'q' is @ %p\n", caller_buf, q);
	*q = 0;
	*len = (q - caller_buf);
 
	return(caller_buf);
}

uc *
convert_inet4_to_ptr(uc *inet4_str, uc *caller_buf, size_t *len)
{
	in_addr_t		inet4_addr;
	uc				*p = NULL, *q = NULL;
	size_t			l;
	Inet_u			inet_u;

	inet_pton(AF_INET, (char *)inet4_str, &inet4_addr);
	inet4_addr = htonl(inet4_addr);
	memset(&inet_u, 0, sizeof(inet_u));
	inet_ntop(AF_INET, &inet4_addr, (char *)inet_u.inet4, INET_ADDRSTRLEN);
	sprintf((char *)caller_buf, ".%s.in-addr.arpa.", (char *)inet_u.inet4);

	q = caller_buf;
	l = strlen((char *)caller_buf);

	while (1)
	  {
		p = q;
		if (q == (caller_buf + (l - 1)))
			break;
		++q;
		while (*q != 0x2e && q < (caller_buf + l))
			++q;
		*p = ((q - p)-1);
	  }

	debug("caller buf is @ %p: pointer 'q' is @ %p\n", caller_buf, q);
	*q = 0;
	*len = (q - caller_buf);

	return(caller_buf);
}

uc *
convert_inet6_to_ptr(uc *inet6_str, uc *caller_buf, size_t *len)
{
	uc					*tmp = NULL, *t = NULL, *p = NULL, *q = NULL;
	int					i;
	struct in6_addr		inet6_addr;
	size_t				l;
	char				c;

	inet_pton(AF_INET6, (char *)inet6_str, &inet6_addr);
	posix_memalign((void **)&tmp, 16, host_max);
	t = tmp;
	for (i = 15; i >= 0; --i)
	  {
		c = (inet6_addr.s6_addr[i] & 0x0f);
		if (c < 0x0a)
			c += 0x30;
		else
			c += 0x57;
		*t++ = c;
		*t++ = 0x2e;

		c = ((inet6_addr.s6_addr[i] >> 4) & 0x0f);
		if (c < 0x0a)
			c += 0x30;
		else
			c += 0x57;

		*t++ = c;
		if (i != 0)
			*t++ = 0x2e;
	  }

	*t = 0;

	sprintf((char *)caller_buf, ".%s.ip6.arpa.", (char *)tmp);
	l = strlen((char *)caller_buf);

	q = caller_buf;

	while (1)
	  {
		p = q;
		if (q == (caller_buf + (l - 1)))
			break;
		++q;
		while (*q != 0x2e && q < (caller_buf + l))
			++q;
		*p = ((q - p)-1);
	  }

	*q = 0;
	*len = (q - caller_buf);

	return(caller_buf);
}

char *
get_time_string(time_t *time_val)
{
	struct tm			*TIME = NULL;

	if (time_val == NULL)
	  {
		time_t		now;

		time(&now);
		TIME = gmtime(&now);
	  }
	else
	  {
		TIME = gmtime(time_val);
	  }

	memset(time_string, 0, 64);
	strftime(time_string, 64, "%a, %d %b %Y %H:%M:%S", TIME);
	return(time_string);
}

void
check_dump_directory(void)
{
	char		*buf = NULL;

	buf = calloc(path_max, sizeof(char));
	sprintf(buf, "%s/DNS_dumps", HOME_DIR);

	if (access(buf, F_OK) != 0)
	  {
		mkdir(buf, S_IRWXU);
	  }

	if (buf != NULL) free(buf);
	return;
}

char *
stringify_rcode(u16 rcode)
{
	switch(rcode)
	  {
		case(RCODE_FMT):
		return("Format Error");
		break;
		case(RCODE_SRV):
		return("Server Error");
		break;
		case(RCODE_NAM):
		return("Domain Name Non-Existant");
		break;
		case(RCODE_IMP):
		return("Not Implemented");
		break;
		case(RCODE_REF):
		return("Query Refused");
		break;
		default:
		return("Successful");
	  }
}

char *
stringify_qtype(u16 qtype)
{
	switch(qtype)
	  {
		case(QTYPE_A):
		return("A");
		break;
		case(QTYPE_NS):
		return("NS");
		break;
		case(QTYPE_CNAME):
		return("CNAME");
		break;
		case(QTYPE_SOA):
		return("SOA");
		break;
		case(QTYPE_PTR):
		return("PTR");
		break;
		case(QTYPE_MX):
		return("MX");
		break;
		case(QTYPE_TXT):
		return("TXT");
		break;
		case(QTYPE_RP):
		return("RP");
		break;
		case(QTYPE_AFSDB):
		return("AFSDB");
		break;
		case(QTYPE_SIG):
		return("SIG");
		break;
		case(QTYPE_KEY):
		return("KEY");
		break;
		case(QTYPE_AAAA):
		return("AAAA");
		break;
		case(QTYPE_LOC):
		return("LOC");
		break;
		case(QTYPE_SRV):
		return("SRV");
		break;
		case(QTYPE_NAPTR):
		return("NAPTR");
		break;
		case(QTYPE_KX):
		return("KX");
		break;
		case(QTYPE_CERT):
		return("CERT");
		break;
		case(QTYPE_DNAME):
		return("DNAME");
		break;
		case(QTYPE_OPT):
		return("OPT");
		break;
		case(QTYPE_APL):
		return("APL");
		break;
		case(QTYPE_DS):
		return("DS");
		break;
		case(QTYPE_SSHFP):
		return("SSHFP");
		break;
		case(QTYPE_IPSECKEY):
		return("IPSECKEY");
		break;
		case(QTYPE_RRSIG):
		return("RRSIG");
		break;
		case(QTYPE_NSEC):
		return("NSEC");
		break;
		case(QTYPE_DNSKEY):
		return("DNSKEY");
		break;
		case(QTYPE_DHCID):
		return("DHCID");
		break;
		case(QTYPE_NSEC3):
		return("NSEC3");
		break;
		case(QTYPE_NSEC3PARAM):
		return("NSEC3PARAM");
		break;
		case(QTYPE_TLSA):
		return("TLSA");
		break;
		case(QTYPE_HIP):
		return("HIP");
		break;
		case(QTYPE_CDS):
		return("CDS");
		break;
		case(QTYPE_CDNSKEY):
		return("CDNSKEY");
		break;
		case(QTYPE_OPENPGPKEY):
		return("OPENPGPKEY");
		break;
		case(QTYPE_TKEY):
		return("TKEY");
		break;
		case(QTYPE_TSIG):
		return("TSIG");
		break;
		case(QTYPE_IXFR):
		return("IXFR");
		break;
		case(QTYPE_AXFR):
		return("AXFR");
		break;
		case(QTYPE_URI):
		return("URI");
		break;
		case(QTYPE_TA):
		return("TA");
		break;
		case(QTYPE_DLV):
		return("DLV");
		break;
		default:
		return(NULL);
	  }
}

char *
stringify_dnskey_algo(uc algo)
{
	switch(algo)
	  {
		case(1):
		return("RSA/MD5");
		break;
		case(2):
		return("Diffie-Hellman");
		break;
		case(3):
		return("DSA/SHA-1");
		break;
		case(4):
		return("Elliptic Curve");
		break;
		case(5):
		return("RSA/SHA-1");
		break;
		case(252):
		return("Indirect");
		break;
		case(253):
		return("Private (PRIVATEDNS)");
		break;
		case(254):
		return("Private (PRIVATEOID)");
		break;
		default:
		return("Unknown");
	  }
	return(NULL);
}

char *
stringify_qclass(u16 qclass)
{
	return(NULL);
}

void
bit_print_fp(uc *data, FILE *stream, size_t len)
{
	uc			TOP_BIT = 0x80;
	int			bit, i;

	for (i = 0; i < len; ++i)
	  {
		for (bit = 0; bit < 8; ++bit)
	  	  {
			if ((data[i] << bit) & TOP_BIT)
				fputc(0x31, stream);
			else
				fputc(0x30, stream);
	  	  }
	  }	
}

char *
b64encode_r(uc *data, uc *out, size_t len, size_t *nlen)
{
	size_t		l;
	int		i, j;

	if (len <= 0)
		l = strlen((char *)data);
	else
		l = len;

	j &= ~j; i &= ~i;

	if (l == 1)
	  {
		out[j++] |= ((data[i] >> 2) & 0x3f);
		out[j++] |= ((data[i] << 4) & 0x30);
		out[j++] = 0x40;
		out[j++] = 0x40;
		out[j] = 0; *nlen = (size_t)j;
		for (i = 0; i < j; ++i)
			out[i] = b64table[(int)(out[i])];
		return((char *)out);
	  }
	else if (l == 2)
	  {
		out[j++] |= ((data[i] >> 2) & 0x3f);
		out[j] |= ((data[i] << 4) & 0x30);
		++i; --l;
		out[j++] |= ((data[i] >> 4) & 0x0f);
		out[j++] |= ((data[i] << 2) & 0x3c);
		++i; --l;
		out[j++] = 0x40;
		out[j] = 0; *nlen = (size_t)j;
		for (i = 0; i < j; ++i)
			out[i] = b64table[(int)(out[i])];
		return((char *)out);
	  }
	else
	  {
		while (l > 0)
	  	  {
			out[j++] |= ((data[i] >> 2) & 0x3f);
			out[j] |= ((data[i] << 4) & 0x30);
			++i; --l;
			out[j++] |= ((data[i] >> 4) & 0x0f);
			out[j] |= ((data[i] << 2) & 0x3c);
			++i; --l;
			out[j++] |= ((data[i] >> 6) & 0x03);
			out[j++] |= (data[i] & 0x3f);
			++i; --l;

			if (l == 1)
		  	  {
				out[j++] |= ((data[i] >> 2) & 0x3f);
				out[j++] |= ((data[i] << 4) & 0x30);
				--l;
				out[j++] = 0x40;
				out[j++] = 0x40;
				out[j] = 0; *nlen = (size_t)j;
				break;
		  	  }
			else if (l == 2)
		  	  {
				out[j++] |= ((data[i] >> 2) & 0x3f);
				out[j] |= ((data[i] << 4) & 0x30);
				++i; --l;
				out[j++] |= ((data[i] >> 4) & 0x0f);
				out[j++] |= ((data[i] << 2) & 0x3c);
				out[j++] = 0x40;
				out[j] = 0; *nlen = (size_t)j;
				break;
		  	  }
	  	  }
		for (i = 0; i < j; ++i)
			out[i] = b64table[(int)(out[i])];
		return((char *)out);
  	  }
}

uc *
b64decode_r(char *data, uc *out, size_t len, size_t *nlen)
{
	size_t			l;
	int			i, j;

	if (len <= 0)
		l = len;
	else
		l = strlen(data);

	i &= ~i; j &= ~j;

	for (i = 0; i < l; ++i)
	  {
		j &= ~j;
		while (b64table[j] != data[i])
			++j;
		data[i] = j;
	  }

	i &= ~i; j &= ~j;
	while (l > 0)
	  {
		out[j] |= ((data[i++] << 2) & 0xfc);
		--l;
		out[j++] |= ((data[i] >> 4) & 0x03);
		out[j] |= ((data[i++] << 4) & 0xf0);
		--l;
		out[j++] |= ((data[i] >> 2) & 0x0f);
		out[j] |= ((data[i++] << 6) & 0xc0);
		--l;
		out[j++] |= (data[i++] & 0x3f);
		--l;
	  }

	out[j] = 0;
	*nlen = (size_t)j;

	return(out);
}

#define SOA_DUP			1
#define SOA_OK			0
#define SOA_ERR			-1

struct Soa_node
{
	char				*soa_digest;
	struct Soa_node		*left_child, *right_child;
};

typedef struct Soa_node Soa_node;

static int __add_soa_node(char *, Soa_node **) __nonnull ((1,2)) __wur;
static void __free_nodes(Soa_node **) __nonnull ((1));
static char *__bin_to_hex(uc *, size_t) __nonnull ((1)) __wur;
static void __shift_records(Soa_record *, int) __nonnull ((1));

static char			*hex = NULL;

int
remove_duplicate_soa_records(Soa_record *records)
{
	EVP_MD_CTX				*ctx = NULL;
	uc						*digest = NULL;
	uc						*record = NULL;
	char					*digest_hex = NULL;
	Soa_node				*root_node = NULL;
	int						duplicates, i;
	unsigned int			dlen;

	duplicates &= ~duplicates;
	posix_memalign((void **)&record, 16, (MAXLINE*3));
	posix_memalign((void **)&hex, 16, (EVP_MD_size(EVP_sha1())*2)+1);

	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	ctx = EVP_MD_CTX_create();
	if (1 != EVP_DigestInit_ex(ctx, EVP_sha1(), NULL))
		goto error;
	if (!(digest = OPENSSL_malloc(EVP_MD_size(EVP_sha1())+1)))
		goto error;
	if (1 != EVP_DigestUpdate(ctx, (uc *)"1234567890", 10))
		goto error;
	if (1 != EVP_DigestFinal_ex(ctx, digest, &dlen))
		goto error;

	digest_hex = __bin_to_hex(digest, dlen);
	digest_hex[dlen*2] = 0;
	assert(strncmp(digest_hex, "01b307acba4f54f55aafc33bb06bbbf6ca803e9a", (dlen*2)) == 0);

	for (i = 0; i < soa_cnt; ++i)
	  {
		memset(record, 0, MAXLINE*3);
		memset(digest, 0, EVP_MD_size(EVP_sha1()));
		memset(hex, 0, (EVP_MD_size(EVP_sha1())*2)+1);

		sprintf((char *)record, "%s%s%u%u%u%u%u",
			(char *)soa_records[i].domain,
			(char *)soa_records[i].mx_name,
			soa_records[i].serial,
			soa_records[i].refresh_time,
			soa_records[i].retry_time,
			soa_records[i].expiry,
			soa_records[i].minimum);

		if (1 != EVP_DigestUpdate(ctx, record, strlen((char *)record)))
			goto error;
		if (1 != EVP_DigestFinal_ex(ctx, digest, &dlen))
			goto error;
		digest[dlen] = 0;
		digest_hex = __bin_to_hex(digest, dlen);
		if (__add_soa_node(digest_hex, &root_node) == SOA_DUP)
		  {
			__shift_records(soa_records, i);
			--i; --soa_cnt;
			++duplicates;
		  }
	  }

	__free_nodes(&root_node);
	if (digest != NULL) OPENSSL_free(digest);
	EVP_MD_CTX_destroy(ctx);
	return(duplicates);

	error:
	if (digest != NULL) OPENSSL_free(digest);
	EVP_MD_CTX_destroy(ctx);
	return(-1);
}

int
__add_soa_node(char *digest, Soa_node **soa_root)
{
	if (*soa_root == NULL)
	  {
		if (posix_memalign((void **)soa_root, 16, sizeof(Soa_node)) < 0)
			return(SOA_ERR);
		memset(*soa_root, 0, sizeof(Soa_node));
		if (posix_memalign((void **)&((*soa_root)->soa_digest), 16, (EVP_MD_size(EVP_sha1())*2)+1) < 0)
			return(SOA_ERR);
		strncpy((*soa_root)->soa_digest, digest, EVP_MD_size(EVP_sha1())*2);
		(*soa_root)->soa_digest[(EVP_MD_size(EVP_sha1())*2)] = 0;
		(*soa_root)->left_child = NULL;
		(*soa_root)->right_child = NULL;
		return (SOA_OK);
	  }

	if (strncmp(digest, (*soa_root)->soa_digest, (EVP_MD_size(EVP_sha1())*2)) < 0)
	  {
		debug("%s is less than %s\n", digest, (*soa_root)->soa_digest);
		return(__add_soa_node(digest, &((*soa_root)->left_child)));
	  }
	else if (strncmp(digest, (*soa_root)->soa_digest, (EVP_MD_size(EVP_sha1())*2)) > 0)
	  {
		debug("%s is greater than %s\n", digest, (*soa_root)->soa_digest);
		return(__add_soa_node(digest, &((*soa_root)->right_child)));
	  }
	else if (strncmp(digest, (*soa_root)->soa_digest, (EVP_MD_size(EVP_sha1())*2)) == 0)
		{ debug("found duplicate SOA\n"); return(SOA_DUP); }
	else
		return(SOA_ERR);
}

void
__free_nodes(Soa_node **soa_root)
{
	if ((*soa_root)->left_child != NULL)
		__free_nodes(&((*soa_root)->left_child));
	if ((*soa_root)->right_child != NULL)
		__free_nodes(&((*soa_root)->right_child));
	if ((*soa_root)->soa_digest != NULL)
	  {
		free((*soa_root)->soa_digest);
		(*soa_root)->soa_digest = NULL;
	  }
	free(*soa_root);
	*soa_root = NULL;
	return;
}

char *
__bin_to_hex(uc *binary, size_t len)
{
	int		i;
	char	c, *p = NULL;

	p = hex;
	for (i = 0; i < len; ++i)
	  {
		c = (char)((binary[i] >> 4) & 0x0f);
		if (c < 0x0a)
			c += 0x30;
		else
			c += 0x57;

		*p++ = c;

		c = (char)(binary[i] & 0x0f);
		if (c < 0x0a)
			c += 0x30;
		else
			c += 0x57;

		*p++ = c;		
	  }

	*p = 0;
	return(hex);
}

void
__shift_records(Soa_record *records, int i)
{
	int			j;

	for (j = i; j < (soa_cnt-1); ++j)
	  {
		memset(&records[j], 0, sizeof(Soa_record));
		memcpy(&records[j], &records[j+1], sizeof(Soa_record));
	  }
	memset(&records[j], 0, sizeof(Soa_record));
}

char *
get_inet4_record(char *name)
{
	DNS_HEADER			*dns_head = NULL;
	DNS_QUESTION		*dnsq = NULL;
	DNS_RRECORD			*record = NULL;
	struct sockaddr_in	dns_server;
	int					dns_socket;
	uc					*buffer = NULL, *p = NULL;
	size_t				delta;
	ssize_t				n;

	posix_memalign((void **)&buffer, 16, DNS_BUFSIZE);
	memset(buffer, 0, DNS_BUFSIZE);

	p = buffer;

	dns_head = (DNS_HEADER *)p;
	dns_head->ident = htons(getpid());
	dns_head->rd = 1;
	dns_head->cd = 1;
	dns_head->qdcnt = htons(1);

	p += sizeof(DNS_HEADER);

	convert_name(name, p, &delta);

	p += (delta + 1);
	dnsq = (DNS_QUESTION *)p;
	dnsq->qtype = htons(QTYPE_A);
	dnsq->qclass = htons(QCLASS_INET);

	p += sizeof(DNS_QUESTION);

	dns_socket = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&dns_server, 0, sizeof(dns_server));
	dns_server.sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, DNS_SERVER, &dns_server.sin_addr.s_addr);

	sendto(dns_socket, buffer, (p - buffer), 0, (struct sockaddr *)&dns_server, (socklen_t)sizeof(dns_server));
	n = recv(dns_socket, buffer, DNS_BUFSIZE-1, 0);

	if (n <= 0)
		return(NULL);

	posix_memalign((void **)&record, 16, sizeof(DNS_RRECORD));
	memset(record, 0, sizeof(DNS_RRECORD));
	posix_memalign((void **)&record->name, 16, host_max);
	get_name(buffer, p, record->name, &delta);
	p += (delta + sizeof(DNS_RDATA));

	inet_ntop(AF_INET, (in_addr_t *)p, inet4_string, INET_ADDRSTRLEN);

	free_record(record);
	free(buffer);
	return(inet4_string);
}

char *
get_inet4_ptr_record(in_addr_t inet4_addr)
{
	uc					*buffer = NULL;
	uc					*p = NULL;
	DNS_HEADER			*dns_head = NULL;
	DNS_QUESTION		*dnsq = NULL;
	DNS_RRECORD			*record = NULL;
	struct sockaddr_in	dns_server;
	int					dns_server_sock, host_max;
	Inet_u				inet_u;
	size_t				inet4_ptr_len, delta;
	ssize_t				n;

	posix_memalign((void **)&buffer, 16, DNS_BUFSIZE);
	memset(buffer, 0, DNS_BUFSIZE);
	p = buffer;

	dns_head = (DNS_HEADER *)p;
	dns_head->ident = htons(getpid());
	dns_head->rd = 1;
	dns_head->cd = 1;
	dns_head->qdcnt = htons(1);

	p += sizeof(DNS_HEADER);
	memset(&inet_u, 0, sizeof(inet_u));
	inet_ntop(AF_INET, &inet4_addr, (char *)inet_u.inet4, INET_ADDRSTRLEN);
	convert_inet4_to_ptr((uc *)inet_u.inet4, (uc *)inet4_ptr_name, &inet4_ptr_len);

	strncpy((char *)p, (char *)inet4_ptr_name, inet4_ptr_len);
	p += (inet4_ptr_len + 1);

	dnsq = (DNS_QUESTION *)p;
	dnsq->qtype = htons(QTYPE_PTR);
	dnsq->qclass = htons(QCLASS_INET);

	p += sizeof(DNS_QUESTION);

	memset(&dns_server, 0, sizeof(dns_server));
	dns_server.sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, DNS_SERVER, &dns_server.sin_addr.s_addr);

	dns_server_sock = socket(AF_INET, SOCK_DGRAM, 0);
	sendto(dns_server_sock, (char *)buffer, (p - buffer), 0, (struct sockaddr *)&dns_server, sizeof(dns_server));
	n = recv(dns_server_sock, (char *)buffer, 2048, 0);
	if (n <= 0)
		goto error;

	host_max = sysconf(_SC_HOST_NAME_MAX);
	posix_memalign((void **)&record, 16, sizeof(DNS_RRECORD));
	memset(record, 0, sizeof(DNS_RRECORD));
	posix_memalign((void **)&record->name, 16, host_max);

	get_name(buffer, p, (uc *)record->name, &delta);
	p += delta;
	posix_memalign((void **)&record->resource, 16, sizeof(DNS_RDATA));
	memcpy(record->resource, p, sizeof(DNS_RDATA));
	p += sizeof(DNS_RDATA);
	get_name(buffer, p, (uc *)inet4_ptr_name, &inet4_ptr_len);
	free_record(record);
	free(buffer);
	return(inet4_ptr_name);

	error:
	free_record(record);
	free(buffer);
	return(NULL);
}

char *
get_inet6_ptr_record(struct in6_addr inet6_addr)
{
	DNS_HEADER			*dns_head = NULL;
	DNS_QUESTION		*dnsq = NULL;
	uc					*buffer = NULL, *p = NULL;
	Inet_u				inet_u;
	size_t				inet6_ptr_len, delta;
	struct sockaddr_in	dns_server;
	int					dns_server_sock;
	ssize_t				n;
	uc					*eat = NULL;

	posix_memalign((void **)&eat, 16, path_max);
	posix_memalign((void **)&buffer, 16, DNS_BUFSIZE);
	memset(buffer, 0, DNS_BUFSIZE);
	p = buffer;

	dns_head = (DNS_HEADER *)p;

	dns_head->ident = htons(getpid());
	dns_head->rd = 1;
	dns_head->cd = 1;
	dns_head->qdcnt = htons(1);

	p += sizeof(DNS_HEADER);

	inet_ntop(AF_INET6, &inet6_addr, (char *)inet_u.inet6, INET6_ADDRSTRLEN);
	convert_inet6_to_ptr((uc *)inet_u.inet6, p, &inet6_ptr_len);

	debug("converted \"%s\" to PTR record format \"%*.*s\"\n",
		(char *)inet_u.inet6,
		(int)inet6_ptr_len, (int)inet6_ptr_len,
		p);

	p += (inet6_ptr_len + 1);

	dnsq = (DNS_QUESTION *)p;

	dnsq->qtype = htons(QTYPE_PTR);
	dnsq->qclass = htons(QCLASS_INET);

	p += sizeof(DNS_QUESTION);

	memset(&dns_server, 0, sizeof(dns_server));
	dns_server.sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, DNS_SERVER, &dns_server.sin_addr.s_addr);
	dns_server_sock = socket(AF_INET, SOCK_DGRAM, 0);

	sendto(dns_server_sock, buffer, (p - buffer), 0, (struct sockaddr *)&dns_server, (socklen_t)sizeof(dns_server));
	n = recv(dns_server_sock, buffer, DNS_BUFSIZE, 0);
	if (n <= 0)
		goto error;

	get_name(buffer, p, eat, &delta);
	p += delta;
	p += sizeof(DNS_RDATA);
	get_name(buffer, p, (uc *)inet6_ptr_name, &delta);

	if (buffer != NULL) free(buffer);
	if (eat != NULL) free(eat);
	return(inet6_ptr_name);		

	error:
	if (buffer != NULL) free(buffer);
	if (eat != NULL) free(eat);
	return(NULL);
}

char *
get_primary_ns(char *host)
{
	DNS_HEADER			*dns_head = NULL;
	DNS_QUESTION		*dnsq = NULL;
	DNS_RRECORD			*record = NULL;
	struct sockaddr_in	dns_server;
	int					dns_socket;
	uc					*buffer = NULL, *p = NULL;
	size_t				delta;
	ssize_t				n;

	buffer = calloc(DNS_BUFSIZE, sizeof(uc));
	memset(buffer, 0, DNS_BUFSIZE);
	p = buffer;

	dns_head = (DNS_HEADER *)p;
	dns_head->ident = htons(getpid());
	dns_head->rd = 1;
	dns_head->cd = 1;
	dns_head->qdcnt = htons(1);

	p += sizeof(DNS_HEADER);

	convert_name(host, p, &delta);
	p += (delta + 1);

	dnsq = (DNS_QUESTION *)p;
	dnsq->qtype = htons(QTYPE_SOA);
	dnsq->qclass = htons(QCLASS_INET);

	p += sizeof(DNS_QUESTION);

	memset(&dns_server, 0, sizeof(dns_server));
	dns_server.sin_port = htons(DNS_PORT);
	inet_pton(AF_INET, DNS_SERVER, &dns_server.sin_addr.s_addr);

	dns_socket = socket(AF_INET, SOCK_DGRAM, 0);
	sendto(dns_socket, buffer, (p - buffer), 0, (struct sockaddr *)&dns_server, (socklen_t)sizeof(dns_server));
	n = recv(dns_socket, buffer, DNS_BUFSIZE, 0);
	if (n <= 0)
		return(NULL);

	record = malloc(sizeof(DNS_RRECORD));
	record->name = calloc(host_max, sizeof(uc));
	record->resource = malloc(sizeof(DNS_RDATA));
	get_name(buffer, p, record->name, &delta);
	p += delta;
	memcpy(record->resource, p, sizeof(DNS_RDATA));
	p += sizeof(DNS_RDATA);
	record->rdata = malloc(htons(record->resource->len));
	memcpy(record->rdata, p, htons(record->resource->len));
	get_name(buffer, record->rdata, (uc *)primary_NS, &delta);

	free_record(record);
	free(buffer);
	close(dns_socket);
	return(primary_NS);
}

int
get_results(DNS_RRECORD *results, int res_cnt, uc *ptr, uc *buffer, size_t *delta)
{
	uc			*p = NULL;
	int			i;

	p = ptr;
	for (i = 0; i < res_cnt; ++i)
	  {
		posix_memalign((void **)&results[i].name, 16, host_max);
		get_name(buffer, ptr, results[i].name, delta);
		p += *delta;
		results[i].resource = malloc(sizeof(DNS_RDATA));
		//posix_memalign((void **)&results[i].resource, 16, sizeof(DNS_RDATA));
		debug("allocated %lu bytes to results.resource\n", sizeof(DNS_RDATA));
		memcpy(results[i].resource, p, sizeof(DNS_RDATA));
		debug("copied %lu bytes to buffer\n", sizeof(DNS_RDATA));
		p += sizeof(DNS_RDATA);
		results[i].rdata = calloc(ntohs(results[i].resource->len)+1, sizeof(char));
		//posix_memalign((void **)&results[i].rdata, 16, ntohs(results[i].resource->len)+1);
		debug("allocated %lu bytes of memory to results.rdata\n", ntohs(results[i].resource->len)+1);
		memcpy(results[i].rdata, p, ntohs(results[i].resource->len));
		debug("copied %lu bytes to buffer\n", ntohs(results[i].resource->len));
		p += ntohs(results[i].resource->len);
	  }

	*delta = (p - ptr);
	return(0);
}

int
sort_results(DNS_RRECORD *results, int res_cnt, uc *buffer)
{
	int		i, j;
	char		*name_string = NULL;
	uc		*ptr = NULL, *p = NULL;
	size_t		delta, d;
	size_t		total_len;
	uc				*eat = NULL;
	DNS_QUESTION	*dnsq = NULL;

	posix_memalign((void **)&eat, 16, host_max);

	/*
	 * Do not use free_record() to free '&results[i]' because these the results
	 * were allocated as pointer to array of DNS_RRECORD;
	 * Otherwise, we get a 'double free or corruption (fasttop)' error
	 */

	for (i = 0; i < res_cnt; ++i)
	  {
		switch(ntohs(results[i].resource->type))
		  {
			case(QTYPE_A):
			++ip4_cnt;
			if (ip4_cnt >= IP4_ALLOC_SIZE)
			  {
				IP4_ALLOC_SIZE *= 2;
				ip4s = realloc(ip4s, (sizeof(in_addr_t) * IP4_ALLOC_SIZE));
			  }
			ip4s[(ip4_cnt)-1] = *((in_addr_t *)results[i].rdata);
			break;
			case(QTYPE_NS):
			++ns_cnt;
			if (ns_cnt >= NS_ALLOC_SIZE)
			  {
				NS_ALLOC_SIZE *= 2;
				name_servers = realloc(name_servers, (sizeof(char *) * NS_ALLOC_SIZE));
				for (j = ns_cnt-1; j < NS_ALLOC_SIZE; ++j)
					name_servers[j] = NULL;
			  }
			name_servers[(ns_cnt-1)] = calloc(host_max, sizeof(char));
			ptr = results[i].rdata;
			get_name(buffer, ptr, (uc *)name_servers[(ns_cnt-1)], &delta);
			break;
			case(QTYPE_CNAME):
			ptr = results[i].rdata;
			posix_memalign((void **)&name_string, 16, host_max);
			get_name(buffer, ptr, (uc *)name_string, &delta);
			ptr += delta;
			printf("\"%s\"\n", name_string);
			free(name_string); name_string = NULL;
			break;
			case(QTYPE_SOA):
			++soa_cnt;
			if (soa_cnt >= SOA_ALLOC_SIZE)
			  {
				SOA_ALLOC_SIZE *= 2;
				soa_records = realloc(soa_records, (sizeof(Soa_record) * SOA_ALLOC_SIZE));
			  }
			ptr = results[i].rdata;

			p = buffer;
			p += sizeof(DNS_HEADER);
			get_name(buffer, p, eat, &d);
			p += d;
			dnsq = (DNS_QUESTION *)p;
			soa_records[(soa_cnt-1)].qtype = ntohs(dnsq->qtype);
			soa_records[(soa_cnt-1)].domain = calloc(host_max, sizeof(char));
			soa_records[(soa_cnt-1)].mx_name = calloc(host_max, sizeof(char));

			get_name(buffer, ptr, (uc *)soa_records[(soa_cnt-1)].domain, &delta);
			ptr += delta;
			get_name(buffer, ptr, (uc *)soa_records[(soa_cnt-1)].mx_name, &delta);
			ptr += delta;
			soa_records[(soa_cnt-1)].serial = ntohl(*((u32 *)ptr));
			ptr += sizeof(u32);
			soa_records[(soa_cnt-1)].refresh_time = ntohl(*((u32 *)ptr));
			ptr += sizeof(u32);
			soa_records[(soa_cnt-1)].retry_time = ntohl(*((u32 *)ptr));
			ptr += sizeof(u32);
			soa_records[(soa_cnt-1)].expiry = ntohl(*((u32 *)ptr));
			ptr += sizeof(u32);
			soa_records[(soa_cnt-1)].minimum = ntohl(*((u32 *)ptr));
			break;
			case(QTYPE_MX):
			ptr = results[i].rdata;
			++mx_cnt;
			if (mx_cnt >= MX_ALLOC_SIZE)
			  {
				MX_ALLOC_SIZE *= 2;
				mx_records = realloc(mx_records, (sizeof(Mx_record) * MX_ALLOC_SIZE));
			  }
			memset(&mx_records[(mx_cnt-1)], 0, sizeof(Mx_record));
			mx_records[(mx_cnt-1)].mx_name = calloc(host_max, sizeof(char));
			mx_records[(mx_cnt-1)].preference = ntohs(*((u16 *)ptr));
			ptr += sizeof(mx_records[(mx_cnt-1)].preference);

			get_name(buffer, ptr, (uc *)mx_records[(mx_cnt-1)].mx_name, &delta);
			break;
			case(QTYPE_TXT):
			++txt_cnt;
			if (txt_cnt >= TXT_ALLOC_SIZE)
			  {
				TXT_ALLOC_SIZE *= 2;
				text_records = realloc(text_records, (sizeof(char *) * TXT_ALLOC_SIZE));
			  }
			for (j = txt_cnt-1; j < TXT_ALLOC_SIZE; ++j)
				text_records[j] = NULL;

			ptr = results[i].rdata;
			text_records[(txt_cnt-1)] = calloc(ntohs(results[i].resource->len)+1, sizeof(char));
			j &= ~j;
			while (ptr < (results[i].rdata + ntohs(results[i].resource->len)))
				text_records[(txt_cnt-1)][j++] = *ptr++;
			break;
			case(QTYPE_AAAA):
			++ip6_cnt;
			if (ip6_cnt >= IP6_ALLOC_SIZE)
			  {
				IP6_ALLOC_SIZE *= 2;
				ip6s = realloc(ip6s, (sizeof(struct in6_addr) * IP6_ALLOC_SIZE));
			  }

			memset(&ip6s[(ip6_cnt-1)], 0, sizeof(struct in6_addr));
			ptr = results[i].rdata;
			ip6s[(ip6_cnt-1)] = *((struct in6_addr *)ptr);
			break;
			case(QTYPE_NSEC):
			++nsec_cnt;
			if (nsec_cnt >= NSEC_ALLOC_SIZE)
			  {
				NSEC_ALLOC_SIZE *= 2;
				nsec_records = realloc(nsec_records, (sizeof(Nsec_record) * NSEC_ALLOC_SIZE));
			  }
			nsec_records[(nsec_cnt-1)].next_domain = calloc(host_max, sizeof(uc));
			total_len = ntohs(results[i].resource->len);
			ptr = results[i].rdata;
			get_name(buffer, ptr, nsec_records[(nsec_cnt-1)].next_domain, &delta);
			ptr += delta; total_len -= delta;
			nsec_records[(nsec_cnt-1)].type_bitmap = calloc(total_len+1, sizeof(uc));
			memcpy(nsec_records[(nsec_cnt-1)].type_bitmap, ptr, total_len);
			nsec_records[(nsec_cnt-1)].type_bitmap[total_len] = 0;
			ptr += total_len;
			break;
			case(QTYPE_DNSKEY):
			++dnskey_cnt;
			if(dnskey_cnt >= DNSKEY_ALLOC_SIZE)
			  {
				DNSKEY_ALLOC_SIZE *= 2;
				dnskey_records = realloc(dnskey_records, (sizeof(Dnskey_record) * DNSKEY_ALLOC_SIZE));
			  }
			total_len = ntohs(results[i].resource->len);
			ptr = results[i].rdata;
			dnskey_records[(dnskey_cnt-1)].key_flag = ntohs(*((u16 *)ptr));
			ptr += sizeof(u16);
			total_len -= sizeof(u16);
			dnskey_records[(dnskey_cnt-1)].key_protocol = *((uc *)ptr);
			++ptr; --total_len;
			dnskey_records[(dnskey_cnt-1)].key_algo = *((uc *)ptr);
			++ptr; --total_len;
			dnskey_records[i].public_key = calloc(total_len+1, sizeof(uc));
			memcpy(dnskey_records[i].public_key, ptr, total_len);
			dnskey_records[i].public_key[total_len] = 0;
			dnskey_records[i].key_len = total_len;
			ptr += total_len;
			break;
			case(QTYPE_RRSIG):
			++rrsig_cnt;
			if (rrsig_cnt >= RRSIG_ALLOC_SIZE)
			  {
				RRSIG_ALLOC_SIZE *= 2;
				rrsig_records = realloc(rrsig_records, (sizeof(Rrsig_record) * RRSIG_ALLOC_SIZE));
			  }
			ptr = results[i].rdata;
			rrsig_records[(rrsig_cnt-1)].type_covered = ntohs(*((u16 *)ptr));
			ptr += sizeof(u16);
			rrsig_records[(rrsig_cnt-1)].algo = *ptr++;
			rrsig_records[(rrsig_cnt-1)].labels = *ptr++;
			rrsig_records[(rrsig_cnt-1)].original_ttl = ntohl(*((u32 *)ptr));
			ptr += sizeof(u32);
			rrsig_records[(rrsig_cnt-1)].sig_expiry = ntohl(*((u32 *)ptr));
			ptr += sizeof(u32);
			rrsig_records[(rrsig_cnt-1)].sig_inception = ntohl(*((u32 *)ptr));
			ptr += sizeof(u32);
			rrsig_records[(rrsig_cnt-1)].key_tag = ntohs(*((u16 *)ptr));
			rrsig_records[(rrsig_cnt-1)].signer_name = calloc(host_max, sizeof(uc));
			get_name(buffer, ptr, rrsig_records[(rrsig_cnt-1)].signer_name, &delta);
			ptr += delta;
			rrsig_records[(rrsig_cnt-1)].sig_len =
				(ntohs(results[i].resource->len) - (ptr - results[i].rdata));
			rrsig_records[(rrsig_cnt-1)].signature = calloc(rrsig_records[(rrsig_cnt-1)].sig_len + 1, sizeof(uc));
			memcpy(rrsig_records[(rrsig_cnt-1)].signature, ptr, rrsig_records[(rrsig_cnt-1)].sig_len);
			rrsig_records[i].signature[rrsig_records[(rrsig_cnt-1)].sig_len] = 0;
			break;
			default:
			continue;
		  }
	  }

	free(eat);
	return (0);
}

uc *
get_name(uc *data, uc *ptr, uc *caller_buf, size_t *delta)
{
	int				offset;
	uc				*p = NULL, *q = NULL, *l = NULL, *s = NULL;

	p = l = ptr;
	q = caller_buf;

	/* 08666163656270706b0363706d0003646e73c005 */
	/* .facebook.com..dns.. */

	while (*l != 0x00 && *p != 0x00)
	  {
		l = p++;
		if (*l >= 0xc0)
		  {
			s = l;
			offset = (((*l) * 0x100) + *(l+1) - (0xc0 * 0x100));
			p = (data + offset);
			l = p++;
		  }
		while (((p - l)-1) < *l)
		  {
			*q++ = *p++;
		  }

		if (*p == 0x00)
			break;
		else
			*q++ = 0x2e;
	  }

	*q = 0;
	if (s != NULL)
		p = s;

	if (*p == 0x00)
		++p;
	else if (*p >= 0xc0)
		p += 2;

	*delta = (p - ptr);
	return(caller_buf);
}

int
dns_dump(char *hostname)
{
	uc			*buffer = NULL, *p = NULL;
	DNS_HEADER		*dns_ptr = NULL;
	DNS_RRECORD		*answers = NULL, *auth = NULL, *additional = NULL;
	DNS_QUESTION		*dnsq = NULL;
	size_t			qnamelen, nbytes, delta;
	int			i, dns_socket;
	struct sockaddr_in	dns_server;
	u16				qtype;

	assert(strlen(hostname) < sysconf(_SC_HOST_NAME_MAX));
	
	memset(&alarm_act, 0, sizeof(alarm_act));
	memset(&alarm_oact, 0, sizeof(alarm_oact));

	alarm_act.sa_handler = __handle_timeout;
	alarm_act.sa_flags = 0;
	sigemptyset(&alarm_act.sa_mask);
	sigaction(SIGALRM, &alarm_act, &alarm_oact);

	posix_memalign((void **)&buffer, 16, DNS_BUFSIZE);
	debug("allocated %lu bytes to buffer @ %p to %p\n", DNS_BUFSIZE, buffer, (buffer + (DNS_BUFSIZE-1)));

	memset(&dns_server, 0, sizeof(dns_server));
	dns_server.sin_port = htons(53);
	inet_pton(AF_INET, DNS_SERVER, &dns_server.sin_addr.s_addr);
	if ((dns_socket = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		log_err_quit("Failed to open socket");

	verbose("opened UDP socket on file descriptor %d\n", dns_socket);

	ip4_cnt &= ~ip4_cnt;
	ip6_cnt &= ~ip6_cnt;
	mx_cnt &= ~mx_cnt;
	ns_cnt &= ~ns_cnt;
	soa_cnt &= ~soa_cnt;
	txt_cnt &= ~txt_cnt;
	dnskey_cnt &= ~dnskey_cnt;
	nsec_cnt &= ~nsec_cnt;
	rrsig_cnt &= ~rrsig_cnt;

	ip4s = calloc(IP4_ALLOC_SIZE, sizeof(in_addr_t));
	ip6s = calloc(IP6_ALLOC_SIZE, sizeof(struct in6_addr));
	mx_records = calloc(MX_ALLOC_SIZE, sizeof(Mx_record));
	soa_records = calloc(SOA_ALLOC_SIZE, sizeof(Soa_record));
	name_servers = calloc(NS_ALLOC_SIZE, sizeof(char *));
	text_records = calloc(TXT_ALLOC_SIZE, sizeof(char *));
	dnskey_records = calloc(DNSKEY_ALLOC_SIZE, sizeof(Dnskey_record));
	nsec_records = calloc(NSEC_ALLOC_SIZE, sizeof(Nsec_record));
	rrsig_records = calloc(RRSIG_ALLOC_SIZE, sizeof(Rrsig_record));

	for (i = 0; i < NS_ALLOC_SIZE; ++i)
		name_servers[i] = NULL;
	for (i = 0; i < TXT_ALLOC_SIZE; ++i)
		text_records[i] = NULL;

	if (sigsetjmp(__dns_dump_timeout, 1) != 0)
	  {
		if (buffer != NULL) { free(buffer); buffer = NULL; }
		log_err_quit("%s request timed out\n", stringify_qtype);
	  }

	for (i = 0; i < 39; ++i)
	  {
		qtype = __map_index_to_qtype(i);
		if (qtype == QTYPE_AXFR)
			continue;
		if (qtype == QTYPE_IXFR)
			continue;

		/*if (__map_index_to_qtype(i) == QTYPE_IXFR)
		  {
				get_ixfr_record(hostname);
				continue;
		  }*/
		memset(buffer, 0, DNS_BUFSIZE);
		p = buffer;
		dns_ptr = (DNS_HEADER *)p;
		dns_ptr->ident = htons(getpid());
		dns_ptr->cd = 1;
		dns_ptr->rd = 1;
		dns_ptr->qdcnt = htons(1);

		p += sizeof(DNS_HEADER);
		convert_name(hostname, p, &qnamelen);
		debug("converted %s to %*.*s\n", hostname, (int)qnamelen, (int)qnamelen, (char *)p);

		p += (qnamelen + 1);
		dnsq = (DNS_QUESTION *)p;
		dnsq->qtype = htons(qtype);
		dnsq->qclass = htons(QCLASS_INET);
		p += sizeof(DNS_QUESTION);

		sendto(dns_socket, buffer, (p - buffer), 0, (struct sockaddr *)&dns_server, (socklen_t)sizeof(dns_server));
		alarm(DNS_TIMEOUT);
		nbytes = recv(dns_socket, buffer, DNS_BUFSIZE-1, 0);
		alarm(0);

		if (dns_ptr->rcode != RCODE_OK)
		  {
			log_info("%s request received error code: %s\n",
				stringify_qtype(ntohs(dnsq->qtype)),
				stringify_rcode(dns_ptr->rcode));
			continue;
		  }

		buffer[nbytes] = 0;

		if (ntohs(dns_ptr->ancnt) > 0)
			posix_memalign((void **)&answers, 16, (ntohs(dns_ptr->ancnt)*sizeof(DNS_RRECORD)));
		if (ntohs(dns_ptr->nscnt) > 0)
			posix_memalign((void **)&auth, 16, (ntohs(dns_ptr->nscnt)*sizeof(DNS_RRECORD)));
		if (ntohs(dns_ptr->arcnt) > 0)
			posix_memalign((void **)&additional, 16, (ntohs(dns_ptr->arcnt)*sizeof(DNS_RRECORD)));

		debug(
			"\tallocated %lu bytes to answers @ %p to %p\n"
			"\tallocated %lu bytes to auth @ %p to %p\n"
			"\tallocated %lu bytes to additional @ %p to %p\n",
			(ntohs(dns_ptr->ancnt) * sizeof(DNS_RRECORD)), answers, (answers + (ntohs(dns_ptr->ancnt) * sizeof(DNS_RRECORD) - 1)),
			(ntohs(dns_ptr->nscnt) * sizeof(DNS_RRECORD)), auth, (auth + (ntohs(dns_ptr->nscnt) * sizeof(DNS_RRECORD) - 1)),
			(ntohs(dns_ptr->arcnt) * sizeof(DNS_RRECORD)), additional, (additional + (ntohs(dns_ptr->arcnt) * sizeof(DNS_RRECORD) - 1)));

		// p points to the start of the data section //

		if (ntohs(dns_ptr->ancnt) > 0)
		  {
			get_results(answers, ntohs(dns_ptr->ancnt), p, buffer, &delta);
			p += delta;
		  }
		if (ntohs(dns_ptr->nscnt) > 0)
		  {
			get_results(auth, ntohs(dns_ptr->nscnt), p, buffer, &delta);
			p += delta;
		  }
		if (ntohs(dns_ptr->arcnt) > 0)
		  {
			get_results(additional, ntohs(dns_ptr->arcnt), p, buffer, &delta);
			p += delta;
		  }
		verbose("%-10s request: received %d answer records, %d authoritative records, and %d additional records\n",
				stringify_qtype(qtype),
				ntohs(dns_ptr->ancnt),
				ntohs(dns_ptr->nscnt),
				ntohs(dns_ptr->arcnt));
		// Sort the records
		if (ntohs(dns_ptr->ancnt) > 0)
			sort_results(answers, ntohs(dns_ptr->ancnt), buffer);
		if (ntohs(dns_ptr->nscnt) > 0)
			sort_results(auth, ntohs(dns_ptr->nscnt), buffer);
		if (ntohs(dns_ptr->arcnt) > 0)
			sort_results(additional, ntohs(dns_ptr->arcnt), buffer);

		if (answers != NULL) { free(answers); answers = NULL; }
		if (auth != NULL) { free(auth); auth = NULL; }
		if (additional != NULL) { free(additional); additional = NULL; }
	  }

	__dump_results(hostname);
	free_results_memory();

	shutdown(dns_socket, SHUT_RDWR);
	close(dns_socket);
	dns_socket = -1;
	return(0);
}

void
__handle_timeout(int signo)
{
	if (signo != SIGALRM)
		return;

	siglongjmp(__dns_dump_timeout, 1);
}

void
__dump_results(char *host)
{
	int			i, j, fd, soa_dups;
	Inet_u			inet_u;
	char			*out_file = NULL;
	char			*string_ptr = NULL;
	FILE			*fp = NULL;
	pid_t			child;
	size_t			b64len;
	size_t			len;
	uc				*p = NULL;
	uc				*b64 = NULL;


	if (TO_FILE)
	  {
		out_file = calloc(path_max, sizeof(char));
		sprintf(out_file, "%s/DNS_dumps/%s_dns_dump.txt", HOME_DIR, host);
		fd = open(out_file, O_RDWR|O_CREAT|O_TRUNC|O_FSYNC, (S_IRWXU & ~S_IXUSR));
		fp = fdopen(fd, "r+");
		verbose("dumping results to \"%s\"\n", out_file);
	  }


	fprintf((TO_FILE?fp:stdout),
			"\n"
			"\n"
			"\t\tDNS dump for %s on %s\n"
			"\n"
			"\n",
			host, get_time_string(NULL));


	if (ip4_cnt > 0)
	  {
		fprintf((TO_FILE?fp:stdout), "\t\t\t\t%s (%d)\n\n", IPV4S_TITLE, ip4_cnt);
		memset(&inet_u, 0, sizeof(inet_u));
		for (i = 0; i < ip4_cnt; ++i)
	  	  {
			string_ptr = (char *)get_inet4_ptr_record(ip4s[i]);
			fprintf((TO_FILE?fp:stdout), "\t\t%*.*s => %s\n",
				(int)INET_ADDRSTRLEN, (int)INET_ADDRSTRLEN,
				inet_ntop(AF_INET, &ip4s[i], (char *)inet_u.inet4, INET_ADDRSTRLEN),
				(string_ptr==NULL?"MAP FAILED":string_ptr));
	  	  }
	  }

	if (ip6_cnt > 0)
	  {
		size_t l;
		len = l = 0;
		for (i = 0; i < ip6_cnt; ++i)
		  {
			if ((l = strlen((char *)inet_ntop(AF_INET6, &ip6s[i], (char *)inet_u.inet6, INET6_ADDRSTRLEN))) > len)
				len = l;
		  }
		fprintf((TO_FILE?fp:stdout), "\n\n\t\t\t\t%s (%d)\n\n", IPV6S_TITLE, ip6_cnt);
		for (i = 0; i < ip6_cnt; ++i)
	  	  {
			string_ptr = (char *)get_inet6_ptr_record(ip6s[i]);
			fprintf((TO_FILE?fp:stdout), "\t\t%*.*s => %s\n",
				(int)len, (int)len,
				inet_ntop(AF_INET6, &ip6s[i], (char *)inet_u.inet6, INET6_ADDRSTRLEN),
				(string_ptr==NULL?"MAP FAILED":string_ptr));
	  	  }
	  }

	if (mx_cnt > 0)
	  {
		fprintf((TO_FILE?fp:stdout), "\n\n\t\t\t\t%s(%d)\n\n", MX_TITLE, mx_cnt);
		len &= ~len;
		for (i = 0; i < mx_cnt; ++i)
			if (strlen((char *)mx_records[i].mx_name) > len)
				len = strlen((char *)mx_records[i].mx_name);
		for (i = 0; i < mx_cnt; ++i)
	  	  {
			fprintf((TO_FILE?fp:stdout), "\t\t%*.*s (%hu)\n",
				(int)len, (int)len,
				(char *)mx_records[i].mx_name, mx_records[i].preference);
		  }
	  }

	if (ns_cnt > 0)
	  {
		fprintf((TO_FILE?fp:stdout), "\n\n\t\t\t\t%s (%d)\n\n", NS_TITLE, ns_cnt);
		len &= ~len;
		for (i = 0; i < ns_cnt; ++i)
			if (strlen((char *)name_servers[i]) > len)
				len = strlen((char *)name_servers[i]);
		for (i = 0; i < ns_cnt; ++i)
	  	  {
			fprintf((TO_FILE?fp:stdout), "\t\t%*.*s => %s\n",
				(int)len, (int)len,
				(char *)name_servers[i],
				get_inet4_record((char *)name_servers[i]));
	  	  }
	  }

	soa_dups = remove_duplicate_soa_records(soa_records);
	assert(soa_dups != -1);

	if (soa_cnt > 0)
	  {
		fprintf((TO_FILE?fp:stdout), "\n\n\t\t\t\t%s\n\t\t\t\t(%d -- removed %d duplicates)\n\n", SOA_TITLE, soa_cnt, soa_dups);
		for (i = 0; i < soa_cnt; ++i)
	  	  {
			fprintf((TO_FILE?fp:stdout),
					"\t\t[%d] Response to %s query\n\n"
					"\t\tPRIMARY NAME SERVER %s => %s\n"
					"\t\t   RESPONSABLE MAIL %s\n"
					"\t\t      SERIAL NUMBER %u\n"
					"\t\t       REFRESH TIME %us\n"
					"\t\t         RETRY TIME %us\n"
					"\t\t         EXPIRES IN %us\n"
					"\t\t       NEGATIVE TTL %us\n",
					i+1,
					stringify_qtype(soa_records[i].qtype),
					(char *)soa_records[i].domain,
					get_inet4_record((char *)soa_records[i].domain),
					(char *)soa_records[i].mx_name,
					soa_records[i].serial,
					soa_records[i].refresh_time,
					soa_records[i].retry_time,
					soa_records[i].expiry,
					soa_records[i].minimum);
			if (i < (soa_cnt - 1))
				fprintf((TO_FILE?fp:stdout), "\n");
	  	  }
	  }

	if (txt_cnt > 0)
	  {
		fprintf((TO_FILE?fp:stdout), "\n\n\t\t\t\t%s (%d)\n\n", TXT_TITLE, txt_cnt);
		for (i = 0; i < txt_cnt; ++i)
	  	  {
			fprintf((TO_FILE?fp:stdout), "%s\n", text_records[i]);
	  	  }
	  }

	if (nsec_cnt > 0)
	  {
		fprintf((TO_FILE?fp:stdout), "\n\n\t\t\t\t%s (%d)\n\n", NSEC_TITLE, nsec_cnt);
		for (i = 0; i < nsec_cnt; ++i)
		  {
			fprintf((TO_FILE?fp:stdout), "\t\tNext Domain %s => %s\n",
				nsec_records[i].next_domain,
				get_inet4_record((char *)nsec_records[i].next_domain));
			p = nsec_records[i].type_bitmap;
			fprintf((TO_FILE?fp:stdout), "\t\t%hhu|", *p++);
			len = 1;
			while (!(*p & 0x01))
			  {
				*p >>= 1;
				++len;
			  }
			fprintf((TO_FILE?fp:stdout), "%lu bytes\n\t\tBitmap\n\t\t", len);
			++p;
			for (j = 0; j < len; ++j)
			  {
				bit_print_fp(p, (TO_FILE?fp:stdout), 1);
				fprintf((TO_FILE?fp:stdout), "\n\t\t");
				++p;
			  }
		  }
	  }

	if (dnskey_cnt > 0)
	  {
		fprintf((TO_FILE?fp:stdout), "\n\n\t\t\t\t%s (%d)\n\n", DNSKEY_TITLE, dnskey_cnt);
		for (i = 0; i < dnskey_cnt; ++i)
	  	  {
			posix_memalign((void **)&b64, 16, 2048);
			if ((dnskey_records[i].key_flag >> 7) & 0x01)
				fprintf((TO_FILE?fp:stdout), "\t\tKey is a DNS zone key\n");
			if (dnskey_records[i].key_protocol != 3)
				fprintf((TO_FILE?fp:stdout), "\t\tKey is invalid (key protocol == %hhu)\n", dnskey_records[i].key_protocol);
			fprintf((TO_FILE?fp:stdout), "\tKey Algorithm: %s\n", stringify_dnskey_algo(dnskey_records[i].key_algo));

			b64len &= ~b64len;
			memset(b64, 0, 2048);
			b64encode_r(dnskey_records[i].public_key, b64, dnskey_records[i].key_len, &b64len);

			for (j = 0; j < b64len; ++j)
				fputc(b64[j], (TO_FILE?fp:stdout));

			fprintf((TO_FILE?fp:stdout), "\n\n");

			if (b64 != NULL) { free(b64); b64 = NULL; }
	  	  }
	  }

	if (rrsig_cnt > 0)
	  {
		fprintf((TO_FILE?fp:stdout), "\n\n\t\t\t\t%s (%d)\n\n", RRSIG_TITLE, rrsig_cnt);
		for (i = 0; i < rrsig_cnt; ++i)
		  {
			posix_memalign((void **)&b64, 16, 2048);
			fprintf((TO_FILE?fp:stdout),
				"\t\t Type covered: %hu\n"
				"\t\t    Algorithm: %s\n"
				"\t\t       Labels: %hhu\n"
				"\t\t   Sig expiry: %u\n"
				"\t\tSig inception: %u\n"
				"\t\t      Key Tag: %hu\n"
				"\t\t  Signer Name: %s\n",
				rrsig_records[i].type_covered,
				stringify_dnskey_algo(rrsig_records[i].algo),
				rrsig_records[i].labels,
				rrsig_records[i].sig_expiry,
				rrsig_records[i].sig_inception,
				rrsig_records[i].key_tag,
				rrsig_records[i].signer_name);

			b64len &= ~b64len;
			memset(b64, 0, 2048);
			b64encode_r(rrsig_records[i].signature, b64, rrsig_records[i].sig_len, &b64len);

			for (j = 0; j < b64len; ++j)
				fputc(b64[j], (TO_FILE?fp:stdout));

			fprintf((TO_FILE?fp:stdout), "\n\n");
			if (b64 != NULL) { free(b64); b64 = NULL; }
		  }
	  }

	if (TO_FILE && !NO_OPEN)
	  {
		fflush(fp);
		sync();
		fclose(fp);

		log_info("Opening \"%s/DNS_dumps/%s_dns_dump.txt\"\n", HOME_DIR, host);
		if ((child = fork()) == 0)
	  	  {
			execlp(TEXT_EDITOR, TEXT_EDITOR, out_file, (char *)0);
			log_err_quit("Failed to open file");
	  	  }
		usleep(5);
		free(out_file);
	  }
}

int
__map_index_to_qtype(int idx)
{
	switch(idx)
	  {
		case(0):
		return(QTYPE_A);
		break;
		case(1):
		return(QTYPE_NS);
		break;
		case(2):
		return(QTYPE_SOA);
		break;
		case(3):
		return(QTYPE_CNAME);
		break;
		case(4):
		return(QTYPE_MX);
		break;
		case(5):
		return(QTYPE_TXT);
		break;
		case(6):
		return(QTYPE_RP);
		break;
		case(7):
		return(QTYPE_AFSDB);
		break;
		case(8):
		return(QTYPE_SIG);
		break;
		case(9):
		return(QTYPE_KEY);
		break;
		case(10):
		return(QTYPE_AAAA);
		break;
		case(11):
		return(QTYPE_LOC);
		break;
		case(12):
		return(QTYPE_NAPTR);
		break;
		case(13):
		return(QTYPE_KX);
		break;
		case(14):
		return(QTYPE_CERT);
		break;
		case(15):
		return(QTYPE_DNAME);
		break;
		case(16):
		return(QTYPE_OPT);
		break;
		case(17):
		return(QTYPE_APL);
		break;
		case(18):
		return(QTYPE_DS);
		break;
		case(19):
		return(QTYPE_SSHFP);
		break;
		case(20):
		return(QTYPE_IPSECKEY);
		break;
		case(21):
		return(QTYPE_RRSIG);
		break;
		case(22):
		return(QTYPE_NSEC);
		break;
		case(23):
		return(QTYPE_DNSKEY);
		break;
		case(24):
		return(QTYPE_DHCID);
		break;
		case(25):
		return(QTYPE_NSEC3);
		break;
		case(26):
		return(QTYPE_NSEC3PARAM);
		break;
		case(27):
		return(QTYPE_TLSA);
		break;
		case(28):
		return(QTYPE_HIP);
		break;
		case(29):
		return(QTYPE_CDS);
		break;
		case(30):
		return(QTYPE_CDNSKEY);
		break;
		case(31):
		return(QTYPE_OPENPGPKEY);
		break;
		case(32):
		return(QTYPE_TKEY);
		break;
		case(33):
		return(QTYPE_TSIG);
		break;
		case(34):
		return(QTYPE_IXFR);
		break;
		case(35):
		return(QTYPE_AXFR);
		break;
		case(36):
		return(QTYPE_URI);
		break;
		case(37):
		return(QTYPE_TA);
		break;
		case(38):
		return(QTYPE_DLV);
		break;
	  }

	return(QTYPE_A);
}
