#include "dns.h"

static sigjmp_buf			__timeout, __pipe__;
static struct sigaction		alarm_act, alarm_oact;
static struct sigaction		pipe_act, pipe_oact;

static void __dump_axfr_data(char *, char *) __nonnull ((1,2));
static void __handle_timeout(int);

void
__catch_sigpipe(int signo)
{
	if (signo != SIGPIPE)
		return;

	siglongjmp(__pipe__, 1);
}

void
__handle_timeout(int signo)
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

	alarm_act.sa_handler = __handle_timeout;
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
