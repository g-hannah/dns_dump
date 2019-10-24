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
