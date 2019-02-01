#include "dns.h"

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
