#include "dns.h"

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
