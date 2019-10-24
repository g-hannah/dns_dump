#include "dns.h"

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
