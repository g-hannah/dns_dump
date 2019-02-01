#include "dns.h"

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
