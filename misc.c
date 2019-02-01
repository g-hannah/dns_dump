#include "dns.h"

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
