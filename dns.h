#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DNS_BUFSIZE		2048
#define DNS_TIMEOUT		5

#define MAXLINE			1024

#define SECS_PER_WEEK (60*60*24*7)
#define TTL_OK(x) ((x) < SECS_PER_WEEK)

#define LOCAL_DNS "127.0.1.1"
#define LOCAL_DNS2 "127.0.0.1"
#define GOOGLE_DNS "8.8.8.8"
#define GOOGLE_DNS2 "8.8.4.4"

#define OUTFILE_WIDTH		115
#define IPV4S_TITLE			"MAPPED IPV4 ADDRESSES"
#define IPV6S_TITLE			"MAPPED IPV6 ADDRESSES"
#define MX_TITLE			"MAIL EXCHANGE RECORDS"
#define NS_TITLE			"NAME SERVER RECORDS"
#define SOA_TITLE			"START OF AUTHORITY RECORDS"
#define TXT_TITLE			"TEXT RECORDS"
#define DNSKEY_TITLE		"DNS PUBLIC KEYS"
#define NSEC_TITLE			"NSEC RECORDS"
#define RRSIG_TITLE			"RRSIG RECORDS"

typedef unsigned char		uc;
typedef unsigned int		ui;
typedef unsigned short		us;
typedef uint8_t				u8;
typedef uint16_t			u16;
typedef uint32_t			u32;
typedef uint64_t			u64;

enum QTYPE
{
	QTYPE_A = 1,
#define QTYPE_A QTYPE_A
	QTYPE_NS = 2,
#define QTYPE_NS QTYPE_NS
	QTYPE_CNAME = 5,
#define QTYPE_CNAME QTYPE_CNAME
	QTYPE_SOA = 6,
#define QTYPE_SOA QTYPE_SOA
	QTYPE_PTR = 12,
#define QTYPE_PTR QTYPE_PTR
	QTYPE_MX = 15,
#define QTYPE_MX QTYPE_MX
	QTYPE_TXT = 16,
#define QTYPE_TXT QTYPE_TXT
	QTYPE_RP = 17,
#define QTYPE_RP QTYPE_RP
	QTYPE_AFSDB = 18,
#define QTYPE_AFSDB QTYPE_AFSDB
	QTYPE_SIG = 24,
#define QTYPE_SIG QTYPE_SIG
	QTYPE_KEY = 25,
#define QTYPE_KEY QTYPE_KEY
	QTYPE_AAAA = 28,
#define QTYPE_AAAA QTYPE_AAAA
	QTYPE_LOC = 29,
#define QTYPE_LOC QTYPE_LOC
	QTYPE_SRV = 33,
#define QTYPE_SRV QTYPE_SRV
	QTYPE_NAPTR = 35,
#define QTYPE_NAPTR QTYPE_NAPTR
	QTYPE_KX = 36,
#define QTYPE_KX QTYPE_KX
	QTYPE_CERT = 37,
#define QTYPE_CERT QTYPE_CERT
	QTYPE_DNAME = 39,
#define QTYPE_DNAME QTYPE_DNAME
	QTYPE_OPT = 41,
#define QTYPE_OPT QTYPE_OPT
	QTYPE_APL = 42,
#define QTYPE_APL QTYPE_APL
	QTYPE_DS = 43,
#define QTYPE_DS QTYPE_DS
	QTYPE_SSHFP = 44,
#define QTYPE_SSHFP QTYPE_SSHFP
	QTYPE_IPSECKEY = 45,
#define QTYPE_IPSECKEY QTYPE_IPSECKEY
	QTYPE_RRSIG = 46,
#define QTYPE_RRSIG QTYPE_RRSIG
	QTYPE_NSEC = 47,
#define QTYPE_NSEC QTYPE_NSEC
	QTYPE_DNSKEY = 48,
#define QTYPE_DNSKEY QTYPE_DNSKEY
	QTYPE_DHCID = 49,
#define QTYPE_DHCID QTYPE_DHCID
	QTYPE_NSEC3 = 50,
#define QTYPE_NSEC3 QTYPE_NSEC3
	QTYPE_NSEC3PARAM = 51,
#define QTYPE_NSEC3PARAM QTYPE_NSEC3PARAM
	QTYPE_TLSA = 52,
#define QTYPE_TLSA QTYPE_TLSA
	QTYPE_HIP = 55,
#define QTYPE_HIP QTYPE_HIP
	QTYPE_CDS = 59,
#define QTYPE_CDS QTYPE_CDS
	QTYPE_CDNSKEY = 60,
#define QTYPE_CDNSKEY QTYPE_CDNSKEY
	QTYPE_OPENPGPKEY = 61,
#define QTYPE_OPENPGPKEY QTYPE_OPENPGPKEY
	QTYPE_TKEY = 249,
#define QTYPE_TKEY QTYPE_TKEY
	QTYPE_TSIG = 250, /* ttl = 0; class = any; */
#define QTYPE_TSIG QTYPE_TSIG
	QTYPE_IXFR = 251,
#define QTYPE_IXFR QTYPE_IXFR
	QTYPE_AXFR = 252,
#define QTYPE_AXFR QTYPE_AXFR
	QTYPE_ANY = 255,
#define QTYPE_ANY QTYPE_ANY
	QTYPE_URI = 256,
#define QTYPE_URI QTYPE_URI
	QTYPE_TA = 32768,
#define QTYPE_TA QTYPE_TA
	QTYPE_DLV = 32769
#define QTYPE_DLV QTYPE_DLV
};

enum QCLASS
{
	QCLASS_INET = 1,
#define QCLASS_INET QCLASS_INET
	QCLASS_CHAOS = 3,
#define QCLASS_CHAOS QCLASS_CHAOS
	QCLASS_HESIOD = 4,
#define QCLASS_HESIOD QCLASS_HESIOD
	QCLASS_NONE = 254,
#define QCLASS_NONE QCLASS_NONE
	QCLASS_ALL = 255
#define QCLASS_ALL QCLASS_ALL
};

enum RCODE
{
	RCODE_OK,
#define RCODE_OK RCODE_OK
	RCODE_FMT,
#define RCODE_FMT RCODE_FMT
	RCODE_SRV,
#define RCODE_SRV RCODE_SRV
	RCODE_NAM,
#define RCODE_NAM RCODE_NAM
	RCODE_IMP,
#define RCODE_IMP RCODE_IMP
	RCODE_REF
#define RCODE_REF RCODE_REF
};

struct HEADER
{
	us ident;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	us rd:1; /* recursion desired */
	us tc:1; /* response truncated */
	us aa:1; /* authoritative answers */
	us opcode:4;
	us qr:1; /* query / response */
	us rcode:4;
	us cd:1;  /* checking disabled */
	us ad:1; /* authentic data */
	us z:1; /* reserved; zero */
	us ra:1; /* recursion available */
#elif __BYTE_ORDER == __BIG_ENDIAN
	us qr:1;
	us opcode:4;
	us aa:1;
	us tc:1;
	us rd:1;
	us ra:1;
	us z:1;
	us ad:1;
	us cd:1;
	us rcode:4;
#else
# error "please adjust <bits/endian.h>"
#endif
	us qdcnt;
	us ancnt;
	us nscnt;
	us arcnt;
};

typedef struct HEADER DNS_HEADER;

struct QUESTION
{
	us qtype;
	us qclass;
};

typedef struct QUESTION DNS_QUESTION;

struct RDATA
{
	us type;
	us _class;
	u32 ttl;
	us len;
} __attribute__ ((__packed__));

typedef struct RDATA DNS_RDATA;

struct RRECORD
{
	uc *name;
	struct RDATA *resource;
	uc *rdata;
};

typedef struct RRECORD DNS_RRECORD;

struct NAPTR_DATA
{
	us order;
	us pref;
	uc *flags;
	uc *services;
	uc *regex;
	uc *replace;
} __attribute__ ((__packed__));

typedef struct NAPTR_DATA NAPTR_DATA;

struct Mx_record
{
	uc		*mx_name;
	u16		preference;
};

typedef struct Mx_record Mx_record;

struct Soa_record
{
	uc		*domain;
	uc		*mx_name;
	u32		serial;
	u32		refresh_time;
	u32		retry_time;
	u32		expiry;
	u32		minimum;
	u32		qtype;
};

typedef struct Soa_record Soa_record;

struct Dnskey_record
{
	u16		key_flag;
	uc		key_protocol;
	uc		key_algo;
	uc		*public_key;
	size_t	key_len;
};

typedef struct Dnskey_record Dnskey_record;

struct Nsec_record
{
	uc		*next_domain;
	uc		*type_bitmap;
};

typedef struct Nsec_record Nsec_record;

struct Rrsig_record
{
	u16		type_covered;
	uc		algo;
	uc		labels;
	u32		original_ttl;
	u32		sig_expiry;
	u32		sig_inception;
	u16		key_tag;
	uc		*signer_name;
	uc		*signature;
	u16		sig_len;
};

typedef struct Rrsig_record Rrsig_record;

union Inet_u
{
	uc		inet4[INET_ADDRSTRLEN];
	uc		inet6[INET6_ADDRSTRLEN];
};

typedef union Inet_u Inet_u;

extern char		*inet4_ptr_name;
extern char		*inet6_ptr_name;
extern char		*inet4_string;
extern char		*primary_NS;
extern char		*time_string;
extern in_addr_t	*ip4s;
extern struct in6_addr	*ip6s;
extern char		**text_records;
extern char		**name_servers;
extern Mx_record	*mx_records;
extern Soa_record	*soa_records;
extern Dnskey_record	*dnskey_records;
extern Nsec_record	*nsec_records;
extern Rrsig_record	*rrsig_records;


extern int		ip4_cnt;
extern int		ip6_cnt;
extern int		mx_cnt;
extern int		soa_cnt;
extern int		txt_cnt;
extern int		ns_cnt;
extern int		dnskey_cnt;
extern int		nsec_cnt;
extern int		rrsig_cnt;

extern int		IP4_ALLOC_SIZE;
extern int		IP6_ALLOC_SIZE;
extern int		MX_ALLOC_SIZE;
extern int		SOA_ALLOC_SIZE;
extern int		TXT_ALLOC_SIZE;
extern int		NS_ALLOC_SIZE;
extern int		DNSKEY_ALLOC_SIZE;
extern int		NSEC_ALLOC_SIZE;
extern int		RRSIG_ALLOC_SIZE;

extern int		DEBUG;
extern int		VERBOSE;
extern int		SERVER;
extern int		TO_FILE;
extern int		NO_OPEN;
extern int		TRACE_PATH;
extern u16		DNS_PORT;
extern char		*DNS_SERVER;
extern int		host_max;
extern int		path_max;
extern char		*TEXT_EDITOR;
extern char		*HOME_DIR;
extern char		*b64table;

// defined in conversion
uc *convert_name(char *, uc *, size_t *) __nonnull ((1,2,3)) __wur;
uc *convert_inet4_to_ptr(uc *, uc *, size_t *) __nonnull ((1,2,3)) __wur;
uc *convert_inet6_to_ptr(uc *, uc *, size_t *) __nonnull ((1,2,3)) __wur;

// defined in records.c
char *get_inet4_record(char *) __nonnull ((1)) __wur;
char *get_inet4_ptr_record(in_addr_t) __wur;
char *get_inet6_ptr_record(struct in6_addr) __wur;
char *get_primary_ns(char *) __nonnull ((1)) __wur;
uc *get_name(uc *, uc *, uc *, size_t *) __nonnull ((1,2,3,4)) __wur;

// defined in results.c
int get_results(DNS_RRECORD *, int, uc *, uc *, size_t *) __nonnull ((1,3,4)) __wur;
int sort_results(DNS_RRECORD *, int, uc *) __nonnull ((1,3)) __wur;
int remove_duplicate_soa_records(Soa_record *) __nonnull ((1)) __wur;
int dns_dump(char *) __nonnull ((1)) __wur;

// defined in misc.c
void check_dump_directory(void);
char *get_time_string(time_t *);
char *stringify_rcode(u16) __wur;
char *stringify_qtype(u16) __wur;
char *stringify_qclass(u16) __wur;
char *stringify_dnskey_algo(uc) __wur;
void bit_print_fp(uc *, FILE *, size_t) __nonnull ((1,2));

// defined in axfr.c
int get_axfr_record(char *) __nonnull ((1)) __wur;
void parse_axfr_data(uc *, size_t, char *, char *) __nonnull ((1,3,4));

// defined in memory.c
void free_record(DNS_RRECORD *);
void free_inet4_recs(in_addr_t **);
void free_inet6_recs(struct in6_addr **);
void free_mx_recs(Mx_record **, int);
void free_soa_recs(Soa_record **, int);
void free_ns_recs(char ***, int);
void free_txt_recs(char ***, int);
void free_results_memory(void);

// defined in encode.c
char *b64encode_r(uc *, uc *, size_t, size_t *) __nonnull ((1,2,4)) __wur;
uc *b64decode_r(char *, uc *, size_t, size_t *) __nonnull ((1,2,4)) __wur;

// defined in logging.c
void debug(char *, ...) __nonnull ((1));
void verbose(char *, ...) __nonnull ((1));
void log_info(char *, ...) __nonnull ((1));
void log_err(char *, ...) __nonnull ((1));
void log_err_quit(char *, ...) __attribute__ ((__noreturn__)) __nonnull ((1));

// defined in trace.c
int trace_path_to_host(char *) __nonnull ((1)) __wur;
