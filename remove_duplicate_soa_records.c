#include <openssl/conf.h>
#include <openssl/evp.h>
#include "dns.h"

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
