#include "dns.h"

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
