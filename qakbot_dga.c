#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

unsigned int crc32(char *formatted_date, int len)
{
	static int crc32_table[] = 
	{
		0x00000000,	0x1DB71064,	0x3B6E20C8,	0x26D930AC,
		0x76DC4190,	0x6B6B51F4,	0x4DB26158,	0x5005713C,
		0xEDB88320,	0xF00F9344,	0xD6D6A3E8,	0xCB61B38C,
		0x9B64C2B0,	0x86D3D2D4,	0xA00AE278,	0xBDBDF21C
	};

	if(len <= 0)
		return 0;

	unsigned int crc = ~0x00000000;
	for(int i = 0;i < len;i++)
	{
		crc ^= formatted_date[i];
		crc = crc32_table[crc & 0xF] ^ (crc >> 4);
		crc = crc32_table[crc & 0xF] ^ (crc >> 4);
	}
	crc = ~crc;

	return crc;
}

// split a string into an array of tokens based on a delimiter
// ex: tokenize("com;net;org", " ", NULL) => {"com", "net", "org"}
char **tokenize(char *str, char *delim, int *token_count_ptr)
{
	int token_count = 1;
	for(char *ptr = str;*ptr;ptr++)
		if(*ptr == *delim)
			token_count++;

	if(token_count_ptr)
		*token_count_ptr = token_count;

	char **token = malloc(token_count * sizeof(char *));

	token[0] = strtok(str, delim);
	for(int i = 1;i < token_count;i++)
		token[i] = strtok(NULL, delim);

	return token;
}

// take a typical recv date string (ex: "Date: Fri, 21 Apr 2017 14:17:20 GMT")
// and generate a CRC32 value from the day, month, and year using logic from QakBot
unsigned int date_crc32(char *date)
{
	char *format = "%u.%s.%s.%08x",
		 formatted_date[0x40];

	char **date_token = tokenize(date + 6, " ", NULL);
	
	char *day = date_token[1],
		 *month = date_token[2],
		 *year = date_token[3];

	// days 1-10 => 0, 11-20 => 1, 21-... => 2
	int day_i = atoi(day);
	if(day_i < 30)
		day_i = (day_i - 1) / 10;
	else
		day_i = 2;

	for(char *p = month;*p;p++)
		*p = tolower(*p);

	// varies from sample to sample of qakbot
	int suffix = 0x00000001;

	snprintf(formatted_date, 0x40, format, day_i, month, year, suffix);

	return crc32(formatted_date, strlen(formatted_date));
}

// initialize the mersenne twister
void mersenne_init(unsigned int seed, unsigned int MT[])
{
	MT[0] = seed;

	for(MT[0x270] = 1;MT[0x270] < 0x270;MT[0x270]++)
		MT[MT[0x270]] = ((MT[MT[0x270] - 1] >> 0x1E) ^ MT[MT[0x270] - 1]) * 0x6C078965 + MT[0x270];
}

// return the next random value from the twister
unsigned int mersenne_gen(unsigned int MT[])
{
	if(MT[0x270] >= 0x270)
	{
		unsigned int xor;

		for(int i = 0;i < 0x270;i++)
		{
			xor = ((MT[i] ^ MT[(i + 1) % 0x270]) & 0x7FFFFFFF) ^ MT[i];
			MT[i] = MT[(i + 0x18D) % 0x270] ^ (xor >> 1);
			if(xor & 1)
				MT[i] ^= 0x9908B0DF;
		}

		MT[0x270] = 0;
	}

	unsigned int raw;
	raw = MT[MT[0x270]];
	MT[0x270] = MT[0x270] + 1;
	raw ^= (raw >> 0xB);
	raw ^= (raw & 0x0FF3A58AD) << 0x7;
	raw ^= ((raw & 0xFFFF0000) | (raw & 0x0000DF8C)) << 0xF;
	return raw ^ (raw >> 0x12);
}

// convert the raw twister value into a value within the range [min, max] inclusive
int mersenne_range(unsigned int MT[], int min, int max)
{
	return (mersenne_gen(MT) & 0x0FFFFFFF) / (float) 0x10000000 * (max - min + 1) + min;
}

// gnerate a domain name using the alphabet
int DGA_alphabet(char *domain, int min, int max, unsigned int MT[])
{
	char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

	int rand_len = mersenne_range(MT, min, max),
		len = strlen(alphabet) - 1;

	for(int i = 0;i < rand_len;i++)
		domain[i] = alphabet[mersenne_range(MT, 0, len)];
	domain[rand_len] = 0;

	return rand_len;
}

// generate a domain name then concatenate it with a top level domain
void DGA(char *domain, unsigned int MT[], char **TLD, int TLD_count)
{
	int rand = mersenne_range(MT, 0, TLD_count - 1);

	DGA_alphabet(domain, 8, 25, MT);

	strcat(domain, ".");
	strcat(domain, TLD[rand]);
}

int main()
{
	// the date QakBot would acquire from a recv request
	char date[] = "Date: Mon, 01 Jan 2018 00:00:00 GMT",
	// the top level domains stored inside QakBot that it will use for domain generation
		 TLDS[] = "com;net;org;info;biz;org";
	// how many domains to generate; QakBot may generate up to 5000 domains, testing 5 at a time
	int DGA_count = 5;

	// generate a CRC32 checksum from the date string
	unsigned int crc = date_crc32(date);

	// initialize a MT19937 mersenne twister using the CRC32 checksum as the seed
	unsigned int MT[0x271];
	mersenne_init(crc, MT);

	// split the top level domain string into an array of TLDs
	int TLD_count;
	char **TLD = tokenize(TLDS, ";", &TLD_count);

	// generate and print domains
	char *domain = calloc(1, 0x100);
	for(int i = 0;i < DGA_count;i++)
	{
		DGA(domain, MT, TLD, TLD_count);
		printf("%s\n", domain);
	}
}