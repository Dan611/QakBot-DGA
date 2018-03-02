# QakBot's Domain Generation Algorithm
## Initial Inspection  

The infected QakBot executable makes several changes to the operating system when run, including copying itself to %APPDATA%/Microsoft/(random name)/, scheduling tasks to run itself again, as well as creating another instance of explorer.exe and injecting malicious code into it. A memory dump of the rogue explorer.exe reveals the likelihood of the DGA being present.

Notable strings in the dump are top level domains ready to be split by a separating character:
```
00A53500  3A 20 69 64 65 6E 74 69 74 79 0D 0A 00 63 6F 6D  : identity...com
00A53510  3B 6E 65 74 3B 6F 72 67 3B 69 6E 66 6F 3B 62 69  ;net;org;info;bi
00A53520  7A 3B 6F 72 67 00 44 65 66 46 72 61 6D 65 50 72  z;org.DefFramePr
```
As well as an alphabet string being referenced from code:
```
00D26BD0  06 59 FF 75 10   BE 2C 45 D3   00 FF 75 0C 8D 7D E4  .Yÿu.¾,EÓ.ÿu..}ä
00D26BD5  BE 2C 45 D3  MOV ESI, D3452C

00D34520  4E 55 4C 4C 00 00 00 00 0D 00 00 00 61 62 63 64  NULL........abcd
00D34530  65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74  efghijklmnopqrst
00D34540  75 76 77 78 79 7A 00 00 61 62 63 64 65 66 67 68  uvwxyz..abcdefgh
```



## General Layout
QakBot's DGA has the following general layout:
	
 * Get the current date by connecting to the internet
 * Calculate the CRC32 checksum of the date string
 * Feed the checksum into a Mersenne Twister random number generator
 * Generate a random amount of random alphabet characters, then append a top level domain

## Current Date Acquisition

When QakBot wants to generate URLs using its domain generation algorithm, the first step is to get the current date. Contained in memory is a string of sites to attempt connections to: `"cnn.com;microsoft.com;baidu.com;facebook.com;yahoo.com;wikipedia.org;qq.com;linkedin.com;mail.ru"`.

Connection requests are crafted manually using the previous list of domains, as well as the following format string and functions:
```c
"GET / HTTP/1.1", 0x0D, 0x0A,
"Accept: text/html, application/xhtml+xml, */*", 0x0D, 0x0A,
"Accept-Language: en-us", 0x0D, 0x0A,
"User-Agent: %s", 0x0D, 0x0A,
"Accept-Encoding: gzip,  deflate", 0x0D, 0x0A,
"Host: %s", 0x0D, 0x0A,
"Connection: Keep-Alive", 0x0D, 0x0A,  0x0D, 0x0A, 0

gethostbyname()
socket()
connect()
send()
recv()
closesocket()
```
The buffer returned by the __recv()__ call is parsed using calls to __StrStr()__, and if a date is detected, the DGA moves on to the next step. Date strings would be of the general format `"Date: Mon, 01 Jan 2018 00:00:00 GMT"`, and the first 6 characters are then stripped out.

Before the date is used for anything, it is adhered to a certain format, `"%u.%s.%s.%08x"`. From left to right, the values placed into this formatted string are the day, month, year, and a special suffix value. But first, these inputs are modified slightly.

Days are converted from 1-31 to 0-2, by subtracting 1 then dividing by 10, and months are made lowercase. The suffix value is either 0 or 1, depending on the version of QakBot, and this sample uses a value of 1. Using the aforementioned date `"Mon, 01 Jan 2018 00:00:00 GMT"`, the formatted date string would become `"0.jan.2018.00000001"`. 

## CRC32 Checksum

The formatted date string and its length are then passed into a CRC32 checksum generating function, quickly recognizable due to its access of a table, whose values contain:
```c
0x00000000, 0x1DB71064, 0x3B6E20C8, 0x26D930AC,
0x76DC4190, 0x6B6B51F4, 0x4DB26158, 0x5005713C,
0xEDB88320, 0xF00F9344, 0xD6D6A3E8, 0xCB61B38C,
0x9B64C2B0, 0x86D3D2D4, 0xA00AE278, 0xBDBDF21C
```

## Mersenne Twister

An MT19937 Mersenne Twister random number generator is set up, recognizable from its use of the constant `0x6C078965`, using the calculated CRC32 value as the seed:

```c
void mersenne_init
(
	unsigned int seed,	// CRC32 value of the formatted date string
	unsigned int MT[]	// pointer where mersenne twister data is to be stored
)
push    ebp
mov     ebp, esp
mov     eax, dword ptr [ebp + MT]
mov     ecx, dword ptr [ebp + crc32]
push    esi
mov     dword ptr [eax], ecx
mov     dword ptr [eax + 0x9C0], 1
push    edi

mersenne_init:
mov     edx, dword ptr [eax + 0x9C0]
mov     esi, dword ptr [eax + edx*4 - 4]
lea     ecx, dword ptr [eax + edx*4]
mov     edi, esi
shr     edi, 0x1E
xor     edi, esi
imul    edi, edi, 0x6C078965
add     edi, edx
mov     dword ptr [ecx], edi
inc     dword ptr [eax + 0x9C0]
cmp     dword ptr [eax + 0x9C0], 0x270
jl      mersenne_init

pop     edi
pop     esi
pop     ebp
retn
```

## Domain Generation

QakBot is now ready to begin generating domain names. The main DGA algorithm is called with the following parameters shown below. The char **TLD pointer-to-strings array contains top level domains that were stored in QakBot's memory, in this case `"com;net;org;info;biz;org"` which is split by the `";"` into an array of TLDs.
```c
void DGA
(
	char *domain,		// buffer for the generated domain
	int domain_size,	// size of the domain buffer; unused
	unsigned int MT[],	// pointer to the mersenne twister stored in memory
	char **TLD,		// array of top level domain names
	int TLD_count		// number of TLDs
)
push    ebp
mov     ebp, esp
mov     eax, dword ptr [ebp + TLD_count]
push    ebx
push    esi
push    edi
dec     eax
push    eax
push    0
push    dword ptr [ebp + MT]
call    mersenne_range		// returned eax stored in ebx, used as TLD[ebx] to append a random TLD
push    dword ptr [ebp + MT]
mov     edi, dword ptr [ebp + domain]
push    25
push    8
push    edi
mov     ebx, eax
call    DGA_alphabet		// actually begin generating the domain name
mov     esi, dword ptr [<&lstrcat>]
add     esp, 0x1C
push    dot			// "."
push    edi
mov     byte ptr [eax + edi], 0	// null terminate the domain name before concatenations
call    esi			// add "." to the end of the domain
mov     eax, dword ptr [ebp + TLDs]
push    dword ptr [eax + ebx*4]
push    edi
call    esi			// add a random TLD to the end of the domain
pop     edi
pop     esi
pop     ebx
pop     ebp
retn
```
The first step the DGA takes is to randomly generate a number between 0 and the number of TLDs there are, to figure out which TLD to append at the end. Next, the DGA will randomly generate a number between 8 and 25, then loop that many times. Each loop it will generate a number between 0 and 25, corresponding to a letter of the alphabet to append to the domain name being generated:

```c
int DGA_alphabet
(
	char *domain,	 	 // pointer to where the domain is to be stored
	int min,		 // min length of the domain name
	int max,		 // max length
	unsigned int MT[]
)
push    ebp
mov     ebp, esp
sub     esp, 0x1C
push    ebx
push    esi
push    edi
push    6
pop     ecx
push    dword ptr [ebp + max]
mov     esi, abc		 // "abcdefghijklmnopqrstuvwxyz"
push    dword ptr [ebp + min]
lea     edi, dword ptr [ebp - 0x1C]
push    dword ptr [ebp + MT]
rep	movsd			 // load the alphabet into local stack variable from memory
movsw
movsb
call    mersenne_range		 // generate a random number between 8 and 25 (domain name length)
mov     edi, dword ptr [ebp + domain]
mov     ebx, eax
add     esp, 0x0C
xor     esi, esi
test    ebx, ebx
je      DGA_done

DGA_loop:
lea     eax, dword ptr [ebp - 0x1C]
push    eax
call    dword ptr [<&j_strlen>]
dec     eax
push    eax
push    0
push    dword ptr [ebp + MT]
call    mersenne_range		 // generate a random number between 0 and 25
mov     al, byte ptr [ebp + eax - 0x1C]
add     esp, 0xC
mov     byte ptr [esi + edi], al // move random alphabet character into domain string
inc     esi
cmp     esi, ebx
jb      DGA_loop

DGA_done:
mov     byte ptr [esi + edi], 0
pop     edi
pop     esi
mov     eax, ebx		 // return the length of the domain
pop     ebx
leave
retn
```
After the domain name is generated, a "." and a randomly selected TLD are appended. This process is repeated in batches of 5 domains at a time, and the DGA may be called up to 5000 times.

[This QakBot DGA implementation](qakbot_dga.c) written in C will generate the first five domains QakBot would create if it was run on January 1st, 2018, using the date string `"Date: Mon, 01 Jan 2018 00:00:00 GMT"`. For this date, the output is:

```
mdjjljhwtmefsumtdcpfnwp.org
aojpkrdnblwmocdob.org
svfamwehjqiht.com
zcevciwmsqbsgutvwhyp.com
bcrovlbako.biz
```

##### QakBot Sample SHA256: 5B7A5A58E4AF312CD23E1F28597F2818953DD23ABDEEDB52ADB882958E2766CB