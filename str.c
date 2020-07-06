#include"str.h"

//
void str_trim_crlf(char *str)
{
	while(*str!='\r' && *str!='\n')
		++str;
	*str = '\0';
}


//str = "listen_port=8080 "
void str_split(const char *str , char *left, char *right, char c)
{
	const char *p = str;
	while(*p!='\0' && *p != c)
		p++;

	if(*p == '\0')
	{
		strcpy(left, str);
	}
	else
	{
		strncpy(left, str, p-str);
		strcpy(right, p+1);
	}
}

int str_all_space(const char *str)
{
	while(*str!='\0' && *str == ' ')
		str++;
	if(*str == '\0')
		return 1;
	return 0;
}


long long str_to_longlong(const char *str)
{
	//return atoll(str);
	long long result = 0;
	long long mult = 1;
	unsigned int len = strlen(str);
	int i;

	if (len > 15)
		return 0;

	for (i=len-1; i>=0; i--) {
		char ch = str[i];
		long long val;
		if (ch < '0' || ch > '9')
			return 0;

		val = ch - '0';
		val *= mult;
		result += val;
		mult *= 10;
	}

	return result;
}