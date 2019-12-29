#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "tools.h"

/**
 * getLowerUpperStr: get a lower or upper string from a const char string
 * Param:{str}: original string
 * Param:{flag}: 0: to lower; 1: toupper
 * Return:{char*}: a buffer own Lower or upper string
 */
char *getLowerUpperStr(const char *str, int flag)
{
	if(!str)return NULL;

	size_t	len = strlen(str);
	char*	p = NULL;
	int	(*pfun)(int) = NULL;
	char*	res = (char*)malloc(len + 1);
	if(!res)return NULL;

	memset(res, 0x00, len + 1);
	memcpy(res, str, len);
	res[len] = '\0';
	p = res;

	if(flag == 0)pfun = &tolower;
	else pfun = &toupper;

	for(; *res != '\0'; res++)
		*res = pfun(*res);
	return p;
}

//int main(int argc, char **argv)
//{
//	const char *str = "aaBsdsdBsdsdsdfsDDSDs";
//	char *p = getLowerUpperStr(str, 0);
//	printf("LOWER String: [%s]\n", p);
//
//	free(p);
//	p = getLowerUpperStr(str, 1);
//	printf("UPPER String: [%s]\n", p);
//	
//	free(p);
//	p = NULL;
//
//	return 0;
//}
