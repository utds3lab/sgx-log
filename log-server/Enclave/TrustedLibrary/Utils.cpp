#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "sgx_tcrypto.h"
#include "sgx_utils.h"
#include "sgx_tseal.h"
#include "handy.h"
#include <string.h>
#include <cstring>





int compareHashValues(char * old_hash, char * new_hash, int len){
	for(int i=0;i<len;i++){
		printf("\n%u %u", old_hash[i], new_hash[i]);
		if((unsigned)old_hash[i]!= (unsigned)new_hash[i]){
			return 0;
		}
	}
	return 1;
}

void reverse(char *str, int length)
{
    int start = 0;
    int end = length -1;
    while (start < end)
    {
    	int temp = *(str+start);
    	*(str+start) = *(str+end);
    	*(str+end) = temp;
        start++;
        end--;
    }
}

int myAtoi(char *str)
{
    int res = 0; // Initialize result

    // Iterate through all characters of input string and
    // update result
    for (int i = 0; str[i] != '\0'; ++i)
        res = res*10 + str[i] - '0';

    // return result.
    return res;
}

// Implementation of itoa()
char* itoa(int num, char* str, int base)
{
    int i = 0;
    bool isNegative = false;

    /* Handle 0 explicitely, otherwise empty string is printed for 0 */
    if (num == 0)
    {
        str[i++] = '0';
        str[i] = '\0';
        return str;
    }

    // In standard itoa(), negative numbers are handled only with
    // base 10. Otherwise numbers are considered unsigned.
    if (num < 0 && base == 10)
    {
        isNegative = true;
        num = -num;
    }

    // Process individual digits
    while (num != 0)
    {
        int rem = num % base;
        str[i++] = (rem > 9)? (rem-10) + 'a' : rem + '0';
        num = num/base;
    }

    // If number is negative, append '-'
    if (isNegative)
        str[i++] = '-';

    str[i] = '\0'; // Append string terminator

    // Reverse the string
    reverse(str, i);

    return str;
}


