#include <stdio.h>
#include <unistd.h>

int main(void)
{
	char secret[] = "FLAG{p4g3_t4bl3_w4lk3r}";

	printf("secret @ %p\n", (void *)secret);
	printf("pid = %d\n", getpid());
	printf("Spinning. Walk the page tables to find the flag.\n");

	while (1)
	{
	}
}
