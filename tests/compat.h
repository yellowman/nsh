/*
 * Prototypes for compat.c's stand-ins, for building the portable tests
 * on a system without them (MinGW): cc -include compat.h ... compat.c
 */
#include <stdio.h>
#include <sys/types.h>

void	*reallocarray(void *, size_t, size_t);
char	*strndup(const char *, size_t);
ssize_t	 getline(char **, size_t *, FILE *);
