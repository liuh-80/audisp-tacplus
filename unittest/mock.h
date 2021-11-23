#ifndef MOCK_H
#define MOCK_H

#include <stddef.h>

// use mock functions when build for UT
#if defined (UNIT_TEST)
void *mock_malloc(size_t size);
void *mock_realloc(void* ptr, size_t size);
void mock_free(void* ptr);
#define malloc  mock_malloc
#define realloc  mock_realloc
#define free    mock_free
#else
#endif

#endif /* MOCK_H */
