
#include "stdarg.h"
#include "stdio.h"
#include "stdlib.h"

void *xrealloc(void *ptr, size_t size);
struct StringBuilder {
  char *str;
  size_t size;
  size_t offset;
};

size_t xadd(size_t a, size_t b);
size_t xmul(size_t a, size_t b);
void die_with_error_proxy(char *);
void die_oom(void);

char *xasprintf(const char *format, ...) {
  char *buffer = NULL;
  va_list args;

  va_start(args, format);
  if (vasprintf(&buffer, format, args) == -1)
    die_oom();
  va_end(args);

  return buffer;
}
