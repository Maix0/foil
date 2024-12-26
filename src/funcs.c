
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

typedef struct StringBuilder StringBuilder;

void strappendf(StringBuilder *dest, const char *fmt, ...) {
  va_list args;
  int len;
  size_t new_offset;

  va_start(args, fmt);
  len =
      vsnprintf(dest->str + dest->offset, dest->size - dest->offset, fmt, args);
  va_end(args);
  if (len < 0)
    die_with_error_proxy("vsnprintf");
  new_offset = xadd(dest->offset, len);
  if (new_offset >= dest->size) {
    dest->size = xmul(xadd(new_offset, 1), 2);
    dest->str = xrealloc(dest->str, dest->size);
    va_start(args, fmt);
    len = vsnprintf(dest->str + dest->offset, dest->size - dest->offset, fmt,
                    args);
    va_end(args);
    if (len < 0)
      die_with_error_proxy("vsnprintf");
  }

  dest->offset = new_offset;
}

char *xasprintf(const char *format, ...) {
  char *buffer = NULL;
  va_list args;

  va_start(args, format);
  if (vasprintf(&buffer, format, args) == -1)
    die_oom();
  va_end(args);

  return buffer;
}
