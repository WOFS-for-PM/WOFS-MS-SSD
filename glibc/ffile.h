#include <stdio.h>

/* Magic number and bits for the _flags field.  The magic number is
   mostly vestigial, but preserved for compatibility.  It occupies the
   high 16 bits of _flags; the low 16 bits are actual flag bits.  */

#define _IO_MAGIC 0xFBAD0000        /* Magic number */
#define _IO_KILLER_MAGIC 0x4B4C4C52 /* KLLR */
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_USER_BUF 0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED 0x0002
#define _IO_NO_READS 0x0004  /* Reading not allowed.  */
#define _IO_NO_WRITES 0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN 0x0010
#define _IO_ERR_SEEN 0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close. */
#define _IO_LINKED 0x0080            /* In the list of all open files.  */
#define _IO_IN_BACKUP 0x0100
#define _IO_LINE_BUF 0x0200
#define _IO_TIED_PUT_GET 0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
/* 0x4000  No longer used, reserved for compat.  */
#define _IO_USER_LOCK 0x8000

#define __set_errno(e) (errno = (e))

FILE *_fopen(const char *filename, const char *mode);

int _fputs(const char *str, FILE *stream);

char *_fgets(char *str, int n, FILE *stream);

size_t _fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

size_t _fread(void *buffer, size_t size, size_t count, FILE *stream);

int _fclose(FILE *stream);

int _fseek(FILE *stream, long int offset, int whence);

int _fflush(FILE *stream);