#ifndef _ASM_GENERIC_ERRNO_BASE_H
#define _ASM_GENERIC_ERRNO_BASE_H

#define	linux_EPERM		 1	/* Operation not permitted */
#define	linux_ENOENT		 2	/* No such file or directory */
#define	linux_ESRCH		 3	/* No such process */
#define	linux_EINTR		 4	/* Interrupted system call */
#define	linux_EIO		 5	/* I/O error */
#define	linux_ENXIO		 6	/* No such device or address */
#define	linux_E2BIG		 7	/* Argument list too long */
#define	linux_ENOEXEC		 8	/* Exec format error */
#define	linux_EBADF		 9	/* Bad file number */
#define	linux_ECHILD		10	/* No child processes */
#define	linux_EAGAIN		11	/* Try again */
#define	linux_ENOMEM		12	/* Out of memory */
#define	linux_EACCES		13	/* Permission denied */
#define	linux_EFAULT		14	/* Bad address */
#define	linux_ENOTBLK		15	/* Block device required */
#define	linux_EBUSY		16	/* Device or resource busy */
#define	linux_EEXIST		17	/* File exists */
#define	linux_EXDEV		18	/* Cross-device link */
#define	linux_ENODEV		19	/* No such device */
#define	linux_ENOTDIR		20	/* Not a directory */
#define	linux_EISDIR		21	/* Is a directory */
#define	linux_EINVAL		22	/* Invalid argument */
#define	linux_ENFILE		23	/* File table overflow */
#define	linux_EMFILE		24	/* Too many open files */
#define	linux_ENOTTY		25	/* Not a typewriter */
#define	linux_ETXTBSY		26	/* Text file busy */
#define	linux_EFBIG		27	/* File too large */
#define	linux_ENOSPC		28	/* No space left on device */
#define	linux_ESPIPE		29	/* Illegal seek */
#define	linux_EROFS		30	/* Read-only file system */
#define	linux_EMLINK		31	/* Too many links */
#define	linux_EPIPE		32	/* Broken pipe */
#define	linux_EDOM		33	/* Math argument out of domain of func */
#define	linux_ERANGE		34	/* Math result not representable */

#endif
