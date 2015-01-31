#ifndef _ASM_GENERIC_ERRNO_H
#define _ASM_GENERIC_ERRNO_H

#include <asm-generic/errno-base.h>

#define	linux_EDEADLK		35	/* Resource deadlock would occur */
#define	linux_ENAMETOOLONG	36	/* File name too long */
#define	linux_ENOLCK		37	/* No record locks available */
#define	linux_ENOSYS		38	/* Function not implemented */
#define	linux_ENOTEMPTY	39	/* Directory not empty */
#define	linux_ELOOP		40	/* Too many symbolic links encountered */
#define	linux_EWOULDBLOCK	EAGAIN	/* Operation would block */
#define	linux_ENOMSG		42	/* No message of desired type */
#define	linux_EIDRM		43	/* Identifier removed */
#define	linux_ECHRNG		44	/* Channel number out of range */
#define	linux_EL2NSYNC	45	/* Level 2 not synchronized */
#define	linux_EL3HLT		46	/* Level 3 halted */
#define	linux_EL3RST		47	/* Level 3 reset */
#define	linux_ELNRNG		48	/* Link number out of range */
#define	linux_EUNATCH		49	/* Protocol driver not attached */
#define	linux_ENOCSI		50	/* No CSI structure available */
#define	linux_EL2HLT		51	/* Level 2 halted */
#define	linux_EBADE		52	/* Invalid exchange */
#define	linux_EBADR		53	/* Invalid request descriptor */
#define	linux_EXFULL		54	/* Exchange full */
#define	linux_ENOANO		55	/* No anode */
#define	linux_EBADRQC		56	/* Invalid request code */
#define	linux_EBADSLT		57	/* Invalid slot */

#define	linux_EDEADLOCK	EDEADLK

#define	linux_EBFONT		59	/* Bad font file format */
#define	linux_ENOSTR		60	/* Device not a stream */
#define	linux_ENODATA		61	/* No data available */
#define	linux_ETIME		62	/* Timer expired */
#define	linux_ENOSR		63	/* Out of streams resources */
#define	linux_ENONET		64	/* Machine is not on the network */
#define	linux_ENOPKG		65	/* Package not installed */
#define	linux_EREMOTE		66	/* Object is remote */
#define	linux_ENOLINK		67	/* Link has been severed */
#define	linux_EADV		68	/* Advertise error */
#define	linux_ESRMNT		69	/* Srmount error */
#define	linux_ECOMM		70	/* Communication error on send */
#define	linux_EPROTO		71	/* Protocol error */
#define	linux_EMULTIHOP	72	/* Multihop attempted */
#define	linux_EDOTDOT		73	/* RFS specific error */
#define	linux_EBADMSG		74	/* Not a data message */
#define	linux_EOVERFLOW	75	/* Value too large for defined data type */
#define	linux_ENOTUNIQ	76	/* Name not unique on network */
#define	linux_EBADFD		77	/* File descriptor in bad state */
#define	linux_EREMCHG		78	/* Remote address changed */
#define	linux_ELIBACC		79	/* Can not access a needed shared library */
#define	linux_ELIBBAD		80	/* Accessing a corrupted shared library */
#define	linux_ELIBSCN		81	/* .lib section in a.out corrupted */
#define	linux_ELIBMAX		82	/* Attempting to link in too many shared libraries */
#define	linux_ELIBEXEC	83	/* Cannot exec a shared library directly */
#define	linux_EILSEQ		84	/* Illegal byte sequence */
#define	linux_ERESTART	85	/* Interrupted system call should be restarted */
#define	linux_ESTRPIPE	86	/* Streams pipe error */
#define	linux_EUSERS		87	/* Too many users */
#define	linux_ENOTSOCK	88	/* Socket operation on non-socket */
#define	linux_EDESTADDRREQ	89	/* Destination address required */
#define	linux_EMSGSIZE	90	/* Message too long */
#define	linux_EPROTOTYPE	91	/* Protocol wrong type for socket */
#define	linux_ENOPROTOOPT	92	/* Protocol not available */
#define	linux_EPROTONOSUPPORT	93	/* Protocol not supported */
#define	linux_ESOCKTNOSUPPORT	94	/* Socket type not supported */
#define	linux_EOPNOTSUPP	95	/* Operation not supported on transport endpoint */
#define	linux_EPFNOSUPPORT	96	/* Protocol family not supported */
#define	linux_EAFNOSUPPORT	97	/* Address family not supported by protocol */
#define	linux_EADDRINUSE	98	/* Address already in use */
#define	linux_EADDRNOTAVAIL	99	/* Cannot assign requested address */
#define	linux_ENETDOWN	100	/* Network is down */
#define	linux_ENETUNREACH	101	/* Network is unreachable */
#define	linux_ENETRESET	102	/* Network dropped connection because of reset */
#define	linux_ECONNABORTED	103	/* Software caused connection abort */
#define	linux_ECONNRESET	104	/* Connection reset by peer */
#define	linux_ENOBUFS		105	/* No buffer space available */
#define	linux_EISCONN		106	/* Transport endpoint is already connected */
#define	linux_ENOTCONN	107	/* Transport endpoint is not connected */
#define	linux_ESHUTDOWN	108	/* Cannot send after transport endpoint shutdown */
#define	linux_ETOOMANYREFS	109	/* Too many references: cannot splice */
#define	linux_ETIMEDOUT	110	/* Connection timed out */
#define	linux_ECONNREFUSED	111	/* Connection refused */
#define	linux_EHOSTDOWN	112	/* Host is down */
#define	linux_EHOSTUNREACH	113	/* No route to host */
#define	linux_EALREADY	114	/* Operation already in progress */
#define	linux_EINPROGRESS	115	/* Operation now in progress */
#define	linux_ESTALE		116	/* Stale file handle */
#define	linux_EUCLEAN		117	/* Structure needs cleaning */
#define	linux_ENOTNAM		118	/* Not a XENIX named type file */
#define	linux_ENAVAIL		119	/* No XENIX semaphores available */
#define	linux_EISNAM		120	/* Is a named type file */
#define	linux_EREMOTEIO	121	/* Remote I/O error */
#define	linux_EDQUOT		122	/* Quota exceeded */

#define	linux_ENOMEDIUM	123	/* No medium found */
#define	linux_EMEDIUMTYPE	124	/* Wrong medium type */
#define	linux_ECANCELED	125	/* Operation Canceled */
#define	linux_ENOKEY		126	/* Required key not available */
#define	linux_EKEYEXPIRED	127	/* Key has expired */
#define	linux_EKEYREVOKED	128	/* Key has been revoked */
#define	linux_EKEYREJECTED	129	/* Key was rejected by service */

/* for robust mutexes */
#define	linux_EOWNERDEAD	130	/* Owner died */
#define	linux_ENOTRECOVERABLE	131	/* State not recoverable */

#define linux_ERFKILL		132	/* Operation not possible due to RF-kill */

#define linux_EHWPOISON	133	/* Memory page has hardware error */

#endif
