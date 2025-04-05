#ifndef __UTIL_H
#define __UTIL_H

#include "arch.h"

#ifndef __FreeBSD__
#ifdef __AMD64__
#define SYS_READ                0
#define SYS_WRITE               1
#define SYS_OPEN                2
#define SYS_CLOSE               3
#define SYS_STAT                4
#define SYS_STAT64              4
#define SYS_LSTAT               6
#define SYS_LSTAT64             6
#define SYS_IOCTL              16
#define SYS_ACCESS             21
#define SYS_MADVISE            28
#define SYS_CONNECT            42
#define SYS_SHUTDOWN           48
#define SYS_BIND               49
#define SYS_EXECVE             59
#define SYS_KILL               62
#define SYS_TRUNCATE           76
#define SYS_CHDIR              80
#define SYS_MKDIR              83
#define SYS_CREAT              85
#define SYS_UNLINK             87
#define SYS_CHMOD              90
#define SYS_CHOWN              92
#define SYS_FCHOWN             93
#define SYS_GETGID            104
#define SYS_SETUID            105
#define SYS_SETGID            106
#define SYS_GETEGID           108
#define SYS_SETREGID          114
#define SYS_SETRESGID         119
#define SYS_TKILL             200
#define SYS_TGKILL            234
#define SYS_MKDIRAT           258
#define SYS_FCHOWNAT          260
#define SYS_FSTATAT           262
#define SYS_UNLINKAT          263
#define SYS_FACCESSAT         269
#endif

#ifdef __i386__
#define SYS_READ                3
#define SYS_WRITE               4
#define SYS_OPEN                5
#define SYS_CLOSE               6
#define SYS_CREAT               8
#define SYS_UNLINK             10
#define SYS_EXECVE             11
#define SYS_CHDIR              12
#define SYS_CHMOD              15
#define SYS_ACCESS             33
#define SYS_KILL               37
#define SYS_MKDIR              39
#define SYS_IOCTL              54
#define SYS_LSTAT              84
#define SYS_TRUNCATE           92
#define SYS_STAT              106
#define SYS_NEWLSTAT          107
#define SYS_STAT64            195
#define SYS_LSTAT64           196
#define SYS_SOCKETCALL        102
#define SYS_GETGID            200
#define SYS_GETEGID           202
#define SYS_SETREGID          204
#define SYS_FCHOWN            207
#define SYS_SETRESGID         210
#define SYS_SETUID            213
#define SYS_SETGID            214
#define SYS_CHOWN             212
#define SYS_MADVISE           219
#define SYS_MKDIRAT           296
#define SYS_LCHOWN            198
#define SYS_FCHOWNAT          298
#define SYS_FSTATAT           300
#define SYS_FSTATAT64         300
#define SYS_UNLINKAT          301
#define SYS_FACCESSAT         307
#endif
#endif

#ifdef __FreeBSD__
#define SYS_READ                3
#define SYS_WRITE               4
#define SYS_OPEN                5
#define SYS_CLOSE               6
#define SYS_CREAT               8
#define SYS_UNLINK             10
#define SYS_CHDIR              12
#define SYS_CHMOD              15
#define SYS_CHOWN              16
#define SYS_SETUID             23
#define SYS_ACCESS             33
#define SYS_KILL               37
#define SYS_GETEGID            43
#define SYS_GETGID             47
#define SYS_IOCTL              54
#define SYS_EXECVE             59
#define SYS_SOCKET             97
#define SYS_CONNECT            98
#define SYS_BIND              104
#define SYS_FCHOWN            123
#define SYS_SETREGID          127
#define SYS_SHUTDOWN          134
#define SYS_MKDIR             136
#define SYS_SETGID            181
#define SYS_STAT              188
#define SYS_STAT64            188
#define SYS_LSTAT             190
#define SYS_LSTAT64           190
#define SYS_LCHOWN            254
#define SYS_SETRESGID         312
#define SYS_TRUNCATE          479
#define SYS_FACCESSAT         489
#define SYS_FCHOWNAT          491
#define SYS_FSTATAT           493
#define SYS_MKDIRAT           496
#define SYS_UNLINKAT          503
#endif

#define XOR(s)                   \
({                               \
    int len = strlen(s);         \
    int x;                       \
    for (x = 0; x < len; x++)    \
        buf[x] = s[x] ^ XOR_KEY; \
    buf[len] = 0;                \
    (const char *)buf;           \
})

#endif
