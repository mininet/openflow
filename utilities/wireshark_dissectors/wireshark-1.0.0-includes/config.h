/* config.h.  Generated from config.h.in by configure.  */
/* config.h.in.  Generated from configure.in by autoheader.  */

/* Directory for data */
#define DATAFILE_DIR "/usr/local/share/wireshark"

/* Link plugins statically into Wireshark */
/* #undef ENABLE_STATIC */

/* Format modifier for printing 64-bit numbers */
/* #undef G_GINT64_MODIFIER */

/* Enable AirPDcap (WPA/WPA2 decryption) */
#define HAVE_AIRPDCAP 1

/* Define to 1 if you have the <arpa/inet.h> header file. */
#define HAVE_ARPA_INET_H 1

/* Define to 1 if you have the <arpa/nameser.h> header file. */
#define HAVE_ARPA_NAMESER_H 1

/* Define to 1 if you have the <direct.h> header file. */
/* #undef HAVE_DIRECT_H */

/* Define to 1 if you have the <dirent.h> header file. */
#define HAVE_DIRENT_H 1

/* Define to 1 if you have the <dlfcn.h> header file. */
#define HAVE_DLFCN_H 1

/* Define to 1 if you have the <fcntl.h> header file. */
#define HAVE_FCNTL_H 1

/* Define to 1 if you have the `gethostbyname2' function. */
#define HAVE_GETHOSTBYNAME2 1

/* Define to 1 if you have the `getprotobynumber' function. */
#define HAVE_GETPROTOBYNUMBER 1

/* Define to use GNU ADNS library */
/* #undef HAVE_GNU_ADNS */

/* Define to 1 if you have the <grp.h> header file. */
#define HAVE_GRP_H 1

/* Define to use heimdal kerberos */
/* #undef HAVE_HEIMDAL_KERBEROS */

/* Define if you have the iconv() function. */
#define HAVE_ICONV 1

/* Define if inet_ntop() prototype exists */
#define HAVE_INET_NTOP_PROTO 1

/* Define to 1 if you have the <inttypes.h> header file. */
#define HAVE_INTTYPES_H 1

/* Define to 1 if you have the `issetugid' function. */
/* #undef HAVE_ISSETUGID */

/* Define to use kerberos */
#define HAVE_KERBEROS 1

/* Define if krb5.h defines KEYTYPE_ARCFOUR_56 */
/* #undef HAVE_KEYTYPE_ARCFOUR_56 */

/* Define to 1 if you have the <lauxlib.h> header file. */
/* #undef HAVE_LAUXLIB_H */

/* Define to use the libcap library */
/* #undef HAVE_LIBCAP */

/* Define to use libgcrypt */
#define HAVE_LIBGCRYPT 1

/* Define to use gnutls library */
#define HAVE_LIBGNUTLS 1

/* Define to use libpcap library */
#define HAVE_LIBPCAP 1

/* Define to use libpcre library */
/* #undef HAVE_LIBPCRE */

/* Define to use libportaudio library */
/* #undef HAVE_LIBPORTAUDIO */

/* Define to 1 if you have the `smi' library (-lsmi). */
/* #undef HAVE_LIBSMI */

/* Define to use libz library */
#define HAVE_LIBZ 1

/* Define to 1 if you have the <lua5.1/lauxlib.h> header file. */
/* #undef HAVE_LUA5_1_LAUXLIB_H */

/* Define to 1 if you have the <lua5.1/lualib.h> header file. */
/* #undef HAVE_LUA5_1_LUALIB_H */

/* Define to 1 if you have the <lua5.1/lua.h> header file. */
/* #undef HAVE_LUA5_1_LUA_H */

/* Define to 1 if you have the <lualib.h> header file. */
/* #undef HAVE_LUALIB_H */

/* Define to use Lua 5.1 */
/* #undef HAVE_LUA_5_1 */

/* Define to 1 if you have the <lua.h> header file. */
/* #undef HAVE_LUA_H */

/* Define to 1 if you have the <memory.h> header file. */
#define HAVE_MEMORY_H 1

/* Define to use MIT kerberos */
#define HAVE_MIT_KERBEROS 1

/* Define to 1 if you have the `mmap' function. */
#define HAVE_MMAP 1

/* Define to 1 if you have the `mprotect' function. */
#define HAVE_MPROTECT 1

/* Define to 1 if you have the <netdb.h> header file. */
#define HAVE_NETDB_H 1

/* Define to 1 if you have the <netinet/in.h> header file. */
#define HAVE_NETINET_IN_H 1

/* Define to 1 if you have OS X frameworks */
/* #undef HAVE_OS_X_FRAMEWORKS */

/* Define if pcap_breakloop is known */
#define HAVE_PCAP_BREAKLOOP 1

/* Define to 1 if you have the `pcap_createsrcstr' function. */
/* #undef HAVE_PCAP_CREATESRCSTR */

/* Define to 1 if you have the `pcap_datalink_name_to_val' function. */
#define HAVE_PCAP_DATALINK_NAME_TO_VAL 1

/* Define to 1 if you have the `pcap_datalink_val_to_name' function. */
#define HAVE_PCAP_DATALINK_VAL_TO_NAME 1

/* Define to 1 if you have the `pcap_findalldevs' function and a pcap.h that
   declares pcap_if_t. */
#define HAVE_PCAP_FINDALLDEVS 1

/* Define to 1 if you have the `pcap_findalldevs_ex' function. */
/* #undef HAVE_PCAP_FINDALLDEVS_EX */

/* Define to 1 if you have the `pcap_freecode' function. */
#define HAVE_PCAP_FREECODE 1

/* Define to 1 if you have the `pcap_get_selectable_fd' function. */
#define HAVE_PCAP_GET_SELECTABLE_FD 1

/* Define to 1 if you have the `pcap_lib_version' function. */
#define HAVE_PCAP_LIB_VERSION 1

/* Define to 1 if you have the `pcap_list_datalinks' function. */
#define HAVE_PCAP_LIST_DATALINKS 1

/* Define to 1 if you have the `pcap_open' function. */
/* #undef HAVE_PCAP_OPEN */

/* Define to 1 if you have the `pcap_open_dead' function. */
#define HAVE_PCAP_OPEN_DEAD 1

/* Define to 1 if you have WinPcap remote capturing support and prefer to use
   these new API features. */
/* #undef HAVE_PCAP_REMOTE */

/* Define to 1 if you have the `pcap_setsampling' function. */
/* #undef HAVE_PCAP_SETSAMPLING */

/* Define to 1 if you have the `pcap_set_datalink' function. */
#define HAVE_PCAP_SET_DATALINK 1

/* Define if libpcap version is known */
#define HAVE_PCAP_VERSION 1

/* Define if plugins are enabled */
#define HAVE_PLUGINS 1

/* Define to 1 if you have the <portaudio.h> header file. */
/* #undef HAVE_PORTAUDIO_H */

/* Define to 1 if you have the <pwd.h> header file. */
#define HAVE_PWD_H 1

/* Define to 1 to enable remote capturing feature in WinPcap library */
/* #undef HAVE_REMOTE */

/* Define if sa_len field exists in struct sockaddr */
/* #undef HAVE_SA_LEN */

/* Define to 1 if you have the `setresgid' function. */
#define HAVE_SETRESGID 1

/* Define to 1 if you have the `setresuid' function. */
#define HAVE_SETRESUID 1

/* Define to 1 if you have the <stdarg.h> header file. */
#define HAVE_STDARG_H 1

/* Define to 1 if you have the <stddef.h> header file. */
#define HAVE_STDDEF_H 1

/* Define to 1 if you have the <stdint.h> header file. */
#define HAVE_STDINT_H 1

/* Define to 1 if you have the <stdlib.h> header file. */
#define HAVE_STDLIB_H 1

/* Define to 1 if you have the <strings.h> header file. */
#define HAVE_STRINGS_H 1

/* Define to 1 if you have the <string.h> header file. */
#define HAVE_STRING_H 1

/* Define to 1 if you have the `sysconf' function. */
#define HAVE_SYSCONF 1

/* Define to 1 if you have the <sys/ioctl.h> header file. */
#define HAVE_SYS_IOCTL_H 1

/* Define to 1 if you have the <sys/param.h> header file. */
#define HAVE_SYS_PARAM_H 1

/* Define to 1 if you have the <sys/socket.h> header file. */
#define HAVE_SYS_SOCKET_H 1

/* Define to 1 if you have the <sys/sockio.h> header file. */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define to 1 if you have the <sys/stat.h> header file. */
#define HAVE_SYS_STAT_H 1

/* Define to 1 if you have the <sys/time.h> header file. */
#define HAVE_SYS_TIME_H 1

/* Define to 1 if you have the <sys/types.h> header file. */
#define HAVE_SYS_TYPES_H 1

/* Define to 1 if you have the <sys/utsname.h> header file. */
#define HAVE_SYS_UTSNAME_H 1

/* Define to 1 if you have the <sys/wait.h> header file. */
#define HAVE_SYS_WAIT_H 1

/* Define to 1 if you have the <unistd.h> header file. */
#define HAVE_UNISTD_H 1

/* HTML viewer, e.g. mozilla */
#define HTML_VIEWER "mozilla"

/* Define as const if the declaration of iconv() needs const. */
#define ICONV_CONST 

/* Define if <inttypes.h> defines PRI[doxu]64 macros */
#define INTTYPES_H_DEFINES_FORMATS 

/* Define if getopt.h needs to be included */
/* #undef NEED_GETOPT_H */

/* Define if g_ascii_strcasecmp.h needs to be included */
/* #undef NEED_G_ASCII_STRCASECMP_H */

/* Define if g_ascii_strtoull.h needs to be included */
/* #undef NEED_G_ASCII_STRTOULL_H */

/* Define if inet/aton.h needs to be included */
/* #undef NEED_INET_ATON_H */

/* Define if inet/v6defs.h needs to be included */
/* #undef NEED_INET_V6DEFS_H */

/* Define if strerror.h needs to be included */
/* #undef NEED_STRERROR_H */

/* Define if strptime.h needs to be included */
/* #undef NEED_STRPTIME_H */

/* Name of package */
#define PACKAGE "wireshark"

/* Define to the address where bug reports for this package should be sent. */
#define PACKAGE_BUGREPORT ""

/* Define to the full name of this package. */
#define PACKAGE_NAME ""

/* Define to the full name and version of this package. */
#define PACKAGE_STRING ""

/* Define to the one symbol short name of this package. */
#define PACKAGE_TARNAME ""

/* Define to the version of this package. */
#define PACKAGE_VERSION ""

/* Define if we are using version of of the Portaudio library API */
/* #undef PORTAUDIO_API_1 */

/* Define to 1 if you have the ANSI C header files. */
#define STDC_HEADERS 1

/* Version number of package */
#define VERSION "1.0.0"

/* Define to 1 if your processor stores words with the most significant byte
   first (like Motorola and SPARC, unlike Intel and VAX). */
/* #undef WORDS_BIGENDIAN */

/* Define as the string to precede external variable declarations in
   dynamically-linked libraries */
#define WS_VAR_IMPORT extern

/* Define to 1 if `lex' declares `yytext' as a `char *' by default, not a
   `char[]'. */
#define YYTEXT_POINTER 1
