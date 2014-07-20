/*
    Sylverant DNS Server

    Copyright (C) 2014 Lawrence Sebald
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above
       copyright notice, this list of conditions and the following
       disclaimer in the documentation and/or other materials provided
       with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
    FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
    COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
    INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
    ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
*/

/*
    This program is a very simple DNS "server" designed simply for sending out
    the faked DNS entries that PSO needs to connect sanely. It is a bit like the
    old DrDNS program that people used to use, but this one aims to be a bit
    more configurable, a bit less simplistic, and (of course) open source.

    The real story behind this program is that I wanted something simple, like
    DNSMasq's built-in DNS responder, but without necessarily giving people that
    are trying to do DNS amplification attacks a way to attack it.

    To that end, this DNS server takes a number of shortcuts and isn't really a
    very good implementation of a DNS server. It only responds to request for A
    records, and it only responds to those that it actually is configured to
    answer for. Everything else just goes into a black hole of ignoredness.
    Also, this server will only ever answer over UDP -- it doesn't bother to
    bind to the TCP port for DNS at all. After all, there's really no reason to
    do TCP for what this program is really designed to do.

    So, in short, if you're looking for a real DNS server, go elsewhere -- you
    won't find it here. I suggest looking at BIND (or DNSMasq for a smaller
    server you might use on your home network). If you're looking for a way to
    convince PSO to connect to your server, then you might be in the right
    place.

    Oh, and and you might have noticed up above, unlike the rest of Sylverant,
    this DNS server is BSD-licensed. For most people, I'd imagine this doesn't
    mean all that much, but it did seem like the right thing to do with this
    little piece of the puzzle.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#if !defined(_WIN32) || defined(__CYGWIN__)
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#ifndef _arch_dreamcast
#include <pwd.h>
#endif

/* I hate you, Windows. I REALLY hate you. */
typedef int SOCKET;
#define INVALID_SOCKET -1

#else
#include <winsock2.h>
#include <ws2tcpip.h>

typedef u_long in_addr_t;

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")

typedef int ssize_t;

#endif

#endif

/* If it hasn't been overridden at compile time, give a sane default for the
   configuration directory. */
#ifndef CONFIG_DIR
#if defined(_WIN32) && !defined(__CYGWIN__)
#define CONFIG_DIR "."
#elif defined(_arch_dreamcast)
#define CONFIG_DIR "/rd"
#else
#define CONFIG_DIR "/etc/sylverant"
#endif
#endif

#ifndef CONFIG_FILE
#define CONFIG_FILE "pso_dns.conf"
#endif

typedef struct dnsmsg {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
    uint8_t data[];
} dnsmsg_t;

#define QTYPE_A         1

typedef struct host_info {
    char *name;
    in_addr_t addr;
} host_info_t;

/* Input and output packet buffers. */
static uint8_t inbuf[1024];
static uint8_t outbuf[1024];

static dnsmsg_t *inmsg = (dnsmsg_t *)inbuf;
static dnsmsg_t *outmsg = (dnsmsg_t *)outbuf;

/* Read from the configuration. */
static host_info_t *hosts;
static int host_count;

#if defined(_WIN32) && !defined(__CYGWIN__)
static WSADATA wsaData;

static int init_ws(void) {
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) {
        fprintf(stderr, "Couldn't initialize winsock!\n");
        return -1;
    }

    return 0;
}

/* Borrowed from my code in KallistiOS... */
static int inet_pton4(const char *src, void *dst) {
    int parts[4] = { 0 };
    int count = 0;
    struct in_addr *addr = (struct in_addr *)dst;

    for(; *src && count < 4; ++src) {
        if(*src == '.') {
            ++count;
        }
        /* Unlike inet_aton(), inet_pton() only supports decimal parts */
        else if(*src >= '0' && *src <= '9') {
            parts[count] *= 10;
            parts[count] += *src - '0';
        }
        else {
            /* Invalid digit, and not a dot... bail */
            return 0;
        }
    }

    if(count != 3) {
        /* Not the right number of parts, bail */
        return 0;
    }

    /* Validate each part, note that unlike inet_aton(), inet_pton() only
       supports the standard xxx.xxx.xxx.xxx addresses. */
    if(parts[0] > 0xFF || parts[1] > 0xFF ||
       parts[2] > 0xFF || parts[3] > 0xFF)
        return 0;

    addr->s_addr = htonl(parts[0] << 24 | parts[1] << 16 |
        parts[2] << 8 | parts[3]);

    return 1;
}

#define inet_pton(a, b, c) inet_pton4(b, c)

#define close(a) closesocket(a)

#endif

static int cmp_str(const char *s1, const char *s2) {
    int v;

    for(;;) {
        v = toupper(*s1) - toupper(*s2);

        if(v || !*s1)
            return v;

        ++s1;
        ++s2;
    }
}

static int read_config(const char *dir, const char *fn) {
    size_t dlen = strlen(dir), flen = strlen(fn);
    char *fullfn;
    FILE *fp;
    int entries = 0, lineno = 0;
    char linebuf[1024], name[1024], ip[16];
    in_addr_t addr;
    void *tmp;

	/* Curse you, Visual C++... */
	if(!(fullfn = (char *)malloc(dlen + flen + 2))) {
		perror("malloc");
		return -1;
	}

    /* Build the filename we'll read from. */
    sprintf(fullfn, "%s/%s", dir, fn);

    /* Open the configuration file */
    if(!(fp = fopen(fullfn, "r"))) {
        perror("read_config - open");
		fprintf(stderr, "Filename was %s\n", fullfn);
        return -1;
    }

    /* Allocate some space to start. We probably won't need this many entries,
       so we'll trim it later on. */
    if(!(hosts = (host_info_t *)malloc(sizeof(host_info_t) * 256))) {
        perror("read_config - malloc");
        return -1;
    }

    host_count = 256;

    /* Read in the configuration file one line at a time. */
    while(fgets(linebuf, 1024, fp)) {
        /* If the line is too long, bail out. */
        flen = strlen(linebuf);
        ++lineno;

        if(linebuf[flen - 1] != '\n' && flen == 1023) {
            fprintf(stderr, "Line %d too long in configuration!\n", lineno);
            return -1;
        }

        /* Ignore any blank lines or comments. */
        if(linebuf[0] == '\n' || linebuf[0] == '#')
            continue;

        /* Attempt to parse the line... */
        if(sscanf(linebuf, "%1023s %15s", name, ip) != 2)
            continue;

        /* Make sure the IP looks sane. */
        if(inet_pton(AF_INET, ip, &addr) != 1) {
            perror("read_config - inet_pton");
            return -1;
        }

        /* Make sure we have enough space in the hosts array. */
        if(entries == host_count) {
            tmp = realloc(hosts, host_count * sizeof(host_info_t) * 2);
            if(!tmp) {
                perror("read_config - realloc");
                return -1;
            }

            host_count *= 2;
            hosts = (host_info_t *)tmp;
        }

        /* Make space to store the hostname. */
        hosts[entries].name = (char *)malloc(strlen(name) + 1);
        if(!hosts[entries].name) {
            perror("read_config - malloc 2");
            return -1;
        }

        /* Fill in the entry and move on to the next one (if any). */
        strcpy(hosts[entries].name, name);
        hosts[entries].addr = addr;

        ++entries;
    }

    /* We're done with the file, so close it. */
    fclose(fp);

    /* Trim the hosts array down to the size that it needs to be. */
    tmp = realloc(hosts, entries * sizeof(host_info_t));
    if(tmp)
        hosts = (host_info_t *)tmp;

    host_count = entries;

	free(fullfn);

    return 0;
}

static SOCKET open_sock(uint16_t port) {
    SOCKET sock;
    struct sockaddr_in addr;

    /* Create the socket. */
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if(sock == INVALID_SOCKET) {
        perror("socket");
        return INVALID_SOCKET;
    }

    /* Bind the socket to the specified port. */
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
        perror("bind");
        close(sock);
        return INVALID_SOCKET;
    }

    return sock;
}

static host_info_t *find_host(const char *hostname) {
    int i;

    /* Linear search through the list for the one we're looking for. */
    for(i = 0; i < host_count; ++i) {
        if(!cmp_str(hosts[i].name, hostname))
            return hosts + i;
    }

    return NULL;
}

static void respond_to_query(SOCKET sock, size_t len, struct sockaddr_in *addr,
                             host_info_t *h) {
    in_addr_t a;

    /* DNS specifies that any UDP messages over 512 bytes are truncated. We
       don't bother sending them at all, since we should never approach that
       size to start with. */
    if(len + 16 > 512)
        return;

    /* Copy the input to the output to start. */
    memcpy(outmsg, inmsg, len);

    /* Set the answer count to 1, and set the flags appropriately. */
    outmsg->ancount = htons(1);
    outmsg->flags = htons(0x8180);

    /* Subtract out the size of the header. */
    len -= sizeof(dnsmsg_t);

    /* Fill in the response. This is ugly, but it works. */
    a = ntohl(h->addr);
    outmsg->data[len++] = 0xc0;
    outmsg->data[len++] = 0x0c;
    outmsg->data[len++] = 0x00;
    outmsg->data[len++] = 0x01;
    outmsg->data[len++] = 0x00;
    outmsg->data[len++] = 0x01;
    outmsg->data[len++] = 0x00; /* Next 4 bytes are the TTL. */
    outmsg->data[len++] = 0x00;
    outmsg->data[len++] = 0x09;
    outmsg->data[len++] = 0xfc;
    outmsg->data[len++] = 0x00; /* Address length is the next 2. */
    outmsg->data[len++] = 0x04;
    outmsg->data[len++] = (uint8_t)(a >> 24);
    outmsg->data[len++] = (uint8_t)(a >> 16);
    outmsg->data[len++] = (uint8_t)(a >> 8);
    outmsg->data[len++] = (uint8_t)a;

    /* Send ther response. */
    sendto(sock, outbuf, len + sizeof(dnsmsg_t), 0, (struct sockaddr *)addr,
           sizeof(struct sockaddr_in));
}

static void process_query(SOCKET sock, size_t len, struct sockaddr_in *addr) {
    size_t i;
    uint8_t partlen = 0;
    static char hostbuf[1024];
    size_t hostlen = 0;
    host_info_t *host;
    uint16_t qdc, anc, nsc, arc;
    size_t olen = len;

    /* Subtract out the size of the header. */
    len -= sizeof(dnsmsg_t);

    /* Switch the byte ordering as needed on everything. */
    qdc = ntohs(inmsg->qdcount);
    anc = ntohs(inmsg->ancount);
    nsc = ntohs(inmsg->nscount);
    arc = ntohs(inmsg->arcount);

    /* Check the message to make sure it looks like it came from PSO. */
    if(qdc != 1 || anc != 0|| nsc != 0 || arc != 0)
        return;

    /* Figure out the name of the host that the client is looking for. */
    i = 0;
    while(i < len) {
        partlen = inmsg->data[i];

        /* Make sure the length is sane. */
        if(len < i + partlen + 5) {
            /* Throw out the obvious bad packet. */
            printf("Throwing out bad packet.\n");
            return;
        }

        /* Did we read the last part? */
        if(partlen == 0) {
            /* Make sure the rest of the message is as we expect it. */
            if(inmsg->data[i + 1] != 0 || inmsg->data[i + 2] != 1 ||
               inmsg->data[i + 3] != 0 || inmsg->data[i + 4] != 1) {
                printf("Throwing out non IN A request.\n");
            }

            hostbuf[hostlen - 1] = '\0';
            i = len;

            /* See if the requested host is in our list. If it is, respond.*/
            if((host = find_host(hostbuf))) {
                respond_to_query(sock, olen, addr, host);
            }

            /* And we're done. */
            return;
        }

        /* We've got a part to copy into our string... Do so. */
        memcpy(hostbuf + hostlen, inmsg->data + i + 1, partlen);
        hostlen += partlen;
        hostbuf[hostlen++] = '.';
        i += partlen + 1;
    }
}

#if !defined(_WIN32) && !defined(_arch_dreamcast)
static int drop_privs(void) {
    struct passwd *pw;
    uid_t uid;
    gid_t gid;

    /* Make sure we're actually root, otherwise some of this will fail. */
    if(getuid() && geteuid()) {
        return 0;
    }

    /* Look for users. We're looking for the user "nobody". */
    if((pw = getpwnam("nobody"))) {
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }
    else {
        fprintf(stderr, "Cannot find user \"nobody\". Bailing out!\n");
        return -1;
    }

    /* Set privileges. */
    if(setgroups(1, &gid)) {
        perror("setgroups");
        return -1;
    }

    if(setgid(gid)) {
        perror("setgid");
        return -1;
    }

    if(setuid(uid)) {
        perror("setuid");
        return -1;
    }

    /* Make sure the privileges stick. */
    if(!getuid() || !geteuid()) {
        fprintf(stderr, "Cannot set non-root privileges. Bailing out!\n");
        return -1;
    }

    return 0;
}
#endif

#ifdef _arch_dreamcast
#include <arch/arch.h>

KOS_INIT_FLAGS(INIT_DEFAULT | INIT_NET);
extern uint8 romdisk[];
KOS_INIT_ROMDISK(romdisk);

#endif

int main(int argc, char *argv[]) {
    SOCKET sock;
    struct sockaddr_in addr;
    socklen_t alen;
    ssize_t rlen;

#if defined(_WIN32) && !defined(__CYGWIN__)
	if(init_ws()) {
		exit(EXIT_FAILURE);
	}
#endif

    /* Open the socket. We will probably need root for this on UNIX-like
       systems. */
    if((sock = open_sock(53)) == INVALID_SOCKET) {
        exit(EXIT_FAILURE);
    }

#if !defined(_WIN32) && !defined(_arch_dreamcast)
    if(drop_privs()) {
        exit(EXIT_FAILURE);
    }

    /* Daemonize. */
    daemon(1, 0);
#endif

    /* Read in the configuration. */
    if(read_config(CONFIG_DIR, CONFIG_FILE)) {
        exit(EXIT_FAILURE);
    }

    /* Go ahead and loop forever... */
    for(;;) {
        alen = sizeof(addr);

        /* Grab the next request from the socket. */
        if((rlen = recvfrom(sock, inbuf, 1024, 0, (struct sockaddr *)&addr,
                            &alen)) > sizeof(dnsmsg_t)) {
            process_query(sock, rlen, &addr);
        }
    }

    /* We'll never actually get here... */
#ifndef _WIN32
    close(sock);
#else
    closesocket(sock);
	WSACleanup();
#endif

    return 0;
}
