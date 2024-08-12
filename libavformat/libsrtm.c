/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file
 * Haivision Open SRT (Secure Reliable Transport) protocol live multi-client listener output
 */

#include <srt/srt.h>
#include <limits.h>
#include <glib.h>

#include "libavutil/opt.h"
#include "libavutil/parseutils.h"
#include "libavutil/time.h"
#include "libavutil/thread.h"
#include "libavutil/avassert.h"
#include "libavutil/intreadwrite.h"

#include "avformat.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"

/* This is for MPEG-TS and it's a default SRTO_PAYLOADSIZE for SRTT_LIVE (8 TS packets) */
#ifndef SRT_LIVE_DEFAULT_PAYLOAD_SIZE
#define SRT_LIVE_DEFAULT_PAYLOAD_SIZE 1316
#endif

/* This is the maximum payload size for Live mode, should you have a different payload type than MPEG-TS */
#ifndef SRT_LIVE_MAX_PAYLOAD_SIZE
#define SRT_LIVE_MAX_PAYLOAD_SIZE 1456
#endif

#define SRT_BUCKET_VOLUME SRT_LIVE_MAX_PAYLOAD_SIZE+2

#define SRT_QUEUE_LENGTH 512

#define SRTM_MAX_THREADS 31

#define CMD_START         "START"
#define CMD_STOP          "STOP"
#define CMD_CONNECTED     "CONN"
#define CMD_DISCONNECTED  "DISC"

static void g_nonfree(gpointer m) {
    if ((gpointer)CMD_START != m && (gpointer)CMD_STOP != m && (gpointer)CMD_CONNECTED != m && (gpointer)CMD_DISCONNECTED != m) {
        g_free(m);
    }
}

enum SRTLogLevel {
    SRT_LL_INVALID = -1,
    SRT_LL_DEBUG = LOG_DEBUG,
    SRT_LL_NOTICE = LOG_NOTICE,
    SRT_LL_WARNING = LOG_WARNING,
    SRT_LL_ERR = LOG_ERR,
    SRT_LL_CRIT = LOG_CRIT
};

typedef struct SRTWriter {
  unsigned int idx;
  URLContext * ctx;
  SRTSOCKET fd;
  GAsyncQueue * q;
  GAsyncQueue * pool;
  GThread * thread;
} SRTWriter;

typedef struct SRTContext {
    const AVClass *class;
    int fd;
    int eid;
    int64_t rw_timeout;
    GMainLoop * loop;
    pthread_t thread_loop;
    GAsyncQueue * q;
    GAsyncQueue * pool;
    GThread * thread_listener;
    GThread * thread_buf;
    volatile int evac;
    unsigned int threads;
    int thread_queue;
    SRTWriter * writers;
    int64_t listen_timeout;
    int send_buffer_size;

    int64_t maxbw;
    int pbkeylen;
    char *passphrase;
    char *passphrase_file;
#if SRT_VERSION_VALUE >= 0x010302
    int enforced_encryption;
    int kmrefreshrate;
    int kmpreannounce;
    int64_t snddropdelay;
#endif
    int mss;
    int ffs;
    int ipttl;
    int iptos;
    int oheadbw;
    int64_t latency;
    int tlpktdrop;
    int nakreport;
    int64_t connect_timeout;
    int payload_size;
    int64_t rcvlatency;
    int64_t peerlatency;
    int sndbuf;
    int lossmaxttl;
    int minversion;
    char *streamid;
    char *smoother;
    int messageapi;
    int linger;
    int tsbpd;
    char *packetfilter;
    enum SRTLogLevel loglevel;
    int drifttracer;
} SRTContext;

#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
#define OFFSET(x) offsetof(SRTContext, x)
static const AVOption libsrtm_options[] = {
    { "timeout",        "Timeout of socket I/O operations (in microseconds)",                   OFFSET(rw_timeout),       AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "listen_timeout", "Connection awaiting timeout (in microseconds)" ,                       OFFSET(listen_timeout),   AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                                 OFFSET(send_buffer_size), AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "pkt_size",       "Maximum SRT packet size",                                              OFFSET(payload_size),     AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, SRT_LIVE_MAX_PAYLOAD_SIZE, .flags = D|E, "payload_size" },
    { "payload_size",   "Maximum SRT packet size",                                              OFFSET(payload_size),     AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, SRT_LIVE_MAX_PAYLOAD_SIZE, .flags = D|E, "payload_size" },
    { "ts_size",        NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRT_LIVE_DEFAULT_PAYLOAD_SIZE }, INT_MIN, INT_MAX, .flags = D|E, "payload_size" },
    { "max_size",       NULL, 0, AV_OPT_TYPE_CONST,  { .i64 = SRT_LIVE_MAX_PAYLOAD_SIZE },     INT_MIN, INT_MAX, .flags = D|E, "payload_size" },
    { "maxbw",          "Maximum bandwidth (bytes per second) that the connection can use",     OFFSET(maxbw),            AV_OPT_TYPE_INT64,    { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "pbkeylen",       "Crypto key len in bytes {16,24,32} Default: 16 (128-bit)",             OFFSET(pbkeylen),         AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 32,        .flags = D|E },
    { "passphrase_file","File with Crypto PBKDF2 Passphrase size[0,10..64] 0:disable crypto",   OFFSET(passphrase_file),  AV_OPT_TYPE_STRING,   { .str = NULL },              .flags = D|E },
#if SRT_VERSION_VALUE >= 0x010302
    { "enforced_encryption", "Enforces that both connection parties have the same passphrase set",                              OFFSET(enforced_encryption), AV_OPT_TYPE_BOOL,  { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "kmrefreshrate",       "The number of packets to be transmitted after which the encryption key is switched to a new key", OFFSET(kmrefreshrate),       AV_OPT_TYPE_INT,   { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "kmpreannounce",       "The interval between when a new encryption key is sent and when switchover occurs",               OFFSET(kmpreannounce),       AV_OPT_TYPE_INT,   { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "snddropdelay",        "The sender's extra delay(in microseconds) before dropping packets",                                     OFFSET(snddropdelay),        AV_OPT_TYPE_INT64,   { .i64 = -2 }, -2, INT64_MAX,   .flags = D|E },
#endif
    { "mss",            "The Maximum Segment Size",                                             OFFSET(mss),              AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 1500,      .flags = D|E },
    { "ffs",            "Flight flag size (window size) (in bytes)",                            OFFSET(ffs),              AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "ipttl",          "IP Time To Live",                                                      OFFSET(ipttl),            AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 255,       .flags = D|E },
    { "iptos",          "IP Type of Service",                                                   OFFSET(iptos),            AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 255,       .flags = D|E },
    { "oheadbw",        "MaxBW ceiling based on % over input stream rate",                      OFFSET(oheadbw),          AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, 100,       .flags = D|E },
    { "latency",        "receiver delay (in microseconds) to absorb bursts of missed packet retransmissions",                     OFFSET(latency),          AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "tsbpddelay",     "deprecated, same effect as latency option",                            OFFSET(latency),          AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "rcvlatency",     "receive latency (in microseconds)",                                    OFFSET(rcvlatency),       AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "peerlatency",    "peer latency (in microseconds)",                                       OFFSET(peerlatency),      AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "tlpktdrop",      "Enable too-late pkt drop",                                             OFFSET(tlpktdrop),        AV_OPT_TYPE_BOOL,     { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "nakreport",      "Enable receiver to send periodic NAK reports",                         OFFSET(nakreport),        AV_OPT_TYPE_BOOL,     { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "connect_timeout", "Connect timeout(in milliseconds). Caller default: 3000, rendezvous (x 10)",                            OFFSET(connect_timeout),  AV_OPT_TYPE_INT64, { .i64 = -1 }, -1, INT64_MAX, .flags = D|E },
    { "sndbuf",         "Send buffer size (in bytes)",                                          OFFSET(sndbuf),           AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "lossmaxttl",     "Maximum possible packet reorder tolerance",                            OFFSET(lossmaxttl),       AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "minversion",     "The minimum SRT version that is required from the peer",               OFFSET(minversion),       AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "streamid",       "A string of up to 512 characters that an Initiator can pass to a Responder",  OFFSET(streamid),  AV_OPT_TYPE_STRING,   { .str = NULL },              .flags = D|E },
    { "srt_streamid",   "A string of up to 512 characters that an Initiator can pass to a Responder",  OFFSET(streamid),  AV_OPT_TYPE_STRING,   { .str = NULL },              .flags = D|E },
    { "smoother",       "The type of Smoother used for the transmission for that socket",       OFFSET(smoother),         AV_OPT_TYPE_STRING,   { .str = NULL },              .flags = D|E },
    { "messageapi",     "Enable message API",                                                   OFFSET(messageapi),       AV_OPT_TYPE_BOOL,     { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "linger",         "Number of seconds that the socket waits for unsent data when closing", OFFSET(linger),           AV_OPT_TYPE_INT,      { .i64 = -1 }, -1, INT_MAX,   .flags = D|E },
    { "tsbpd",          "Timestamp-based packet delivery",                                      OFFSET(tsbpd),            AV_OPT_TYPE_BOOL,     { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "packetfilter",   "SRT packet filter",                                                    OFFSET(packetfilter),     AV_OPT_TYPE_STRING,   { .str = NULL },              .flags = D|E },
    { "loglevel",       "libsrt logging level",                                                 OFFSET(loglevel),         AV_OPT_TYPE_INT,      { .i64 = SRT_LL_INVALID }, -1, INT_MAX, .flags = D|E, "loglevel" },
    { "drifttracer",    "Enables or disables time drift tracer (receiver)",                     OFFSET(drifttracer),      AV_OPT_TYPE_BOOL,     { .i64 = -1 }, -1, 1,         .flags = D|E },
    { "threads",        "Number of writing threads",                                            OFFSET(threads),          AV_OPT_TYPE_INT,      { .i64 = 4 }, 1, SRTM_MAX_THREADS, .flags = D|E },
    { "thread_queue",   "Writing thread queue length, SRT packets number.",                     OFFSET(thread_queue),     AV_OPT_TYPE_INT,      { .i64 = SRT_QUEUE_LENGTH }, -1, INT_MAX, .flags = D|E },
    { NULL }
};

static int libsrt_neterrno(URLContext *h)
{
    int os_errno;
    int err = srt_getlasterror(&os_errno);
    if (err == SRT_EASYNCRCV || err == SRT_EASYNCSND)
        return AVERROR(EAGAIN);
    av_log(h, AV_LOG_ERROR, "%s\n", srt_getlasterror_str());
    return os_errno ? AVERROR(os_errno) : AVERROR_UNKNOWN;
}

static int libsrt_getsockopt(URLContext *h, int fd, SRT_SOCKOPT optname, const char * optnamestr, void * optval, int * optlen)
{
    if (srt_getsockopt(fd, 0, optname, optval, optlen) < 0) {
        av_log(h, AV_LOG_ERROR, "failed to get option %s on socket: %s\n", optnamestr, srt_getlasterror_str());
        return AVERROR(EIO);
    }
    return 0;
}

static int libsrt_socket_nonblock(int socket, int enable)
{
    int ret, blocking = enable ? 0 : 1;
    /* Setting SRTO_{SND,RCV}SYN options to 1 enable blocking mode, setting them to 0 enable non-blocking mode. */
    ret = srt_setsockopt(socket, 0, SRTO_SNDSYN, &blocking, sizeof(blocking));
    if (ret < 0)
        return ret;
    return srt_setsockopt(socket, 0, SRTO_RCVSYN, &blocking, sizeof(blocking));
}

static int libsrt_epoll_create(URLContext *h, int fd)
{
    int modes = SRT_EPOLL_ACCEPT;
    int eid = srt_epoll_create();
    if (eid < 0)
        return libsrt_neterrno(h);
    if (srt_epoll_add_usock(eid, fd, &modes) < 0) {
        srt_epoll_release(eid);
        return libsrt_neterrno(h);
    }
    return eid;
}

static int libsrt_setsockopt(URLContext *h, int fd, SRT_SOCKOPT optname, const char * optnamestr, const void * optval, int optlen)
{
    if (srt_setsockopt(fd, 0, optname, optval, optlen) < 0) {
        av_log(h, AV_LOG_ERROR, "failed to set option %s on socket: %s\n", optnamestr, srt_getlasterror_str());
        return AVERROR(EIO);
    }
    return 0;
}

/* - The "POST" options can be altered any time on a connected socket.
     They MAY have also some meaning when set prior to connecting; such
     option is SRTO_RCVSYN, which makes connect/accept call asynchronous.
     Because of that this option is treated special way in this app. */
static int libsrt_set_options_post(URLContext *h, int fd)
{
    SRTContext *s = h->priv_data;

    if (s->oheadbw >= 0 && libsrt_setsockopt(h, fd, SRTO_OHEADBW, "SRTO_OHEADBW", &s->oheadbw, sizeof(s->oheadbw)) < 0) {
        return AVERROR(EIO);
    }
    return 0;
}

/* - The "PRE" options must be set prior to connecting and can't be altered
     on a connected socket, however if set on a listening socket, they are
     derived by accept-ed socket. */
static int libsrt_set_options_pre(URLContext *h, int fd)
{
    SRTContext *s = h->priv_data;
    int yes = 1;
    int latency = s->latency / 1000;
    int rcvlatency = s->rcvlatency / 1000;
    int peerlatency = s->peerlatency / 1000;
#if SRT_VERSION_VALUE >= 0x010302
    int snddropdelay = s->snddropdelay > 0 ? s->snddropdelay / 1000 : s->snddropdelay;
#endif
    int connect_timeout = s->connect_timeout;
    SRT_TRANSTYPE transtype = SRTT_LIVE;

    if ((libsrt_setsockopt(h, fd, SRTO_TRANSTYPE, "SRTO_TRANSTYPE", &transtype, sizeof(transtype)) < 0) ||
        (s->maxbw >= 0 && libsrt_setsockopt(h, fd, SRTO_MAXBW, "SRTO_MAXBW", &s->maxbw, sizeof(s->maxbw)) < 0) ||
        (s->pbkeylen >= 0 && libsrt_setsockopt(h, fd, SRTO_PBKEYLEN, "SRTO_PBKEYLEN", &s->pbkeylen, sizeof(s->pbkeylen)) < 0) ||
        (s->passphrase && libsrt_setsockopt(h, fd, SRTO_PASSPHRASE, "SRTO_PASSPHRASE", s->passphrase, strlen(s->passphrase)) < 0) ||
        (s->packetfilter && libsrt_setsockopt(h, fd, SRTO_PACKETFILTER, "SRTO_PACKETFILTER", s->packetfilter, strlen(s->packetfilter)) < 0) ||
        (s->drifttracer >= 0 && libsrt_setsockopt(h, fd, SRTO_DRIFTTRACER, "SRTO_DRIFTTRACER", &s->drifttracer, sizeof(s->drifttracer)) < 0) ||
#if SRT_VERSION_VALUE >= 0x010302
#if SRT_VERSION_VALUE >= 0x010401
        (s->enforced_encryption >= 0 && libsrt_setsockopt(h, fd, SRTO_ENFORCEDENCRYPTION, "SRTO_ENFORCEDENCRYPTION", &s->enforced_encryption, sizeof(s->enforced_encryption)) < 0) ||
#else
        /* SRTO_STRICTENC == SRTO_ENFORCEDENCRYPTION (53), but for compatibility, we used SRTO_STRICTENC */
        (s->enforced_encryption >= 0 && libsrt_setsockopt(h, fd, SRTO_STRICTENC, "SRTO_STRICTENC", &s->enforced_encryption, sizeof(s->enforced_encryption)) < 0) ||
#endif
        (s->kmrefreshrate >= 0 && libsrt_setsockopt(h, fd, SRTO_KMREFRESHRATE, "SRTO_KMREFRESHRATE", &s->kmrefreshrate, sizeof(s->kmrefreshrate)) < 0) ||
        (s->kmpreannounce >= 0 && libsrt_setsockopt(h, fd, SRTO_KMPREANNOUNCE, "SRTO_KMPREANNOUNCE", &s->kmpreannounce, sizeof(s->kmpreannounce)) < 0) ||
        (s->snddropdelay  >=-1 && libsrt_setsockopt(h, fd, SRTO_SNDDROPDELAY,  "SRTO_SNDDROPDELAY",  &snddropdelay, sizeof(snddropdelay)) < 0) ||
#endif
        (s->mss >= 0 && libsrt_setsockopt(h, fd, SRTO_MSS, "SRTO_MSS", &s->mss, sizeof(s->mss)) < 0) ||
        (s->ffs >= 0 && libsrt_setsockopt(h, fd, SRTO_FC, "SRTO_FC", &s->ffs, sizeof(s->ffs)) < 0) ||
        (s->ipttl >= 0 && libsrt_setsockopt(h, fd, SRTO_IPTTL, "SRTO_IPTTL", &s->ipttl, sizeof(s->ipttl)) < 0) ||
        (s->iptos >= 0 && libsrt_setsockopt(h, fd, SRTO_IPTOS, "SRTO_IPTOS", &s->iptos, sizeof(s->iptos)) < 0) ||
        (s->latency >= 0 && libsrt_setsockopt(h, fd, SRTO_LATENCY, "SRTO_LATENCY", &latency, sizeof(latency)) < 0) ||
        (s->rcvlatency >= 0 && libsrt_setsockopt(h, fd, SRTO_RCVLATENCY, "SRTO_RCVLATENCY", &rcvlatency, sizeof(rcvlatency)) < 0) ||
        (s->peerlatency >= 0 && libsrt_setsockopt(h, fd, SRTO_PEERLATENCY, "SRTO_PEERLATENCY", &peerlatency, sizeof(peerlatency)) < 0) ||
        (s->tlpktdrop >= 0 && libsrt_setsockopt(h, fd, SRTO_TLPKTDROP, "SRTO_TLPKTDROP", &s->tlpktdrop, sizeof(s->tlpktdrop)) < 0) ||
        (s->nakreport >= 0 && libsrt_setsockopt(h, fd, SRTO_NAKREPORT, "SRTO_NAKREPORT", &s->nakreport, sizeof(s->nakreport)) < 0) ||
        (connect_timeout >= 0 && libsrt_setsockopt(h, fd, SRTO_CONNTIMEO, "SRTO_CONNTIMEO", &connect_timeout, sizeof(connect_timeout)) <0 ) ||
        (s->sndbuf >= 0 && libsrt_setsockopt(h, fd, SRTO_SNDBUF, "SRTO_SNDBUF", &s->sndbuf, sizeof(s->sndbuf)) < 0) ||
        (s->lossmaxttl >= 0 && libsrt_setsockopt(h, fd, SRTO_LOSSMAXTTL, "SRTO_LOSSMAXTTL", &s->lossmaxttl, sizeof(s->lossmaxttl)) < 0) ||
        (s->minversion >= 0 && libsrt_setsockopt(h, fd, SRTO_MINVERSION, "SRTO_MINVERSION", &s->minversion, sizeof(s->minversion)) < 0) ||
        (s->streamid && libsrt_setsockopt(h, fd, SRTO_STREAMID, "SRTO_STREAMID", s->streamid, strlen(s->streamid)) < 0) ||
#if SRT_VERSION_VALUE >= 0x010401
        (s->smoother && libsrt_setsockopt(h, fd, SRTO_CONGESTION, "SRTO_CONGESTION", s->smoother, strlen(s->smoother)) < 0) ||
#else
        (s->smoother && libsrt_setsockopt(h, fd, SRTO_SMOOTHER, "SRTO_SMOOTHER", s->smoother, strlen(s->smoother)) < 0) ||
#endif
        (s->messageapi >= 0 && libsrt_setsockopt(h, fd, SRTO_MESSAGEAPI, "SRTO_MESSAGEAPI", &s->messageapi, sizeof(s->messageapi)) < 0) ||
        (s->payload_size >= 0 && libsrt_setsockopt(h, fd, SRTO_PAYLOADSIZE, "SRTO_PAYLOADSIZE", &s->payload_size, sizeof(s->payload_size)) < 0) ||
        ((h->flags & AVIO_FLAG_WRITE) && libsrt_setsockopt(h, fd, SRTO_SENDER, "SRTO_SENDER", &yes, sizeof(yes)) < 0) ||
        (s->tsbpd >= 0 && libsrt_setsockopt(h, fd, SRTO_TSBPDMODE, "SRTO_TSBPDMODE", &s->tsbpd, sizeof(s->tsbpd)) < 0)) {
        return AVERROR(EIO);
    }

    if (s->linger >= 0) {
        struct linger lin;
        lin.l_linger = s->linger;
        lin.l_onoff  = lin.l_linger > 0 ? 1 : 0;
        if (libsrt_setsockopt(h, fd, SRTO_LINGER, "SRTO_LINGER", &lin, sizeof(lin)) < 0)
            return AVERROR(EIO);
    }
    return 0;
}

/**
 * @brief Create a listening socket and its epoll.
 * 
 * @param h URLContext pointer
 * @param uri URI
 * @return int 0 on success.
 */
static int libsrt_create_listen(URLContext *h, const char * uri) {
    struct addrinfo hints = { 0 }, *ai, *cur_ai;
    int port, fd;
    SRTContext *s = h->priv_data;
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
    /* int64_t open_timeout = 0; */
    /* int eid, write_eid; */
    int reuse = 1;

    av_log(h, AV_LOG_WARNING, "%s() \'%s\' start.\n", __FUNCTION__, uri);

    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    if (strcmp(proto, "srtm"))
        return AVERROR(EINVAL);
    if (port <= 0 || port >= 65536) {
        av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
        return AVERROR(EINVAL);
    }
    p = strchr(uri, '?');
    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "timeout", p)) {
            s->rw_timeout = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtoll(buf, NULL, 10);
        }
    }
    /*
    if (s->rw_timeout >= 0) {
        open_timeout = h->rw_timeout = s->rw_timeout;
    }
    */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    hints.ai_flags |= AI_PASSIVE;
    ret = getaddrinfo(hostname[0] ? hostname : NULL, portstr, &hints, &ai);
    if (ret) {
        av_log(h, AV_LOG_ERROR,
               "Failed to resolve hostname %s: %s\n",
               hostname, gai_strerror(ret));
        return AVERROR(EIO);
    }

    cur_ai = ai;

 restart:

#if SRT_VERSION_VALUE >= 0x010401
    fd = srt_create_socket();
#else
    fd = srt_socket(cur_ai->ai_family, cur_ai->ai_socktype, 0);
#endif
    if (fd < 0) {
        ret = libsrt_neterrno(h);
        goto fail;
    }

    if ((ret = libsrt_set_options_pre(h, fd)) < 0) {
        goto fail;
    }

    {
        int packet_size = 0;
        int optlen = sizeof(packet_size);
        if (0 > libsrt_getsockopt(h, fd, SRTO_PAYLOADSIZE, "SRTO_PAYLOADSIZE", &packet_size, &optlen)) {
            goto fail;
        }
        if (packet_size > 0) {
            h->max_packet_size = packet_size;
        }
    }

    if (s->send_buffer_size > 0) {
        srt_setsockopt(fd, SOL_SOCKET, SRTO_UDP_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }
    if (libsrt_socket_nonblock(fd, 1) < 0)
        av_log(h, AV_LOG_WARNING, "libsrt_socket_nonblock failed\n");

    ret = libsrt_epoll_create(h, fd);
    if (ret < 0)
        goto fail1;

    s->fd = fd;
    s->eid = ret;

    if (srt_setsockopt(fd, SOL_SOCKET, SRTO_REUSEADDR, &reuse, sizeof(reuse))) {
        av_log(h, AV_LOG_WARNING, "setsockopt(SRTO_REUSEADDR) failed\n");
    }
    if (srt_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen))
        return libsrt_neterrno(h);

    if (srt_listen(fd, s->threads))
        return libsrt_neterrno(h);

    freeaddrinfo(ai);

    av_log(h, AV_LOG_WARNING, "%s() end.\n", __FUNCTION__);

    return 0;

 fail:
    if (cur_ai->ai_next) {
        cur_ai = cur_ai->ai_next;
        if (fd >= 0)
            srt_close(fd);
        ret = 0;
        goto restart;
    }
 fail1:
    if (fd >= 0)
        srt_close(fd);
    freeaddrinfo(ai);

    av_log(h, AV_LOG_WARNING, "%s() end.\n", __FUNCTION__);

    return ret;
}

/**
 * @brief Listen for a new connection if active threads count is below all the threads number.
 * Signals a free threads about new connections. Receives signals from newly free threads.
 *
 * @param data URLContext pointer
 * @return NULL
 */
static void * libsrt_thread_listener(void * data)
{
    URLContext * h = data;
    SRTContext * s = h->priv_data;
    int ret;
    int readfds_len = s->threads+1;
    SRTSOCKET * readfds = malloc(sizeof(SRTSOCKET) * (readfds_len+1));
    unsigned int threads_cnt = 0;

    av_log(h, AV_LOG_WARNING, "%s() start.\n", __FUNCTION__);

    // Don't wait for a signal for closing.
    while (0 == s->evac) {

        if (ff_check_interrupt(&h->interrupt_callback)) {
            av_log(h, AV_LOG_WARNING, "%s(): stop on an interrupt.\n", __FUNCTION__);
            s->evac = 1;
            continue;
        }

        //Listen to the epoll
        readfds_len = s->threads+1;
        ret = srt_epoll_wait(s->eid, readfds, &readfds_len, NULL, NULL, POLLING_TIME, 0, 0, 0, 0);
        if (0 > ret) {
            if (srt_getlasterror(NULL) != SRT_ETIMEOUT) {
                av_log(h, AV_LOG_ERROR, "%s(): srt_epoll_wait() error!\n", __FUNCTION__);
                libsrt_neterrno(h);
            }
            continue;
        }
        if (0 < readfds_len) {
            //Find all the sockets and ...
            for (int i = 0; i < readfds_len; i++) {
                if (readfds[i] == s->fd) {
                    // ... accept on the main
                    struct sockaddr_in addr;
                    int len = sizeof(addr);

                    char streamid[513];
                    int streamid_len = sizeof(streamid);
                    ret = srt_accept(s->fd, (struct sockaddr *)&addr, &len);
                    if (ret < 0) {
                        av_log(h, AV_LOG_ERROR, "%s() error on srt_accept()!\n", __FUNCTION__);
                        libsrt_neterrno(h);
                        break;
                    } else {
                        char buf[1024];
                        getnameinfo((struct sockaddr *)&addr, len, buf, 1024, NULL, 0, NI_NUMERICHOST | NI_NUMERICSERV);
                        av_log(h, AV_LOG_WARNING, "%s() accepted \'%s:%d\'.\n", __FUNCTION__, buf, ntohs(addr.sin_port));
                    }
                    if (0 > libsrt_set_options_post(h, ret)) {
                        av_log(h, AV_LOG_WARNING, "libsrt_set_options_post() failed!\n");
                    }
                    if (0 > libsrt_socket_nonblock(ret, 1)) {
                        av_log(h, AV_LOG_WARNING, "libsrt_socket_nonblock() failed!\n");
                    }
                    if (!libsrt_getsockopt(h, ret, SRTO_STREAMID, "SRTO_STREAMID", streamid, &streamid_len))
                        av_log(h, AV_LOG_VERBOSE, "accept streamid [%s], length %d\n", streamid, streamid_len);
                    libsrt_set_options_post(h, ret);

                    if (threads_cnt == s->threads) {
                        //Close an accepted one if there is no space.
                        av_log(h, AV_LOG_WARNING, "%s() close an accepted socket because there is no place for it.\n", __FUNCTION__);
                        srt_close(ret);
                    } else {
                        //Find an empty writer
                        int j = 0;
                        while(j < s->threads) {
                            SRTWriter * one = s->writers+j;
                            int modes = SRT_EPOLL_ERR | SRT_EPOLL_OUT;
                            j++;
                            if (-1 != one->fd) {
                                continue;
                            }
                            //Fill an empty writer
                            av_log(h, AV_LOG_WARNING, "%s() writer %d shell accept the new connection.\n", __FUNCTION__, one->idx);
                            srt_epoll_update_usock(s->eid, ret, &modes);
                            one->fd = ret;
                            threads_cnt += 1;
                            g_async_queue_push_front(one->q, (gpointer)CMD_CONNECTED);
                            break;
                        }
                        av_assert0(j <= s->threads);
                    }
                    continue;
                } else {
                    // ... close accepted
                    for (int j = 0; j < s->threads; j++) {
                        SRTWriter * one = s->writers+j;
                        if (readfds[i] == one->fd) {
                            av_log(h, AV_LOG_ERROR, "%s(): writer %d shell disconnect on its socket error event!\n", __FUNCTION__, one->idx);
                            srt_epoll_remove_usock(s->eid, one->fd);
                            srt_close(one->fd);
                            one->fd = -1;
                            threads_cnt -= 1;
                            g_async_queue_push_front(one->q, (gpointer)CMD_DISCONNECTED);
                        }
                    }
                }
            }
        }
    }

    srt_epoll_release(s->eid);
    srt_close(s->fd);

    av_log(h, AV_LOG_WARNING, "%s() end.\n", __FUNCTION__);

    return NULL;
}

/**
 * @brief A thread function just for GLib Main Loop.
 *
 * @param data URLContext pointer
 * @return NULL
 */
static void * libsrt_thread_loop(void * data)
{
    URLContext * h = data;
    SRTContext * s = h->priv_data;
    s->loop = g_main_loop_new(NULL, TRUE);
    g_main_loop_run(s->loop);
    g_main_loop_unref(s->loop);

    return NULL;
}

/**
 * @brief A thread function just for GLib Main Loop.
 *
 * @param data SRTWriter pointer
 * @return NULL
 */
static void * libsrt_thread_writer(void * data)
{
    SRTWriter * me = data;
    URLContext * h = me->ctx;
    gboolean alive = TRUE;
    gboolean conn  = FALSE;
    gchar * bucket = NULL;
    int size       = 0;

    av_log(h, AV_LOG_WARNING, "%s() start writer %d.\n", __FUNCTION__, me->idx);

    while (alive) {
        if (0 == size) {
            bucket = g_async_queue_timeout_pop(me->q, 1000);
            if (NULL == bucket) {
                continue;
            }

            if (0 == memcmp(CMD_STOP, bucket, sizeof CMD_STOP)) {
                av_log(h, AV_LOG_WARNING, "%s() writer %d got \"%s\" command.\n", __FUNCTION__, me->idx, bucket);
                alive = FALSE;
                continue;
            }
            if (0 == memcmp(CMD_CONNECTED, bucket, sizeof CMD_CONNECTED)) {
                av_log(h, AV_LOG_WARNING, "%s() writer %d got \"%s\" command.\n", __FUNCTION__, me->idx, bucket);
                conn = TRUE;
                continue;
            }
            if (0 == memcmp(CMD_DISCONNECTED, bucket, sizeof CMD_DISCONNECTED)) {
                av_log(h, AV_LOG_WARNING, "%s() writer %d got \"%s\" command.\n", __FUNCTION__, me->idx, bucket);
                conn = FALSE;
                continue;
            }

            size = AV_RL16(bucket);
            av_assert0(0 < size);
            av_assert0(SRT_LIVE_DEFAULT_PAYLOAD_SIZE >= size);
        }

        if (!conn) {
            memset(bucket, 0, size+2);
            g_async_queue_push(me->pool, bucket);
            size = 0;
            continue;
        }

        {
            int len = 1;
            SRTSOCKET write[1];
            SRTContext * srt_ctx = (SRTContext *)h->priv_data;
            if (1 > srt_epoll_wait(srt_ctx->eid, NULL, NULL, write, &len, 1, 0, 0, 0, 0))
            {
                continue;
            }
        }
        srt_send(me->fd, bucket+2, size);

        memset(bucket, 0, size+2);
        g_async_queue_push(me->pool, bucket);
        size = 0;
    }

    av_log(h, AV_LOG_WARNING, "%s() end writer %d.\n", __FUNCTION__, me->idx);

    return NULL;
}

/**
 * @brief Waits for incoming packets from libsrt_write() in the main FIFO. Puts them to individual buffers of each writer.
 *
 * @param data URLContext pointer
 * @return NULL
 */
static void * libsrt_thread_buf(void * data)
{
    URLContext * h = data;
    SRTContext * s = h->priv_data;
    int size = 0;
    gboolean alive = TRUE;
    gchar * bucket = NULL;

    av_log(h, AV_LOG_WARNING, "%s() start.\n", __FUNCTION__);

    while (alive) {

        if (0 == size) {
            bucket = g_async_queue_timeout_pop(s->q, 1000);
            if (NULL == bucket) {
                continue;
            }

            //Check if we are going to go out.
            if (0 == memcmp(CMD_STOP, bucket, sizeof CMD_STOP)) {
                for (int k=0; k<s->threads; k++) {
                    g_async_queue_push_front((s->writers+k)->q, (gpointer)CMD_STOP);
                }
                for (int k=0; k<s->threads; k++) {
                    g_thread_join((s->writers+k)->thread);
                }

                alive = FALSE;
                continue;
            }

            size = AV_RL16(bucket);
            av_assert0(0 < size);
            av_assert0(SRT_LIVE_DEFAULT_PAYLOAD_SIZE >= size);
        }

        for (int k=0; k<s->threads; k++) {
            SRTWriter * one = s->writers+k;
            gchar * sink = g_async_queue_try_pop(one->pool);
            if (NULL == sink) {
                av_log(h, AV_LOG_WARNING, "%s() %d writer's pool is empty!\n", __FUNCTION__, one->idx);
                continue;
            }
            memcpy(sink, bucket, size+2);
            g_async_queue_push(one->q, sink);
        }

        memset(bucket, 0, size+2);
        g_async_queue_push(s->pool, bucket);
        size = 0;
    }

    av_log(h, AV_LOG_WARNING, "%s() end.\n", __FUNCTION__);

    return NULL;
}

static int libsrt_open(URLContext *h, const char *uri, int flags)
{
    SRTContext *s = h->priv_data;
    const char * p;
    char buf[1024];
    int ret = 0;

    av_assert0(0 == (AVIO_FLAG_READ & flags));
    av_assert0(0 != (AVIO_FLAG_WRITE & flags));

    av_log(h, AV_LOG_WARNING, "%s() \'%s\' 0x04%X start.\n", __FUNCTION__, uri, flags);

    if (srt_startup() < 0) {
        return AVERROR_UNKNOWN;
    }

    /* SRT options (srt/srt.h) */
    p = strchr(uri, '?');
    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "maxbw", p)) {
            s->maxbw = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "pbkeylen", p)) {
            s->pbkeylen = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "passphrase_file", p)) {
            int fd = -1;
            int l = -1;
            char pass[65];
            av_freep(&s->passphrase_file);
            av_freep(&s->passphrase);
            s->passphrase_file = av_strndup(buf, strlen(buf));
            if (-1 == (fd = open(s->passphrase_file, 0, O_RDONLY)))
            {
                ret = AVERROR(errno);
                goto err;
            }
            if (-1 == (l = read(fd, pass, 64)))
            {
                ret = AVERROR(errno);
                goto err;
            }
            if (0 == l)
            {
                ret = AVERROR(EINVAL);
                goto err;
            }
            pass[l] = 0;
            close(fd);
            s->passphrase = av_strndup(pass, strlen(pass));
        }
        if (av_find_info_tag(buf, sizeof(buf), "packetfilter", p)) {
            av_freep(&s->packetfilter);
            s->packetfilter = av_strndup(buf, strlen(buf));
        }
        if (av_find_info_tag(buf, sizeof(buf), "loglevel", p)) {
            if (!strcmp(buf, "fatal")) {
                s->loglevel = SRT_LL_CRIT;
            } else if (!strcmp(buf, "error")) {
                s->loglevel = SRT_LL_ERR;
            } else if (!strcmp(buf, "warning")) {
                s->loglevel = SRT_LL_WARNING;
            } else if (!strcmp(buf, "note")) {
                s->loglevel = SRT_LL_NOTICE;
            } else if (!strcmp(buf, "debug")) {
                s->loglevel = SRT_LL_DEBUG;
            } else {
                ret = AVERROR(EINVAL);
                goto err;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "threads", p)) {
            s->threads = strtol(buf, NULL, 10);
            if (s->threads > SRTM_MAX_THREADS) {
                ret = AVERROR(EINVAL);
                goto err;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "thread_queue", p)) {
            s->thread_queue = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "drifttracer", p)) {
            s->drifttracer = strtol(buf, NULL, 10);
        }
#if SRT_VERSION_VALUE >= 0x010302
        if (av_find_info_tag(buf, sizeof(buf), "enforced_encryption", p)) {
            s->enforced_encryption = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "kmrefreshrate", p)) {
            s->kmrefreshrate = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "kmpreannounce", p)) {
            s->kmpreannounce = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "snddropdelay", p)) {
            s->snddropdelay = strtoll(buf, NULL, 10);
        }
#endif
        if (av_find_info_tag(buf, sizeof(buf), "mss", p)) {
            s->mss = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "ffs", p)) {
            s->ffs = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "ipttl", p)) {
            s->ipttl = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "iptos", p)) {
            s->iptos = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "oheadbw", p)) {
            s->oheadbw = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "latency", p)) {
            s->latency = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "tsbpddelay", p)) {
            s->latency = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "rcvlatency", p)) {
            s->rcvlatency = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "peerlatency", p)) {
            s->peerlatency = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "tlpktdrop", p)) {
            s->tlpktdrop = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "nakreport", p)) {
            s->nakreport = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "connect_timeout", p)) {
            s->connect_timeout = strtoll(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "payload_size", p) ||
            av_find_info_tag(buf, sizeof(buf), "pkt_size", p)) {
            s->payload_size = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "sndbuf", p)) {
            s->sndbuf = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "lossmaxttl", p)) {
            s->lossmaxttl = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "minversion", p)) {
            s->minversion = strtol(buf, NULL, 0);
        }
        if (av_find_info_tag(buf, sizeof(buf), "streamid", p)) {
            av_freep(&s->streamid);
            s->streamid = av_strdup(buf);
            if (!s->streamid) {
                ret = AVERROR(ENOMEM);
                goto err;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "smoother", p)) {
            av_freep(&s->smoother);
            s->smoother = av_strdup(buf);
            if(!s->smoother) {
                ret = AVERROR(ENOMEM);
                goto err;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "messageapi", p)) {
            s->messageapi = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "linger", p)) {
            s->linger = strtol(buf, NULL, 10);
        }
    }
    if (SRT_LL_INVALID != s->loglevel) {
        srt_setloglevel(s->loglevel);
    }
    pthread_create(&s->thread_loop, NULL, libsrt_thread_loop, h);
    ret = libsrt_create_listen(h, uri);
    if (ret < 0)
      goto err;

    s->writers = malloc(s->threads * sizeof(SRTWriter));
    for (int i=0; i<s->threads; i++) {
        SRTWriter * one = s->writers+i;
        one->ctx = h;
        one->idx = i;
        one->fd = -1;
        one->q    = g_async_queue_new_full(g_nonfree);
        one->pool = g_async_queue_new_full(g_nonfree);
        for (int k=0; k<SRT_QUEUE_LENGTH; k++) {
            gpointer bucket = g_malloc0(SRT_BUCKET_VOLUME);
            g_async_queue_push(one->pool, bucket);
        }
        one->thread = g_thread_new("Writer thread", libsrt_thread_writer, one);
    }

    s->q    = g_async_queue_new_full(g_nonfree);
    s->pool = g_async_queue_new_full(g_nonfree);
    for (int k=0; k<SRT_QUEUE_LENGTH; k++) {
        gpointer bucket = g_malloc0(SRT_BUCKET_VOLUME);
        g_async_queue_push(s->pool, bucket);
    }
    s->thread_buf      = g_thread_new("Main buffer thread", libsrt_thread_buf, h);
    s->thread_listener = g_thread_new("Listener thread", libsrt_thread_listener, h);

    h->is_streamed = 1;

    av_log(h, AV_LOG_WARNING, "%s() end.\n", __FUNCTION__);

    return 0;

err:
    av_freep(&s->smoother);
    av_freep(&s->streamid);
    srt_cleanup();

    av_log(h, AV_LOG_WARNING, "%s() end.\n", __FUNCTION__);

    return ret;
}

static int libsrt_write(URLContext *h, const uint8_t *buf, int size)
{
    SRTContext *s = h->priv_data;
    int ret;
    gpointer bucket;

    av_assert0(0 <= size);
    av_assert0(SRT_LIVE_DEFAULT_PAYLOAD_SIZE >= size);

    bucket = g_async_queue_try_pop(s->pool);
    if (NULL != bucket) {
        AV_WL16(bucket, size);
        memcpy(((gchar *)bucket)+2, buf, size);
        g_async_queue_push(s->q, bucket);
    } else {
        av_log(h, AV_LOG_WARNING, "%s(): Pool is empty!\n", __FUNCTION__);
    }
    ret = size;
    return ret;
}

static int libsrt_close(URLContext *h)
{
    SRTContext *s = h->priv_data;

    av_log(h, AV_LOG_WARNING, "%s() start.\n", __FUNCTION__);

    // Finish buffering.
    s->evac = 1;

    g_async_queue_push_front(s->q, (gpointer)CMD_STOP);
    g_thread_join(s->thread_buf);
    g_async_queue_unref(s->q);
    g_async_queue_unref(s->pool);

    // Finish listening.
    g_thread_join(s->thread_listener);

    srt_epoll_release(s->eid);
    srt_close(s->fd);
    srt_cleanup();

    g_main_loop_quit(s->loop);
    pthread_join(s->thread_loop, NULL);

    av_log(h, AV_LOG_WARNING, "%s() end.\n", __FUNCTION__);

    return 0;
}

static const AVClass libsrtm_class = {
    .class_name = "libsrtm",
    .item_name  = av_default_item_name,
    .option     = libsrtm_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

const URLProtocol ff_libsrtm_protocol = {
    .name                = "srtm",
    .url_open            = libsrt_open,
    .url_write           = libsrt_write,
    .url_close           = libsrt_close,
    .priv_data_size      = sizeof(SRTContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &libsrtm_class,
};
