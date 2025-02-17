/**
 *  Copyright (C) 2011-2012  Juho Vähä-Herttua
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "raop_rtp.h"
#include "raop.h"
#include "raop_buffer.h"
#include "netutils.h"
#include "compat.h"
#include "logger.h"
#include "byteutils.h"
#include "mirror_buffer.h"
#include "stream.h"

#define NO_FLUSH (-42)

struct h264codec_s {
    unsigned char compatibility;
    short lengthofPPS;
    short lengthofSPS;
    unsigned char level;
    unsigned char numberOfPPS;
    unsigned char* picture_parameter_set;
    unsigned char profile_high;
    unsigned char reserved3andSPS;
    unsigned char reserved6andNAL;
    unsigned char* sequence;
    unsigned char version;

};

struct raop_rtp_s {
    logger_t *logger;
    raop_callbacks_t callbacks;

    /* Buffer to handle all resends */
    raop_buffer_t *buffer;

    mirror_buffer_t *mirror;
    /* Remote address as sockaddr */
    struct sockaddr_storage remote_saddr;
    socklen_t remote_saddr_len;

    /* MUTEX LOCKED VARIABLES START */
    /* These variables only edited mutex locked */
    int running;
    int joined;

    float volume;
    int volume_changed;
    unsigned char *metadata;
    int metadata_len;
    unsigned char *coverart;
    int coverart_len;
    char *dacp_id;
    char *active_remote_header;
    unsigned int progress_start;
    unsigned int progress_curr;
    unsigned int progress_end;
    int progress_changed;

    int flush;
    thread_handle_t thread;
    //thread_handle_t thread_time;
    mutex_handle_t run_mutex;
    //mutex_handle_t time_mutex;
    //cond_handle_t time_cond;
    /* MUTEX LOCKED VARIABLES END */

    /* Remote control and timing ports */
    unsigned short control_rport;
    unsigned short timing_rport;

    /* Sockets for control, timing and data */
    int csock, tsock, dsock;

    /* Local control, timing and data ports */
    unsigned short control_lport;
    unsigned short timing_lport;
    unsigned short data_lport;

    /* Initialized after the first control packet */
    struct sockaddr_storage control_saddr;
    socklen_t control_saddr_len;
    unsigned short control_seqnum;

    /* 同步时间:sync_time是1970开始的真实时间,sync_timestamp是sync_time对应的rtp_timestamp */
    uint64_t sync_time;
    unsigned int sync_timestamp;

};

static int
raop_rtp_parse_remote(raop_rtp_t *raop_rtp, const unsigned char *remote, int remotelen)
{
    char current[25];
    int family;
    int ret;
    assert(raop_rtp);
    if (remotelen == 4) {
        family = AF_INET;
    } else if (remotelen == 16) {
        family = AF_INET6;
    } else {
        return -1;
    }
    memset(current, 0, sizeof(current));
    sprintf(current, "%d.%d.%d.%d", remote[0], remote[1], remote[2], remote[3]);
    logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_parse_remote ip = %s", current);
    ret = netutils_parse_address(family, current,
                                 &raop_rtp->remote_saddr,
                                 sizeof(raop_rtp->remote_saddr));
    if (ret < 0) {
        return -1;
    }
    raop_rtp->remote_saddr_len = ret;
    return 0;
}

raop_rtp_t *
raop_rtp_init(logger_t *logger, raop_callbacks_t *callbacks, const unsigned char *remote, int remotelen,
               const unsigned char *aeskey, const unsigned char *aesiv, const unsigned char *ecdh_secret, unsigned short timing_rport)
{
    raop_rtp_t *raop_rtp;

    assert(logger);
    assert(callbacks);

    raop_rtp = calloc(1, sizeof(raop_rtp_t));
    if (!raop_rtp) {
        return NULL;
    }
    raop_rtp->logger = logger;
    raop_rtp->timing_rport = timing_rport;

    memcpy(&raop_rtp->callbacks, callbacks, sizeof(raop_callbacks_t));
    raop_rtp->buffer = raop_buffer_init(logger, aeskey, aesiv, ecdh_secret);
    if (!raop_rtp->buffer) {
        free(raop_rtp);
        return NULL;
    }
    if (raop_rtp_parse_remote(raop_rtp, remote, remotelen) < 0) {
		free(raop_rtp);
		return NULL;
	}

    raop_rtp->running = 0;
    raop_rtp->joined = 1;
    raop_rtp->flush = NO_FLUSH;

    MUTEX_CREATE(raop_rtp->run_mutex);
    //MUTEX_CREATE(raop_rtp->time_mutex);
    //COND_CREATE(raop_rtp->time_cond);
    return raop_rtp;
}


void
raop_rtp_destroy(raop_rtp_t *raop_rtp)
{
    if (raop_rtp) {
        raop_rtp_stop(raop_rtp);
        MUTEX_DESTROY(raop_rtp->run_mutex);
        //MUTEX_DESTROY(raop_rtp->time_mutex);
        //COND_DESTROY(raop_rtp->time_cond);
        raop_buffer_destroy(raop_rtp->buffer);
        free(raop_rtp->metadata);
        free(raop_rtp->coverart);
        free(raop_rtp->dacp_id);
        free(raop_rtp->active_remote_header);
        free(raop_rtp);
    }
}

static int
raop_rtp_resend_callback(void *opaque, unsigned short seqnum, unsigned short count)
{
    raop_rtp_t *raop_rtp = opaque;
    unsigned char packet[8];
    unsigned short ourseqnum;
    struct sockaddr *addr;
    socklen_t addrlen;
    int ret;

    addr = (struct sockaddr *)&raop_rtp->control_saddr;
    addrlen = raop_rtp->control_saddr_len;

    logger_log(raop_rtp->logger, LOGGER_DEBUG, "Got resend request %d %d", seqnum, count);
    ourseqnum = raop_rtp->control_seqnum++;

    /* Fill the request buffer */
    packet[0] = 0x80;
    packet[1] = 0x55|0x80;
    packet[2] = (ourseqnum >> 8);
    packet[3] =  ourseqnum;
    packet[4] = (seqnum >> 8);
    packet[5] =  seqnum;
    packet[6] = (count >> 8);
    packet[7] =  count;

    ret = sendto(raop_rtp->csock, (const char *)packet, sizeof(packet), 0, addr, addrlen);
    if (ret == -1) {
        logger_log(raop_rtp->logger, LOGGER_WARNING, "Resend failed: %d", SOCKET_GET_ERROR());
    }

    return 0;
}

static int
raop_rtp_init_sockets(raop_rtp_t *raop_rtp, int use_ipv6, int use_udp)
{
    int csock = -1, tsock = -1, dsock = -1;
    unsigned short cport = 0, tport = 0, dport = 0;

    assert(raop_rtp);

    csock = netutils_init_socket(&cport, use_ipv6, 1);
    tsock = netutils_init_socket(&tport, use_ipv6, 1);
    dsock = netutils_init_socket(&dport, use_ipv6, 1);

    if (csock == -1 || tsock == -1 || dsock == -1) {
        goto sockets_cleanup;
    }

    /* Set socket descriptors */
    raop_rtp->csock = csock;
    raop_rtp->tsock = tsock;
    raop_rtp->dsock = dsock;

    /* Set port values */
    raop_rtp->control_lport = cport;
    raop_rtp->timing_lport = tport;
    raop_rtp->data_lport = dport;
    return 0;

    sockets_cleanup:
    if (csock != -1) closesocket(csock);
    if (tsock != -1) closesocket(tsock);
    if (dsock != -1) closesocket(dsock);
    return -1;
}

static int
raop_rtp_process_events(raop_rtp_t *raop_rtp, void *cb_data)
{
    int flush;
    float volume;
    int volume_changed;
    unsigned char *metadata;
    int metadata_len;
    unsigned char *coverart;
    int coverart_len;
    char *dacp_id;
    char *active_remote_header;
    unsigned int progress_start;
    unsigned int progress_curr;
    unsigned int progress_end;
    int progress_changed;

    assert(raop_rtp);

    MUTEX_LOCK(raop_rtp->run_mutex);
    if (!raop_rtp->running) {
        MUTEX_UNLOCK(raop_rtp->run_mutex);
        return 1;
    }

    /* Read the volume level */
    volume = raop_rtp->volume;
    volume_changed = raop_rtp->volume_changed;
    raop_rtp->volume_changed = 0;

    /* Read the flush value */
    flush = raop_rtp->flush;
    raop_rtp->flush = NO_FLUSH;

    /* Read the metadata */
    metadata = raop_rtp->metadata;
    metadata_len = raop_rtp->metadata_len;
    raop_rtp->metadata = NULL;
    raop_rtp->metadata_len = 0;

    /* Read the coverart */
    coverart = raop_rtp->coverart;
    coverart_len = raop_rtp->coverart_len;
    raop_rtp->coverart = NULL;
    raop_rtp->coverart_len = 0;

    /* Read DACP remote control data */
    dacp_id = raop_rtp->dacp_id;
    active_remote_header = raop_rtp->active_remote_header;
    raop_rtp->dacp_id = NULL;
    raop_rtp->active_remote_header = NULL;

    /* Read the progress values */
    progress_start = raop_rtp->progress_start;
    progress_curr = raop_rtp->progress_curr;
    progress_end = raop_rtp->progress_end;
    progress_changed = raop_rtp->progress_changed;
    raop_rtp->progress_changed = 0;

    MUTEX_UNLOCK(raop_rtp->run_mutex);

    /* Call set_volume callback if changed */
    if (volume_changed) {
        if (raop_rtp->callbacks.audio_set_volume) {
            raop_rtp->callbacks.audio_set_volume(raop_rtp->callbacks.cls, cb_data, volume);
        }
    }

    /* Handle flush if requested */
    if (flush != NO_FLUSH) {
        raop_buffer_flush(raop_rtp->buffer, flush);
        if (raop_rtp->callbacks.audio_flush) {
            raop_rtp->callbacks.audio_flush(raop_rtp->callbacks.cls, cb_data);
        }
    }

    if (metadata != NULL) {
        if (raop_rtp->callbacks.audio_set_metadata) {
            raop_rtp->callbacks.audio_set_metadata(raop_rtp->callbacks.cls, cb_data, metadata, metadata_len);
        }
        free(metadata);
        metadata = NULL;
    }

    if (coverart != NULL) {
        if (raop_rtp->callbacks.audio_set_coverart) {
            raop_rtp->callbacks.audio_set_coverart(raop_rtp->callbacks.cls, cb_data, coverart, coverart_len);
        }
        free(coverart);
        coverart = NULL;
    }
    if (dacp_id && active_remote_header) {
        if (raop_rtp->callbacks.audio_remote_control_id) {
            raop_rtp->callbacks.audio_remote_control_id(raop_rtp->callbacks.cls, dacp_id, active_remote_header);
        }
        free(dacp_id);
        free(active_remote_header);
        dacp_id = NULL;
        active_remote_header = NULL;
    }

    if (progress_changed) {
        if (raop_rtp->callbacks.audio_set_progress) {
            raop_rtp->callbacks.audio_set_progress(raop_rtp->callbacks.cls, cb_data, progress_start, progress_curr, progress_end);
        }
    }
    return 0;
}
/* 目前用不到先注释 */
//static THREAD_RETVAL
//raop_rtp_thread_time(void *arg)
//{
//    raop_rtp_t *raop_rtp = arg;
//    assert(raop_rtp);
//    struct sockaddr_storage saddr;
//    socklen_t saddrlen;
//    unsigned char packet[128];
//    unsigned int packetlen;
//    unsigned char time[32]={0x80,0xd2,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
//            ,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
//    };
//    uint64_t base = now_us();
//    uint64_t rec_pts = 0;
//    while (1) {
//        MUTEX_LOCK(raop_rtp->run_mutex);
//        if (!raop_rtp->running) {
//            MUTEX_UNLOCK(raop_rtp->run_mutex);
//            break;
//        }
//        MUTEX_UNLOCK(raop_rtp->run_mutex);
//        uint64_t send_time = now_us() - base + rec_pts;
//
//        byteutils_put_timeStamp(time, 24, send_time);
//        logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_thread_time send time 32 bytes, port = %d", raop_rtp->timing_rport);
//        struct sockaddr_in *addr = (struct sockaddr_in *)&raop_rtp->remote_saddr;
//        addr->sin_port = htons(raop_rtp->timing_rport);
//        int sendlen = sendto(raop_rtp->tsock, (char *)time, sizeof(time), 0, (struct sockaddr *) &raop_rtp->remote_saddr, raop_rtp->remote_saddr_len);
//        logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_thread_time sendlen = %d", sendlen);
//
//        saddrlen = sizeof(saddr);
//        packetlen = recvfrom(raop_rtp->tsock, (char *)packet, sizeof(packet), 0,
//                             (struct sockaddr *)&saddr, &saddrlen);
//        int type_t = packet[1] & ~0x80;
//        logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_thread_time receive time type_t 0x%02x, packetlen = %d", type_t, packetlen);
//        if (type_t == 0x53) {
//
//        }
//        /* 9-16 NTP请求报文离开发送端时发送端的本地时间。  T1 */
//        uint64_t Origin_Timestamp = byteutils_read_timeStamp(packet, 8);
//        /* 17-24 NTP请求报文到达接收端时接收端的本地时间。 T2 */
//        uint64_t Receive_Timestamp = byteutils_read_timeStamp(packet, 16);
//        /* 25-32 Transmit Timestamp：应答报文离开应答者时应答者的本地时间。 T3 */
//        uint64_t Transmit_Timestamp = byteutils_read_timeStamp(packet, 24);
//
//        //logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_thread_time Transmit_Timestamp = %llu", Transmit_Timestamp);
//
//        /* FIXME: 先简单这样写吧 */
//        rec_pts = Receive_Timestamp;
//
//#ifdef _WIN32
//        MUTEX_LOCK(raop_rtp->time_mutex);
//        WaitForSingleObject(&raop_rtp->time_cond, 3000);
//        MUTEX_UNLOCK(raop_rtp->time_mutex);
//#else
//        struct timeval now;
//        struct timespec outtime;
//        MUTEX_LOCK(raop_rtp->time_mutex);
//        gettimeofday(&now, NULL);
//        outtime.tv_sec = now.tv_sec + 3;
//        outtime.tv_nsec = now.tv_usec * 1000;
//        int ret = pthread_cond_timedwait(&raop_rtp->time_cond, &raop_rtp->time_mutex, &outtime);
//        MUTEX_UNLOCK(raop_rtp->time_mutex);
//#endif
//
//    }
//
//    logger_log(raop_rtp->logger, LOGGER_INFO, "Exiting UDP raop_rtp_thread_time thread");
//    return 0;
//}

static THREAD_RETVAL
raop_rtp_thread_udp(void *arg)
{
    raop_rtp_t *raop_rtp = arg;
    logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_thread_udp");
    unsigned char packet[RAOP_PACKET_LEN];
    unsigned int packetlen;
    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    assert(raop_rtp);
    void *cb_data = raop_rtp->callbacks.audio_init(raop_rtp->callbacks.cls);
    while(1) {
        fd_set rfds;
        struct timeval tv;
        int nfds, ret;

        /* Check if we are still running and process callbacks */
        if (raop_rtp_process_events(raop_rtp, cb_data)) {
            break;
        }

        /* Set timeout value to 5ms */
        tv.tv_sec = 0;
        tv.tv_usec = 5000;

        /* Get the correct nfds value */
        nfds = raop_rtp->csock+1;
        if (raop_rtp->dsock >= nfds)
            nfds = raop_rtp->dsock+1;

        /* Set rfds and call select */
        FD_ZERO(&rfds);
        FD_SET(raop_rtp->csock, &rfds);
        FD_SET(raop_rtp->dsock, &rfds);


        ret = select(nfds, &rfds, NULL, NULL, &tv);
        if (ret == 0) {
            /* Timeout happened */
            continue;
        } else if (ret == -1) {
            /* FIXME: Error happened */
            break;
        }

        if (FD_ISSET(raop_rtp->csock, &rfds)) {
           saddrlen = sizeof(saddr);
           packetlen = recvfrom(raop_rtp->csock, (char *)packet, sizeof(packet), 0,
                                (struct sockaddr *)&saddr, &saddrlen);

            memcpy(&raop_rtp->control_saddr, &saddr, saddrlen);
            raop_rtp->control_saddr_len = saddrlen;
            int type_c = packet[1] & ~0x80;
            logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_thread_udp type_c 0x%02x, packetlen = %d", type_c, packetlen);
            if (type_c == 0x56) {
                /* 处理重传的包，去除头部4个字节 */
                int ret = raop_buffer_queue(raop_rtp->buffer, packet+4, packetlen-4, &raop_rtp->callbacks);
                assert(ret >= 0);
            } else if (type_c == 0x54) {
                /**
                 * packetlen = 20
                 * bytes	description
                    8	RTP header without SSRC
                    8	current NTP time
                    4	RTP timestamp for the next audio packet
                 */
                uint64_t ntp_time = byteutils_read_timeStamp(packet, 8);
                unsigned int rtp_timestamp = (packet[4] << 24) | (packet[5] << 16) |
                        (packet[6] << 8) | packet[7];
                unsigned int next_timestamp = (packet[16] << 24) | (packet[17] << 16) |
                        (packet[18] << 8) | packet[19];
                //logger_log(raop_rtp->logger, LOGGER_DEBUG, "rtp audio ntp time = %llu", ntp_time);
                //logger_log(raop_rtp->logger, LOGGER_DEBUG, "rtp audio rtp_timestamp = %u", rtp_timestamp);
                //logger_log(raop_rtp->logger, LOGGER_DEBUG, "rtp audio next_timestamp = %u", next_timestamp);
                /* ntp_time和rtp_timestamp 用于音画同步 */
                raop_rtp->sync_time = ntp_time - OFFSET_1900_TO_1970 * 1000000;
                raop_rtp->sync_timestamp = rtp_timestamp;
            } else {
                logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_thread_udp unknown packet");
            }
        }
        if (FD_ISSET(raop_rtp->dsock, &rfds)) {
            // logger_log(raop_rtp->logger, LOGGER_INFO, "Would have data packet in queue");
            /* 这里接收音频数据 */
            saddrlen = sizeof(saddr);
            packetlen = recvfrom(raop_rtp->dsock, (char *)packet, sizeof(packet), 0,
                                 (struct sockaddr *)&saddr, &saddrlen);
            /* rtp payload type */
            int type_d = packet[1] & ~0x80;
            // logger_log(raop_rtp->logger, LOGGER_DEBUG, "raop_rtp_thread_udp type_d 0x%02x, packetlen = %d", type_d, packetlen);

            /* 出现len=16 如果没有发时间的话 */
            if (packetlen >= 12) {
                int no_resend = (raop_rtp->control_rport == 0);/* false */
                int buf_ret;
                const void *audiobuf;
                int audiobuflen;
                unsigned int timestamp;
                buf_ret = raop_buffer_queue(raop_rtp->buffer, packet, packetlen, &raop_rtp->callbacks);
                assert(buf_ret >= 0);
                /* Decode all frames in queue */
                while ((audiobuf = raop_buffer_dequeue(raop_rtp->buffer, &audiobuflen, &timestamp, no_resend))) {
                    pcm_data_struct pcm_data;
                    //modified by huanggang 20190617
                    pcm_data.data_len = audiobuflen;//960;
                    //end modify
                    pcm_data.data = audiobuf;
                    /* 根据sync_time和sync_timestamp计算timestamp对应的pts */
                    pcm_data.pts = (uint64_t) (timestamp - raop_rtp->sync_timestamp) * 1000000 / 44100 + raop_rtp->sync_time;
                    raop_rtp->callbacks.audio_process(raop_rtp->callbacks.cls, cb_data, &pcm_data);
                }
                /* Handle possible resend requests */
                if (!no_resend) {
                    raop_buffer_handle_resends(raop_rtp->buffer, raop_rtp_resend_callback, raop_rtp);
                }
            }

        }
    }
    logger_log(raop_rtp->logger, LOGGER_INFO, "Exiting UDP raop_rtp_thread_udp thread");
    raop_rtp->callbacks.audio_destroy(raop_rtp->callbacks.cls, cb_data);
    return 0;
}

/* 启动rtp服务,三个udp端口 */
void
raop_rtp_start_audio(raop_rtp_t *raop_rtp, int use_udp, unsigned short control_rport,
                     unsigned short *control_lport, unsigned short *timing_lport, unsigned short *data_lport)
{
    logger_log(raop_rtp->logger, LOGGER_INFO, "raop_rtp_start_audio");
    int use_ipv6 = 0;

    assert(raop_rtp);

    MUTEX_LOCK(raop_rtp->run_mutex);
    if (raop_rtp->running || !raop_rtp->joined) {
        MUTEX_UNLOCK(raop_rtp->run_mutex);
        return;
    }

    /* Initialize ports and sockets */
    raop_rtp->control_rport = control_rport;
    if (raop_rtp->remote_saddr.ss_family == AF_INET6) {
        use_ipv6 = 1;
    }
    use_ipv6 = 0;
    if (raop_rtp_init_sockets(raop_rtp, use_ipv6, use_udp) < 0) {
        logger_log(raop_rtp->logger, LOGGER_INFO, "Initializing sockets failed");
        MUTEX_UNLOCK(raop_rtp->run_mutex);
        return;
    }
    if (control_lport) *control_lport = raop_rtp->control_lport;
    if (timing_lport) *timing_lport = raop_rtp->timing_lport;
    if (data_lport) *data_lport = raop_rtp->data_lport;
    /* Create the thread and initialize running values */
    raop_rtp->running = 1;
    raop_rtp->joined = 0;

    THREAD_CREATE(raop_rtp->thread, raop_rtp_thread_udp, raop_rtp);
    //THREAD_CREATE(raop_rtp->thread_time, raop_rtp_thread_time, raop_rtp);
    MUTEX_UNLOCK(raop_rtp->run_mutex);
}

int
raop_rtp_is_running(raop_rtp_t *raop_rtp)
{
    int running;
    assert(raop_rtp);
    MUTEX_LOCK(raop_rtp->run_mutex);
    running = raop_rtp->running || !raop_rtp->joined;
    MUTEX_UNLOCK(raop_rtp->run_mutex);
    return running;
}

void
raop_rtp_set_volume(raop_rtp_t *raop_rtp, float volume)
{
    assert(raop_rtp);

    if (volume > 0.0f) {
        volume = 0.0f;
    } else if (volume < -144.0f) {
        volume = -144.0f;
    }

    /* Set volume in thread instead */
    MUTEX_LOCK(raop_rtp->run_mutex);
    raop_rtp->volume = volume;
    raop_rtp->volume_changed = 1;
    MUTEX_UNLOCK(raop_rtp->run_mutex);
}

void
raop_rtp_set_metadata(raop_rtp_t *raop_rtp, const char *data, int datalen)
{
    unsigned char *metadata;

    assert(raop_rtp);

    if (datalen <= 0) {
        return;
    }
    metadata = malloc(datalen);
    assert(metadata);
    memcpy(metadata, data, datalen);

    /* Set metadata in thread instead */
    MUTEX_LOCK(raop_rtp->run_mutex);
    raop_rtp->metadata = metadata;
    raop_rtp->metadata_len = datalen;
    MUTEX_UNLOCK(raop_rtp->run_mutex);
}

void
raop_rtp_set_coverart(raop_rtp_t *raop_rtp, const char *data, int datalen)
{
    unsigned char *coverart;

    assert(raop_rtp);

    if (datalen <= 0) {
        return;
    }
    coverart = malloc(datalen);
    assert(coverart);
    memcpy(coverart, data, datalen);

    /* Set coverart in thread instead */
    MUTEX_LOCK(raop_rtp->run_mutex);
    raop_rtp->coverart = coverart;
    raop_rtp->coverart_len = datalen;
    MUTEX_UNLOCK(raop_rtp->run_mutex);
}

void
raop_rtp_remote_control_id(raop_rtp_t *raop_rtp, const char *dacp_id, const char *active_remote_header)
{
    assert(raop_rtp);

    if (!dacp_id || !active_remote_header) {
        return;
    }

    /* Set dacp stuff in thread instead */
    MUTEX_LOCK(raop_rtp->run_mutex);
    raop_rtp->dacp_id = strdup(dacp_id);
    raop_rtp->active_remote_header = strdup(active_remote_header);
    MUTEX_UNLOCK(raop_rtp->run_mutex);
}

void
raop_rtp_set_progress(raop_rtp_t *raop_rtp, unsigned int start, unsigned int curr, unsigned int end)
{
    assert(raop_rtp);

    /* Set progress in thread instead */
    MUTEX_LOCK(raop_rtp->run_mutex);
    raop_rtp->progress_start = start;
    raop_rtp->progress_curr = curr;
    raop_rtp->progress_end = end;
    raop_rtp->progress_changed = 1;
    MUTEX_UNLOCK(raop_rtp->run_mutex);
}

void
raop_rtp_flush(raop_rtp_t *raop_rtp, int next_seq)
{
    assert(raop_rtp);

    /* Call flush in thread instead */
    MUTEX_LOCK(raop_rtp->run_mutex);
    raop_rtp->flush = next_seq;
    MUTEX_UNLOCK(raop_rtp->run_mutex);
}

void
raop_rtp_stop(raop_rtp_t *raop_rtp)
{
    assert(raop_rtp);

    /* Check that we are running and thread is not
     * joined (should never be while still running) */
    MUTEX_LOCK(raop_rtp->run_mutex);
    if (!raop_rtp->running || raop_rtp->joined) {
        MUTEX_UNLOCK(raop_rtp->run_mutex);
        return;
    }
    raop_rtp->running = 0;
    MUTEX_UNLOCK(raop_rtp->run_mutex);

    /* Join the thread */
    THREAD_JOIN(raop_rtp->thread);

    //MUTEX_LOCK(raop_rtp->time_mutex);
    //COND_SIGNAL(raop_rtp->time_cond);
    //MUTEX_UNLOCK(raop_rtp->time_mutex);

    //THREAD_JOIN(raop_rtp->thread_time);
    
    if (raop_rtp->csock != -1) closesocket(raop_rtp->csock);
    if (raop_rtp->tsock != -1) closesocket(raop_rtp->tsock);
    if (raop_rtp->dsock != -1) closesocket(raop_rtp->dsock);

    /* Flush buffer into initial state */
    raop_buffer_flush(raop_rtp->buffer, -1);

    /* Mark thread as joined */
    MUTEX_LOCK(raop_rtp->run_mutex);
    raop_rtp->joined = 1;
    MUTEX_UNLOCK(raop_rtp->run_mutex);
}
