/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0) {
  }
  result = after(sock->window.last_ack_received, seq);
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {printf("handle message:");
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags = get_flags(hdr);

  switch (flags) {
    case ACK_FLAG_MASK: {printf("ack\n");
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }

      while(pthread_mutex_lock(&sock->state_lock) != 0);
      sock->state = 2;
      pthread_mutex_unlock(&sock->state_lock);
      break;
    }
    case SYN_FLAG_MASK:{// listener
      sock->window.next_seq_expected = get_seq(hdr) + 1;    printf("rcv syn\n");  
   
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received + 1;
/*
      //add timestamp in payload
      timestamp_option_t send_time;
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      send_time.time = ts.tv_sec;
      send_time.millitime = (uint16_t) (ts.tv_nsec / 1000000);
      
      uint8_t *payload = &send_time;
      uint16_t payload_len = sizeof(timestamp_option_t);


      // 将数据包中的timestamp复制回复过去
      timestamp_option_t* tm = (timestamp_option_t*)(pkt + sizeof(cmu_tcp_header_t));
      uint16_t ext_len = TIMESTAMP_OPTION_SIZE;
      uint8_t *ext_data = (uint8_t *)tm;
*/
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = sock->window.next_seq_expected;

      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;  printf("plen:%d\n",plen);
      uint8_t flags = SYN_FLAG_MASK | ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);
printf("send synack\n");        
      while(pthread_mutex_lock(&sock->state_lock) != 0);
      sock->state = 1;
      pthread_mutex_unlock(&sock->state_lock);
      break;
    }
    case SYN_FLAG_MASK | ACK_FLAG_MASK:{// initiator   
      while(pthread_mutex_lock(&sock->state_lock) != 0){}   printf("rcv synack\n");  
      sock->state = 2;
      pthread_mutex_unlock(&sock->state_lock);
      
      sock->window.next_seq_expected = get_seq(hdr) + 1;      
   
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received++;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;
/*
      // 将payload中的timestamp复制到header回复过去
      timestamp_option_t* tm = (timestamp_option_t*)(get_payload(pkt));
      uint16_t ext_len = TIMESTAMP_OPTION_SIZE;
      uint8_t *ext_data = (uint8_t *)tm;

      // set rtt
      timestamp_option_t* tm_sent = (timestamp_option_t*)(pkt + sizeof(cmu_tcp_header_t));
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      uint32_t rtt; // in ms
      rtt = (ts.tv_sec - tm_sent->time) * 1000 + (ts.tv_nsec/1000000 - tm_sent->millitime);
      while (pthread_mutex_lock(&sock->rtt_lock)!= 0);
      sock->rtt.srtt = rtt;
      sock->rtt.devrtt = 0;
      sock->rtt.rto = rtt;
      pthread_mutex_unlock(&sock->rtt_lock);
*/

      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);
printf("send ack\n");    
      break;
    }
    default: {printf("default\n");
      socklen_t conn_len = sizeof(sock->conn);
      uint32_t seq = sock->window.last_ack_received;

      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;

      // No extension.
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = ACK_FLAG_MASK;
      uint16_t adv_window = 1;
      uint8_t *response_packet =
          create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                        ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, response_packet, plen, 0,
             (struct sockaddr *)&(sock->conn), conn_len);
      free(response_packet);

      seq = get_seq(hdr);

      if (seq == sock->window.next_seq_expected) {
        sock->window.next_seq_expected = seq + get_payload_len(pkt);
        payload_len = get_payload_len(pkt);
        payload = get_payload(pkt);

        // Make sure there is enough space in the buffer to store the payload.
        sock->received_buf =
            realloc(sock->received_buf, sock->received_len + payload_len);
        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
        sock->received_len += payload_len;
      }
    }
  }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after 3 seconds.
      if (poll(&ack_fd, 1, 3000) <= 0) {
        while(pthread_mutex_lock(&(sock->timeout_lock)) != 0){
        }
        sock->last_check_timeout = 1;
        pthread_mutex_unlock(&(sock->timeout_lock));
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr); printf("checking data: plen=%d\n", plen);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
/**/
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN((uint16_t)buf_len, (uint16_t)MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }

      data_offset += payload_len;
    }
  }
}


/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 * 
 * waiting for debugging --xtl
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */ 
/* void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {printf("single send: buflen = %d\n", buf_len);
  uint8_t *msg;
  // dataoffset 指向第一个没确认的offset
  // 只有发送完window中的pkt，并且收到所有pkt（或者超时），进入下一次循环前，才会更新
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {// buflen指未确认收到的长度 只有发送完window中的pkt，并且收到所有pkt（或者超时），进入下一次循环前，才会更新

    while (buf_len != 0) {//每次循环内部，窗口固定；只有当发出的pkt全部确认，或其中一个出现timeout，才会再次循环

      // 每次循环内部，固定
      uint32_t base = sock->window.last_ack_received;
      uint32_t len_have_sent = 0;
      uint32_t len_have_rcvd = 0;

      // 发送循环
      // 对于本窗口，将所有的pkt都发出去
      // 窗口大小固定为WINDOW_INITIAL_WINDOW_SIZE byte
      while(1)
      {
        uint16_t payload_len = MIN((uint16_t)(buf_len - len_have_sent), (uint16_t)MSS);
        // maybe 0, means all buf has been sent, but some is not acked
        if (payload_len == 0)
          break;
        
        // 如果再发会超过窗口大小
        if (len_have_sent + payload_len > WINDOW_INITIAL_WINDOW_SIZE)
          break;
        
        uint16_t src = sock->my_port;
        uint16_t dst = ntohs(sock->conn.sin_port);
        uint32_t seq = sock->window.last_ack_received + len_have_sent;
        uint32_t ack = sock->window.next_seq_expected; // ???symmetic
        uint16_t hlen = sizeof(cmu_tcp_header_t); // add timestamp
        uint16_t plen = hlen + payload_len;
        uint8_t flags = 0;
        uint16_t adv_window = 1; // unchanged
       
        uint8_t *payload = data_offset + len_have_sent;

        uint16_t ext_len = 0;
        uint8_t *ext_data = NULL;
        msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                            ext_len, ext_data, payload, payload_len);
printf("send: plen=%d, content=%s\n", plen, payload);
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);

        len_have_sent += payload_len;
      }
printf("send all in a window. now check...\n");
      // 接受循环
      // 检查收到的ack，仅当收到所有ack或者timeout才结束循环
      while (1)
      {
        check_for_data(sock, TIMEOUT);
        if (sock->last_check_timeout){

          while(pthread_mutex_lock(&(sock->timeout_lock)) != 0){
          }
          sock->last_check_timeout = 0;
          pthread_mutex_unlock(&(sock->timeout_lock));

          len_have_rcvd = sock->window.last_ack_received - base;
          break;
        }
        else{
          
          if (has_been_acked(sock, base + len_have_sent - 1)){//收到所有ack
            len_have_rcvd = len_have_sent;
            break;
          }

        }
      }

      // len_have_rcvd 已被更新
      //更新dataoffset和buflen
      data_offset += len_have_rcvd;
      buf_len -= len_have_rcvd;
    }
  }
} */

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;

  // handshake
  if (sock->type == TCP_INITIATOR){// client
    while(1){
      size_t conn_len = sizeof(sock->conn);
      // No payload.
      uint8_t *payload = NULL;
      uint16_t payload_len = 0;
      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected; // ???symmetic
      uint16_t hlen = sizeof(cmu_tcp_header_t); // add timestamp
      uint16_t plen = hlen + payload_len;
      uint8_t flags = SYN_FLAG_MASK;
      uint16_t adv_window = 1; // unchanged
      /*
      //add timestamp
      uint16_t ext_len = TIMESTAMP_OPTION_SIZE;
      timestamp_option_t send_time;
      struct timespec ts;
      clock_gettime(CLOCK_REALTIME, &ts);
      send_time.time = ts.tv_sec;
      send_time.millitime = (uint16_t) (ts.tv_nsec / 1000000);
      
      uint8_t *ext_data =(uint8_t *) &send_time;
*/
      uint16_t ext_len = 0;
      uint8_t* ext_data = NULL;
      uint8_t *msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);

      sendto(sock->socket, msg, plen, 0, (struct sockaddr *)&(sock->conn),
              conn_len);
      free(msg);
printf("send syn\n");  
      while(pthread_mutex_lock(&sock->state_lock) != 0);
      sock->state = 1;
      pthread_mutex_unlock(&sock->state_lock);


      // check
      check_for_data(sock, TIMEOUT);
      if (sock->state == 2)
        break;

    }

  }else{ // server/listener
  
    while(1){      
      while(pthread_mutex_lock(&sock->state_lock) != 0);
      if(sock->state == 2)
        break;
      pthread_mutex_unlock(&sock->state_lock);
      check_for_data(sock, NO_FLAG);
    }
    pthread_mutex_unlock(&sock->state_lock);

  }
  printf("finish handshake\n");

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      single_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }

  pthread_exit(NULL);
  return NULL;
}
