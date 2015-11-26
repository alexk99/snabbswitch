#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdint.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include "core/packet.h"
#include <string.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define VLAN_HEADER_SIZE 4

struct vlan_tag {
   u_int16_t       vlan_tpid;              /* ETH_P_8021Q */
   u_int16_t       vlan_tci;               /* VLAN TCI */
};

int send_packet(int fd, struct packet *p) {
  if (write(fd, &p->data, p->length) == -1) {
    perror("sendmsg");
    return(-1);
  }
  return(0);
}

int receive_packet(int fd, struct packet *p) {
   ssize_t s;
   struct cmsghdr *cmsg;
   union {
      struct cmsghdr cmsg;
      char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
   } cmsg_buf;
   struct msghdr msg;
   struct iovec iov;
   struct vlan_tag *tag;

   iov.iov_base = p->data;
   iov.iov_len = sizeof(p->data);
   msg.msg_iov = &iov;
   msg.msg_iovlen = 1;
   msg.msg_control = &cmsg_buf;
   msg.msg_controllen = sizeof cmsg_buf;
   msg.msg_name = NULL;
   int vlan_offset = 12; // src mac (6) + dst_mac (6) than vlan_header

   do {
     s = recvmsg(fd, &msg, MSG_TRUNC);
   } while (s < 0 && errno == EINTR);

   if (s == -1) {
      perror("read");
      return(-1);
   }
   p->length = s;

   for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      struct tpacket_auxdata *aux;
      
      if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))
         || cmsg->cmsg_level != SOL_PACKET
         || cmsg->cmsg_type != PACKET_AUXDATA) {
         continue;
      }
      
      aux = (struct tpacket_auxdata *)(void *)CMSG_DATA(cmsg);
      if (aux->tp_vlan_tci) {
         // create space for the vlan header
         if (p->length <= vlan_offset) {
            continue;
         }
         memmove(&p->data[vlan_offset + VLAN_HEADER_SIZE], &p->data[vlan_offset], p->length - vlan_offset);
         
         tag = (struct vlan_tag *)(&p->data[vlan_offset]);
         tag->vlan_tpid = htons(0x8100);
         tag->vlan_tci = htons(aux->tp_vlan_tci);
         
         p->length += VLAN_HEADER_SIZE;
      }
   }
   
   return p->length;
}

int can_receive(int fd) {
  fd_set fds;
  struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
  int result;

  FD_ZERO(&fds);
  FD_SET(fd, &fds);
  if ((result = select(fd+1, &fds, NULL, NULL, &tv)) == -1) {
    perror("select");
    return(-1);
  }
  return(result);
}

int can_transmit(int fd) {
  fd_set fds;
  struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
  int result;

  FD_ZERO(&fds);
  FD_SET(fd, &fds);
  if ((result = select(fd+1, NULL, &fds, NULL, &tv)) == -1) {
    perror("select");
    return(-1);
  }
  return(result);
}
