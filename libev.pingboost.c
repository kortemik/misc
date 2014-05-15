/*
    Simple udp caching program to lower the load of any ArcheBlade server
    Copyright (C) 2014 Mikko Kortelainen


    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <libev/ev.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <resolv.h>
#include <pthread.h>

#define LISTEN_PORT "7776"
#define BUF_SIZE 4096

#define CONNECT_PORT "7779"
#define CONNECT_HOST "127.0.0.1"

int sockfd;

char *cacher_message;
int *cacher_len;

static void connect_local_cb (struct ev_loop *loop, ev_timer *timer, int revents) {
  int clsockfd;
  struct addrinfo hints, *servinfo, *p;
  int rv;
  int numbytes;
  
  
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  if ((rv = getaddrinfo(CONNECT_HOST, CONNECT_PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
  }

  // loop through all the results and make a socket
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((clsockfd = socket(p->ai_family, p->ai_socktype,
			 p->ai_protocol)) == -1) {
      perror("talker: socket");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "talker: failed to bind socket\n");
  }

  char initial_query[] = {0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x20, 0x45, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x20, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00};



  if ((numbytes = sendto(clsockfd, initial_query, sizeof(initial_query), 0, p->ai_addr, p->ai_addrlen)) == -1) {
    perror("talker: sendto");
  }
  else {

    /*
      replying with cached message
    */

    char *buffer = malloc(BUF_SIZE);
    if ((numbytes = recvfrom(clsockfd, buffer, BUF_SIZE, 0, (struct sockaddr*) p->ai_addr, &(p->ai_addrlen))) == -1) {
      perror("recvfrom");
    }
    else {
      /*
	not threading safe
	updating cached message
      */
      memcpy(cacher_message, buffer, numbytes);
      *cacher_len = numbytes;
      /*
	printing debug output 
      */
      //    char *output = malloc(BUF_SIZE+1);
      //snprintf(output, BUF_SIZE, "%s: %s (%d)\n", inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s), buffer, numbytes);
      //printf("%s", output);
      //    free(output);
    }
  }

  freeaddrinfo(servinfo);

  printf("talker: sent %d bytes to %s\n", numbytes, CONNECT_HOST);
  close(clsockfd);
}
/*
  static ev_tstamp my_rescheduler(ev_periodic *w, ev_tstamp now)
  {
  return now;
  }
*/

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*)sa)->sin6_addr);
}



/*
  cache interface callack
  updates query message
  returns cache message  
 */
static void udp_cb(EV_P_ ev_io *w, int revents) {
  puts("cache message requested");

  struct sockaddr_storage their_addr;
  socklen_t addr_len;
  addr_len = sizeof their_addr;
  int numbytes;

  /*
    receiving query
  */
  char *buffer = malloc(BUF_SIZE);
  if ((numbytes = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*) &their_addr, &addr_len)) == -1) {
    perror("recvfrom");
  }
  else {
    /*
      not threading safe
      updating query message
    */
    //memcpy(updq_message, &buffer, BUF_SIZE);

    /*
      printing debug output 
    */
    //    char *output = malloc(BUF_SIZE+1);
    //snprintf(output, BUF_SIZE, "%s: %s (%d)\n", inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s), buffer, numbytes);
    //printf("%s", output);

    /*
      replying with cached message
    */

    //sendto(sockfd, buffer, numbytes, 0, (struct sockaddr*) &their_addr, sizeof(their_addr));
    sendto(sockfd, cacher_message, (size_t)*cacher_len, 0, (struct sockaddr*) &their_addr, sizeof(their_addr));
    
    //free(output);
    //  free(buffer);
  }
}


int main(void) {

  puts("udp cacher started");

  /* initial values */

  cacher_message = malloc(BUF_SIZE);
  memset(cacher_message, 0, BUF_SIZE);
  
  /*
    listening for cacheable connections
  */

  struct addrinfo hints, *servinfo, *p;
  int rv;



  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC; // set to AF_INET to force IPv4
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE; // use my IP


  if ((rv = getaddrinfo(NULL, LISTEN_PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    return 1;
  }


  // loop through all the results and bind to the first we can
  for(p = servinfo; p != NULL; p = p->ai_next) {
    if ((sockfd = socket(p->ai_family, p->ai_socktype,
			 p->ai_protocol)) == -1) {
      perror("listener: socket");
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("listener: bind");
      continue;
    }

    break;
  }
  if (p == NULL) {
    fprintf(stderr, "listener: failed to bind socket\n");
    return 2;
  }

  freeaddrinfo(servinfo);

  printf("cache interface active\n");



  // Do the libev stuff.
  //ev_periodic_init(&con_loc_t, connect_local_cb, time(NULL), 10., my_rescheduler);

  // Do the libev stuff.
  struct ev_loop *loop = ev_default_loop(0);
  ev_periodic con_loc_t;

  ev_periodic_init(&con_loc_t, connect_local_cb, time(NULL), 10., NULL);
  ev_periodic_start(loop, &con_loc_t);
    
  ev_io udp_watcher;
  ev_io_init(&udp_watcher, udp_cb, sockfd, EV_READ);
  ev_io_start(loop, &udp_watcher);
  ev_loop(loop, 0);

  // This point is never reached.
  close(sockfd);

  return EXIT_SUCCESS;
}



