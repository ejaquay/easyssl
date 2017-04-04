/* easyssl.h:   Header file for easy to use multi client ip server           

   Copyright (c) 2010, 2016  Edward J Jaquay 

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
   EDWARD JAQUAY BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

   Except as contained in this notice, the name of Edward Jaquay shall not be
   used in advertising or otherwise to promote the sale, use or other dealings
   in this Software without prior written authorization from Edward Jaquay.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#ifdef WIN32
#include <winsock.h>
#include <process.h>
#define WSAerrno (WSAGetLastError())
WSADATA WSAData;
#else
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/* Structure for client control data. Passed to client handler */
struct ipclient {
    int cid;                    /* Client ID number     */
    int sock;                   /* Client socket        */
    char *inbuf;                /* Buffer address       */
    struct in_addr ip;          /* Client IP addr       */
    int port;                   /* Client port          */
    int bcnt;                   /* Buffer data count    */
    int toct;                   /* Time out counter     */
    SSL *ssl;                   /* libssl client handle */
};

/* BSIZ establishes the maximum size of client messages. If a  */
/* data terminator is not seen before the buffer is full the   */
/* client is disconnected.  Allocation is dynamic.             */

#define BSIZ   1024             /* Size of buffers */

/* Max clients establishes the number of ipclient slots to  */
/* declare. The sets the maximum connected clients.         */

#define MAXCL 32                /* Max clients */

/* Event types sent to dispatch routine */

#define TIMER_EXPIRED  0
#define CLIENT_CONNECT 1
#define CLIENT_DATA    2
#define CLIENT_EOD     3
#define CLIENT_ERROR   4
#define CLIENT_OVERFL  5
#define CLIENT_TIMEOUT 6

/* The server */
void easyssl(int, void (*)(int, struct ipclient *));

/* Send a string to the client */
int easyssl_send(struct ipclient *, char *);

/* Drop client */
void easyssl_drop(struct ipclient *);

/* Terminate the service */
void easyssl_exit(void);
