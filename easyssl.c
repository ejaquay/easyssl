/* easyssl.c:   Easy to use secure multi client server           

   Copyright (c) 2010, 2017  Edward J Jaquay 

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

   24-Feb-13 EJJ Adapt for Windows Sockets API 
   02-Apr-17 EJJ Add SSL components
   06-Apr-17 EJJ Eliminate check for ^D. Client handler can check if needed.

   This module implements a tcpip service that accepts ASCII strings as
   messages from clients and passes the strings to a user supplied client  
   handler for processing. Messages are terminated by NULL, CR, LF, or ^D

   The easyssl routine accepts two arguments, an integer port number and a 
   pointer to the user supplied client handler routine.

   The client handler receives an event type and a pointer to an ipclient 
   structure.

   The ipclient structure contains the client number, client buffer pointers, 
   socket descriptor, client address, length of buffer contents, and a timout 
   count.  The client handler should not alter the contents of this structure.

   The event type is one of CLIENT_CONNECT, CLIENT_DATA, CLIENT_TIMEOUT,
   CLIENT_EOD, CLIENT_ERROR, CLIENT_OVERFL, CLIENT_REJECT, or TIMER_EXPIRED.  

   In the case of CLIENT_CONNECT or CLIENT_DATA the socket descriptor can be 
   used to send replies to the client, which must be ready to receive them.

   In the case of CLIENT_TIMEOUT, CLIENT_EOD, CLIENT_ERROR, or CLIENT_OVERFL
   the client is dropped and the socket descriptor is not valid.  

   Regardless of the number of client connections the client handler is 
   called approximately once a minute with a TIMER_EXPIRED event code.  In this
   case the ipclient structure pointer is NULL.  The  TIMER_EXPIRED event
   can be used to perform time based tasks, for instance re-opening a log file.

   The one minute clock is also used by easyssl to decrement the time out
   count, which is done before calling the client handler.  If there is no
   activity for a client for approximately 10 minutes the client is dropped 
   and the client handler is called with CLIENT_TIMEOUT event code.

   There is no return from the easyssl function.  Program termination is done
   by the c standard exit function, which calls exit handlers established by
   atexit().  If the client handler desires to cause program termination 
   it should do so by calling exit(status)
      
   Informational and error messages are written to stderr.
*/

#include "easyssl.h"

/* Windows uses closesocket instead of close. Make */
/* them equivalent so we can use closesocket here  */
#define  closesocket close

struct ipclient IPCL[MAXCL];    /* IP clients  */
fd_set RDSET;                   /* Current read set  */

/* Send data to a client */
int easyssl_send(struct ipclient *cl, char * msg) {
      return SSL_write(cl->ssl, msg, strlen(msg));
}

/* Drop a client */
void easyssl_drop(struct ipclient *cl)
{
    int csock = cl->sock;
    SSL *ssl = cl->ssl;

    if (csock) {
        if (ssl) { 
            SSL_free(ssl);
            cl->ssl = NULL;
        }
        FD_CLR(csock, &RDSET);
        shutdown(csock, 2);
        closesocket(csock);
        cl->sock = 0;
    }
}


/* Exit the server */
void easyssl_exit(void)
{
    int clnt;
    for (clnt = 0; clnt < MAXCL; clnt++) {
        easyssl_drop(&IPCL[clnt]);
        if (IPCL[clnt].inbuf) free(IPCL[clnt].inbuf);
    }
#ifdef WIN32
    WSACleanup();
#endif
}

/* Look for end of data mark in client message. This could be changed */
/* to look for the end of a counted string to allow for binary data  */
/* Returns location of end of data or zero if not found */

static char *my_findterm(struct ipclient *cl)
{
    int len;
    char *buf;

    /* Only need to look in part of message just read */
    len = cl->rdcnt;
    buf = cl->bptr;

    while (len-- > 0) {
        switch (*buf) {
        case '\0':
            return buf;
        case '\n': 
        case '\r': 
        case '\004':
            /* Null terminate data for client handler.   */
            /* Preserve non-null terminator if possible. */
            if (cl->bcnt < BSIZ) {
                buf++;
                cl->bcnt += 1;
            }
            *buf = '\0';
            return buf;
        }
        buf++;
    }
    return 0;
}

void easyssl(int port, void (*dispatch) (int, struct ipclient *))
{
    struct sockaddr_in lsadr;   /* Listen sock addr   */
    struct sockaddr_in csadr;   /* Client sock addr   */
    struct timeval tmo;         /* Timeout value      */
    fd_set fds;                 /* Generic fd set     */
    time_t ctime;               /* Current unix time  */
    time_t ptime;               /* Prev. unix time    */
    char termchr;               /* Terminator char    */
    int bfree;                  /* Buffer free space  */
    int clnt;                   /* Client number      */
    int csock;                  /* Client socket      */
    int lsock;                  /* Listen socket      */
    int selcnt;                 /* fd selected count  */
    SSL_CTX *ctx;               /* ssl context        */
    SSL *ssl;                   /* ssl client handle  */

/***********************************/
/*         Initialize              */
/***********************************/

    memset(&IPCL, 0, sizeof(IPCL));
    FD_ZERO(&RDSET);

    /* Set previous time to the start of prev minute */
    time(&ctime);
    ptime = ctime - (ctime % 60);

#ifdef WIN32
    if (WSAStartup(0x0101, &WSAData)) {
        fprintf(stderr, "WSAStartup failed\n");
        exit(1);
    }
#endif

    /* initialize ssl */
    SSL_library_init();
    SSL_load_error_strings();

    /* Establish context - a multi version SSL server */
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) < 0) {
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) < 0 ) {
        exit(EXIT_FAILURE);
    }

    /* Establish exit handler */
    atexit(easyssl_exit);

/***********************************/
/* Set up listen on specified port */
/***********************************/

#ifdef WIN32
    if ((lsock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        fprintf(stderr, "Create error: %s\n", strerror(errno));
        exit(1);
    }
#else
    if ((lsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Create error: %s\n", strerror(errno));
        exit(1);
    }
#endif

    /* Allow reuse of address */
    int setbits = 1;
    setsockopt(lsock, SOL_SOCKET,SO_REUSEADDR, &setbits, sizeof (setbits));

    /* Bind to the port */
    lsadr.sin_family = AF_INET;
    lsadr.sin_port = htons(port);
    lsadr.sin_addr.s_addr = INADDR_ANY;

    if (bind(lsock, (struct sockaddr *) &lsadr, sizeof(lsadr))) {
        fprintf(stderr, "Bind error port %d: %s\n", port, strerror(errno));
        perror("");
        exit(1);
    }

    /* Listen on socket */
    if (listen(lsock, 5) < 0) { /* backlog is 5 */
        fprintf(stderr, "Listen error port %d: %s\n", port,
                strerror(errno));
        exit(1);
    }

    /* Add the listen socket to the reading set */
    FD_SET(lsock, &RDSET);
    fprintf(stderr, "Listening on port %d socket %d\n", port, lsock);

/***********************************/
/*    Loop forever getting input   */
/***********************************/

    while (1) {

        fds = RDSET;
        tmo.tv_sec = 1;
        tmo.tv_usec = 0;
        selcnt = select(MAXCL + 8, &fds, NULL, NULL, &tmo);
        if (selcnt < 0) {
            fprintf(stderr, "Select error %s\n", strerror(errno));
            exit(1);
        }

/***********************************/
/*  Check for timeout              */
/***********************************/

        time(&ctime);

        if (ctime - ptime >= 60) {
            ptime = ctime - (ctime % 60);

            /* Drop timed out clients */
            for (clnt = 0; clnt < MAXCL; clnt++) {
                if ((csock = IPCL[clnt].sock)) {
                    if ((IPCL[clnt].tictoc += 1) > 9) {
                        (*dispatch) (CLIENT_TIMEOUT, &IPCL[clnt]);
                        easyssl_drop(&IPCL[clnt]);
                    }
                }
            }

            /* Dispatch a timeout */
            (*dispatch) (TIMER_EXPIRED, NULL);
        }

        if (selcnt < 1) continue;

/***********************************/
/*    Connection request           */
/***********************************/

        if (FD_ISSET(lsock, &fds)) {

            /* Accept the connection */
            socklen_t sasiz = sizeof(csadr);
            csock = accept(lsock, (struct sockaddr *) &csadr, &sasiz);

            /* Find slot for the socket */
            for (clnt = 0; clnt < MAXCL; clnt++) {
                if (IPCL[clnt].sock == 0)
                    break;
            }

            if (clnt >= MAXCL) {
                fprintf(stderr, "Max clients exceeded %d\n", csock);
                shutdown(csock, 2);
                closesocket(csock);

            } else {

                /* Input buffers are allocated dynamically as needed.  */
                /* Once used buffers are not freed until program exit. */
                if (IPCL[clnt].inbuf == NULL) {
                    IPCL[clnt].inbuf=malloc(BSIZ);
                    if (IPCL[clnt].inbuf == NULL) {
                        perror("malloc error");
                        exit(1);
                    }
                }

                ssl = SSL_new(ctx);
                SSL_set_fd(ssl,csock);

                if (SSL_accept(ssl) <= 0) {
                    fprintf(stderr, "Client SSL accept failed\n");
                    SSL_free(ssl);
                    shutdown(csock, 2);
                    closesocket(csock);
                } else {            
                    IPCL[clnt].cid = clnt + 1;
                    IPCL[clnt].sock = csock;
                    IPCL[clnt].ip = csadr.sin_addr;
                    IPCL[clnt].bcnt = 0;
                    IPCL[clnt].tictoc = 0;
                    IPCL[clnt].overflow = 0;
                    IPCL[clnt].ssl = ssl;
                    FD_SET(csock, &RDSET);
                    (*dispatch) (CLIENT_CONNECT, &IPCL[clnt]);
                }
            }
        }

/*************************************/
/*   Check for data from clients     */
/*************************************/

        /* Search clients for input activity */
        for (clnt = 0; clnt < MAXCL; clnt++) {

            /* Skip unused client slots */
            if (!(csock = IPCL[clnt].sock)) continue;

            /* Skip inactive clients */
            if (!FD_ISSET(csock, &fds)) continue;

            /* Get buffer address. Must not be NULL */
            if (IPCL[clnt].inbuf == NULL) {
                fprintf(stderr, "Internal buffer error\n");
                exit(1);
            }

            /* Establish buffer read pointer */
            IPCL[clnt].bptr = IPCL[clnt].inbuf + IPCL[clnt].bcnt;

            /* Check space in buffer */
            bfree = BSIZ - IPCL[clnt].bcnt;
            if (bfree < 4) {
                (*dispatch) (CLIENT_OVERFL, &IPCL[clnt]);
                IPCL[clnt].bcnt = 0;
                IPCL[clnt].overflow = 1;
                continue;
            }
 
            /* Get data from client */
            IPCL[clnt].rdcnt = SSL_read(IPCL[clnt].ssl,IPCL[clnt].bptr,bfree);

            if (IPCL[clnt].rdcnt > 0) {
                IPCL[clnt].bcnt += IPCL[clnt].rdcnt; /* Add to buffer content */
                IPCL[clnt].tictoc = 0;               /* Clear timout counter  */

            } else {
                if (IPCL[clnt].rdcnt < 0) perror("SSL_read");
                (*dispatch) (CLIENT_ERROR, &IPCL[clnt]);
                easyssl_drop(&IPCL[clnt]);
                continue;
            }

            /* Check for end of client message */
            if (my_findterm(&IPCL[clnt])) {
                if (!(IPCL[clnt].overflow)) { 
                    (*dispatch) (CLIENT_DATA, &IPCL[clnt]);
                }
                IPCL[clnt].overflow = 0;
                IPCL[clnt].bcnt = 0;

            }                   /* End if data terminator */
        }                       /* End search descriptors */
    }                           /* End loop getting input */
}                               /* End main */
