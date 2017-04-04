/*****************************************************************/
/*                                                               */
/* Example secure server responds to hello, path, and goodby     */
/*                                                               */
/* Use make to build, test with                                  */ 
/*     'openssl s_client -connect <hostname>:6666'               */
/*                                                               */
/* Server requires key.pem and cert.pem certificates.            */
/*                                                               */
/* To create self-signed certificates:                           */ 
/*     'openssl req -newkey rsa:2048 -new -nodes -x509 \         */ 
/*                  -days 3650 -keyout key.pem -out cert.pem'    */
/*                                                               */
/* All data transmitted is encrypted.  Yet to do is host and     */
/* client authentication.                                        */
/*                                                               */
/*****************************************************************/

#include "easyssl.h"

/* The easyssl routine keeps track of clients and dispatching
 * client requests, but a handler is required to process them. */

void client_handler(int event, struct ipclient *cl)
{
    switch (event) {

    /* Client is connecting */
    case CLIENT_CONNECT:

        easyssl_send(cl, "Greetings\n> ");
        printf("Client %d connected from %s\n", cl->cid, inet_ntoa(cl->ip));
        break;

    /* Client has been disconnected for some reason. */
    case CLIENT_EOD:
    case CLIENT_ERROR:
    case CLIENT_TIMEOUT:

        printf("Client %d dropped\n", cl->cid);
        break;

    /* Client sent something. Respond as required.            */
    /* code to do real stuff (including auth) can be put here */
    case CLIENT_DATA:

        printf("client %d sent %d bytes.\n",cl->cid,cl->bcnt);

        if (strncmp(cl->inbuf, "hello", 5) == 0) {
            easyssl_send(cl, "Hello\n> ");

        } else if (strncmp(cl->inbuf, "path", 4) == 0) {
            easyssl_send(cl, getenv("PATH"));
            easyssl_send(cl, "\n> ");

        } else if (strncmp(cl->inbuf, "goodby", 6) == 0) {
            printf("Client %d said goodby\n", cl->cid);
            easyssl_send(cl, "So long...\n");
            easyssl_drop(cl);

        } else {
            easyssl_send(cl, "You said \"");
            easyssl_send(cl, cl->inbuf);
            easyssl_send(cl, "\"\n> ");
        }
        break;
    }
}

/* For this simple example main just calls the easyssl routine */

int main()
{
    easyssl(6666, &client_handler);   /* never returns */
    return 1;
}
