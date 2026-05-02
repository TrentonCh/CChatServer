#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include "inet.h"
#include "common.h"
#include <sys/queue.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define _GNU_SOURCE
#define CA_FILE "certs/ca-cert.pem"

// These will be set based on the topic name at runtime
static char CERT_FILE[256]; // the certificate
static char KEY_FILE[256];  // the key


void sighandler(int signo); // signal handler
void handle_deregister(char *topic); // helper method to handle deregistering

volatile sig_atomic_t check_signal = 0; // check variable for signal handler

static void make_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

int mylen(const char *s) {
    int n = 0;
    while (n < MAX && s[n] != '\0') n++;
    return n;
}


void set_cert_paths(const char *topic) {
    
    
    char topic1[] = "KSU Football";
    char topic2[] = "KSU Basketball";
    char topic3[] = "KSU Compsci";
    char topic4[] = "Puppies";
    char topic5[] = "Fortnite";
    // returns the correct certificate based on what the topic is that the chatserver has
    if(strncmp(topic , topic1, MAX) == 0){
        snprintf(CERT_FILE, sizeof(CERT_FILE), "certs/ksu-football-cert.pem");
        snprintf(KEY_FILE, sizeof(KEY_FILE), "certs/ksu-football-key.pem");
    }else if(strncmp(topic, topic2 , MAX) == 0){
        snprintf(CERT_FILE, sizeof(CERT_FILE), "certs/ksu-basketball-cert.pem");
        snprintf(KEY_FILE, sizeof(KEY_FILE), "certs/ksu-basketball.pem");
    }else if(strncmp(topic, topic3 , MAX) == 0){
        snprintf(CERT_FILE, sizeof(CERT_FILE), "certs/ksu-compsci-cert.pem");
        snprintf(KEY_FILE, sizeof(KEY_FILE), "certs/ksu-compsci.pem");
    }else if(strncmp(topic, topic4 , MAX) == 0){
          snprintf(CERT_FILE, sizeof(CERT_FILE), "certs/puppies-cert.pem");
          snprintf(KEY_FILE, sizeof(KEY_FILE), "certs/puppies.pem");
    }else if(strncmp(topic, topic5 , MAX) == 0){
          snprintf(CERT_FILE, sizeof(CERT_FILE), "certs/fortnite-cert.pem");
          snprintf(KEY_FILE, sizeof(KEY_FILE), "certs/fortnite.pem");
    }else{
        perror("Unusable Topic Name please choose from the pre aproved topics");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    fprintf(stderr, "Using certificates: %s and %s\n", CERT_FILE, KEY_FILE);
}

/* SSL functions --------------------------------------------------*/

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

// Client context for connecting to directory server 
SSL_CTX *create_client_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL client context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set minimum TLS version to 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}

void configure_client_context(SSL_CTX *ctx) {
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

    // Load CA certificate for verifying directory server
    if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL)) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //directory server certificate verification
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

//  Server context for accepting chat client connections 
SSL_CTX *create_server_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL server context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set minimum TLS version to 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

    return ctx;
}

void configure_server_context(SSL_CTX *ctx) {
    // Load our certificate and private key 
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }

    // No client certificate verification 
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
}

/* Main Function -------------------------------------- */
int main(int argc, char **argv)
{
    signal(SIGINT, sighandler);

    if (argc != 3) { // check that there's 3 command line arguments
        fprintf(stderr, "Please make sure to use this format: %s '<topic name>' <port number>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    char *topic = argv[1]; // topic of the chat server
    
    // Set certificate paths based on topic name
    set_cert_paths(topic);
    
    int port;
    int check = sscanf(argv[2], "%d", &port);
    if (check != 1) {
        fprintf(stderr, "Error with getting port number.");
        return EXIT_FAILURE;
    }
    if (port < 49150 || port > 65537) { // ensure that the port inputted is in range
        fprintf(stderr, "Port number is out of range. Choose a number between 49151 - 65536.");
        return EXIT_FAILURE;
    }

    // Initialize SSL
    init_openssl();
    
    // Create contexts for both client server parts of the chat servers
    SSL_CTX *client_ssl_ctx = create_client_context();
    configure_client_context(client_ssl_ctx);
    
    SSL_CTX *server_ssl_ctx = create_server_context();
    configure_server_context(server_ssl_ctx);

    int sockfd;         /* Listening socket */
    struct sockaddr_in cli_addr, serv_addr, dir_addr;
    fd_set readset;

    /* Create communication endpoint */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket");
        return EXIT_FAILURE;
    }

    /* Add SO_REUSEADDRR option to prevent address in use errors */
    int true = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
        perror("server: can't set stream socket address reuse option");
        return EXIT_FAILURE;
    }

    /* Bind socket to local address */
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family         = AF_INET;
    serv_addr.sin_addr.s_addr    = htonl(INADDR_ANY);    
    serv_addr.sin_port           = htons((uint16_t)port);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("server: can't bind local address");
        return EXIT_FAILURE;
    }

    make_nonblocking(sockfd);

    // Connect to directory server with SSL
    int dirsock;
    if ((dirsock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket");
        return EXIT_FAILURE;
    }

    /* Set up address for directory server */
    memset((char *) &dir_addr, 0, sizeof(dir_addr));
    dir_addr.sin_family         = AF_INET;
    dir_addr.sin_addr.s_addr    = inet_addr(SERV_HOST_ADDR);
    dir_addr.sin_port           = htons(SERV_TCP_PORT);

    if (connect(dirsock, (struct sockaddr *) &dir_addr, sizeof(dir_addr)) < 0) {
        perror("server: can't connect to directory server");
        return EXIT_FAILURE;
    }

    // Create SSL connection to directory server
    SSL *dir_ssl = SSL_new(client_ssl_ctx);
    SSL_set_fd(dir_ssl, dirsock);

    // Perform SSL handshake
    if (SSL_connect(dir_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL handshake failed with directory server\n");
        SSL_free(dir_ssl);
        close(dirsock);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "SSL connection established with directory server\n");

    // Verify directory server certificate
    X509 *cert = SSL_get_peer_certificate(dir_ssl);
    if (cert == NULL) {
        fprintf(stderr, "No certificate presented by directory server\n");
        SSL_shutdown(dir_ssl);
        SSL_free(dir_ssl);
        close(dirsock);
        return EXIT_FAILURE;
    }

    char cn[256];
    X509_NAME *subject = X509_get_subject_name(cert);
    X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
    fprintf(stderr, "Directory server certificate CN: %s\n", cn);
    
    // Verify CN matches "Directory Server"
    if (strncasecmp(cn, "Directory Server", 256) != 0) {
        fprintf(stderr, "Certificate CN mismatch. Expected 'Directory Server', got '%s'\n", cn);
        X509_free(cert);
        SSL_shutdown(dir_ssl);
        SSL_free(dir_ssl);
        close(dirsock);
        return EXIT_FAILURE;
    }
    
    X509_free(cert);

    // Send registration message via SSL
    char message[MAX];
    snprintf(message, MAX, "R %s %d", topic, port);
    
    int write_result = SSL_write(dir_ssl, message, mylen(message));
    if (write_result <= 0) {
        int err = SSL_get_error(dir_ssl, write_result);
        fprintf(stderr, "Failed to send registration message. SSL error: %d\n", err);
        ERR_print_errors_fp(stderr);
        SSL_shutdown(dir_ssl);
        SSL_free(dir_ssl);
        close(dirsock);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Sent registration: %s\n", message);

    // Read response from directory server
    char response[MAX];
    int read_result = SSL_read(dir_ssl, response, MAX - 1);
    if (read_result <= 0) {
        int err = SSL_get_error(dir_ssl, read_result);
        fprintf(stderr, "Failed to read response from directory server. SSL error: %d\n", err);
        ERR_print_errors_fp(stderr);
        SSL_shutdown(dir_ssl);
        SSL_free(dir_ssl);
        close(dirsock);
        return EXIT_FAILURE;
    }
    
    response[read_result] = '\0';
    fprintf(stderr, "Directory server response: %s\n", response);

    // Check if registration was successful
    if (strncmp(response, "Error", 5) == 0) {
        fprintf(stderr, "Registration failed: %s\n", response);
        SSL_shutdown(dir_ssl);
        SSL_free(dir_ssl);
        close(dirsock);
        return EXIT_FAILURE;
    }

    SSL_shutdown(dir_ssl);
    SSL_free(dir_ssl);
    close(dirsock);

    listen(sockfd, 5);

    struct connection { // struct for connections that contains socket, SSL object, and username
        int socket;
        SSL *ssl;
        char username[MAX];
        int handshake_complete;
        LIST_ENTRY(connection) connections;
    };

    LIST_HEAD(connection_list_head, connection); //head of connection for linked list
    struct connection_list_head head;
    LIST_INIT(&head);

    for (;;) { // main for loop
        /* Initialize and populate your readset and compute maxfd */
        FD_ZERO(&readset);
        FD_SET(sockfd, &readset);
        int max_fd = sockfd;

        struct connection *new_pointer;
        LIST_FOREACH(new_pointer, &head, connections) {
            FD_SET(new_pointer->socket, &readset);
            if (max_fd < new_pointer->socket) {max_fd = new_pointer->socket;}
        }

        if (check_signal == 1) { 
            fprintf(stderr, "Signal was caught. Now deregister server.\n");
            
            // Clean up all client connections
            while (!LIST_EMPTY(&head)) {
                struct connection *conn = LIST_FIRST(&head);
                if (conn->ssl) {
                    SSL_shutdown(conn->ssl);
                    SSL_free(conn->ssl);
                }
                close(conn->socket);
                LIST_REMOVE(conn, connections);
                free(conn);
            }
            
            handle_deregister(topic);
            close(sockfd);
            SSL_CTX_free(client_ssl_ctx);
            SSL_CTX_free(server_ssl_ctx);
            cleanup_openssl();
            return EXIT_SUCCESS;
        }

        if (select(max_fd+1, &readset, NULL, NULL, NULL) > 0) {

            /* Check to see if our listening socket has a pending connection */
            if (FD_ISSET(sockfd, &readset)) {
                socklen_t clilen = sizeof(cli_addr);
                int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

                if (newsockfd < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        perror("server: accept error");
                } else {
                    make_nonblocking(newsockfd);

                    // Create SSL object for new client connection
                    SSL *client_ssl = SSL_new(server_ssl_ctx);
                    if (client_ssl == NULL) {
                        fprintf(stderr, "Failed to create SSL object for client\n");
                        ERR_print_errors_fp(stderr);
                        close(newsockfd);
                        continue;
                    }
                    
                    SSL_set_fd(client_ssl, newsockfd);
                    SSL_set_accept_state(client_ssl);
                    SSL_set_mode(client_ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

                    struct connection *new_connection = calloc(1, sizeof(struct connection));
                    new_connection->socket = newsockfd;
                    new_connection->ssl = client_ssl;
                    new_connection->username[0] = '\0';
                    new_connection->handshake_complete = 0;

                    LIST_INSERT_HEAD(&head, new_connection, connections);
                }
            }

            // iterate through all connections
            struct connection *connect1 = LIST_FIRST(&head);
            while (connect1 != NULL) {
                struct connection *connect1_next = LIST_NEXT(connect1, connections);
                
                if (FD_ISSET(connect1->socket, &readset)) {

                    // Handle SSL handshake if not complete
                    if (!connect1->handshake_complete) {
                        int accept_result = SSL_accept(connect1->ssl);
                        if (accept_result <= 0) {
                            int err = SSL_get_error(connect1->ssl, accept_result);
                            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                                // Handshake in progress, continue
                                connect1 = connect1_next;
                                continue;
                            } else {
                                // Handshake failed
                                fprintf(stderr, "SSL handshake failed with client\n");
                                ERR_print_errors_fp(stderr);
                                
                                if (connect1->ssl) {
                                    SSL_free(connect1->ssl);
                                }
                                close(connect1->socket);
                                LIST_REMOVE(connect1, connections);
                                free(connect1);
                                connect1 = connect1_next;
                                continue;
                            }
                        }
                        
                        // Handshake complete
                        connect1->handshake_complete = 1;
                        fprintf(stderr, "SSL handshake completed with client\n");
                        
                        // Send welcome message
                        char get_name[MAX];
                        snprintf(get_name, MAX, "Enter in your name: ");
                        int write_ret = SSL_write(connect1->ssl, get_name, mylen(get_name));
                        if (write_ret <= 0) {
                            int err = SSL_get_error(connect1->ssl, write_ret);
                            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                                fprintf(stderr, "Failed to send welcome message\n");
                                ERR_print_errors_fp(stderr);
                                
                                SSL_shutdown(connect1->ssl);
                                SSL_free(connect1->ssl);
                                close(connect1->socket);
                                LIST_REMOVE(connect1, connections);
                                free(connect1);
                            }
                        }
                        connect1 = connect1_next;
                        continue;
                    }

                    char s[MAX];
                    char notif[MAX];

                    ssize_t nread = SSL_read(connect1->ssl, s, MAX-1);

                    if (nread <= 0) {
                        int err = SSL_get_error(connect1->ssl, nread);
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                            connect1 = connect1_next;
                            continue;
                        }
                        
                        // Connection closed or error
                        struct connection *current_sockets;
                        LIST_FOREACH(current_sockets, &head, connections) {
                            if (connect1 != current_sockets && current_sockets->handshake_complete) {
                                snprintf(notif, MAX,
                                    "The user, %.60s, has left the chat\n",
                                    connect1->username);

                                SSL_write(current_sockets->ssl, notif, mylen(notif));
                            }
                        }

                        LIST_REMOVE(connect1, connections);
                        if (connect1->ssl) {
                            SSL_shutdown(connect1->ssl);
                            SSL_free(connect1->ssl);
                        }
                        close(connect1->socket);
                        free(connect1);

                        if(LIST_EMPTY(&head)) { 
                            handle_deregister(topic);
                            close(sockfd);
                            SSL_CTX_free(client_ssl_ctx);
                            SSL_CTX_free(server_ssl_ctx);
                            cleanup_openssl();
                            return EXIT_SUCCESS;
                        }
                        connect1 = connect1_next;
                        continue;
                    }

                    s[nread] = '\0';

                    int checkIfNicknameIsValid = 0;
                    if (connect1->username[0] == '\0') {
                        int i = 0;
                        while (i < MAX - 1 && s[i] != '\0' && s[i] != '\n' && s[i] != '\r') {
                            connect1->username[i] = s[i];
                            i++;
                        }
                        connect1->username[i] = '\0';

                        int count = 0;
                        struct connection *view_connect;
                        LIST_FOREACH(view_connect, &head, connections) {
                            if (connect1 != view_connect && view_connect->handshake_complete) {
                                count++;
                                if (strncasecmp(connect1->username, view_connect->username, MAX) == 0) {
                                    checkIfNicknameIsValid = 1;
                                } 
                            }    
                        }
                        if (checkIfNicknameIsValid == 1) {
                            connect1->username[0] = '\0';
                            snprintf(notif, MAX, "Your nickname has been taken.\nPlease enter in a new nickname: ");
                            SSL_write(connect1->ssl, notif, mylen(notif));
                        }
                        else {
                            int users_name_check = 0;
                            LIST_FOREACH(view_connect, &head, connections) {
                                if (view_connect->username[0] != '\0' && connect1 != view_connect && view_connect->handshake_complete) {
                                    users_name_check++;
                                }
                            }
                            if (users_name_check == 0) {
                                snprintf(notif, MAX, "You are the first user to join the chat.");
                                SSL_write(connect1->ssl, notif, mylen(notif));
                            }
                            else { 
                                LIST_FOREACH(view_connect, &head, connections) {
                                    if (connect1 != view_connect && view_connect->username[0] != '\0' && view_connect->handshake_complete) {
                                        snprintf(notif, MAX, "The user, %.*s, has joined the chat\n", 67, connect1->username);
                                        SSL_write(view_connect->ssl, notif, mylen(notif));
                                    }
                                }
                            }
                        }
                    }
                    else {
                        struct connection *all_connections;
                        LIST_FOREACH(all_connections, &head, connections) {
                            if (connect1 != all_connections && all_connections->handshake_complete && all_connections->username[0] != '\0') {
                                snprintf(notif, MAX, "%.*s: %.*s", 25, connect1->username, 71, s);
                                SSL_write(all_connections->ssl, notif, mylen(notif));
                            }
                        }
                    }    
                }
                
                connect1 = connect1_next;
            }
        }
    }
} 

void sighandler(int signo) { 
    fprintf(stderr, "Caught signal %d\n", signo);
    check_signal = 1;
}

void handle_deregister(char *topic) {
    // Set certificate paths based on topic name
    set_cert_paths(topic); // Currently hardcoded as always KSU footbal 
    
    // Initialize SSL for deregistration
    init_openssl();
    SSL_CTX *ssl_ctx = create_client_context();
    configure_client_context(ssl_ctx);

    int dirsock_deregister;
    if ((dirsock_deregister = socket(AF_INET, SOCK_STREAM, 0)) < 0) { 
        perror("server: can't open deregister socket");
        SSL_CTX_free(ssl_ctx);
        cleanup_openssl();
        return;
    }

    struct sockaddr_in dir_addr_deregister; 
    memset((char *) &dir_addr_deregister, 0, sizeof(dir_addr_deregister));
    dir_addr_deregister.sin_family      = AF_INET;
    dir_addr_deregister.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
    dir_addr_deregister.sin_port        = htons(SERV_TCP_PORT);

    if (connect(dirsock_deregister, (struct sockaddr *) &dir_addr_deregister, sizeof(dir_addr_deregister)) < 0) {
        perror("server: can't connect to directory server for deregister");
        close(dirsock_deregister);
        SSL_CTX_free(ssl_ctx);
        cleanup_openssl();
        return;
    }

    // Create SSL connection for deregistration
    SSL *dir_ssl = SSL_new(ssl_ctx);
    SSL_set_fd(dir_ssl, dirsock_deregister);

    if (SSL_connect(dir_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL handshake failed during deregistration\n");
        SSL_free(dir_ssl);
        close(dirsock_deregister);
        SSL_CTX_free(ssl_ctx);
        cleanup_openssl();
        return;
    }

    char sendInformation[MAX];
    snprintf(sendInformation, MAX, "D %s", topic); 
    
    if (SSL_write(dir_ssl, sendInformation, mylen(sendInformation)) > 0) {
        fprintf(stderr, "Sent deregister: %s\n", sendInformation);
    } else {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Failed to send deregister message\n");
    }

    SSL_shutdown(dir_ssl);
    SSL_free(dir_ssl);
    close(dirsock_deregister);
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
}