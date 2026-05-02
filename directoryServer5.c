#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "inet.h"
#include "common.h"
#include <sys/queue.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define _GNU_SOURCE
#define CERT_FILE "certs/directory-server-cert.pem"
#define KEY_FILE "certs/directory-server-key.pem"
#define CA_FILE "certs/ca-cert.pem"


void init_openssl() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
	EVP_cleanup();
}

SSL_CTX *create_context() {
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Set minimum TLS version to 1.3
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

	return ctx;
}

void configure_context(SSL_CTX *ctx) {
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

	// Load CA certificate for verifying chat servers
	if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL)) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}

int set_nonblocking(int sockfd) {
	int flags = fcntl(sockfd, F_GETFL, 0);
	if (flags == -1) return -1;
	return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;
  
  signal(SIGPIPE, SIG_IGN); // this is what stops the directory from crashing if you deregister a chat room


  signal(SIGPIPE, SIG_IGN); // this is what stops the directory from crashing if you deregister a chat room


	struct sockaddr_in cli_addr, serv_addr;
	fd_set readset;
	SSL_CTX *ctx;

	init_openssl();
	ctx = create_context();
	configure_context(ctx);

	int sockfd;
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("server: can't open stream socket");
		return EXIT_FAILURE;
	}

	int true = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&true, sizeof(true)) < 0) {
		perror("server: can't set stream socket address reuse option");
		return EXIT_FAILURE;
	}

	memset((char *)&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(SERV_TCP_PORT);

	if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		perror("server: can't bind local address");
		return EXIT_FAILURE;
	}

	struct chatServer {
		char IP_address[MAX];
		int port;
		char topic[MAX];
		LIST_ENTRY(chatServer) serverDirectory;
	};

	LIST_HEAD(serverDirectory_list_head, chatServer);
	struct serverDirectory_list_head head;
	LIST_INIT(&head);

	listen(sockfd, 5);
	fprintf(stderr, "Directory server listening on port %d\n", SERV_TCP_PORT);

	for (;;) {
		FD_ZERO(&readset);
		FD_SET(sockfd, &readset);
		int max_fd = sockfd;

		char s[MAX] = {'\0'};

		if (select(max_fd + 1, &readset, NULL, NULL, NULL) > 0) {
			int newsockfd;
			if (FD_ISSET(sockfd, &readset)) {
				socklen_t clilen = sizeof(cli_addr);
				newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
				if (newsockfd < 0) {
					perror("server: accept error");
					continue;
				}

				fprintf(stderr, "Accepted new connection from %s\n", inet_ntoa(cli_addr.sin_addr));

				// Set socket to non-blocking
				set_nonblocking(newsockfd);

				// Create SSL structure
				SSL *ssl = SSL_new(ctx);
				if (!ssl) {
					fprintf(stderr, "Failed to create SSL object\n");
					close(newsockfd);
					continue;
				}
				SSL_set_fd(ssl, newsockfd);

				// Set SSL to non-blocking mode
				SSL_set_mode(ssl, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

				// Accept SSL connection
				int ssl_err;
				while ((ssl_err = SSL_accept(ssl)) <= 0) {
					int err = SSL_get_error(ssl, ssl_err);
					if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
						// Need to retry, wait for socket to be ready
						fd_set tempset;
						FD_ZERO(&tempset);
						FD_SET(newsockfd, &tempset);
						
						if (err == SSL_ERROR_WANT_READ) {
							select(newsockfd + 1, &tempset, NULL, NULL, NULL);
						} else {
							select(newsockfd + 1, NULL, &tempset, NULL, NULL);
						}
						continue;
					} else {
						fprintf(stderr, "SSL handshake failed\n");
						ERR_print_errors_fp(stderr);
						SSL_free(ssl);
						close(newsockfd);
						goto next_connection;
					}
				}

				fprintf(stderr, "SSL handshake successful\n");

				// Read the request - need to know what type of client this is
				ssize_t nread = SSL_read(ssl, s, MAX - 1);
				if (nread <= 0) {
					int err = SSL_get_error(ssl, nread);
					if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
						fprintf(stderr, "Error reading from client\n");
					}
					SSL_shutdown(ssl);
					SSL_free(ssl);
					close(newsockfd);
					continue;
				}
				s[nread] = '\0';

				fprintf(stderr, "Received message: %s\n", s);

				// Handle different message types
				if (s[0] == 'R') {
					fprintf(stderr, "Processing registration request\n");
					// Registration - MUST verify certificate
					X509 *cert = SSL_get_peer_certificate(ssl);
					if (!cert) {
						fprintf(stderr, "Registration attempt without certificate\n");
						char error_msg[MAX];
						snprintf(error_msg, MAX, "Error: Certificate required for registration\n");
						SSL_write(ssl, error_msg, strnlen(error_msg, MAX));
						SSL_shutdown(ssl);
						SSL_free(ssl);
						close(newsockfd);
						continue;
					}

					char cn[256];
					X509_NAME *subject = X509_get_subject_name(cert);
					X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
					X509_free(cert);

					struct chatServer *server = calloc(1, sizeof(struct chatServer));
					if (!server) {
						fprintf(stderr, "Failed to allocate memory for server\n");
						SSL_shutdown(ssl);
						SSL_free(ssl);
						close(newsockfd);
						continue;
					}

					char *address = inet_ntoa(cli_addr.sin_addr);
					int i;
					for (i = 0; i < MAX - 1 && address[i] != '\0'; i++) {
						server->IP_address[i] = address[i];
					}
					server->IP_address[i] = '\0';

					// Expect format: R <topic with spaces> <port>
					// Skip leading "R "
					char *msg = s + 2;

					// Find last space before the port
					char *last_space = NULL;
					for (char *p = msg; *p != '\0'; p++) {
						if (*p == ' ') {
							last_space = p;
						}
					}
					/* after the loop, last_space points to the last ' ' in msg, or stays NULL if none */


					
					if (!last_space) {
						fprintf(stderr, "Error parsing registration message (missing port)\n");
						free(server);
						SSL_shutdown(ssl);
						SSL_free(ssl);
						close(newsockfd);
						continue;
					}

					// Extract port
					if (sscanf(last_space + 1, "%d", &server->port) != 1) {
						fprintf(stderr, "Error parsing port number in registration message\n");
						free(server);
						SSL_shutdown(ssl);
						SSL_free(ssl);
						close(newsockfd);
						continue;
					}

					// Extract topic (everything before the last space)
					size_t topic_len = last_space - msg;
					if (topic_len >= MAX) topic_len = MAX - 1;

					snprintf(server->topic, MAX, "%.*s", (int)topic_len, msg);

					fprintf(stderr, "Parsed: topic='%s', IP='%s', port=%d, CN='%s'\n", 
							server->topic, server->IP_address, server->port, cn);

					// Verify certificate CN matches topic
					if (strncasecmp(cn, server->topic, MAX) != 0) {
						fprintf(stderr, "Certificate CN '%s' does not match topic '%s'\n", cn, server->topic);
						char error_msg[MAX];
						snprintf(error_msg, MAX, "Error: Certificate mismatch\n");
						SSL_write(ssl, error_msg, strnlen(error_msg, MAX));
						free(server);
						SSL_shutdown(ssl);
						SSL_free(ssl);
						close(newsockfd);
						continue;
					}

					// Check for duplicates
					int duplicate_check = 0;
					struct chatServer *check_duplicates;
					LIST_FOREACH(check_duplicates, &head, serverDirectory) {
						if (strncasecmp(check_duplicates->topic, server->topic, MAX) == 0) {
							char duplicates[MAX];
							snprintf(duplicates, MAX, "Error: A server with the same name/topic already exists.\n");
							SSL_write(ssl, duplicates, strnlen(duplicates, MAX));
							free(server);
							duplicate_check = 1;
							break;
						}
					}

					if (duplicate_check == 0) {
						LIST_INSERT_HEAD(&head, server, serverDirectory);
						SSL_write(ssl, s, strnlen(s, MAX));
						fprintf(stderr, "Registered: %s at %s:%d\n", server->topic, server->IP_address, server->port);
					}

					SSL_shutdown(ssl);
					SSL_free(ssl);
					close(newsockfd);

				} else if (s[0] == 'L') {
					// List request - clients don't have certificates, that's OK
					char servers_list[MAX];
          memset(servers_list, 0, MAX);
					struct chatServer *current_servers;
					LIST_FOREACH(current_servers, &head, serverDirectory) {
						char single_server[MAX];
						snprintf(single_server, MAX, "%s %s %d\n", 
								 current_servers->topic, 
								 current_servers->IP_address, 
								 current_servers->port);
						
						// Check if there's room before adding
						if (strnlen(servers_list, MAX) + strnlen(single_server, MAX) < MAX - 1) {
							strncat(servers_list, single_server, MAX - strnlen(servers_list, MAX) - 1);
						} else {
							fprintf(stderr, "Warning: Server list buffer full, some servers not included\n");
							break;
						}
					}
					
					fprintf(stderr, "Sending server list (%zu bytes)\n", strnlen(servers_list, MAX));
					SSL_write(ssl, servers_list, strnlen(servers_list, MAX));
					SSL_shutdown(ssl);
					SSL_free(ssl);
					close(newsockfd);

				} else if (s[0] == 'D') {
					fprintf(stderr, "Processing deregistration request\n");
					// Deregistration - verify certificate
					X509 *cert = SSL_get_peer_certificate(ssl);
					if (!cert) {
						fprintf(stderr, "Deregistration attempt without certificate\n");
						SSL_shutdown(ssl);
						SSL_free(ssl);
						close(newsockfd);
						continue;
					}
					X509_free(cert);

					char name_remove[MAX];
          memset(name_remove, 0, MAX);
          
          // Skip "D " and get the rest of the string (the topic name)
          if (nread < 3) {
              fprintf(stderr, "Malformed deregister message\n");
              SSL_shutdown(ssl);
              SSL_free(ssl);
              close(newsockfd);
              continue;
          }
          
          char *topic_start = s + 2;  // Skip "D "
          
          // Copy the topic name, handling spaces
          int i = 0;
          while (i < MAX - 1 && topic_start[i] != '\0' && topic_start[i] != '\n' && topic_start[i] != '\r') {
              name_remove[i] = topic_start[i];
              i++;
          }
          name_remove[i] = '\0';
          
          fprintf(stderr, "Attempting to deregister: '%s'\n", name_remove);

					struct chatServer *remove_temp = NULL;
					struct chatServer *remove_server;
					LIST_FOREACH(remove_server, &head, serverDirectory) {
						fprintf(stderr, "Comparing '%s' with '%s'\n", name_remove, remove_server->topic);
						if (strncasecmp(name_remove, remove_server->topic, MAX) == 0) {
							remove_temp = remove_server;
							break;
						}
					}

					if (remove_temp != NULL) {
						fprintf(stderr, "Chatroom '%s' was deregistered\n", remove_temp->topic);
						LIST_REMOVE(remove_temp, serverDirectory);
						free(remove_temp);
					} else {
						fprintf(stderr, "Attempted to deregister non-existent chatroom: '%s'\n", name_remove);
					}

					fprintf(stderr, "Closing connection after deregistration\n");
					SSL_shutdown(ssl);
					SSL_free(ssl);
					close(newsockfd);
					fprintf(stderr, "Connection closed successfully\n");

				} else {
					fprintf(stderr, "Invalid request: %c\n", s[0]);
					snprintf(s, MAX, "Invalid request");
					SSL_write(ssl, s, strnlen(s, MAX));
					SSL_shutdown(ssl);
					SSL_free(ssl);
					close(newsockfd);
				}

				next_connection:
				continue;
			}
		}
	}

	SSL_CTX_free(ctx);
	cleanup_openssl();
	return 0;
}