#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "inet.h"
#include "common.h"
#include <sys/queue.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define _POSIX_C_SOURCE 200809L
#define CA_FILE "certs/ca-cert.pem" 

void init_openssl() {
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
	EVP_cleanup();
}

SSL_CTX *create_context() {
	const SSL_METHOD *method = TLS_client_method();
	SSL_CTX *ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Set minimum TLS version to 1.3
	SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

	// Load CA certificate
	if (!SSL_CTX_load_verify_locations(ctx, CA_FILE, NULL)) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}

	// Require server certificate verification
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	return ctx;
}

int main() {
	init_openssl();
	SSL_CTX *ctx = create_context();

	int sockfd;
	struct sockaddr_in dir_serv_addr;
	fd_set readset;
	char s[MAX] = {'\0'};

	// Set up directory server address
	memset((char *)&dir_serv_addr, 0, sizeof(dir_serv_addr));
	dir_serv_addr.sin_family = AF_INET;
	dir_serv_addr.sin_addr.s_addr = inet_addr(SERV_HOST_ADDR);
	dir_serv_addr.sin_port = htons(SERV_TCP_PORT);

	// Create socket and connect to directory server
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("client: can't open stream socket");
		return EXIT_FAILURE;
	}

	if (connect(sockfd, (struct sockaddr *)&dir_serv_addr, sizeof(dir_serv_addr)) < 0) {
		perror("client: can't connect to server");
		return EXIT_FAILURE;
	}

	// Create SSL connection
	SSL *dir_ssl = SSL_new(ctx);
	SSL_set_fd(dir_ssl, sockfd);

	if (SSL_connect(dir_ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		return EXIT_FAILURE;
	}

	// Verify directory server certificate
	X509 *cert = SSL_get_peer_certificate(dir_ssl);
	if (!cert) {
		fprintf(stderr, "No certificate from directory server\n");
		return EXIT_FAILURE;
	}

	char cn[256];
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn));
	X509_free(cert);

	if (strncmp(cn, "Directory Server", 256) != 0) {
		fprintf(stderr, "Certificate CN mismatch: expected 'Directory Server', got '%s'\n", cn);
		return EXIT_FAILURE;
	}

	fprintf(stderr, "Connected to %s \n", cn);

	// Request list of chat rooms
	char getList[2] = "L";
	SSL_write(dir_ssl, getList, 1);

	fprintf(stderr, "Enter the name of the chat room you want to join (ie: KSU Football): \n");
	fprintf(stderr, "Current Chat Rooms:\n");
	
	// Clear the buffer first
	char response_from_directory[MAX];
	memset(response_from_directory, 0, MAX);

	// Read and null-terminate
	ssize_t nread = SSL_read(dir_ssl, response_from_directory, MAX - 1);
	if (nread <= 0) {
		fprintf(stderr, "Error reading from directory server\n");
		SSL_shutdown(dir_ssl);
		SSL_free(dir_ssl);
		close(sockfd);
		SSL_CTX_free(ctx);
		cleanup_openssl();
		return EXIT_FAILURE;
	}
	response_from_directory[nread] = '\0';

	struct chatServer {
		char IP_address[MAX];
		int port;
		char topic[MAX];
		LIST_ENTRY(chatServer) serverDirectory;
	};

	LIST_HEAD(serverDirectory_list_head, chatServer);
	struct serverDirectory_list_head head;
	LIST_INIT(&head);

	// Parse line by line manually
	char *current = response_from_directory;
	char *line_end;

	while (*current != '\0') {
		// Find the end of the current line
		line_end = current;
		while (*line_end != '\0' && *line_end != '\n') {
			line_end++;
		}
		
		// Calculate line length
		size_t line_len = line_end - current;
		
		// Skip empty lines
		if (line_len == 0) {
			if (*line_end == '\n') current = line_end + 1;
			else break;
			continue;
		}
		
		// Copy line to temporary buffer
		char line[MAX];
		memset(line, 0, MAX);
		if (line_len >= MAX) line_len = MAX - 1;
		snprintf(line, line_len + 1, current);
		line[line_len] = '\0';
		
		// Allocate new node
		struct chatServer *node = malloc(sizeof(struct chatServer));
		if (!node) {
			perror("malloc failed");
			exit(EXIT_FAILURE);
		}
		
		memset(node->topic, 0, MAX);
		memset(node->IP_address, 0, MAX);
		node->port = 0;
		
		// Parse: "Topic Name IP Port"
		// Find last space (before port)
		char *last_space = NULL;
		char *p = line;
		while (*p != '\0') {
			if (*p == ' ') last_space = p;
			p++;
		}
		
		if (!last_space) {
			fprintf(stderr, "Malformed line: %s\n", line);
			free(node);
			if (*line_end == '\n') current = line_end + 1;
			else break;
			continue;
		}
		
		// Extract port
		if (sscanf(last_space + 1, "%d", &node->port) != 1) {
			fprintf(stderr, "Error parsing port number in line: %s\n", line);
			free(node);
			if (*line_end == '\n') current = line_end + 1;
			else break;
			continue;
		}
		
		// Find second-to-last space (before IP)
		char *second_last_space = NULL;
		p = line;
		while (p < last_space) {
			if (*p == ' ') second_last_space = p;
			p++;
		}
		
		if (!second_last_space) {
			fprintf(stderr, "Malformed line: %s\n", line);
			free(node);
			if (*line_end == '\n') current = line_end + 1;
			else break;
			continue;
		}
		
		// Extract IP address
		size_t ip_len = last_space - second_last_space - 1;
		if (ip_len >= MAX) ip_len = MAX - 1;
		snprintf(node->IP_address, MAX, second_last_space + 1);
		node->IP_address[ip_len] = '\0';
		
		// Extract topic
		size_t topic_len = second_last_space - line;
		if (topic_len >= MAX) topic_len = MAX - 1;
		snprintf(node->topic, MAX, line);
		node->topic[topic_len] = '\0';
		
		// Add node to linked list
		LIST_INSERT_HEAD(&head, node, serverDirectory);
		
		// Move to next line
		if (*line_end == '\n') {
			current = line_end + 1;
		} else {
			break;
		}
	}

	int count = 0;
	struct chatServer *iterprint;
	LIST_FOREACH(iterprint, &head, serverDirectory) {
		printf("Topic: %s, IP: %s, Port: %d\n", iterprint->topic, iterprint->IP_address, iterprint->port);
		count++;
	}
	
	if (count > 0) {
		fprintf(stderr, "Enter in the topic of the chat room that you would like to join: ");
	} else {
		fprintf(stderr, "There are currently no chatrooms for you to join.\n");
		SSL_CTX_free(ctx);
		cleanup_openssl();
		return EXIT_FAILURE;
	}

	// Select chat room
	char input[MAX];
	if (fgets(input, MAX, stdin) != NULL) {
		int i = 0;
		while (i < MAX && input[i] != '\0' && input[i] != '\n' && input[i] != '\r') {
			i++;
		}
		input[i] = '\0';

		struct chatServer *iter;
		struct chatServer *selected = NULL;
		LIST_FOREACH(iter, &head, serverDirectory) {
			if (strncmp(iter->topic, input, MAX) == 0) {
				selected = iter;
				break; // stop searching
			}
		}

		if (!selected) {
			fprintf(stderr, "Chat room '%s' not found\n", input);
			SSL_shutdown(dir_ssl);
			SSL_free(dir_ssl);
			close(sockfd);
			SSL_CTX_free(ctx);
			cleanup_openssl();
			return EXIT_FAILURE;
		}

		// Close directory server connection
		SSL_shutdown(dir_ssl);
		SSL_free(dir_ssl);
		close(sockfd);

		// Create TCP socket for chat server
		int chatsockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (chatsockfd < 0) {
			perror("client: can't open chat stream socket");
			SSL_CTX_free(ctx);
			cleanup_openssl();
			return EXIT_FAILURE;
		}

		// Set up chat server address
		struct sockaddr_in chat_serv_addr;
		memset(&chat_serv_addr, 0, sizeof(chat_serv_addr));
		chat_serv_addr.sin_family = AF_INET;
		chat_serv_addr.sin_addr.s_addr = inet_addr(selected->IP_address);
		chat_serv_addr.sin_port = htons((uint16_t)selected->port);

		if (connect(chatsockfd, (struct sockaddr *)&chat_serv_addr, sizeof(chat_serv_addr)) < 0) {
			perror("client: can't connect to chat server");
			close(chatsockfd);
			SSL_CTX_free(ctx);
			cleanup_openssl();
			return EXIT_FAILURE;
		}

		// Create SSL connection
		SSL *chat_ssl = SSL_new(ctx);
		if (!chat_ssl) {
			perror("SSL_new failed");
			close(chatsockfd);
			SSL_CTX_free(ctx);
			cleanup_openssl();
			return EXIT_FAILURE;
		}

		SSL_set_fd(chat_ssl, chatsockfd);
		SSL_set_mode(chat_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

		if (SSL_connect(chat_ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			SSL_free(chat_ssl);
			close(chatsockfd);
			SSL_CTX_free(ctx);
			cleanup_openssl();
			return EXIT_FAILURE;
		}

		// Verify certificate
		cert = SSL_get_peer_certificate(chat_ssl);
		if (!cert) {
			fprintf(stderr, "No certificate from chat server\n");
			SSL_shutdown(chat_ssl);
			SSL_free(chat_ssl);
			close(chatsockfd);
			SSL_CTX_free(ctx);
			cleanup_openssl();
			return EXIT_FAILURE;
		}

		
		X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn, sizeof(cn));
		X509_free(cert);

		if (strncasecmp(cn, selected->topic, MAX) != 0) {
			fprintf(stderr, "Certificate CN mismatch: expected '%s', got '%s'\n", selected->topic, cn);
			SSL_shutdown(chat_ssl);
			SSL_free(chat_ssl);
			close(chatsockfd);
			SSL_CTX_free(ctx);
			cleanup_openssl();
			return EXIT_FAILURE;
		}

		fprintf(stderr, "Connected to chat server '%s'\n", selected->topic);

		for (;;) {
			FD_ZERO(&readset);
			FD_SET(STDIN_FILENO, &readset);
			FD_SET(chatsockfd, &readset);

			if (select(chatsockfd + 1, &readset, NULL, NULL, NULL) > 0) {
				// Check user input
				if (FD_ISSET(STDIN_FILENO, &readset)) {
					if (fgets(s, MAX, stdin) != NULL) {
						SSL_write(chat_ssl, s, strnlen(s, MAX));
					} else {
						fprintf(stderr, "%s:%d Error reading user input\n", __FILE__, __LINE__);
					}
				}

				// Check message from server
				if (FD_ISSET(chatsockfd, &readset)) {
					nread = SSL_read(chat_ssl, s, MAX - 1);
					if (nread <= 0) {
						int err = SSL_get_error(chat_ssl, nread);
						if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
							fprintf(stderr, "%s:%d Error reading from server\n", __FILE__, __LINE__);
							break;
						}
					} else {
						s[nread] = '\0';
						fprintf(stderr, "%s\n", s);
					}
				}
			}
		}
		SSL_shutdown(chat_ssl);
		SSL_free(chat_ssl);
		close(chatsockfd);
		SSL_CTX_free(ctx);
		cleanup_openssl();
		return 0;
	}
	
	SSL_CTX_free(ctx);
	cleanup_openssl();
	return EXIT_FAILURE;
}