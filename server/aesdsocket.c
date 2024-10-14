/*
** server.c -- a stream socket server demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <syslog.h>
#include <stdbool.h>

#define PORT "9000"  // the port users will be connecting to
#define BACKLOG 10	 // how many pending connections queue will hold
#define FILENAME "/var/tmp/aesdsocketdata"
#define INITIAL_RX_BUF_SIZE 256
#define BUFFER_GROWTH_FACTOR 2

int _sockfd = -1;

void _send_file(int client_socket, const char *filepath) {

    FILE *file = fopen(filepath, "r");
    if (file == NULL) {
		syslog(LOG_ERR, "Error opening file: '%s'\n", filepath);
        return;
    }

    char *buffer = NULL;
    size_t bufsize = 0;
    ssize_t line_size;
    while ((line_size = getline(&buffer, &bufsize, file)) != -1) {
        send(client_socket, buffer, line_size, 0);
    }

    free(buffer);
    fclose(file);
}

char *_receive_message(int client_socket) {
    size_t buffer_size = INITIAL_RX_BUF_SIZE;
    size_t total_bytes_received = 0;
    ssize_t bytes_received;

    char *buffer = malloc(INITIAL_RX_BUF_SIZE);
    if (!buffer) {
        perror("Failed to allocate initial buffer");
        return NULL;
    }

    while (1) {
        bytes_received = recv(client_socket, buffer + total_bytes_received, 
                              buffer_size - total_bytes_received, 0);
        
        if (bytes_received <= 0) {
            free(buffer);
            return NULL;  // Error or connection closed
        }

        total_bytes_received += bytes_received;

        // Check if we've received a newline
        if (memchr(buffer + total_bytes_received - bytes_received, '\n', bytes_received)) {
            break;  // Found newline, message complete
        }

        // If buffer is full, expand it
        if (total_bytes_received == buffer_size) {
            buffer_size *= BUFFER_GROWTH_FACTOR;
            char* new_buffer = realloc(buffer, buffer_size);
            if (!new_buffer) {
                perror("Failed to reallocate buffer");
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
    }

    // Null-terminate the string
    buffer[total_bytes_received] = '\0';

    return buffer;
}

int _append_str_to_file(const char *str, const char *filename) {
    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        perror("Failed to open file");
        return -1;
    }

    if (fputs(str, file) == EOF) {
        perror("Failed to write to file");
        fclose(file);
        return -1;
    }

    if (fclose(file) != 0) {
        perror("Failed to close file");
        return -1;
    }

    return 0;
}

static int _client_handler(int client_fd) 
{
	char *msg = _receive_message(client_fd);
	if (msg) {
		syslog(LOG_DEBUG, "Received: '%s'\n", msg);
	} else {
		syslog(LOG_DEBUG, "Error receiving message\n");
	}

	_append_str_to_file(msg, FILENAME);
	free(msg);

	_send_file(client_fd, FILENAME);

	return 0;
}

// get sockaddr, IPv4 or IPv6:
static void *_get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void _sig_handler(int sig)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

	if (sig == SIGINT || sig == SIGTERM) {
		syslog(LOG_ERR, "Caught signal, exiting");
        if (_sockfd != -1) {
            close(_sockfd);
        }
    	remove(FILENAME);
	}

    errno = saved_errno;
	exit(0);
}

int main(int argc, char *argv[])
{
	struct addrinfo hints;
	struct addrinfo *servinfo;
	struct addrinfo *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	int yes = 1;
	char s[INET6_ADDRSTRLEN];
	int rv;
	bool is_daemon = false;

	if ((argc == 2) && (strcmp(argv[1], "-d") == 0)) {
		printf("Running server as daemon...\n");
		is_daemon = true;
	}

	// Hints imposes restrictions on what addrinfo structs are returned.
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE; // use my IP

	// Get a linked list of addrinfo structs
	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return -1;
	}

	// loop through all the results and bind to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		// Attempt to create a socket endpoint...
		if ((_sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		// Endpoint created! Now set its options...
		// SOL_SOCKET - Manipulate options at the sockets API level
		// SO_REUSEADDR - Allow sockets to bind to a port that still isn't fully released by the OS
		if (setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
			return -1;
		}

		// Assign an address to the socket
		if (bind(_sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(_sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo);

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		return -1;
	}

	if (listen(_sockfd, BACKLOG) == -1) {
		perror("listen");
		return -1;
	}

	if (is_daemon) {
		if (daemon(0, 0) == -1) {
			syslog(LOG_ERR, "Failed to launch daemon!");
			return -1;
		}
	}

	struct sigaction sa;
    sa.sa_handler = _sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if ((sigaction(SIGINT, &sa, NULL) == -1) || (sigaction(SIGTERM, &sa, NULL) == -1)) {
        syslog(LOG_ERR, "Failed to setup signal handlers!");
        return -1;
    }

	remove(FILENAME);

	syslog(LOG_DEBUG, "Listening for a new connection...");

	while (1) {
		sin_size = sizeof(their_addr);
		int client_fd = accept(_sockfd, (struct sockaddr *)&their_addr, &sin_size);
		if (client_fd < 0) {
			syslog(LOG_ERR, "Failed to accept client connection.");
			perror("accept");
			continue;
		}

		inet_ntop(their_addr.ss_family, _get_in_addr((struct sockaddr *)&their_addr), s, sizeof(s));
		syslog(LOG_DEBUG, "Accepted connection from %s", s);
		_client_handler(client_fd);
		close(client_fd);
		syslog(LOG_DEBUG, "Closed connection from %s", s);
	}

    close(_sockfd);

	return 0;
}
