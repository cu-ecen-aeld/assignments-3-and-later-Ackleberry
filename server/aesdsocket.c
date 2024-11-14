/** 
 * server.c -- a stream socket server demo
**/

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
#include "queue.h"
#include <pthread.h>
#include <time.h>

#define PORT "9000"  // the port users will be connecting to
#define BACKLOG 10	 // how many pending connections queue will hold

#define FILENAME "/var/tmp/aesdsocketdata"
#define INITIAL_RX_BUF_SIZE 256

static pthread_mutex_t _file_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct client_info_s {
    int fd;
    bool is_complete;
    pthread_t t_id;
    char addr_str[INET6_ADDRSTRLEN];
} client_info_t;

typedef struct slist_data_s slist_data_t;
struct slist_data_s {
    client_info_t *c_info;
    SLIST_ENTRY(slist_data_s) entries;
};

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
    size_t buf_size = INITIAL_RX_BUF_SIZE;
    size_t total_rx_bytes = 0;
    ssize_t rx_bytes;

    char *buffer = malloc(INITIAL_RX_BUF_SIZE);
    if (!buffer) {
        syslog(LOG_ERR, "Failed to allocate message buffer\n");
        return NULL;
    }

    while (1) {
        rx_bytes = recv(client_socket, buffer + total_rx_bytes, buf_size - total_rx_bytes, 0);
        
        if (rx_bytes <= 0) {
            free(buffer);
            return NULL;
        }

        total_rx_bytes += rx_bytes;

        // Did we get a newline?
        if (memchr(buffer + total_rx_bytes - rx_bytes, '\n', rx_bytes)) {
            break;
        }

        // If buffer is full, expand it
        if (total_rx_bytes == buf_size) {
            buf_size *= 2; // Double the size of the buffer
            char* new_buffer = realloc(buffer, buf_size);
            if (!new_buffer) {
                syslog(LOG_ERR, "Failed to reallocate message buffer\n");
                free(buffer);
                return NULL;
            }
            buffer = new_buffer;
        }
    }

    buffer[total_rx_bytes] = '\0';
    return buffer;
}

int _append_str_to_file(const char *str, const char *filename) {
    pthread_mutex_lock(&_file_mutex);

    FILE *file = fopen(filename, "a");
    if (file == NULL) {
        syslog(LOG_ERR, "Failed to open file '%s'", filename);
        pthread_mutex_unlock(&_file_mutex);
        return -1;
    }

    if (fputs(str, file) == EOF) {
        syslog(LOG_ERR, "Failed to write to file '%s'", filename);
        fclose(file);
        pthread_mutex_unlock(&_file_mutex);
        return -1;
    }

    if (fclose(file) != 0) {
        syslog(LOG_ERR, "Failed to close file '%s'", filename);
        pthread_mutex_unlock(&_file_mutex);
        return -1;
    }

    pthread_mutex_unlock(&_file_mutex);
    return 0;
}

void *_client_handler(void *arg) 
{
    client_info_t *c_info = (client_info_t *)arg;

    char *msg = _receive_message(c_info->fd);
    if (msg) {
        syslog(LOG_DEBUG, "Received: '%s'\n", msg);
        _append_str_to_file(msg, FILENAME);
        free(msg);
        _send_file(c_info->fd, FILENAME);
    } else {
        syslog(LOG_DEBUG, "Error receiving message\n");
    }

    c_info->is_complete = true;
    return NULL;
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
    int saved_errno = errno;

    if (sig == SIGINT || sig == SIGTERM) {
        syslog(LOG_ERR, "Caught signal, exiting...");
        if (_sockfd != -1) {
            close(_sockfd);
        }
        remove(FILENAME);
    }

    errno = saved_errno;
    exit(0);
}

static void _timer_thread(union sigval sigval)
{
    (void)sigval;

    time_t t = time(NULL);
    struct tm *tm_ptr = localtime(&t);
    if (tm_ptr == NULL) {
        fprintf(stderr, "Local time error.\n");
        return;
    }

    char time_msg[128] = "";
    if (strftime(time_msg, sizeof(time_msg), "timestamp:%a, %d %b %Y %T %z\n", tm_ptr) == 0) {
        fprintf(stderr, "strftime returned 0.\n");
        return;
    }

    if (_append_str_to_file(time_msg, FILENAME)) {
        fprintf(stderr, "Failed to append to file.\n");
        return;
    }
}

int main(int argc, char *argv[])
{
    int rv;

    bool is_daemon = false;
    if ((argc == 2) && (strcmp(argv[1], "-d") == 0)) {
        printf("Running server as daemon...\n");
        is_daemon = true;
    }

    if (pthread_mutex_init(&_file_mutex, NULL) != 0) {
        fprintf(stderr, "Error %d (%s) initializing thread mutex!\n", errno, strerror(errno));
        return -1;
    }

    timer_t timerid;
    struct sigevent sev;
    int clock_id = CLOCK_MONOTONIC;
    memset(&sev, 0, sizeof(struct sigevent));
    sev.sigev_notify = SIGEV_THREAD;
    sev.sigev_value.sival_ptr = &timerid;
    sev.sigev_notify_function = _timer_thread;

    if (timer_create(clock_id, &sev, &timerid) != 0) {
        printf("Error %d (%s) creating timer!\n", errno, strerror(errno));
    }

    struct itimerspec its = {
        .it_value.tv_sec = 10, .it_value.tv_nsec = 0,
        .it_interval.tv_sec = 10, .it_interval.tv_nsec = 0
    };

    if (timer_settime(timerid, 0, &its, NULL) != 0) {
        printf("Error %d (%s) arming timer!\n", errno, strerror(errno));
    }

    // Hints suggests restrictions on what getaddrinfo() structs are returned.
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = AI_PASSIVE; // For wildcard IP address

    // Get a linked list of addrinfo structs
    struct addrinfo *servinfo;
    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the address structs and bind to the first we can
    struct addrinfo *p;
    for (p = servinfo; p != NULL; p = p->ai_next) {
        // Attempt to create a socket endpoint...
        if ((_sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            perror("server: socket");
            continue;
        }

        // Endpoint created! Now set its options...
        // SOL_SOCKET - Manipulate options at the sockets API level
        // SO_REUSEADDR - Allow sockets to bind to a port that still isn't fully released by the OS
        int yes = 1;
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

        break; /* Success! */
    }

    freeaddrinfo(servinfo);

    /* Make sure we didn't iterate through the whole address list */
    if (p == NULL)  {
        fprintf(stderr, "server: failed to bind\n");
        return -1;
    }

    if (listen(_sockfd, BACKLOG) == -1) {
        syslog(LOG_ERR, "listen() failed!");
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

    SLIST_HEAD(slisthead, slist_data_s) head;
    SLIST_INIT(&head);

    while (_sockfd != -1) {
        struct sockaddr_storage client_addr;
        socklen_t addr_size = sizeof(client_addr);
        int client_fd = accept(_sockfd, (struct sockaddr *)&client_addr, &addr_size);
        if (client_fd < 0) {
            syslog(LOG_ERR, "Failed to accept client connection.");
            continue;
        }

        client_info_t *c_info = malloc(sizeof(client_info_t));
        c_info->fd = client_fd;
        c_info->is_complete = false;
        c_info->t_id = 0;

        inet_ntop(client_addr.ss_family, 
                  _get_in_addr((struct sockaddr *)&client_addr), 
                  c_info->addr_str, 
                  sizeof(c_info->addr_str));
        syslog(LOG_DEBUG, "Accepted connection from %s", c_info->addr_str);

        // Create thread to handle client
        if (pthread_create(&c_info->t_id, NULL, _client_handler, (void *)c_info) != 0) {
            perror("Failed to create thread");
            close(c_info->fd);
            free(c_info);
            continue;
        }

        // Add this thread to the linked list
        slist_data_t *d_ptr = malloc(sizeof(slist_data_t));
        d_ptr->c_info = c_info;
        SLIST_INSERT_HEAD(&head, d_ptr, entries);

        // Check if any thread has completed, if so free up resources
        struct slist_data_s *iter, *tmp = NULL;
        SLIST_FOREACH_SAFE(iter, &head, entries, tmp) {
            if (iter->c_info->is_complete) {
                close(iter->c_info->fd);
                syslog(LOG_DEBUG, "Closed connection from %s", iter->c_info->addr_str);
                pthread_join(iter->c_info->t_id, NULL);
                SLIST_REMOVE(&head, iter, slist_data_s, entries);
                free(iter->c_info);
                free(iter);
            }
        }
    }

    // Ensure all threads have completed and free up resources
    struct slist_data_s *iter, *tmp = NULL;
    SLIST_FOREACH_SAFE(iter, &head, entries, tmp) {
        if (iter->c_info->is_complete) {
            close(iter->c_info->fd);
            syslog(LOG_DEBUG, "Closed connection from %s", iter->c_info->addr_str);
            pthread_join(iter->c_info->t_id, NULL);
            SLIST_REMOVE(&head, iter, slist_data_s, entries);
            free(iter->c_info);
            free(iter);
        }
    }

    if (timer_delete(timerid) != 0) {
        printf("Error %d (%s) deleting timer!\n", errno, strerror(errno));
    }

    close(_sockfd);
    return 0;
}
