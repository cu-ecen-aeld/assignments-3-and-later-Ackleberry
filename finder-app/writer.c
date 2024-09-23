#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

int main(int argc, char *argv[])
{
    openlog(argv[0], LOG_PID | LOG_CONS, LOG_USER);

    if (argc != 3) {
        syslog(LOG_ERR, "Usage: %s <file_path> <text_string>\n", argv[0]);
        return 1;
    }

    const char *file = argv[1];
    const char *content = argv[2];
    syslog(LOG_DEBUG, "Writing %s to %s", content, file);

    int fd = creat(file, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        syslog(LOG_ERR, "creat() failed!");
        return 1;
    }

    size_t nbytes = write(fd, content, strlen(content));
    if (nbytes != strlen(content)) {
        syslog(LOG_ERR, "write() failed!");
        return 1; 
    }

    close(fd);
    closelog();

    return 0;
}