#include "systemcalls.h"

#include <sys/wait.h>
#include <sys/fcntl.h>

#include <stdlib.h>
#include <unistd.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    if (!cmd) {
        return false;
    }

    int ret = system(cmd);
    if (ret == -1) {
        perror("system() failed!");
        return false;
    }

    if (WIFEXITED(ret)) {
        int exit_code = WEXITSTATUS(ret);
        return exit_code == EXIT_SUCCESS;
    } else {
        return false;
    }
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/
bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i = 0; i < count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    va_end(args);

    /**
     * Create a new process by duplicating the current process. The new child process begins executing
     * this same code right after the fork call.
     */
    pid_t cpid = fork();
    if (cpid == -1) {
        perror("fork() failed!");
        return false;
    }

    if (cpid == 0) {
        /* 0 - Child process */
        /* Replace the forked process with a new program. */
        execv(command[0], command);

        /* The new program should never run this code. If it does, it failed. */
        perror("execv() failed!");
        _exit(1);
    } else {
        /* Parent process */
        int wstatus;
        /* Wait for the child process to complete and get its status */
        if (waitpid(cpid, &wstatus, 0) == -1) {
            perror("waitpid() failed!");
            return false;
        }

        if (WIFEXITED(wstatus)) {
            int exit_code = WEXITSTATUS(wstatus);
            printf("Child '%d' exited with exit status '%d'\n", cpid, exit_code);
            return exit_code == EXIT_SUCCESS;
        }
    }

    return true;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i = 0; i < count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    va_end(args);

    int fd = open(outputfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if (fd < 0) {
        perror("open() failed!");
        return false;
    }
    /**
     * Create a new process by duplicating the current process. The new child process begins executing
     * this same code right after the fork call.
     */
    pid_t cpid = fork();
    switch (cpid) {
        case -1:;
            perror("fork() failed!");
            close(fd);
            return false;
        case 0:; /* 0 - Child process */
            /* Duplicate the file descriptor in the child process, send stdout of the child to it */
            if (dup2(fd, STDOUT_FILENO) < 0) {
                perror("dup2() failed!");
                close(fd);
                _exit(1);
            }
            close(fd);

            /* Replace the forked process with a new program. Its output should go to the stdout file */
            execv(command[0], command);

            /* The new program should never run this code. If it does, it failed. */
            perror("execv() failed!");
            _exit(1);
        default:; /* Parent process */
            close(fd);
            int wstatus;
            /* Wait for the child process to complete and get its status */
            if (waitpid(cpid, &wstatus, 0) == -1) {
                perror("waitpid() failed!");
                return false;
            }

            if (WIFEXITED(wstatus)) {
                printf("Child '%d' exited with exit status '%d'\n", cpid, WEXITSTATUS(wstatus));
            } else if (WIFSIGNALED(wstatus)) {
                printf("Child '%d' was killed by signal '%d'\n", cpid, WTERMSIG(wstatus));
            }
    }

    return true;
}
