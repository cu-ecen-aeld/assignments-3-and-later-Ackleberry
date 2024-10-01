#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void *thread_param)
{
    struct thread_data *args = (struct thread_data *)thread_param;
    usleep(args->wait_to_obtain_ms);
    pthread_mutex_lock(args->mutex);
    usleep(args->wait_to_release_ms);
    pthread_mutex_unlock(args->mutex);
    args->thread_complete_success = true;
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    struct thread_data *args = (struct thread_data *)calloc(1, sizeof(*args));
    args->mutex = mutex;
    args->wait_to_obtain_ms = wait_to_obtain_ms;
    args->wait_to_release_ms = wait_to_release_ms;

    return (pthread_create(thread, NULL, threadfunc, args) == 0);
}

