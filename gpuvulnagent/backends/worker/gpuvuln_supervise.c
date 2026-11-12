/*
 * gpuvuln_supervise.c -- independent wait-status reporter.
 *
 * Why this exists: a container's exit status cannot tell you whether a program called
 * exit(139) or was killed by SIGSEGV. Docker reports 139 for both, and so does a shell.
 * Inferring "crash" from the number is a guess, and this project does not report guesses
 * as crashes.
 *
 * This supervisor is started as PID 1 of the experiment. It forks the real command,
 * waits for it, and records exactly what happened -- exited with a code, or terminated by
 * a signal -- in a status file that the harness reads afterwards.
 *
 * The status file is opened with O_NOFOLLOW so a symlink planted in the work directory
 * cannot redirect the write outside the experiment.
 *
 * Usage:  gpuvuln_supervise <status_path> <program> [args...]
 * Exit:   the child's exit code, or 128 + signal number (the usual convention).
 *
 * Build:  gcc -O2 -static -o gpuvuln_supervise gpuvuln_supervise.c
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *signal_name(int number) {
    switch (number) {
        case SIGHUP: return "SIGHUP";
        case SIGINT: return "SIGINT";
        case SIGQUIT: return "SIGQUIT";
        case SIGILL: return "SIGILL";
        case SIGTRAP: return "SIGTRAP";
        case SIGABRT: return "SIGABRT";
        case SIGBUS: return "SIGBUS";
        case SIGFPE: return "SIGFPE";
        case SIGKILL: return "SIGKILL";
        case SIGUSR1: return "SIGUSR1";
        case SIGSEGV: return "SIGSEGV";
        case SIGUSR2: return "SIGUSR2";
        case SIGPIPE: return "SIGPIPE";
        case SIGALRM: return "SIGALRM";
        case SIGTERM: return "SIGTERM";
        case SIGXCPU: return "SIGXCPU";
        case SIGXFSZ: return "SIGXFSZ";
        case SIGSYS: return "SIGSYS";
        default: return "SIGUNKNOWN";
    }
}

/* Write one JSON object describing how the child ended. */
static int write_status(const char *path, pid_t child, int status, int exec_error) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    int exited = WIFEXITED(status) ? 1 : 0;
    int signaled = WIFSIGNALED(status) ? 1 : 0;
    int code = exited ? WEXITSTATUS(status) : -1;
    int signal_number = signaled ? WTERMSIG(status) : 0;
    const char *name = signaled ? signal_name(signal_number) : "";
    char body[512];
    int length = snprintf(body, sizeof(body),
                          "{\"exited\":%s,\"exit_code\":%d,\"signaled\":%s,"
                          "\"signal\":%d,\"signal_name\":\"%s\",\"child_pid\":%d,"
                          "\"exec_error\":%d}\n",
                          exited ? "true" : "false", code,
                          signaled ? "true" : "false", signal_number, name,
                          (int)child, exec_error);
    ssize_t written = write(fd, body, (size_t)length);
    int close_result = close(fd);
    (void)written;
    return close_result == 0 ? 0 : -1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <status_path> <program> [args...]\n", argv[0]);
        return 120;
    }
    const char *status_path = argv[1];

    /* Refuse a status path that is a symlink: the evidence must land where we intend. */
    struct stat probe;
    if (lstat(status_path, &probe) == 0 && S_ISLNK(probe.st_mode)) {
        fprintf(stderr, "supervise: status path is a symlink, refusing\n");
        return 121;
    }

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "supervise: fork failed: %s\n", strerror(errno));
        write_status(status_path, -1, 0, errno);
        return 122;
    }
    if (child == 0) {
        /* Child: replace this process with the experiment. */
        execvp(argv[2], &argv[2]);
        fprintf(stderr, "supervise: cannot execute %s: %s\n", argv[2], strerror(errno));
        _exit(127);
    }

    int status = 0;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            write_status(status_path, child, 0, errno);
            return 123;
        }
    }
    write_status(status_path, child, status, 0);

    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 124;
}
