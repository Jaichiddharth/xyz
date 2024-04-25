/* 
 * This file is part of the Hawker container engine developed by
 * the HExSA Lab at Illinois Institute of Technology.
 *
 * Copyright (c) 2018, Kyle C. Hale <khale@cs.iit.edu>
 *
 * All rights reserved.
 *
 * Author: Kyle C. Hale <khale@cs.iit.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the 
 * file "LICENSE.txt".
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <sys/mount.h>
#include <sys/mman.h> 
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


#include "hawker.h"
#include "net.h"
#include "img.h"

static pid_t child_pid = -1;

static void setup_pid_namespace(pid_t pid);
static void setup_resource_controls(pid_t pid, int cpu_pct, long mem_limit);

static void
set_child_pid (long pid)
{
    child_pid = pid;
}

static void setup_pid_namespace(pid_t pid) {
    // Example: write to /proc/[pid]/uid_map
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
    FILE *file = fopen(path, "w");
    if (file) {
        fprintf(file, "0 %d 1", pid);  // Mapping the external root to the internal root
        fclose(file);
    } else {
        perror("Failed to open uid_map file");
        exit(EXIT_FAILURE);
    }
}

static void setup_resource_controls(pid_t pid, int cpu_pct, long mem_limit) {
    // Example: set CPU shares and memory limit for the process
    char path[256];
    
    // Setting CPU shares
    snprintf(path, sizeof(path), "/sys/fs/cgroup/cpu,cpuacct/hawker/%d/cpu.shares", pid);
    FILE *cpu_file = fopen(path, "w");
    if (cpu_file) {
        fprintf(cpu_file, "%d", cpu_pct * 1024 / 100);  // Convert percentage to shares
        fclose(cpu_file);
    } else {
        perror("Failed to set CPU shares");
        exit(EXIT_FAILURE);
    }

    // Setting memory limit
    snprintf(path, sizeof(path), "/sys/fs/cgroup/memory/hawker/%d/memory.limit_in_bytes", pid);
    FILE *mem_file = fopen(path, "w");
    if (mem_file) {
        fprintf(mem_file, "%ld", mem_limit);
        fclose(mem_file);
    } else {
        perror("Failed to set memory limit");
        exit(EXIT_FAILURE);
    }
}

static int
check_or_create_file (char * path, mode_t mode)
{
    if (access(path, F_OK) != 0) {
        int fd = open(path, O_CREAT, mode);
        close(fd);
    }

    return 0;
}

static int
check_or_create_dir (char * path, mode_t mode)
{
    if (access(path, F_OK) != 0) {
        if (mkdir(path, mode) != 0) {
            ERRSTR("Could not create %s", path);
            return -1;
        }
    }

    return 0;
}

static int
mount_vfs_dirs (void)
{
    check_or_create_dir("/sys", 0555);

    if (mount("none", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, "") != 0) {
        ERRSTR("couldn't mount sysfs");
        return -1;
    }

    check_or_create_dir("/tmp", 0777);

    if (mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "") != 0) {
        ERRSTR("couldn't mount tmpfs");
        return -1;
    }

    check_or_create_dir("/proc", 0555);

    if (mount("none", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "") != 0) {
        ERRSTR("couldn't mount procfs");
        return -1;
    }

    return 0;
}


static int
check_or_create_chdev (char * base, char * node, mode_t mode, unsigned maj, unsigned min)
{
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "%s/%s", base, node);

    if (access(path, F_OK) != 0) {
        dev_t dev = makedev(maj, min);
        if (mknod(path, S_IFCHR | mode, dev) != 0) {
            ERRSTR("couldn't create device node for '%s'", path);
            return -1;
        }
    }

    return 0;
}


static int
make_dev_nodes (char * base)
{
    char base_path[PATH_MAX];
    char pts_path[PATH_MAX];

    snprintf(base_path, PATH_MAX, "%s/dev", base);
    snprintf(pts_path, PATH_MAX, "%s/dev/pts", base);

    check_or_create_dir(base_path, 0755);

    if (mount("tmpfs", base_path, "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755,size=65536k") != 0) {
        ERRSTR("couldn't mount /dev for container");
        return -1;
    }

    check_or_create_chdev(base_path, "tty", 0666, 5, 0);
    check_or_create_chdev(base_path, "console", 0622, 5, 1);
    check_or_create_chdev(base_path, "ptmx", 0666, 5, 2);
    check_or_create_chdev(base_path, "null", 0666, 1, 3);
    check_or_create_chdev(base_path, "zero", 0666, 1, 5);
    check_or_create_chdev(base_path, "random", 0444, 1, 8);
    check_or_create_chdev(base_path, "urandom", 0444, 1, 9);

    check_or_create_dir(pts_path, 0620);

    if (mount("devpts", pts_path, "devpts", MS_NOSUID | MS_NOEXEC, "mode=620,ptmxmode=666") != 0) {
        ERRSTR("couldn't mount devpts for container");
        return -1;
    }

    return 0;
}
static int file_contains_entry(const char *filepath, const char *entry) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        return -1;  // Return -1 if the file cannot be opened (it might not exist)
    }

    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, entry) != NULL) {
            found = 1;
            break;
        }
    }

    fclose(file);
    return found;
}   

static int add_root_user (void) {
    // Ensure /etc directory exists
    if (check_or_create_dir("/etc", 0755) != 0) {
        ERRSTR("Could not ensure /etc directory exists");
        return -1;
    }

    // Check if the root group already exists in /etc/group
    if (file_contains_entry("/etc/group", "root:x:0:") != 1) {
        check_or_create_file("/etc/group", 0644);
        if (system("addgroup -g 0 root") != 0) {
            ERRSTR("Could not add group 'root'");
            return -1;
        }
    }

    // Check if the root user already exists in /etc/passwd
    if (file_contains_entry("/etc/passwd", "root:x:0:0:") != 1) {
        check_or_create_file("/etc/passwd", 0644);
        // Don't create password, don't create homedir
        if (system("adduser -D -H -G root -u 0 root") != 0) {
            ERRSTR("Could not add root user");
            return -1;
        }
    }

    return 0;
}


extern char ** environ;

static char **
setup_env (void)
{
    char * path  = "PATH=/bin:/usr/bin:/usr/local/bin:/usr/sbin:/usr/local/sbin";
    char * user  = "USER=root";
    char ** envp = calloc(sizeof(char*)*3, 1);

    if (!envp) {
        ERROR("Could not allocate environment ptr\n");
        return NULL;
    }

    envp[0] = strndup(path, strnlen(path, PATH_MAX));
    envp[1] = strndup(user, strnlen(user, PATH_MAX));

    if (!envp[0]) {
        ERRSTR("Could not copy PATH variable");
        goto out_err;
    }

    envp[2] = NULL;

    putenv(path);

    return envp;

out_err:
    free(envp);
    return NULL;
}


static int
pty_setup ()
{
    if (setsid() < 0) {
        ERRSTR("couldn't become session leader");
        return -1;
    }

    int cons_fd = open("/dev/console", O_RDWR);

    if (cons_fd < 0) {
        ERRSTR("couldn't open console");
        return -1;
    }

    if (ioctl(cons_fd, TIOCSCTTY, 0) < 0) {
        ERRSTR("Couldn't set console as controlling terminal");
        return -1;
    }

    int fd = posix_openpt(O_RDWR);

    if (fd < 0) {
        ERRSTR("couldn't get pty pair");
        return - 1;
    }

    char * slave = ptsname(fd);

    printf("got slave %s\n", slave);

    if (grantpt(fd) != 0) {
        ERRSTR("Coudln't grant terminal ownership");
        return -1;
    }

    if (unlockpt(fd) != 0) {
        ERRSTR("Couldn't unlock terminal slave");
        return -1;
    }


    int slavefd = open(slave, O_RDWR);

    if (slavefd < 0) {
        ERRSTR("Couldn't open terminal slave");
        return -1;
    }


    close(slavefd);
    close(fd);



    return 0;
}


/* This is the (child) container process. By the time it invokes the user command
 * specified (using execvpe()), it will be in a fully isolated container
 * environment.
 */
static int 
child_exec (void * arg)
{
    struct parms *p           = (struct parms*)arg;
    const char * new_hostname = DEFAULT_HOSTNAME;
    char c;
    char ** envp;

    // If our parent dies and doesn't kill us explicitly, we should also die
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    close(p->pipefd[1]); // Close write end of our pipe

    // Wait for the parent to hang up its write end of the pipe
    if (read(p->pipefd[0], &c, 1) != 0) {
        ERRSTR("read from pipe in child returned nonzero status");
        exit(EXIT_FAILURE);
    }

    close(p->pipefd[0]); // Close read end of the pipe, we're done with it

    // Change root to the new directory for the image
    char img_path[PATH_MAX];
    //snprintf(img_path, sizeof(img_path), "/var/lib/hawker/images/%s", p->img);
    snprintf(img_path, sizeof(img_path), "/var/lib/hawker/images/test/busybox-1.36.1");
    if (chroot(img_path) != 0 || chdir("/") != 0) {
        ERRSTR("Failed to change root to %s", img_path);
        exit(EXIT_FAILURE);
    }

    // Change our hostname to the specified default
    if (sethostname(new_hostname, strlen(new_hostname)) != 0) {
        ERRSTR("Failed to set hostname to %s", new_hostname);
        exit(EXIT_FAILURE);
    }

    // Setup environment variables
    envp = setup_env(); // Assumes setup_env() returns a properly allocated and populated env array

    // Execute the command that the user gave us
    if (execvpe(p->cmd, p->argv, envp) == -1) {
        ERRSTR("Failed to execute %s", p->cmd);
        exit(EXIT_FAILURE);
    }

    // Cleanup, though this code should never be reached because execvpe does not return on success
    for (int i = 0; envp[i] != NULL; i++) {
        free(envp[i]);
    }
    free(envp);

    // Should never reach here
    exit(EXIT_FAILURE);
}

static int 
write_proc_file (char * filp_fmt, char * str, long pid)
{
    char buf[PATH_MAX];
    int fd;

    snprintf(buf, PATH_MAX, filp_fmt, pid);

    fd = open(buf, O_WRONLY);

    if (fd < 0) {
        ERRSTR("Could not open file (%s)", buf);
        return -1;
    }

    if (write(fd, str, strlen(str)) != strlen(str)) {
        ERRSTR("Could not write string (%s)", str);
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}


static void
version ()
{
    printf("hawker %s\n", VERSION_STRING);
}


static void
usage (char * prog)
{
    printf("\n\thawker -- the container engine\n\n");

    printf("\tDescription\n");
    printf("\t\thawker is a minimal container engine.\n");
    printf("\t\tIt creates a container and runs the\n");
    printf("\t\tspecified command inside of it.\n\n");

    printf("\tUsage: %s [OPTIONS] IMAGE COMMAND [ARG...]\n", prog);

    printf("\n\tOptions:\n");

    printf("\t\t  -c, ---cpu-share <percentage> : percent of CPU to give to container (from 0 to 100); default=100\n");
    printf("\t\t  -m, ---mem-limit <limit-in-bytes> : max amount of memory that the container can use\n");
    printf("\t\t  -C, --clear-cache : clear all cached container images\n");
    printf("\t\t  -h, ---help : display this message\n");
    printf("\t\t  -v, --version : display the version number and exit\n");

    printf("\n");
}


static void
parse_args (int argc, char **argv, struct parms * p)
{
        int cpu_pct    = DEFAULT_CPU_PCT;
        long mem_limit = DEFAULT_MEM_LIMIT;
        int optidx     = 0;
        char c;

        while (1) {

            static struct option lopts[] = {
                {"cpu-share", required_argument, 0, 'c'},
                {"mem-limit", required_argument, 0, 'm'},
                {"clear-cache", no_argument, 0, 'C'},
                {"help", no_argument, 0, 'h'},
                {"version", no_argument, 0, 'v'},
                {0, 0, 0, 0}
            };

            c = getopt_long(argc, argv, "+c:m:Chv", lopts, &optidx);

            if (c == -1) {
                break;
            }

            switch (c) {
                case 'c':
                    cpu_pct = atoi(optarg);
                    break;
                case 'C':
                    hkr_clear_img_cache();
                    exit(EXIT_SUCCESS);
                case 'm':
                    mem_limit = atol(optarg);
                    break;
                case 'h':
                    usage(argv[0]);
                    exit(EXIT_SUCCESS);
                case 'v':
                    version();
                    exit(EXIT_SUCCESS);
                case '?':
                    break;
                default:
                    printf("?? getopt returned character code 0%o ??\n", c);
            }
        }

        if (optind < argc) {
            p->img = argv[optind++];
        } else {
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        }

        if (optind < argc) {
            p->cmd = argv[optind];
        } else {
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        }

        p->argv      = &argv[optind];
        p->mem_limit = mem_limit;
        p->cpu_pct   = cpu_pct;
}


static inline void
construct_cgroup_path (char * buf, size_t len, long pid, char * subdir)
{
    memset(buf, 0, len);
    snprintf(buf, len, "/sys/fs/cgroup/%s/hawker/%ld", subdir, pid);
}


static inline void
construct_cgroup_subpath (char * buf, size_t len, long pid, char * subdir, char * subent)
{
    memset(buf, 0, len);
    snprintf(buf, len, "/sys/fs/cgroup/%s/hawker/%ld/%s", subdir, pid, subent);
}


static void
make_cgroup_subdir(long pid, char * subdir)
{
    char path[PATH_MAX];
    construct_cgroup_path(path, PATH_MAX, pid, subdir);

    // does it already exist?
    if (access(path, F_OK) == 0) {
        return;
    }

    if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        ERRSTR("Could not create cgroup dir for '%s' (Did you run the setup script?)", subdir);
        exit(EXIT_FAILURE);
    }
}


static void
remove_cgroup_subdir(long pid, char * subdir)
{
    char path[PATH_MAX];

    construct_cgroup_path(path, PATH_MAX, pid, subdir);

    // dir isn't there
    if (access(path, F_OK) != 0) {
        return;
    }

    if (rmdir(path) != 0) {
        ERRSTR("Could not remove cgroup dir");
        exit(EXIT_FAILURE);
    }
}


static void
setup_cgroup_dirs (long pid)
{
    make_cgroup_subdir(pid, "cpuacct");
    make_cgroup_subdir(pid, "memory");
}


static void
cleanup_cgroup_dirs (long pid)
{
    remove_cgroup_subdir(pid, "cpuacct");
    remove_cgroup_subdir(pid, "memory");
}


#define MAX_CGROUP_LEN 64


static void 
set_cgroup_file_val (long pid, char * subdir, char * subent, unsigned val, int append)
{
    char path[PATH_MAX];
    char val_str[MAX_CGROUP_LEN];
    int fd;
    int flags = O_RDWR;

    construct_cgroup_subpath(path, PATH_MAX, pid, subdir, subent);

    if (append) {
        flags |= O_APPEND;
    } else {
        flags |= O_TRUNC;
    }

    fd = open(path, O_RDWR | O_TRUNC);

    if (fd < 0) {
        ERRSTR("Could not open cgroup path (%s)", path);
        exit(EXIT_FAILURE);
    }

    memset(val_str, 0, MAX_CGROUP_LEN);
    snprintf(val_str, MAX_CGROUP_LEN, "%u", val);

    if (write(fd, val_str, strnlen(val_str, MAX_CGROUP_LEN)) != strnlen(val_str, MAX_CGROUP_LEN)) {
        ERRSTR("Could not write to shares dir");
        exit(EXIT_FAILURE);
    }

    close(fd);
}


static inline void
assign_pid_to_cgroup (long pid, char * subdir) 
{
    set_cgroup_file_val(pid, subdir, "tasks", (unsigned long)pid, 1);
}


static inline void
set_cgroup_val (long pid, unsigned long val, char * subdir, char * subent, int append)
{
    set_cgroup_file_val(pid, subdir, subent, val, append);
    assign_pid_to_cgroup(pid, subdir);
}


// uses the completely fair scheduler (CFS) subsystem
static inline void
set_cpu_share (long pid, unsigned long share)
{
    unsigned long period = 1000000;
    unsigned long quota;

    // truncate, we can't get more than 1024
    if (share > 100) {
        share = 100;
    }

    quota  = (period / 100) * share;

    set_cgroup_file_val(pid, "cpuacct", "cpu.cfs_quota_us", quota, 0);
    set_cgroup_file_val(pid, "cpuacct", "cpu.cfs_period_us", period, 0);
    assign_pid_to_cgroup(pid, "cpuacct");
}


static inline void
set_mem_limit (long pid, long limit)
{
    // only set the mem limit if the user asked
    if (limit > 0) {
        set_cgroup_val(pid, (unsigned long)limit, "memory", "memory.limit_in_bytes", 0);
    }
}


static void
cleanup (void)
{
    cleanup_cgroup_dirs(child_pid);
}

static void 
death_handler (int sig)
{
    kill(child_pid, SIGKILL);
    // if we don't wait for the child to
    // completely die here, cgroups won't let us remove
    // the subdirectories
    waitpid(child_pid, NULL, 0);
    cleanup();
}

static void
set_child_user_maps (long pid, unsigned from, unsigned to)
{
    char map[PATH_MAX];

    snprintf(map, PATH_MAX, "%u %u 1", from, to);

    // http://man7.org/linux/man-pages/man7/user_namespaces.7.html 
    write_proc_file("/proc/%ld/uid_map", map, pid);
    write_proc_file("/proc/%ld/setgroups", "deny", pid);
    write_proc_file("/proc/%ld/gid_map", map, pid);
}



// Global variable to keep track of the child PID
//static pid_t global_child_pid = -1;




 /* void death_handler(int sig) {
    if (global_child_pid != -1) {
        // Attempt to terminate the child process
        kill(global_child_pid, SIGTERM);
        
        // Wait for the child to exit to avoid leaving a zombie process
        int status;
        waitpid(global_child_pid, &status, 0);
        
        // Log or handle the child's exit status if necessary
        if (WIFEXITED(status)) {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("Child killed by signal %d\n", WTERMSIG(status));
        }
    }

    // Exit the program after handling the signal and cleanup
    printf("Process %d received signal %d, exiting...\n", getpid(), sig);
    exit(EXIT_SUCCESS);
}*/

int main(int argc, char **argv) {
    struct parms p; 
    void *child_stack;
    unsigned stk_sz = DEFAULT_STACKSIZE;
    int clone_flags;
    pid_t pid;

    // Initialize network subsystem (Assuming this function exists)
    if (hkr_net_init() != 0) {
        fprintf(stderr, "Could not initialize network subsystem\n");
        exit(EXIT_FAILURE);
    }

    // Create a cache for our container images (Assuming this function exists)
    if (hkr_img_cache_init() != 0) {
        fprintf(stderr, "Could not create hawker image cache\n");
        exit(EXIT_FAILURE);
    }

    parse_args(argc, argv, &p); // Assuming this function parses command line arguments

    // Check if the image is cached
    if (!hkr_img_exists(p.img)) { // Assuming this function checks for image existence
        printf("Unable to find image '%s' locally\n", p.img);
        if (hkr_net_get_img(p.img) != 0) { // Assuming this function downloads the image
            fprintf(stderr, "Image '%s' not found in hawker repository\n", p.img);
            exit(EXIT_FAILURE);
        }
        if (hkr_img_extract(p.img) != 0) { // Assuming this function extracts the image
            fprintf(stderr, "Could not extract compressed image (%s)\n", p.img);
            exit(EXIT_FAILURE);
        }
    }

    // Ensure device nodes are created
    if (make_dev_nodes(hkr_get_img(p.img)) != 0) {
        fprintf(stderr, "Could not create device nodes\n");
        exit(EXIT_FAILURE);
    }

    // Set up namespaces
    clone_flags = CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWIPC | SIGCHLD;

    // Allocate stack for the child process
    child_stack = mmap(NULL, stk_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (child_stack == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    // Create a pipe for communication
    if (pipe(p.pipefd) != 0) {
        perror("Could not create pipe");
        exit(EXIT_FAILURE);
    }
    
   
    // Clone the child process
    pid = clone(child_exec, child_stack + stk_sz, clone_flags, &p);
    if (pid == -1) {
        perror("Clone failed");
        exit(EXIT_FAILURE);
    }

    set_child_pid(pid);

    // Setup PID namespace for the child
    setup_pid_namespace(pid);

    // Setup resource controls
    setup_resource_controls(pid, p.cpu_pct, p.mem_limit);
    
    // Signal the child to continue
    close(p.pipefd[0]); // Close read end of pipe
    close(p.pipefd[1]); // Close write end of pipe

    // Catch SIGINT to cleanup properly
    signal(SIGINT, death_handler);

    // Wait for the child to exit
    waitpid(pid, NULL, 0);

    // Cleanup
    munmap(child_stack, stk_sz); // Free the allocated stack
    cleanup_cgroup_dirs(pid); // Assuming this function cleans up cgroup directories

    exit(EXIT_SUCCESS);
}
