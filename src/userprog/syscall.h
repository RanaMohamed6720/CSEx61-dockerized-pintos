#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// added headers
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "stdbool.h"
// end of added headers

void syscall_init(void);

/* lock required for functions */
struct lock file_lock;

void handle_exit(int status);
void handle_halt(void);
int close(int fd);
int filesize(int fd);
int tell(int fd);
void remove_file(int fd);
struct file *get_file(int fd);
int open(const char *file);
bool remove(const char *file);
void handle_exit(int status);
int seek(int fd, unsigned position);
bool create(const char *file, unsigned initial_size);
int write(int fd, void *buffer, unsigned size);
int read(int fd, void *buffer, unsigned size);

// Validation functions
void check_ref_valid(void *address);
void valid_user_space(const void *src, int address_Bytes);
static int get_user(const uint8_t *uaddr);

#endif /* userprog/syscall.h */