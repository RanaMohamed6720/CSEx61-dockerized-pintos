#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct lock file_lock;

void syscall_init (void);

struct child_proc *find_child_proc(int pid);
void handle_exit(int status);

#endif /* userprog/syscall.h */
