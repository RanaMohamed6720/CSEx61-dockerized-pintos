#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/kernel/stdio.h"
// what is left ?
/*
  check validity of each pointer
  add list of files open by each process
  find the file open with each process using fd
  add page fault handling (exit with status -1)
*/
static struct lock file_lock;

static void syscall_handler(struct intr_frame *);
void handle_halt();
void handle_exit(int status);
bool create(const char *file, unsigned initial_size);
struct child_proc *find_child_proc(int pid);
void close(int fd);
unsigned tell(int fd);
void seek(int fd, unsigned position);
int write(int fd, void *buffer, unsigned size);
int read(int fd, void *buffer, unsigned size);
int filesize(int fd);
int open(const char *file);
bool remove(const char *file);
void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  uint32_t *args = ((uint32_t *)f->esp);
  if (args[0] == SYS_HALT)
  {
    handle_halt();
  }
  else if (args[0] == SYS_EXIT)
  {
    f->eax = args[1];
    handle_exit(args[1]);
  }
  else if (args[0] == SYS_EXEC)
  {
    // NOT IMPLEMENTED YET
  }
  else if (args[0] == SYS_WAIT)
  {
    // NOT IMPLEMENTED YET
    // get_args(f, &arg[0], 1);
    // f->eax = process_wait(arg[0]);
  }
  else if (args[0] == SYS_CREATE || args[0] == SYS_REMOVE || args[0] == SYS_OPEN)
  {
    char *name = args[1];
    if (args[0] == SYS_CREATE)
    {
      int initial_size = args[2];
      f->eax = create(name, initial_size);
    }
    else if (args[0] == SYS_REMOVE)
    {
      f->eax = remove(name);
    }
    else if (args[0] == SYS_OPEN)
    {
      f->eax = open(name);
    }
  }
  else
  {
    int fd = args[1];
    if (args[0] == SYS_FILESIZE)
    {
      f->eax = filesize(fd);
    }
    else if (args[0] == SYS_SEEK)
    {
      unsigned new_pos = args[2];
      seek(fd, new_pos);
    }
    else if (args[0] == SYS_TELL)
    {
      f->eax = tell(fd);
    }
    else if (args[0] == SYS_CLOSE)
    {
      close(fd);
    }
    else
    {
      void *buffer = args[2];
      int size = args[3];
      if (args[0] == SYS_READ)
      {
        f->eax = read(fd, buffer, size);
      }
      else if (args[0] == SYS_WRITE)
      {
        f->eax = write(fd, buffer, size);
      }
    }
  }
  thread_exit();
}
void handle_halt()
{
  shutdown_power_off();
}
void handle_exit(int status)
{
  struct thread *cur = thread_current();
  /*
    terminate all sub processes of current process HERE and release all resources
  */
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}
bool create(const char *file, unsigned initial_size)
{

  lock_acquire(&file_lock);
  bool value = filesys_create(file, initial_size);
  lock_release(&file_lock);

  return value;
}
bool remove(const char *file)
{

  lock_acquire(&file_lock);
  bool value = filesys_remove(file);
  lock_release(&file_lock);

  return value;
}
int open(const char *file)
{

  lock_acquire(&file_lock);
  struct file *f = filesys_open(file);

  if (f == NULL)
    return -1;
  else
    return 0; // should return fd

  lock_release(&file_lock);
}
int filesize(int fd)
{
  // check page fault here

  lock_acquire(&file_lock);
  return file_length(fd);
  lock_release(&file_lock);
}
int read(int fd, void *buffer, unsigned size)
{
  int size_read = size;
  if (fd == 0) // read from input stream (from keyboard)
  {
    while (size-- != 0)
    {
      lock_acquire(&file_lock);
      buffer += input_getc();
      lock_release(&file_lock);
    }
  }
  else
  {
    // find the file that fd releate to
    struct file *file;
    // check page fault
    lock_acquire(&file_lock);
    size_read = file_read(file, buffer, size);
    lock_release(&file_lock);
  }
  return size_read;
}
int write(int fd, void *buffer, unsigned size)
{
  // find the file that fd releate to
  struct file *file;
  int write_size;
  // check page fault
  if (fd == 1)
  {
    lock_acquire(&file_lock);
    putbuf(buffer, size);
    lock_release(&file_lock);
    write_size = size;
  }
  else
  {
    lock_acquire(&file_lock);
    write_size = file_write(file, &buffer, size);
    lock_release(&file_lock);
  }
  return write_size;
}
void seek(int fd, unsigned position)
{
  // find the file that fd releate to
  struct file *file;
  // check page fault
  lock_acquire(&file_lock);
  file_seek(fd, position);
  lock_release(&file_lock);
}
unsigned tell(int fd)
{
  // find the file that fd releate to
  struct file *file;
  // check page fault
  lock_acquire(&file_lock);
  file_tell(file);
  lock_release(&file_lock);
}
void close(int fd)
{
  // find the file that fd releate to
  struct file *file;
  // check page fault
  lock_acquire(&file_lock);
  file_close(file);
  lock_release(&file_lock);
  // remove that fd from file list
}
struct child_proc *find_child_proc(int pid)
{

  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin(&t->child_list); e = !list_end(&t->child_list); e = list_next(e))
  {
    struct child_proc *cp = list_entry(e, struct child_proc, elem);
    if (pid == cp->pid)
      return cp;
  }

  return NULL;
}
