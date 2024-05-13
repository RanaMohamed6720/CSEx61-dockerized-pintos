#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "lib/kernel/stdio.h"
#include "devices/shutdown.h"
#include "devices/input.h"

static void syscall_handler(struct intr_frame *);
void handle_halt(void);
void close(int fd);
int filesize(int fd);
unsigned tell(int fd);
void remove_file(int fd);
struct file *get_file(int fd);
int open(const char *file);
bool remove(const char *file);
void handle_exit(int status);
void seek(int fd, unsigned position);
bool create(const char *file, unsigned initial_size);
int write(int fd, void *buffer, unsigned size);
int read(int fd, void *buffer, unsigned size);
struct child_proc *find_child_proc(int pid);
void* check_ref_valid (void *address);
static void syscall_handler(struct intr_frame *f);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler(struct intr_frame *f)
{
  uint32_t *args = ((uint32_t *)f->esp);
  check_ref_valid(args);
  if (*args > 12){
    handle_exit(-1);
  }

  if (args[0] == SYS_HALT)
  {
    handle_halt();
  }
  else if (args[0] == SYS_EXIT)
  {
    check_ref_valid(args+1);
    handle_exit(*(args+1));
  }
  else if (args[0] == SYS_EXEC)
  {
    // check_ref_valid(args[1]);
    // check_ref_valid(*(args+1));
    // NOT IMPLEMENTED YET
  }
  else if (args[0] == SYS_WAIT)
  {
    check_ref_valid(args+1);
    f->eax = process_wait(*(args+1));
  }
  else if (args[0] == SYS_CREATE || args[0] == SYS_REMOVE || args[0] == SYS_OPEN)
  {
    char *name = (char*) args[1];
    if (args[0] == SYS_CREATE)
    {
      check_ref_valid((void*)*(args+1));
      int initial_size = args[2];
      f->eax = create(name, initial_size);
    }
    else if (args[0] == SYS_REMOVE)
    {
      check_ref_valid(args+1);
      check_ref_valid((void*)*(args+1));
      f->eax = remove(name);
    }
    else if (args[0] == SYS_OPEN)
    {
      check_ref_valid(args+1);
      check_ref_valid((void*)*(args+1));
      f->eax = open(name);
    }
  }
  else
  {
    int fd = args[1];
    if (args[0] == SYS_FILESIZE)
    {
      check_ref_valid(args+1);
      f->eax = filesize(fd);
    }
    else if (args[0] == SYS_SEEK)
    {
      check_ref_valid(args+2);
      unsigned new_pos = args[2];
      seek(fd, new_pos);
    }
    else if (args[0] == SYS_TELL)
    {
      check_ref_valid(args+1);
      f->eax = tell(fd);
    }
    else if (args[0] == SYS_CLOSE)
    {
      check_ref_valid(args+1);
      close(fd);
    }
    else
    {
      check_ref_valid(args+2);
      check_ref_valid((void*)*(args+3));
      void *buffer = (void*) args[2];
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

void* check_ref_valid (void *address) {
  if (!is_user_vaddr(address))
	{
		handle_exit(-1);
		return 0;
	}
  void *ptr = pagedir_get_page(thread_current()->pagedir, address);
	if (!ptr)
	{
		handle_exit(-1);
		return 0;
	}
	return ptr;
}

void handle_halt()
{
  shutdown_power_off();
}

void handle_exit(int status)
{
  struct thread *cur = thread_current();
  struct list_elem *e;

  for (e=list_begin(&cur->parent->child_list); e!=list_end(&cur->parent->child_list); e=list_next(e))
  {
    struct child_proc *c = list_entry(e, struct child_proc, elem);
    if (c->pid == cur->tid){
      c->used = true;
      c->exit_error = status;
    }
  }
  
  cur->exit_error = status;

  if (cur->parent->waiting_on == cur->tid) {
    sema_up(&cur->parent->child_lock);
  }

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
  lock_release(&file_lock);
  if (f == NULL)
    return -1;

  // add file to the file list(open files) of the thread
  struct file_elem *elem = malloc(sizeof(struct file_elem));
  elem->file = f;
  int fd = thread_current()->next_fd;
  elem->fd = fd;
  thread_current()->next_fd++;
  list_push_back(&thread_current()->file_list, &elem->elem);

  return fd;
}
int filesize(int fd)
{
  // find the file that fd releate to
  struct file *file = get_file(fd);
  if (file == NULL)
    return -1;
  lock_acquire(&file_lock);
  int size = file_length(file);
  lock_release(&file_lock);
  return size;
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
    // find the file that fd relate to
    struct file *file = get_file(fd);
    if (file == NULL)
      return -1;
    lock_acquire(&file_lock);
    size_read = file_read(file, buffer, size);
    lock_release(&file_lock);
  }
  return size_read;
}
int write(int fd, void *buffer, unsigned size)
{
  int write_size;
  if (fd == 1)
  {
    lock_acquire(&file_lock);
    putbuf(buffer, size);
    lock_release(&file_lock);
    write_size = size;
  }
  else
  {
    // find the file that fd releate to
    struct file *file = get_file(fd);
    if (file == NULL)
      return -1;
    lock_acquire(&file_lock);
    write_size = file_write(file, &buffer, size);
    lock_release(&file_lock);
  }
  return write_size;
}
void seek(int fd, unsigned position)
{
  // find the file that fd releate to
  struct file *file = get_file(fd);
  if (file == NULL)
    return;
  lock_acquire(&file_lock);
  file_seek(file, position);
  lock_release(&file_lock);
}
unsigned tell(int fd)
{
  // find the file that fd relate to
  struct file *file = get_file(fd);
  if (file == NULL)
    return -1;
  lock_acquire(&file_lock);
  int pos = file_tell(file);
  lock_release(&file_lock);
  return pos;
}
void close(int fd)
{
  // find the file that fd releate to
  struct file *file = get_file(fd);
  if (file == NULL)
    return;
  lock_acquire(&file_lock);
  file_close(file);
  lock_release(&file_lock);

  // remove that file from file list(open files)
  remove_file(fd);
}
struct file *get_file(int fd)
{
  struct list_elem *e;

  struct thread *cur = thread_current();
  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list);
       e = list_next(e))
  {
    struct file_elem *f = list_entry(e, struct file_elem, elem);
    if (f->fd == fd)
      return f->file;
  }
  return NULL; // if we don't found that file
}
void remove_file(int fd)
{
  struct list_elem *e;

  struct thread *cur = thread_current();
  for (e = list_begin(&cur->file_list); e != list_end(&cur->file_list);
       e = list_next(e))
  {
    struct file_elem *f = list_entry(e, struct file_elem, elem);
    if (f->fd == fd)
    { 
      list_remove(&f->elem);
    }
  }
}
struct child_proc *find_child_proc(int pid)
{

  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin(&t->child_list); e != list_end(&t->child_list); e = list_next(e))
  {
    struct child_proc *cp = list_entry(e, struct child_proc, elem);
    if (pid == cp->pid)
      return cp;
  }

  return NULL;
}
