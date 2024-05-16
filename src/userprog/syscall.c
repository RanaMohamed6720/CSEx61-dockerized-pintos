#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h" 
#include "threads/init.h"  
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/list.h"

static void syscall_handler(struct intr_frame *f UNUSED);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
}

static void
syscall_handler(struct intr_frame *f UNUSED)
{
  uint32_t *args = ((uint32_t *)f->esp);
  check_ref_valid(args);
  
  if (args[0] == SYS_HALT)
  {
    handle_halt();
  }
  else if (args[0] == SYS_EXIT)
  {
    int status = *((int *)f->esp + 1);
    f->eax = status;
    handle_exit(status);
  }
  else if (args[0] == SYS_WAIT)
  {
    tid_t tid = *((int *)f->esp + 1);
    f->eax = handle_wait(tid);
  }
  else if (args[0] == SYS_EXEC || args[0] == SYS_CREATE || args[0] == SYS_REMOVE || args[0] == SYS_OPEN)
  {
    char *name = (char*) args[1];
    if(name == NULL) handle_exit(-1);
    if (args[0] == SYS_EXEC)
    {
      f->eax = process_execute(name);
    }
    else if (args[0] == SYS_CREATE)
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
  else if (args[0] == SYS_FILESIZE)
  {
    int fd = args[1];
    f->eax = filesize(fd);
  }
  else if (args[0] == SYS_READ)
  {
    int fd = args[1];
    void *buffer = (void*) args[2];
    if (fd == STDOUT_FILENO || !(is_user_vaddr(buffer)))
    {
      handle_exit(-1);
    }
    
    int size = args[3];
    f->eax = read(fd, buffer, size);
  }
  else if (args[0] == SYS_WRITE)
  {
    int fd = args[1];
    void *buffer = (void*) args[2];
    if (fd == STDIN_FILENO || pagedir_get_page(thread_current()->pagedir, buffer) == NULL)
    { 
      handle_exit(-1);
    }
    int size = args[3];
    f->eax = write(fd, buffer, size);
  }
  else if (args[0] == SYS_SEEK)
  {
    int fd = args[1];
    unsigned new_pos = args[2];
    f->eax = seek(fd, new_pos);
  }
  else if (args[0] == SYS_TELL)
  {
    int fd = args[1];
    f->eax = tell(fd);
  }
  else if (args[0] == SYS_CLOSE)
  {
    int fd = args[1];
    f->eax = close(fd);
  } 
}

void handle_halt()
{
  shutdown_power_off();
}

void handle_exit(int status)
{
    thread_current()->exit_status = status;
    thread_exit();
}

tid_t  handle_wait(tid_t tid)
{
  return (tid_t)process_wait(tid);
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Uses get_user to validate reference. */
void valid_user_space(const void * src, int address_Bytes) {
  /* Check that a user pointer points below PHYS_BASE. */
  if (src < PHYS_BASE && (src + address_Bytes) < PHYS_BASE) {
    for(int i = 0; i < address_Bytes; i++)
      if (get_user((uint8_t *) src + i)== -1) return false;
    return;
  } 
  handle_exit(-1);
}

/* Uses valid_user_space to validate specific reference depending on the passed args. */
void check_ref_valid (void *address) {
  valid_user_space((void *)address, 4);
  int adr = *(int*)address;
  if (adr != SYS_HALT) {
  	valid_user_space((int *)(address + 1), 4);
  	if (adr == SYS_CREATE || adr == SYS_SEEK || adr == SYS_READ || adr == SYS_WRITE) {
  		valid_user_space((char *)(address + 2), 4);
  		if (adr == SYS_READ || adr == SYS_WRITE)
  			valid_user_space((int *)(address + 3),4);
  	}
  }
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
    struct file_elem *elem = (struct file_elem *)malloc(sizeof(struct file_elem));
  elem->file = f;
  int fd = thread_current()->next_fd;
  elem->fd = fd;
  thread_current()->next_fd++;
  list_push_back(&thread_current()->file_list, &elem->elem);

  return fd;
}

int seek(int fd, unsigned position)
{
  // find the file that fd releate to
  struct file *file = get_file(fd);
  if (file == NULL)
    return -1;
  lock_acquire(&file_lock);
  file_seek(file, position);
  lock_release(&file_lock);
  return position;
}
int tell(int fd)
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
int close(int fd)
{
  // find the file that fd releate to
  struct file *file = get_file(fd);
  if (file == NULL)
    return -1;
  lock_acquire(&file_lock);
  file_close(file);
  lock_release(&file_lock);

  // remove that file from file list(open files)
  remove_file(fd);

  return 1;
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
  int write_size = size;
  if (fd == 1)
  {
    lock_acquire(&file_lock);
    putbuf(buffer, size);
    lock_release(&file_lock);
  }
  else
  {
    // find the file that fd releate to
    struct file *file = get_file(fd);
    if (file == NULL)
      return -1;
    lock_acquire(&file_lock);
    write_size = file_write(file, buffer, size);
    lock_release(&file_lock);
  }
  return write_size;
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