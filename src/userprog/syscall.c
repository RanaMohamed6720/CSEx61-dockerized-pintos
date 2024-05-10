#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler(struct intr_frame *);

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int sys_call = *((int*)f->esp);
  printf("system call!\n");
  if (sys_call == SYS_HALT){
    handle_halt();
  }
  else if (sys_call == SYS_EXIT){
    int status = *((int*)(f->esp + 4)); // edit
    handle_exit(status);
  }
  else if (sys_call == SYS_EXEC){
    // NOT IMPLEMENTED YET 
  }
  else if (sys_call == SYS_WAIT){
    // NOT IMPLEMENTED YET 
  }
  else if (sys_call == SYS_CREATE || sys_call == SYS_REMOVE || sys_call == SYS_OPEN){
    char *name = *((char*)(f->esp +4));
    if (sys_call == SYS_CREATE){
      int initial_size = *((int*)(f->esp + 8));
      filesys_create(&name, initial_size);
    }
    else if (sys_call == SYS_REMOVE){
      filesys_remove(&name);
    }
    else if (sys_call == SYS_OPEN){
      filesys_open(&name);
    }
  }
  else{
    struct file *file = (struct file*)(f->esp +4);
    if (sys_call == SYS_FILESIZE){
      // lock here
      file_length(&file);
    }
    else if (sys_call == SYS_SEEK){
      int new_pos;
      // lock here
      file_seek(&file, new_pos);
    }
    else if (sys_call == SYS_TELL){
      // lock here
      file_tell(&file);
    }
    else if (sys_call == SYS_CLOSE){
      file_close(&file);
    }
    else{
      void *buffer = (f->esp + 8);
      int size = *((int*)(f->esp + 12));
      if (sys_call == SYS_READ)
      {
      // lock here
        file_read(&file, &buffer, size);
      }
      else if (sys_call == SYS_WRITE)
      {
      // lock here
        file_write(&file, &buffer, size);
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
    terminate all sub processes of current process HERE
  */
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();
}
