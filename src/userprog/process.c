#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
//## Add this INCOMPLETE struct to process.c
///* Struct used to share between process_execute() in the
//   invoking thread and start_process() inside the newly invoked
//      thread. */
//
struct exec_helper
{
	const char *file_name;    //## Program to load (entire command line)
	struct semaphore exec_sema;//##Add semaphore for loading (for resource race cases!)
	bool prog_succ;//##Add bool for determining if program loaded successfully
	//## Add other stuff you need to transfer between process_execute and process_start (hint, think of the children... need a way to add to the child's list, see below about thread's child list.)
	struct list_elem exec_children;
	tid_t exec_tid;
	struct hold_stat *waiter;
};
					      
/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  struct exec_helper exec;
  char thread_name[16];
  //char *fn_copy;     //get rid of this code as per TA guideline
  tid_t tid;

  //#Set exec file name here
  exec.file_name = file_name;
  strlcpy(thread_name, file_name, sizeof(thread_name));
  
  //##Initialize a semaphore for loading here
  sema_init(&exec.exec_sema, 0);

    //##Add program name to thread_name, watch out for the size, strtok_r......
  char *saveptr;
  char *token = strtok_r(thread_name, " ", &saveptr);
  //my way - safer, probably works
  /*unsigned int i = 0;
  while(token[i] != NULL)
  {
  	  i++;
  }

  if((token != NULL) && (i <= 16)) 
  {
  	  for(unsigned int j = 0; j != i; j++)
  	  {
  	  	  thread_name[j] = token[j];
  	  }
  }*/
  //michael's way - risky, don't know if it works
  if((token != NULL) && (strlen(token) <= 16))
  {
  	  strlcpy(thread_name, token, sizeof(thread_name));
  }
  
  //Change file_name in thread_create to thread_name
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, &exec); //##remove fn_copy, Add exec to the end of these params
  if (tid != TID_ERROR)
  {
  	  sema_down(&exec.exec_sema);
  	  if(exec.prog_succ)
  	  {
  	  	  list_push_back(&thread_current()->children_list, &exec.waiter->elem);
  	  }
  	  else
  	  {
  	  	  tid = TID_ERROR;
  	  }
  }
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
//TA helped us construct function with the following variables
static void
start_process (void *exec_ )
{
	//points to our exec_helper struct
	struct exec_helper *exec_ptr = exec_;
	//char temp[sizeof(&exec_ptr->file_name)];  //because we cannot point to a const char*, we need to convert to a char array
	//strlcpy(temp, exec_ptr->file_name, sizeof(temp));
	//char *file_name = temp; // THIS-----> &exec_ptr->file_name <---- DOES NOT WORK BUT IT IS THE FINAL IDEA..............points to the "command line" in the struct of exec_helper
	struct intr_frame if_;
	bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (exec_ptr->file_name, &if_.eip, &if_.esp);

  if(success)
  {
  	  thread_current()->waiter = malloc(sizeof(*exec_ptr->waiter));
  	  exec_ptr->waiter = thread_current()->waiter;
  	  if(exec_ptr->waiter != NULL)
  	  {
  	  	  success = true;
  	  }
  	  else
  	  {
  	  	  success = false;
  	  }
  }

  if(success)
  {
  	  lock_init(&exec_ptr->waiter->pick);
  	  exec_ptr->waiter->todo_helper = 1;
  	  exec_ptr->waiter->tid = thread_current()->tid;
  	  sema_init(&exec_ptr->waiter->stat_sema, 0);
  }
  exec_ptr->prog_succ = success;  //allow the parent thread to communicate
  /* If load failed, quit. */
  //palloc_free_page (file_name);
  sema_up(&exec_ptr->exec_sema);	//sema up regardless of pass or fail to allow parent to run and tell it that the child tried 
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

static void unuse_process(struct hold_stat *ptr)
{
	int temp;
	lock_acquire(&ptr->pick);
	temp = --(ptr->todo_helper);
	lock_release(&ptr->pick);
	if(temp == -1)
	{
		free(ptr);
	}
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
	struct thread *t = thread_current();
	struct list_elem *e;
	struct hold_stat *t_child_stat;
	int child_exit_stat;
	for(e = list_begin(&t->children_list); e != list_end(&t->children_list); e = list_next(e))
	{
		t_child_stat = list_entry(e, struct hold_stat, elem);
		if(t_child_stat->tid == child_tid)
		{
			list_remove(e);
			sema_down(&t_child_stat->stat_sema);
			child_exit_stat = t_child_stat->exit_stat;
			unuse_process(t_child_stat);
			return child_exit_stat;
		}
	}
	return -1;

	//this is our old way - TA said it wouldnt work but we were on the right track
	
	/*struct list child_list = thread_current()->children_list;
	struct exec_helper exec_helper_info;
	struct list_elem * e;
	bool found = false; //bool for checking if child_tid is one of the current threads children
	for(e = list_begin(child_list); e != list_end(child_list); e = list_next(e))
	{
		exec_helper_info = list_entry(e, struct exec_helper, exec_children); //grabbing the encompassing exec_helper struct
		if(exec_helper_info.tid_exec == child_tid) //checking tid
		{
			found = true;
		}
	}
	if(!found || (child_tid == TID_ERROR)) //if not found or TID is invalid
	{
		return -1;
	}
	else  //check for the child exit code using sema between
	{
		return 0;
	}*/
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  struct list_elem *e;
  struct hold_stat *cur_proc;
  printf("%s: exit(%d)\n", cur->name, cur->exit_stat);

  if(cur->waiter != NULL)
  {
  	  cur_proc = cur->waiter;
  	  cur_proc->exit_stat = cur->exit_stat;
  	  sema_up(&cur_proc->stat_sema);
  	  unuse_process(cur_proc);
  }

  for(e = list_begin(&cur->children_list); e != list_end(&cur->children_list); e = list_next(e))
  {
  	  cur_proc = list_entry(e, struct hold_stat, elem);
  	  unuse_process(cur_proc);
  }

  //we must implement this here instead of in the load function
  file_close(cur->exec_file);
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (const char *cmd_line, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
//Follow guidelines from TA
bool
load (const char *cmd_line, void (**eip) (void), void **esp) //change file_name to cmd_line!
{
  struct thread *t = thread_current ();
  char file_name[NAME_MAX + 2];	//add a file name variable here, they are different
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  //use strtok_r to remove file_name from cmd_line
  char *saveptr;
  char *token;
  strlcpy(file_name, cmd_line, sizeof(file_name));
  token = strtok_r(file_name, " ", &saveptr);
  strlcpy(file_name, token, sizeof(file_name));

  /* Open executable file. */
    //## Set the thread's bin file to this as well! It is super helpful to have each thread have a pointer to the file they are using for when you need to close it in process_exit
  file = filesys_open (file_name);
  t->exec_file = file;
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
    //##Disable file write for 'file' here. GO TO BOTTOM. DON'T CHANGE ANYTHING IN THESE IF AND FOR STATEMENTS
    file_deny_write(file);
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (cmd_line, esp))		////##Add cmd_line to setup_stack param here, also change setup_stack
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);    ##Remove this!!!!!!!!Since thread has its own file, close it when process is done (hint: in process exit.
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/*Push function given to us by TA */
static void * push(uint8_t *kpage, size_t *offset, const void *buf, size_t size)
{
	size_t padsize = ROUND_UP(size, sizeof(uint32_t));
	if(*offset < padsize)
	{
		return NULL;
	}

	*offset -=padsize;
	memcpy(kpage + *offset + (padsize - size), buf, size);
	return kpage + *offset + (padsize - size);
}

/* Will help us set up the stack being called in setup_stack. Skeleton template given by TA, implementation completed */
static bool setup_stack_helper (const char *cmd_line, uint8_t *kpage, uint8_t *upage, void ** esp)
{
	size_t ofs = PGSIZE;
	char *const null = NULL;
	char *pushed_cmd;
	char *temp;
	char *karg;
	char *saveptr;
	int argc = 0;
	char **argv;
	char **argw;
	void *uarg;

	pushed_cmd = push(kpage, &ofs, cmd_line, strlen(cmd_line) + 1);
	if(pushed_cmd == NULL)
	{
		return false;
	}

	temp = push(kpage, &ofs, &null, sizeof(NULL));
	if(temp == NULL)
	{
		return false;
	}

	//we must get argc
	for(karg = strtok_r(pushed_cmd, " ", &saveptr); karg != NULL; karg = strtok_r(NULL, " ", &saveptr))
	{
		uarg = upage + (karg - (char *) kpage);
		temp = push(kpage, &ofs, &uarg, sizeof(uarg));
		if(temp == NULL)
		{
			return false;
		}
		argc++;
	}
	
	//puts the commands in reverse order like the diagram in the instruction page
	argv = (char **) (upage + ofs);
	argw = (char **) (kpage + ofs);
	int i = 0;
	for(i = argc; i > 1; i -=2, argw++)
	{
		temp = argw[0];
		argw[0] = argw[i - 1];
		argw[i - 1] = temp;
	}
	
	//if any of the pushes are NULL then we have to return false
	temp = push(kpage, &ofs, &argv, sizeof(argv));
	karg = push(kpage, &ofs, &argc, sizeof(argc));
	saveptr = push(kpage, &ofs, &null, sizeof(null));
	if((temp == NULL) || (karg == NULL) || (saveptr == NULL))
	{
		return false;
	}

	//if you've reached this point, everything is good and so return true
	*esp = upage + ofs;
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (const char *cmd_line, void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
  {
    	uint8_t *upage = ( (uint8_t *) PHYS_BASE ) - PGSIZE;
    	success = install_page (upage, kpage, true);
    	if (success)
    	{
    		//*esp = PHYS_BASE;		//take out according to TA
    		success = setup_stack_helper(cmd_line, kpage, upage, esp);
    	}
    	else
    	{
    		palloc_free_page (kpage);
    	}
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
