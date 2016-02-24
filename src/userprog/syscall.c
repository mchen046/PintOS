#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/init.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "devices/shutdown.h"

static int our_halt(void);
static int our_exit(int status);
static int our_exec(const char *cmd_line);
static int our_wait(tid_t proc_id);
static int our_create(const char *file, unsigned initial_size);
static int our_remove(const char *file);
static int our_open(const char *file);
static int our_filesize(int fd);
static int our_read(int fd, void *buffer, unsigned size);
static int our_write(int fd, const void *buffer, unsigned size);
static int our_seek(int fd, unsigned position);
static int our_tell(int fd);
static int our_close(int fd);

//the following are given functions
static void syscall_handler (struct intr_frame *);

/* Copies a byte from user address USRC to kernel address DST.
 *    USRC must be below PHYS_BASE.
 *       Returns true if successful, false if a segfault occurred. */
static inline bool get_user (uint8_t *dst, const uint8_t *usrc)
{
	int eax;
	    asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
	           : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
	      return eax != 0;
}

/* Copies SIZE bytes from user address USRC to kernel address
 *    DST.
 *       Call thread_exit() if any of the user accesses are invalid. */
static void copy_in (void *dst_, const void *usrc_, size_t size) 
{
	uint8_t *dst = dst_;
	const uint8_t *usrc = usrc_;
	for (; size > 0; size--, dst++, usrc++)
	{
		if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc))
		{
			thread_exit ();
		}
	}
}

/* Creates a copy of user string US in kernel memory
*    and returns it as a page that must be freed with
*       palloc_free_page().
*          Truncates the string at PGSIZE bytes in size.
*             Call thread_exit() if any of the user accesses are invalid. */
static char *copy_in_string (const char *us) 
{
	char *ks;
	size_t length;     
	
	ks = palloc_get_page (0);
	if (ks == NULL) 
		thread_exit ();
		
	for (length = 0; length < PGSIZE; length++)
	{
		if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
		{
			palloc_free_page (ks);
			thread_exit ();
		}
		if (ks[length] == '\0')
			return ks;
	}
	ks[PGSIZE - 1] = '\0';
	return ks;
}

/* Returns true if UADDR is a valid, mapped user address,
 *    false otherwise. */
static bool verify_user (const void *uaddr) 
{
	  return (uaddr < PHYS_BASE && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}

void syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

///-------------------------//
//need to create some sort of way to access the functions we want
typedef int function_to_call(int, int, int);

struct function_info
{
	size_t argc;
	function_to_call *ptr_to_func;
};

static const struct function_info table_of_funcs[] = 
{
	{0, (function_to_call *) our_halt},
	{1, (function_to_call *) our_exit},
	{1, (function_to_call *) our_exec},
	{1, (function_to_call *) our_wait},
	{2, (function_to_call *) our_create},
	{1, (function_to_call *) our_remove},
	{1, (function_to_call *) our_open},
	{1, (function_to_call *) our_filesize},
	{3, (function_to_call *) our_read},
	{3, (function_to_call *) our_write},
	{2, (function_to_call *) our_seek},
	{1, (function_to_call *) our_tell},
	{1, (function_to_call *) our_close},
};

static void syscall_handler (struct intr_frame *f)
{
	unsigned callNum;
	int args[3];
	const struct function_info *func_to_call;
	//##Get syscall number
	copy_in (&callNum, f->esp, sizeof callNum);
	//##Using the number find out which system call is being used
	if(callNum >= (sizeof(table_of_funcs)/sizeof(*table_of_funcs)))
	{
		thread_exit();
	}
	//if it is a proper call number, move the pointer to the proper function struct
	func_to_call = table_of_funcs + callNum;
	
	ASSERT (func_to_call->argc <= (sizeof(args)/sizeof(*args)));
	//initialize args to 0
	int i;
	for(i = 0; i < 3; ++i)
	{
		args[i] = 0;
	}
	copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * func_to_call->argc);
	//##Use switch statement or something and run this below for each
	//##Depending on the callNum...
	f->eax = func_to_call->ptr_to_func(args[0], args[1], args[2]);
}

static int our_halt(void)
{
	shutdown_power_off();
}

static int our_exit(int status)
{
	thread_current()->exit_stat = status;
	thread_exit();
	NOT_REACHED();
}

static int our_exec(const char *cmd_line)
{
	char *string_to_page = copy_in_string(cmd_line);
	tid_t tid = process_execute(string_to_page);
	palloc_free_page(string_to_page);
	return tid;
}

static int our_wait(tid_t proc_id)
{
	return process_wait(proc_id);
}

static int our_create(const char *file, unsigned initial_size)
{
	char *string_to_page = copy_in_string(file);
	bool check = filesys_create(string_to_page, initial_size);
	palloc_free_page(string_to_page);
	return check;
}

