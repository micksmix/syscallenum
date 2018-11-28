Simple x64 Linux binary to enumerate syscalls.

Currently it statically links seccomp, so that this can be run on systems that lack seccomp libraries.

I plan to add more functionality to this tool:
 1. ability to list filtered syscalls
 2. ability to output as json
 3. support for compiling with shared seccomp (reduces binary size greatly)


 Example:

 ```
 $ ./syscallenum
 -- syscall(1) is write = 0 : Success (0)
 -- syscall(2) is open = -1 : Bad address (14)
 -- syscall(3) is close = 0 : Success (0)
 -- syscall(4) is stat = -1 : Bad address (14)
[.......]
 -- syscall(321) is bpf = -1 : Function not implemented (38)
 -- syscall(322) is execveat = -1 : Function not implemented (38)
 -- syscall(323) is userfaultfd = -1 : Function not implemented (38)
 -- syscall(324) is membarrier = -1 : Function not implemented (38)
 -- syscall(325) is mlock2 = -1 : Function not implemented (38)
 -- syscall(326) is copy_file_range = -1 : Function not implemented (38)
 -- syscall(327) is (null) = -1 : Function not implemented (38)
 -- syscall(328) is (null) = -1 : Function not implemented (38)

```

Note the currently non-existent syscalls of 327 and 328 return `(null)` for the syscall name, which indicates they are not valid.