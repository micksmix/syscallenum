Simple x64 Linux binary to enumerate syscalls.

Currently it statically links seccomp, so that this can be run on systems that lack seccomp libraries.

I plan to add more functionality to this tool:
 * support for compiling with shared seccomp (reduces binary size greatly)


 Example:

 ```
 $ ./syscallenum | sort | uniq
000|read|allowed|Success|0
001|write|allowed|Success|0
002|open|allowed|Bad address|14
003|close|allowed|Success|0
004|stat|allowed|Bad address|14
005|fstat|allowed|Bad address|14
006|lstat|allowed|Bad address|14
007|poll|allowed|Success|0
008|lseek|allowed|Illegal seek|29
009|mmap|allowed|Invalid argument|22
[.......]
319|memfd_create|allowed|Function not implemented|38
320|kexec_file_load|allowed|Function not implemented|38
321|bpf|allowed|Function not implemented|38
322|execveat|allowed|Function not implemented|38
323|userfaultfd|allowed|Function not implemented|38
324|membarrier|allowed|Function not implemented|38
325|mlock2|allowed|Function not implemented|38
326|copy_file_range|allowed|Function not implemented|38
327|
328|

```

Note the currently non-existent syscalls of 327 and 328 return nothing, which indicates they are not valid.

To show only filtered syscalls:
```
./syscallenum -f
```

To show only allowed syscalls:
```
./syscallenum -a
```

When run without parameters `syscallenum` will return allowed, filtered, and non-existent syscall results
