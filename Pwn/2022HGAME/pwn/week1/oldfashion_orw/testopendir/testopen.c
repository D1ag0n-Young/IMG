       #define _GNU_SOURCE
       #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>
       #include <stdio.h>
       #include <stdlib.h>
       #include <unistd.h>
       #include <errno.h>
       #include <string.h>

       #define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)

       int
       main(int argc, char *argv[])
       {
    char filename[] = "flag";
struct file_handle tmp_handle;
int mount_id;
tmp_handle.handle_bytes = 0;
if (name_to_handle_at(AT_FDCWD,filename, &tmp_handle, &mount_id, 0) != -1 || errno != EOVERFLOW) {
    printf("%d\n",1);
    exit(-1); // Unexpected behavior
}
struct file_handle *handle = (struct file_handle *)malloc(tmp_handle.handle_bytes);
handle->handle_bytes = tmp_handle.handle_bytes;
int mount_id2;
name_to_handle_at(AT_FDCWD,filename, handle, &mount_id2, 0);
int fd = open_by_handle_at(mount_id2, handle, O_RDONLY);
printf("%d\n",fd);
       }