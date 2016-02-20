#include <iostream>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include "gassyfs_ioctl.h"

int main(int argc, char **argv)
{
  int fd = open(argv[1], O_RDWR);
  if (fd < 0) {
    perror("open");
    exit(1);
  }

  struct gassy_string s;
  memset(&s, 0, sizeof(s));
  sprintf(s.string, "%s", "hello from gassy-cmd");

  int ret = ioctl(fd, GASSY_IOC_PRINT_STRING, &s);
  std::cout << "ioctl ret = " << ret << std::endl;
  if (ret == -1)
    perror("ioctl");

  close(fd);

  return 0;
}
