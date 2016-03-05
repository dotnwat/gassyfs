#include <iostream>
#include <fstream>
#include <streambuf>
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
  if (argc < 3) {
    std::cerr << "USAGE: <file> <cmd> [policy]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  where cmd can be:" << std::endl;
    std::cerr << "    print_string  print a string inside GassyFS" << std::endl;
    std::cerr << "    setlua_atime  set the policy for setting the atime" << std::endl;
    std::cerr << "    getlua_atime  print the policy for setting the atime" << std::endl;
    std::cerr << "  where policy is the Lua file to inject" << std::endl;
    exit(1);
  }

  int fd = open(argv[1], O_RDWR);
  char *cmd = argv[2];

  if (fd < 0) {
    perror("open");
    exit(1);
  }

  struct gassy_string s;
  if (argc > 3) {
    std::ifstream ifs(argv[3]);
    std::string line, file;
    while(std::getline(ifs, line)) {
      file.append(line);
      file.append("\n");
    }
    memset(&s, 0, file.length());
    sprintf(s.string, "%s", file.c_str());
  }

  int op = -1;
  if (!strcmp(cmd, "print_string"))
    op = GASSY_IOC_PRINT_STRING;
  else if (!strcmp(cmd, "getlua_atime"))
    op = GASSY_IOC_GETLUA_ATIME;
  else if (!strcmp(cmd, "setlua_atime"))
    op = GASSY_IOC_SETLUA_ATIME;
  else if (!strcmp(cmd, "checkpoint"))
    op = GASSY_IOC_CHECKPOINT;
  else {
    std::cerr << "unknown command" << std::endl;
    exit(1);
  }

  int ret = ioctl(fd, op, &s);
  if (ret == -1)
    perror("ioctl failed");

  close(fd);

  return 0;
}
