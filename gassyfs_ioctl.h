#ifndef GASSYFS_IOCTL_H_
#define GASSYFS_IOCTL_H_

#define GASSY_IOC_MAGIC 0x98

struct gassy_string {
  char string[1024];
};

#define GASSY_IOC_PRINT_STRING _IOW(GASSY_IOC_MAGIC, 1, struct gassy_string)

#endif
