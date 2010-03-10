/* ****************************************************************************
 * $Id: nf2util.h 3764 2008-05-22 06:48:34Z grg $
 *
 * Module: nf2util.h
 * Project: NetFPGA 2 Linux Kernel Driver
 * Description: Header file for kernel driver
 *
 * Change history:
 *
 */

#ifndef _NF2UTIL_H
#define _NF2UTIL_H	1

#define PATHLEN		80
#define DEVICE_STR_LEN 100


/*
 * Structure to represent an nf2 device to a user mode programs
 */
struct nf2device {
	char *device_name;
	int fd;
	int net_iface;
};

/* Function declarations */

int readReg(struct nf2device *nf2, unsigned reg, unsigned *val);
int writeReg(struct nf2device *nf2, unsigned reg, unsigned val);
int check_iface(struct nf2device *nf2);
int openDescriptor(struct nf2device *nf2);
int closeDescriptor(struct nf2device *nf2);
void nf2_read_info(struct nf2device *nf2);
void printHello (struct nf2device *nf2, int *val);

extern unsigned cpci_version;
extern unsigned cpci_revision;
extern unsigned nf2_device_id;
extern unsigned nf2_revision;
extern unsigned nf2_cpci_version;
extern unsigned nf2_cpci_revision;
extern char nf2_device_str[DEVICE_STR_LEN];

#endif
