/********************************************************************************/
/*										*/
/*			        TPM Delegation Routines				*/
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: delegation.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2006, 2010.					*/
/*										*/
/* All rights reserved.								*/
/*                                                                              */
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/*                                                                              */
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/*                                                                              */
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/*                                                                              */
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/*                                                                              */
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <tpm.h>
#include <tpmfunc.h>
#include <tpmutil.h>
#include <oiaposap.h>
#include <hmac.h>
#include <tpm_types.h>
#include <tpm_constants.h>
#include <tpm_error.h>


struct delegation_blob
{
        uint32_t etype;
        uint32_t keyhandle;
        unsigned char keyDigest[TPM_DIGEST_SIZE];
        uint32_t blobSize;
        unsigned char passHash[TPM_HASH_SIZE];
        unsigned char oldPassHash[TPM_HASH_SIZE];
};

static
char* getDelegationFile(void)
{
        char* filename;
        char* inst = getenv("TPM_INSTANCE");

        if (NULL == inst) {
                inst = "0";
        }
        filename = malloc(strlen(inst) + strlen("/tmp/.delegation-") + 2);
        sprintf(filename, "/tmp/.delegation-%s", inst);
        return filename;
}

static
TPM_BOOL TPM_FindDelegationBlob(uint32_t etype,
                                uint32_t keyhandle,
                                int* fd)
{
        unsigned int entry = 0;
        TPM_BOOL rc = FALSE;
        char* filename = getDelegationFile();

        *fd = open(filename,O_RDWR | O_CREAT,S_IRWXU);
        free(filename);
        if (*fd > 0) {
                while (1) {
                        struct delegation_blob db;
                        int n;

                        if (sizeof(db) == read(*fd, &db, sizeof(db))) {
                                if (db.etype == etype &&
                                    db.keyhandle == keyhandle) {
                                        /* found it */
                                        n = lseek(*fd, -sizeof(db), SEEK_CUR);
#ifdef __CYGWIN__
                                        lseek(*fd, n, SEEK_SET);
                                        rc = TRUE;
#else
                                        if (n >= 0) {
                                                rc = TRUE;
                                        }
#endif
                                        break;
                                }
                                /* Not the right one. */
                                /* Jump over the blob */
                                n = lseek(*fd, db.blobSize, SEEK_CUR);
#ifdef __CYGWIN__
                                lseek(*fd, n, SEEK_SET);
#endif
                                entry++;
                        } else {
                                /* Read failed. Assuming I am at the end of the
                                   file
                                 */
                                rc = FALSE;
                                break;
                        }
                }
        }

        return rc;
}

static
uint32_t TPM_GetDelegationBlobFromFile(uint32_t etype,
                                       unsigned char* buffer, uint32_t* bufferSize)
{
        uint32_t ret = 0;
        char* name = NULL;

        switch (etype) {
        case TPM_ET_DEL_KEY_BLOB:
                name = getenv("TPM_DSAP_KEYBLOB");
                break;

        case TPM_ET_DEL_OWNER_BLOB:
                name = getenv("TPM_DSAP_OWNERBLOB");
                break;
        }

        if (name) {
                int fd = 0;

                fd = open(name, O_RDONLY);
                if (fd > 0) {
                        struct stat _stat;

                        fstat(fd, &_stat);
                        if ((off_t)*bufferSize <= _stat.st_size) {
                                *bufferSize = read(fd, buffer, _stat.st_size);
                        } else {
                                ret = ERR_BUFFER;
                        }
                        close(fd);
                }
        } else {
                ret = ERR_ENV_VARIABLE;
        }

        return ret;
}

uint32_t TPM_GetDelegationBlob(uint32_t etype,
                               uint32_t keyhandle,
                               unsigned char* newPassHash,
                               unsigned char* buffer, uint32_t* bufferSize)
{
        int fd = 0;
        TPM_BOOL found;

        (void)newPassHash;

        if (0 == TPM_GetDelegationBlobFromFile(etype,
                                               buffer, bufferSize)) {
                return 0;
        }

        found = TPM_FindDelegationBlob(etype,
                                       keyhandle,
                                       &fd);
        if (TRUE == found) {
                if (fd > 0) {
                        struct delegation_blob db;

                        if (sizeof(db) == read(fd, &db, sizeof(db))) {
                                if (*bufferSize < db.blobSize) {
                                        return ERR_BUFFER;
                                }
                                if ((int)db.blobSize == read(fd, buffer, db.blobSize)) {
                                        *bufferSize = db.blobSize;
                                        return 0;
                                } else {
                                        return ERR_BAD_FILE;
                                }
                        } else {
                                return ERR_BAD_FILE;
                        }
                } else {
                        return ERR_BAD_FILE;
                }
        } else {
                return ERR_NOT_FOUND;
        }
        return ERR_NOT_FOUND;
}
