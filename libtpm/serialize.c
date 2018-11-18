/********************************************************************************/
/*										*/
/*			        TPM Serializing Routines                        */
/*			     Written by S. Berger				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: serialize.c 4702 2013-01-03 21:26:29Z kgoldman $		*/
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
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tpm.h"
#include "tpmutil.h"
#include "tpm_structures.h"
#include "tpmkeys.h"
#include "tpmfunc.h"

#include "serialize.h"

uint32_t TPM_WritePCRComposite(struct tpm_buffer* buffer, TPM_PCR_COMPOSITE* comp)
{
        uint32_t ret;

        if (0 == comp->select.sizeOfSelect) {
                comp->select.sizeOfSelect = sizeof(comp->select.pcrSelect);
                memset(comp->select.pcrSelect,
                       0x0,
                       comp->select.sizeOfSelect);
        }
        ret = TSS_buildbuff(FORMAT_TPM_PCR_COMPOSITE, buffer,
                            PARAMS_TPM_PCR_COMPOSITE_W(comp));

        return ret;
}

uint32_t TPM_ReadPCRComposite(const struct tpm_buffer* buffer, uint32_t offset, TPM_PCR_COMPOSITE* tpc)
{
        uint32_t ret;

        ret = TSS_parsebuff(FORMAT_TPM_PCR_COMPOSITE, buffer, offset,
                            PARAMS_TPM_PCR_COMPOSITE_R(tpc));
        return ret;
}

uint32_t TPM_ReadPCRInfoLong(struct tpm_buffer* buffer, uint32_t offset, TPM_PCR_INFO_LONG* info)
{
        return TSS_parsebuff(FORMAT_TPM_PCR_INFO_LONG, buffer, offset,
                             PARAMS_TPM_PCR_INFO_LONG_R(info));
}

uint32_t TPM_WritePCRInfoLong(struct tpm_buffer* buffer, TPM_PCR_INFO_LONG* info)
{
        uint32_t ret;

        if (0 == info->creationPCRSelection.sizeOfSelect) {
                info->creationPCRSelection.sizeOfSelect = sizeof(info->creationPCRSelection.pcrSelect);
                memset(info->creationPCRSelection.pcrSelect,
                       0x0,
                       info->creationPCRSelection.sizeOfSelect);
        }
        if (0 == info->releasePCRSelection.sizeOfSelect) {
                info->releasePCRSelection.sizeOfSelect = sizeof(info->releasePCRSelection.pcrSelect);
                memset(info->releasePCRSelection.pcrSelect,
                       0x0,
                       info->releasePCRSelection.sizeOfSelect);
        }
        ret = TSS_buildbuff(FORMAT_TPM_PCR_INFO_LONG, buffer,
                            PARAMS_TPM_PCR_INFO_LONG_W(info));
        return ret;
}

uint32_t TPM_WritePCRInfoShort(struct tpm_buffer* buffer, TPM_PCR_INFO_SHORT* info)
{
        uint32_t ret;

        if (0 == info->pcrSelection.sizeOfSelect) {
                info->pcrSelection.sizeOfSelect = sizeof(info->pcrSelection.pcrSelect);
                memset(info->pcrSelection.pcrSelect,
                       0x0,
                       info->pcrSelection.sizeOfSelect);
        }
        ret = TSS_buildbuff(FORMAT_TPM_PCR_INFO_SHORT, buffer,
                            PARAMS_TPM_PCR_INFO_SHORT_W(info));

        return ret;
}

uint32_t TPM_ReadPCRInfoShort(const struct tpm_buffer* buffer, uint32_t offset, TPM_PCR_INFO_SHORT* info)
{
        uint32_t ret;

        ret = TSS_parsebuff(FORMAT_TPM_PCR_INFO_SHORT, buffer, offset,
                            PARAMS_TPM_PCR_INFO_SHORT_R(info));
        return ret;
}

uint32_t TPM_WritePCRInfo(struct tpm_buffer* buffer, TPM_PCR_INFO* info)
{
        uint32_t ret;

        if (0 == info->pcrSelection.sizeOfSelect) {
                info->pcrSelection.sizeOfSelect = sizeof(info->pcrSelection.pcrSelect);
                memset(info->pcrSelection.pcrSelect,
                       0x0,
                       info->pcrSelection.sizeOfSelect);
        }
        ret = TSS_buildbuff(FORMAT_TPM_PCR_INFO, buffer,
                            PARAMS_TPM_PCR_INFO_W(info));
        return ret;
}

uint32_t TPM_ReadPCRInfo(struct tpm_buffer* buffer, uint32_t offset, TPM_PCR_INFO* info)
{
        uint32_t ret;

        ret = TSS_parsebuff(FORMAT_TPM_PCR_INFO, buffer, offset,
                            PARAMS_TPM_PCR_INFO_R(info));
        return ret;
}

uint32_t TPM_WritePCRSelection(struct tpm_buffer* buffer, TPM_PCR_SELECTION* sel)
{
        uint32_t ret;

        if (0 == sel->sizeOfSelect) {
                sel->sizeOfSelect = sizeof(sel->pcrSelect);
                memset(sel->pcrSelect,
                       0x0,
                       sel->sizeOfSelect);
        }
        ret = TSS_buildbuff(FORMAT_TPM_PCR_SELECTION, buffer,
                            PARAMS_TPM_PCR_SELECTION_W(sel));
        return ret;
}

uint32_t TPM_ReadPCRSelection(struct tpm_buffer* buffer, uint32_t offset,
                              TPM_PCR_SELECTION* sel)
{
        uint32_t ret;

        ret = TSS_parsebuff(FORMAT_TPM_PCR_SELECTION, buffer, offset,
                            PARAMS_TPM_PCR_SELECTION_R(sel));
        return ret;
}

uint32_t TPM_ReadFile(const char* filename, unsigned char** buffer, uint32_t* buffersize)
{
        uint32_t ret = 0;
        FILE* f = fopen(filename, "r");

        if (f) {
                struct stat _stat;

                if (0 == fstat(fileno(f), &_stat)) {
                        *buffer = (unsigned char*)malloc(_stat.st_size);
                        *buffersize = (uint32_t)_stat.st_size;

                        if ((size_t)_stat.st_size != fread(*buffer, 1, _stat.st_size, f)) {
                                free(*buffer);
                                *buffer = NULL;
                                *buffersize = 0;
                                ret = ERR_BAD_FILE;
                        }
                        if (fclose(f) != 0)
                                ret = ERR_BAD_FILE_CLOSE;
                } else {
                        fclose(f);
                        ret = ERR_BAD_FILE;
                }
        } else {
                ret = ERR_MEM_ERR;
        }

        return ret;
}

uint32_t TPM_WriteFile(const char* filename, unsigned char* buffer, uint32_t buffersize)
{
        uint32_t ret = 0;

        if (buffer == NULL) {
                return ERR_BUFFER;
        }
        FILE* f = fopen(filename, "w");

        if (NULL != f) {
                if (buffersize != fwrite(buffer, 1, buffersize,f)) {
                        ret = ERR_BAD_FILE;
                }
                if (fclose(f) != 0)
                        ret = ERR_BAD_FILE_CLOSE;
        } else {
                ret = ERR_BAD_FILE;
        }

        return ret;
}

uint32_t TPM_WriteTransportLogIn(struct tpm_buffer* buffer,
                                 TPM_TRANSPORT_LOG_IN* ttli)
{
        return TSS_buildbuff(FORMAT_TPM_TRANSPORT_LOG_IN, buffer,
                             PARAMS_TPM_TRANSPORT_LOG_IN_W(ttli));
}

uint32_t TPM_WriteTransportLogOut(struct tpm_buffer* buffer,
                                  TPM_TRANSPORT_LOG_OUT* ttlo)
{
        return TSS_buildbuff(FORMAT_TPM_TRANSPORT_LOG_OUT, buffer,
                             PARAMS_TPM_TRANSPORT_LOG_OUT_W(ttlo));
}

uint32_t TPM_WriteCurrentTicks(struct tpm_buffer* buffer,
                               TPM_CURRENT_TICKS* tct)
{
        return TSS_buildbuff(FORMAT_TPM_CURRENT_TICKS, buffer,
                             PARAMS_TPM_CURRENT_TICKS_W(tct));
}

uint32_t TPM_ReadCurrentTicks(struct tpm_buffer* buffer,
                              uint32_t offset,
                              TPM_CURRENT_TICKS* tct)
{
        return TSS_parsebuff(FORMAT_TPM_CURRENT_TICKS, buffer, offset,
                             PARAMS_TPM_CURRENT_TICKS_R(tct));
}

#if 0
/****************************************************************************/
/*                                                                          */
/* Walk down a Key blob extracting information                              */
/*                                                                          */

/****************************************************************************/
uint32_t TSS_KeyExtract(const struct tpm_buffer* tb, uint32_t offset,
                        keydata* k)
{
        return TPM_ReadKey(tb, offset, k);
}

/****************************************************************************/
/*                                                                          */
/* Walk down a Public Key blob extracting information                       */
/*                                                                          */

/****************************************************************************/
uint32_t TSS_PubKeyExtract(const struct tpm_buffer* tb, uint32_t offset,
                           pubkeydata* k)
{
        uint32_t ret;

        ret = TSS_parsebuff(FORMAT_TPM_PUBKEY_EMB_RSA, tb, offset,
                            PARAMS_TPM_PUBKEY_EMB_RSA_R(k));
        return ret;
}

#endif
