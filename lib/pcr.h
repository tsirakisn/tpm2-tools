//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
#ifndef SRC_PCR_H_
#define SRC_PCR_H_

#include <stdbool.h>

#include <tss2/tss2_sys.h>

bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels);
bool pcr_parse_list(const char *str, size_t len, TPMS_PCR_SELECTION *pcrSel);
TSS2_RC get_max_supported_pcrs(TSS2_SYS_CONTEXT *sapi_context, UINT32 *max_pcrs);

int pcr_get_id(const char *arg, UINT32 *pcrId);
int pcr_parse_arg(char *arg, UINT32 *pcrId, BYTE *forwardHash, bool *hash_set);

typedef struct pcr_struct {
	UINT32 pcr;
	BYTE forwardHash[32];
	bool hash_set;
} pcr_struct;

#define SET_PCR_SELECT_BIT( pcrSelection, pcr ) \
    (pcrSelection).pcrSelect[( (pcr)/8 )] |= ( 1 << ( (pcr) % 8) );

#define CLEAR_PCR_SELECT_BITS( pcrSelection ) \
    (pcrSelection).pcrSelect[0] = 0; \
    (pcrSelection).pcrSelect[1] = 0; \
    (pcrSelection).pcrSelect[2] = 0;

#define SET_PCR_SELECT_SIZE( pcrSelection, size ) \
    (pcrSelection).sizeofSelect = size;

#define TEST_PCR_SELECT_BIT( pcrSelection, pcr ) \
    ((pcrSelection).pcrSelect[( (pcr)/8 )] & ( 1 << ( (pcr) % 8) ))

#endif /* SRC_PCR_H_ */
