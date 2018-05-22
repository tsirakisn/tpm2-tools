#ifndef SRC_SHARED_H
#define SRC_SHARED_H

#include <tss2/tss2_sys.h>

#include "tpm_session.h"
#include "pcr.h"

int create(TSS2_SYS_CONTEXT *sapi_context, TPMI_DH_OBJECT parent_handle, TPM2B_PUBLIC *in_public, TPM2B_SENSITIVE_CREATE *in_sensitive, TPMI_ALG_PUBLIC type, TPMI_ALG_HASH nameAlg, char *input, char *opu_path, char *opr_path, int H_flag, int g_flag, int G_flag, int I_flag, int o_flag, int O_flag, int A_flag, TPMA_OBJECT objectAttributes);

int build_policy_external(TSS2_SYS_CONTEXT *sysContext, SESSION **policySession, int trial, pcr_struct **pcrList, INT32 pcrCount, TPM2B_DIGEST *policyDigestOut, TPMI_ALG_HASH nameAlg);

#endif /* SRC_SHARED_H */
