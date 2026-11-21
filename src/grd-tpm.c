/*
 * Copyright (C) 2022 Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 */

#include "config.h"

#include "grd-tpm.h"

#include <gio/gio.h>
#include <stdio.h>

G_GNUC_BEGIN_IGNORE_DEPRECATIONS
#include <tss2_esys.h>
#include <tss2_mu.h>
#include <tss2_rc.h>
#include <tss2_tctildr.h>
G_GNUC_END_IGNORE_DEPRECATIONS

#include "grd-debug.h"

/*
 * Sealed secrets are persisted as the sealed object's public and private
 * areas (wire-format TPM2B_PUBLIC / TPM2B_PRIVATE, base64), see
 * SEALED_OBJECT_VARIANT_TYPE. Restoring re-derives the primary key from the
 * owner hierarchy seed and loads the object under it; both survive a TPM
 * Reset, so the secret stays readable across reboots.
 *
 * The primary key is ECC NIST P-256: deriving it happens on every restore,
 * and RSA-2048 derivation takes ~18 s on some TPMs (e.g. STM ST33 in
 * ThinkPad P14s) versus ~0.4 s for ECC.
 *
 * Secrets written by older versions are a TPMS_CONTEXT of the loaded object
 * (LEGACY_CONTEXT_VARIANT_TYPE). Saved contexts are bound to the TPM Reset
 * count, so they only restore within the boot they were written in; they are
 * still read for compatibility until re-stored.
 */
#define SEALED_OBJECT_VARIANT_TYPE "(uss)"
#define SEALED_OBJECT_FORMAT_VERSION 1
#define LEGACY_CONTEXT_VARIANT_TYPE "(uutqs)"

struct _GrdTpm
{
  GObject parent;

  TSS2_TCTI_CONTEXT *tcti_context;
  ESYS_CONTEXT *esys_context;

  ESYS_TR hmac_session;
  ESYS_TR trial_session;
  ESYS_TR policy_session;
};

G_DEFINE_TYPE (GrdTpm, grd_tpm, G_TYPE_OBJECT)

static gboolean
check_tpm_existence (GError **error)
{
  g_autoptr (GFile) tpm_dev = NULL;
  g_autoptr (GFile) tpmrm_dev = NULL;

  tpm_dev = g_file_new_for_path ("/dev/tpm0");
  tpmrm_dev = g_file_new_for_path ("/dev/tpmrm0");
  if (!g_file_query_exists (tpm_dev, NULL) ||
      !g_file_query_exists (tpmrm_dev, NULL))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                   "No TPM device found");
      return FALSE;
    }

  return TRUE;
}

static gboolean
init_transmission_interface (GrdTpm  *tpm,
                             GError **error)
{
  TSS2_RC rc;

  rc = Tss2_TctiLdr_Initialize (NULL, &tpm->tcti_context);

  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to initialize transmission interface context: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }

  return TRUE;
}

static gboolean
init_tss2_esys (GrdTpm  *tpm,
                GError **error)
{
  TSS2_RC rc;

  rc = Esys_Initialize (&tpm->esys_context, tpm->tcti_context, NULL);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to initialize ESYS context: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }

  return TRUE;
}

static gboolean
start_hmac_session (GrdTpm  *tpm,
                    GError **error)
{
  TPMT_SYM_DEF symmetric = {
    .algorithm = TPM2_ALG_NULL,
  };
  TSS2_RC rc;

  rc = Esys_StartAuthSession (tpm->esys_context,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC,
                              &symmetric,
                              TPM2_ALG_SHA256,
                              &tpm->hmac_session);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to start auth session: %s (%d)",
                   Tss2_RC_Decode (rc), rc);
      return FALSE;
    }

  return TRUE;
}

static gboolean
start_trial_session (GrdTpm  *tpm,
                     GError **error)
{
  TPMT_SYM_DEF symmetric = {
    .algorithm = TPM2_ALG_NULL,
  };
  TSS2_RC rc;

  rc = Esys_StartAuthSession (tpm->esys_context,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_TRIAL,
                              &symmetric,
                              TPM2_ALG_SHA256,
                              &tpm->trial_session);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to start policy session: %s (%d)",
                   Tss2_RC_Decode (rc), rc);
      return FALSE;
    }

  return TRUE;
}

static gboolean
start_policy_session (GrdTpm  *tpm,
                      GError **error)
{
  TPMT_SYM_DEF symmetric = {
    .algorithm = TPM2_ALG_NULL,
  };
  TSS2_RC rc;

  rc = Esys_StartAuthSession (tpm->esys_context,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_POLICY,
                              &symmetric,
                              TPM2_ALG_SHA256,
                              &tpm->policy_session);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to start policy session: %s (%d)",
                   Tss2_RC_Decode (rc), rc);
      return FALSE;
    }

  return TRUE;
}

gboolean
grd_tpm_create_primary (GrdTpm   *tpm,
                        ESYS_TR  *primary_handle_out,
                        GError  **error)
{
  TPM2B_SENSITIVE_CREATE in_sensitive_primary = {};
  TPM2B_PUBLIC in_public = {
    .publicArea = {
      .type = TPM2_ALG_ECC,
      .nameAlg = TPM2_ALG_SHA256,
      .objectAttributes = (TPMA_OBJECT_RESTRICTED |
                           TPMA_OBJECT_DECRYPT |
                           TPMA_OBJECT_FIXEDTPM |
                           TPMA_OBJECT_FIXEDPARENT |
                           TPMA_OBJECT_SENSITIVEDATAORIGIN |
                           TPMA_OBJECT_USERWITHAUTH),
      .parameters.eccDetail = {
        .symmetric = {
          .algorithm = TPM2_ALG_AES,
          .keyBits.aes = 128,
          .mode.aes = TPM2_ALG_CFB,
        },
        .scheme.scheme = TPM2_ALG_NULL,
        .curveID = TPM2_ECC_NIST_P256,
        .kdf.scheme = TPM2_ALG_NULL,
      },
    },
  };
  TPM2B_DATA outside_info = {};
  TPML_PCR_SELECTION creation_pcr = {};
  TSS2_RC rc;

  g_assert (tpm->hmac_session);

  rc = Esys_CreatePrimary (tpm->esys_context,
                           ESYS_TR_RH_OWNER,
                           tpm->hmac_session,
                           ESYS_TR_NONE,
                           ESYS_TR_NONE,
                           &in_sensitive_primary,
                           &in_public,
                           &outside_info,
                           &creation_pcr,
                           primary_handle_out,
                           NULL, NULL, NULL, NULL);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Esys_CreatePrimary failed: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }

  return TRUE;
}

gboolean
grd_tpm_read_pcr (GrdTpm              *tpm,
                  TPML_PCR_SELECTION **pcr_selection_out,
                  TPML_DIGEST        **pcr_digest_out,
                  GError             **error)
{
  TPML_PCR_SELECTION pcr_selection_in = {
    .count = 1,
    .pcrSelections = {
      {
        .hash = TPM2_ALG_SHA256,
        .sizeofSelect = 3,
        .pcrSelect = { 1 << 0 | 1 << 1 | 1 << 2 | 1 << 3, },
      },
    }
  };
  TSS2_RC rc;

  rc = Esys_PCR_Read (tpm->esys_context,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      ESYS_TR_NONE,
                      &pcr_selection_in,
                      NULL,
                      pcr_selection_out,
                      pcr_digest_out);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Esys_PCR_Read failed: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }

  return TRUE;
}

gboolean
do_create_policy (GrdTpm              *tpm,
                  ESYS_TR              session,
                  TPML_PCR_SELECTION  *pcr_selection,
                  TPML_DIGEST         *pcr_digest,
                  TPM2B_DIGEST       **policy_digest_out,
                  GError             **error)
{
  g_autoptr (GChecksum) checksum = NULL;
  TPM2B_DIGEST pcr_hash_digest = {};
  size_t size;
  int i;
  TSS2_RC rc;

  checksum = g_checksum_new (G_CHECKSUM_SHA256);
  for (i = 0; i < pcr_digest->count; i++)
    {
      g_checksum_update (checksum,
                         pcr_digest->digests[i].buffer,
                         pcr_digest->digests[i].size);
    }

  size = G_N_ELEMENTS (pcr_hash_digest.buffer);
  g_checksum_get_digest (checksum,
                         (uint8_t *) &pcr_hash_digest.buffer,
                         &size);
  pcr_hash_digest.size = size;

  rc = Esys_PolicyPCR (tpm->esys_context, session,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       ESYS_TR_NONE,
                       &pcr_hash_digest,
                       pcr_selection);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Esys_PolicyPCR failed: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }

  rc = Esys_PolicyGetDigest (tpm->esys_context, session,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             ESYS_TR_NONE,
                             policy_digest_out);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Esys_PolicyGetDigest failed: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }

  return TRUE;
}

static char *
marshal_public_base64 (TPM2B_PUBLIC  *public,
                       GError       **error)
{
  uint8_t buffer[sizeof (TPM2B_PUBLIC)];
  size_t offset = 0;
  TSS2_RC rc;

  rc = Tss2_MU_TPM2B_PUBLIC_Marshal (public, buffer, sizeof (buffer), &offset);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to marshal sealed object public area: %s",
                   Tss2_RC_Decode (rc));
      return NULL;
    }

  return g_base64_encode (buffer, offset);
}

static char *
marshal_private_base64 (TPM2B_PRIVATE  *private,
                        GError        **error)
{
  uint8_t buffer[sizeof (TPM2B_PRIVATE)];
  size_t offset = 0;
  TSS2_RC rc;

  rc = Tss2_MU_TPM2B_PRIVATE_Marshal (private, buffer, sizeof (buffer),
                                      &offset);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to marshal sealed object private area: %s",
                   Tss2_RC_Decode (rc));
      return NULL;
    }

  return g_base64_encode (buffer, offset);
}

gboolean
grd_tpm_store_secret (GrdTpm              *tpm,
                      const char          *secret,
                      ESYS_TR              primary_handle,
                      TPML_PCR_SELECTION  *pcr_selection,
                      TPML_DIGEST         *pcr_digest,
                      GVariant           **secret_variant_out,
                      GError             **error)
{
  size_t secret_size;
  size_t offset = 0;
  g_autofree TPM2B_DIGEST *policy_digest = NULL;
  TPM2B_TEMPLATE template = {};
  TPM2B_PUBLIC template_public;
  TPM2B_SENSITIVE_CREATE in_sensitive;
  ESYS_TR secret_handle;
  g_autofree TPM2B_PRIVATE *out_private = NULL;
  g_autofree TPM2B_PUBLIC *out_public = NULL;
  g_autofree char *public_base64 = NULL;
  g_autofree char *private_base64 = NULL;
  TSS2_RC rc;

  g_assert (tpm->trial_session);

  secret_size = strlen (secret) + 1;
  if (secret_size > G_N_ELEMENTS (in_sensitive.sensitive.data.buffer))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Secret too large (%lu exceeds %lu max)",
                   secret_size,
                   G_N_ELEMENTS (in_sensitive.sensitive.data.buffer));
      return FALSE;
    }

  if (!do_create_policy (tpm, tpm->trial_session,
                         pcr_selection,
                         pcr_digest,
                         &policy_digest,
                         error))
    return FALSE;

  template_public = (TPM2B_PUBLIC) {
    .publicArea = {
      .type = TPM2_ALG_KEYEDHASH,
      .nameAlg = TPM2_ALG_SHA256,
      .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT,
      .parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL,
    },
  };
  memcpy (template_public.publicArea.authPolicy.buffer,
          policy_digest->buffer,
          policy_digest->size);
  template_public.publicArea.authPolicy.size = policy_digest->size;

  rc = Tss2_MU_TPMT_PUBLIC_Marshal (&template_public.publicArea,
                                    template.buffer,
                                    G_N_ELEMENTS (template.buffer),
                                    &offset);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to marshal public template: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }
  template.size = offset;

  in_sensitive = (TPM2B_SENSITIVE_CREATE) {
    .sensitive.data.size = secret_size,
  };
  memcpy (in_sensitive.sensitive.data.buffer, secret, secret_size);

  rc = Esys_CreateLoaded (tpm->esys_context,
                          primary_handle,
                          tpm->hmac_session,
                          ESYS_TR_NONE,
                          ESYS_TR_NONE,
                          &in_sensitive,
                          &template,
                          &secret_handle,
                          &out_private,
                          &out_public);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Esys_CreateLoaded failed: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }

  Esys_FlushContext (tpm->esys_context, secret_handle);

  public_base64 = marshal_public_base64 (out_public, error);
  if (!public_base64)
    return FALSE;

  private_base64 = marshal_private_base64 (out_private, error);
  if (!private_base64)
    return FALSE;

  *secret_variant_out = g_variant_new (SEALED_OBJECT_VARIANT_TYPE,
                                       SEALED_OBJECT_FORMAT_VERSION,
                                       public_base64,
                                       private_base64);

  return TRUE;
}

static gboolean
decode_sealed_object_variant (GVariant       *variant,
                              TPM2B_PUBLIC   *public_out,
                              TPM2B_PRIVATE  *private_out,
                              GError        **error)
{
  uint32_t version;
  const char *public_base64;
  const char *private_base64;
  g_autofree uint8_t *public_buffer = NULL;
  g_autofree uint8_t *private_buffer = NULL;
  size_t public_size;
  size_t private_size;
  size_t offset;
  TSS2_RC rc;

  g_variant_get (variant, "(u&s&s)",
                 &version, &public_base64, &private_base64);
  if (version != SEALED_OBJECT_FORMAT_VERSION)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                   "Unsupported sealed TPM object format version %u",
                   version);
      return FALSE;
    }

  public_buffer = g_base64_decode (public_base64, &public_size);
  offset = 0;
  rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal (public_buffer, public_size,
                                       &offset, public_out);
  if (rc != TSS2_RC_SUCCESS || offset != public_size)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to decode sealed TPM object public area");
      return FALSE;
    }

  private_buffer = g_base64_decode (private_base64, &private_size);
  offset = 0;
  rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal (private_buffer, private_size,
                                        &offset, private_out);
  if (rc != TSS2_RC_SUCCESS || offset != private_size)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Failed to decode sealed TPM object private area");
      return FALSE;
    }

  return TRUE;
}

static gboolean
load_sealed_object (GrdTpm    *tpm,
                    GVariant  *variant,
                    ESYS_TR   *loaded_secret_handle_out,
                    GError   **error)
{
  TPM2B_PUBLIC in_public = {};
  TPM2B_PRIVATE in_private = {};
  ESYS_TR primary_handle = ESYS_TR_NONE;
  TSS2_RC rc;

  if (!decode_sealed_object_variant (variant, &in_public, &in_private, error))
    return FALSE;

  if (!grd_tpm_create_primary (tpm, &primary_handle, error))
    return FALSE;

  rc = Esys_Load (tpm->esys_context,
                  primary_handle,
                  tpm->hmac_session,
                  ESYS_TR_NONE,
                  ESYS_TR_NONE,
                  &in_private,
                  &in_public,
                  loaded_secret_handle_out);
  Esys_FlushContext (tpm->esys_context, primary_handle);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Esys_Load failed: %s",
                   Tss2_RC_Decode (rc));
      return FALSE;
    }

  return TRUE;
}

static gboolean
decode_legacy_context_variant (GVariant      *variant,
                               TPMS_CONTEXT  *tpms_context,
                               GError       **error)
{
  g_autofree char *base64 = NULL;
  g_autofree uint8_t *decoded = NULL;
  size_t size;

  g_variant_get (variant, LEGACY_CONTEXT_VARIANT_TYPE,
                 &tpms_context->hierarchy,
                 &tpms_context->savedHandle,
                 &tpms_context->sequence,
                 &tpms_context->contextBlob.size,
                 &base64);

  decoded = g_base64_decode (base64, &size);
  if (size != tpms_context->contextBlob.size)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Invalid tpms context blob length");
      return FALSE;
    }

  memcpy (tpms_context->contextBlob.buffer, decoded, size);

  return TRUE;
}

char *
grd_tpm_restore_secret (GrdTpm              *tpm,
                        GVariant            *variant,
                        TPML_PCR_SELECTION  *pcr_selection,
                        TPML_DIGEST         *pcr_digest,
                        GError             **error)
{
  TSS2_RC rc;
  ESYS_TR loaded_secret_handle = ESYS_TR_NONE;
  g_autofree TPM2B_SENSITIVE_DATA *unsealed_data = NULL;

  g_assert (tpm->policy_session);

  if (g_variant_is_of_type (variant,
                            G_VARIANT_TYPE (SEALED_OBJECT_VARIANT_TYPE)))
    {
      if (!load_sealed_object (tpm, variant, &loaded_secret_handle, error))
        return NULL;
    }
  else if (g_variant_is_of_type (variant,
                                 G_VARIANT_TYPE (LEGACY_CONTEXT_VARIANT_TYPE)))
    {
      TPMS_CONTEXT secret_tpms_context;

      if (!decode_legacy_context_variant (variant, &secret_tpms_context, error))
        return NULL;

      rc = Esys_ContextLoad (tpm->esys_context, &secret_tpms_context,
                             &loaded_secret_handle);
      if (rc != TSS2_RC_SUCCESS)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Esys_ContextLoad failed: %s "
                       "(legacy saved-context secret, re-store it)",
                       Tss2_RC_Decode (rc));
          return NULL;
        }
    }
  else
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Invalid sealed secret variant type %s",
                   g_variant_get_type_string (variant));
      return NULL;
    }

  if (!do_create_policy (tpm, tpm->policy_session,
                         pcr_selection,
                         pcr_digest,
                         NULL,
                         error))
    {
      Esys_FlushContext (tpm->esys_context, loaded_secret_handle);
      return NULL;
    }

  rc = Esys_Unseal (tpm->esys_context,
                    loaded_secret_handle,
                    tpm->policy_session,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &unsealed_data);
  Esys_FlushContext (tpm->esys_context, loaded_secret_handle);
  if (rc != TSS2_RC_SUCCESS)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Esys_Unseal failed: %s",
                   Tss2_RC_Decode (rc));
      return NULL;
    }

  if (strnlen ((char *) unsealed_data->buffer, unsealed_data->size) !=
      unsealed_data->size - 1)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Secret not a zero terminated string");
      return NULL;
    }

  return g_strdup ((char *) unsealed_data->buffer);
}

static const char *
get_algorithm_name (uint32_t algorithm)
{
  switch (algorithm)
    {
    case TPM2_ALG_SHA256:
      return "SHA-256";
    case TPM2_ALG_RSA:
      return "RSA";
    case TPM2_ALG_ECC:
      return "ECC";
    default:
      return "unknown";
    }
}

static const char *
get_command_name (uint32_t command)
{
  switch (command)
    {
    case TPM2_CC_CreatePrimary:
      return "CreatePrimary";
    case TPM2_CC_StartAuthSession:
      return "StartAuthSession";
    case TPM2_CC_FlushContext:
      return "FlushContext";
    case TPM2_CC_PCR_Read:
      return "PCR_Read";
    case TPM2_CC_PolicyPCR:
      return "PolicyPCR";
    case TPM2_CC_PolicyGetDigest:
      return "PolicyGetDigest";
    case TPM2_CC_CreateLoaded:
      return "CreateLoaded";
    case TPM2_CC_ContextSave:
      return "ContextSave";
    case TPM2_CC_ContextLoad:
      return "ContextLoad";
    case TPM2_CC_Load:
      return "Load";
    case TPM2_CC_Unseal:
      return "Unseal";
    default:
      return "unkown";
    }
}

gboolean
grd_tpm_check_capabilities (GrdTpm  *tpm,
                            GError **error)
{
  const struct
  {
    TPM2_CAP capability;
    uint32_t property;
    int count;
  } capabilities[] = {
    { .capability = TPM2_CAP_ALGS, .property = TPM2_ALG_SHA256 },
    { .capability = TPM2_CAP_ALGS, .property = TPM2_ALG_ECC },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_CreatePrimary },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_StartAuthSession },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_FlushContext },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_PCR_Read },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_PolicyPCR },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_PolicyGetDigest },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_CreateLoaded },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_ContextLoad },
    { .capability = TPM2_CAP_COMMANDS, .property = TPM2_CC_Load },
  };
  gboolean sha256_pcrs_found = FALSE;
  uint32_t property = 0;
  uint32_t count = TPM2_MAX_TPM_PROPERTIES;
  int i;

  for (i = 0; i < G_N_ELEMENTS (capabilities); i++)
    {
      g_autofree TPMS_CAPABILITY_DATA *data = NULL;
      TSS2_RC rc;

      rc = Esys_GetCapability (tpm->esys_context,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               capabilities[i].capability,
                               capabilities[i].property,
                               1,
                               NULL,
                               &data);
      if (rc != TSS2_RC_SUCCESS)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Failed to get capability: %s",
                       Tss2_RC_Decode (rc));
          return FALSE;
        }

      switch (capabilities[i].capability)
        {
        case TPM2_CAP_ALGS:
          g_warn_if_fail (data->data.algorithms.count == 1);

          if (capabilities[i].property !=
              data->data.algorithms.algProperties[0].alg)
            {
              g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                           "Algorithm %s not supported",
                           get_algorithm_name (capabilities[i].property));
              return FALSE;
            }

          break;

        case TPM2_CAP_COMMANDS:
          g_warn_if_fail (data->data.command.count == 1);

          if ((data->data.command.commandAttributes[0] &
               TPMA_CC_COMMANDINDEX_MASK) !=
              capabilities[i].property)
            {
              g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                           "Command %s not supported",
                           get_command_name (capabilities[i].property));
              return FALSE;
            }

          break;

        case TPM2_CAP_PCRS:
          g_warn_if_fail (data->data.assignedPCR.count == 1);
          break;
        }
    }

  while (TRUE)
    {
      TPMI_YES_NO more_data = TPM2_NO;
      g_autofree TPMS_CAPABILITY_DATA *data = NULL;
      TSS2_RC rc;

      rc = Esys_GetCapability (tpm->esys_context,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               TPM2_CAP_PCRS,
                               property,
                               count,
                               &more_data,
                               &data);
      if (rc != TSS2_RC_SUCCESS)
        {
          g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "Failed to get capability: %s",
                       Tss2_RC_Decode (rc));
          return FALSE;
        }

      property += data->data.assignedPCR.count;
      count -= data->data.assignedPCR.count;

      for (i = 0; i < data->data.assignedPCR.count; i++)
        {
          if (data->data.assignedPCR.pcrSelections[i].hash != TPM2_ALG_SHA256)
            continue;

          if (data->data.assignedPCR.pcrSelections[i].pcrSelect[0] &
              (1 << 0 | 1 << 1 | 1 << 2))
            {
              sha256_pcrs_found = TRUE;
              break;
            }
        }

      if (more_data == TPM2_NO)
        break;
    }

  if (!sha256_pcrs_found)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                   "SHA-256 PCRs not available");
      return FALSE;
    }

  return TRUE;
}

GrdTpm *
grd_tpm_new (GrdTpmMode   mode,
             GError     **error)
{
  g_autoptr (GrdTpm) tpm = NULL;

  tpm = g_object_new (GRD_TYPE_TPM, NULL);

  if (!(grd_get_debug_flags () & GRD_DEBUG_TPM))
    g_setenv ("TSS2_LOGFILE", "/dev/null", TRUE);

  if (!check_tpm_existence (error))
    return NULL;

  if (!init_transmission_interface (tpm, error))
    return NULL;

  if (!init_tss2_esys (tpm, error))
    return NULL;

  switch (mode)
    {
    case GRD_TPM_MODE_NONE:
      break;
    case GRD_TPM_MODE_WRITE:
      if (!start_hmac_session (tpm, error))
        return NULL;
      if (!start_trial_session (tpm, error))
        return NULL;
      break;
    case GRD_TPM_MODE_READ:
      if (!start_hmac_session (tpm, error))
        return NULL;
      if (!start_policy_session (tpm, error))
        return NULL;
      break;
    }

  return g_steal_pointer (&tpm);
}

static void
grd_tpm_finalize (GObject *object)
{
  GrdTpm *tpm = GRD_TPM (object);

  if (tpm->policy_session)
    Esys_FlushContext (tpm->esys_context, tpm->policy_session);
  if (tpm->trial_session)
    Esys_FlushContext (tpm->esys_context, tpm->trial_session);
  if (tpm->hmac_session)
    Esys_FlushContext (tpm->esys_context, tpm->hmac_session);
  if (tpm->esys_context)
    Esys_Finalize (&tpm->esys_context);
  if (tpm->tcti_context)
    Tss2_TctiLdr_Finalize (&tpm->tcti_context);

  G_OBJECT_CLASS (grd_tpm_parent_class)->finalize (object);
}

static void
grd_tpm_init (GrdTpm *tpm)
{
}

static void
grd_tpm_class_init (GrdTpmClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = grd_tpm_finalize;
}
