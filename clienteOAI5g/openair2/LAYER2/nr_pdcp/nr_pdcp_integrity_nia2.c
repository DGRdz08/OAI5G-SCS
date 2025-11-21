/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#include "nr_pdcp_integrity_nia2.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "common/utils/assertions.h"
#include "secu_defs.h"

stream_security_context_t *nr_pdcp_integrity_nia2_init(uint8_t integrity_key[16])
{
  /* Delegar la inicialización al servidor remoto. */
  return stream_integrity_init(EIA2_128_ALG_ID, integrity_key);
}

void nr_pdcp_integrity_nia2_integrity(stream_security_context_t *integrity_context, unsigned char *out, unsigned char *buffer, int length, int bearer, uint32_t count, int direction)
{
  DevAssert(integrity_context != NULL);
  DevAssert(out != NULL);
  DevAssert(buffer != NULL);
  DevAssert(length > -1);
  DevAssert(bearer > 0 && bearer < 33);

  (void)bearer; (void)direction; /* usados dentro del stream_cipher */

  uint8_t result[16] = {0};

  nas_stream_cipher_t sc = {
    .context = integrity_context,
    .count = count,
    .bearer = (uint8_t)(bearer > 0 ? bearer - 1 : 0),
    .direction = (uint8_t)direction,
    .message = buffer,
    .blength = (uint32_t)(length * 8)
  };

  stream_compute_integrity(EIA2_128_ALG_ID, &sc, result);
  memcpy(out, result, 4);
}

void nr_pdcp_integrity_nia2_free_integrity(stream_security_context_t *integrity_context)
{
  /* Delegar la liberación del contexto al cliente remoto; la función
   * `stream_integrity_free` libera la estructura si corresponde. */
  stream_integrity_free(EIA2_128_ALG_ID, integrity_context);
}
