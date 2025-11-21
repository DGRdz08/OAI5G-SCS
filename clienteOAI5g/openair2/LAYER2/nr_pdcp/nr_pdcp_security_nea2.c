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

#include "common/utils/assertions.h"

#include "nr_pdcp_security_nea2.h"
#include "secu_defs.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

stream_security_context_t *nr_pdcp_security_nea2_init(unsigned char *ciphering_key)
{
  // This is a hack, IMO init, cipher and free functions should be reduced to cipher.
  // Test show a ~10% more processing time
  return (stream_security_context_t *)ciphering_key;
}

void nr_pdcp_security_nea2_cipher(stream_security_context_t *security_context, unsigned char *buffer, int length, int bearer, uint32_t count, int direction)
{
  DevAssert(security_context != NULL);
  DevAssert(buffer != NULL);
  DevAssert(length > 0);
  DevAssert(bearer > -1 && bearer < 32);
  DevAssert(direction > -1 && direction < 2);

  uint8_t out[length];
  memset(out, 0, length);

  nas_stream_cipher_t sc = {
    .context = security_context,
    .count = count,
    .bearer = (uint8_t)(bearer > 0 ? bearer - 1 : 0),
    .direction = (uint8_t)direction,
    .message = buffer,
    .blength = (uint32_t)(length * 8)
  };

  /* Delegar el cifrado al servidor remoto mediante la API definida en secu_defs.h */
  stream_compute_encrypt(EEA2_128_ALG_ID, &sc, out);

  memcpy(buffer, out, length);
}

void nr_pdcp_security_nea2_free_security(stream_security_context_t *security_context)
{
  (void)security_context;
}
