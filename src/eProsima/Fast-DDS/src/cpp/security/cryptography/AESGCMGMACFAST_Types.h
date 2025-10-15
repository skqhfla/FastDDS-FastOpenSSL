// Copyright 2016 Proyectos y Sistemas de Mantenimiento SL (eProsima).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*!
 * @file AESGCMGMACFAST_Types.h
 */

#ifndef _SECURITY_AUTHENTICATION_AESGCMGMACFAST_TYPES_H_
#define _SECURITY_AUTHENTICATION_AESGCMGMACFAST_TYPES_H_

#include <security/cryptography/AESGCMGMAC_Types.h>
#include <fastdds/rtps/security/cryptography/CryptoTypes.h>
#include <fastdds/rtps/attributes/PropertyPolicy.h>
#include <fastdds/rtps/security/common/Handle.h>
#include <fastdds/rtps/security/common/SharedSecretHandle.h>
#include <fastdds/rtps/security/accesscontrol/ParticipantSecurityAttributes.h>
#include <fastdds/rtps/security/accesscontrol/EndpointSecurityAttributes.h>

#include <cassert>
#include <functional>
#include <limits>
#include <mutex>

#include <atomic>
#include <cstddef>
#include <cstring>

// Fix compilation error on Windows
#if defined(WIN32) && defined(max)
#undef max
#endif // if defined(WIN32) && defined(max)

//No encryption, no authentication tag
#define CRYPTO_TRANSFORMATION_KIND_NONE             { {0, 0, 0, 0} }

//No encryption, AES128-GMAC authentication
#define CRYPTO_TRANSFORMATION_KIND_AES128_GMAC      { {0, 0, 0, 1} }

//Authenticated encryption via AES128
#define CRYPTO_TRANSFORMATION_KIND_AES128_GCM       { {0, 0, 0, 2} }

//No encryption, AES256-GMAC authentication
#define CRYPTO_TRANSFORMATION_KIND_AES256_GMAC      { {0, 0, 0, 3} }

// Authenticated encryption via AES256-GMC
#define CRYPTO_TRANSFORMATION_KIND_AES256_GCM       { {0, 0, 0, 4} }

//FAST-OpenSSL
#define KEY_LENGTH 32
#define IV_LENGTH 12
#define AUTO_TAG_LENGTH 16
#define SLEEP_INTERVAL 10000

#define BUFFAR_SIZE 8192
#define WAIT_INTERVAL 10

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {



/* Key Storage
 * -----------
 *  Contains common key and specific key
 *      -The common key is used to cipher (same for all receivers)
 *      -The specific key is used to sign (specific for each receiver)
 *  One KeyMaterial is used to store either:
 *      -The keys needed to send a message to another element
 *      -The keys needed to receive a message from another element
 *  Note: Key_Ids are ensured to be unique within a Cryptogaphic domain (Participant)
 */


/* SecureSubMessageElements
 * ------------------------
 */

/* Key Management
 * --------------
 * Keys are stored and managed as Cryptohandles
 * There are CryptoHandles for Participant, DataWriter and DataReader keys
 * Each CryptoHandle stores different data, but share common traits.
 *
 * All CryptoHandle instances hold
 * -A copy of the common key: the key used to cypher and known by all possible receivers
 * -A copy of the (direct) specific key: the key used to sign outgoing messages (receiver_specific_macs).
 * -A copy of the (reverse) specific key: the key used to verify the signature of incoming messages.
 *
 * In the case of a LocalCryptoHandle, one instance of the specific keys is stored for each matching element.
 * In the case of a RemoteCryptoHandle, only the keys pertaining the remote element are stored.
 *
 * Note: the common key of the remote cryptohandle is stored along with the specific keys. KeyMaterial->master_sender_key
 */

class AESGCMGMACFAST_KeyFactory;
/*
typedef HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory> AESGCMGMACFAST_WriterCryptoHandle;
typedef HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory> AESGCMGMACFAST_ReaderCryptoHandle;
typedef HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory> AESGCMGMACFAST_EntityCryptoHandle;
*/
typedef HandleImpl<ParticipantKeyHandle, AESGCMGMACFAST_KeyFactory> AESGCMGMACFAST_ParticipantCryptoHandle;


} //namespaces security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _SECURITY_AUTHENTICATION_AESGCMGMACFAST_TYPES_H_
