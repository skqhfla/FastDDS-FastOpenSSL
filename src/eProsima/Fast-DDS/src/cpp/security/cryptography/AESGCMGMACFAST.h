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
 * @file AESGCMGMACFAST.h
 */

#ifndef _SECURITY_AUTHENTICATION_AESGCMGMACFAST_H_
#define _SECURITY_AUTHENTICATION_AESGCMGMACFAST_H_

#include <fastdds/rtps/security/cryptography/Cryptography.h>
#include <fastdds/rtps/attributes/PropertyPolicy.h>

#include <security/cryptography/AESGCMGMACFAST_KeyExchange.h>
#include <security/cryptography/AESGCMGMACFAST_KeyFactory.h>
#include <security/cryptography/AESGCMGMACFAST_Transform.h>

#include <memory>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

class AESGCMGMACFAST : public Cryptography
{
    CryptoKeyExchange* m_cryptokeyexchange;
    std::shared_ptr<AESGCMGMACFAST_KeyFactory> m_cryptokeyfactory;
    CryptoTransform* m_cryptotransform;

public:

    AESGCMGMACFAST();
    ~AESGCMGMACFAST();

    CryptoKeyExchange* cryptokeyexchange() override
    {
        return keyexchange();
    }

    CryptoKeyFactory* cryptokeyfactory() override
    {
        return keyfactory().get();
    }

    CryptoTransform* cryptotransform() override
    {
        return transform();
    }

    AESGCMGMACFAST_KeyExchange* keyexchange();
    std::shared_ptr<AESGCMGMACFAST_KeyFactory> keyfactory();
    AESGCMGMACFAST_Transform* transform();
};

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _SECURITY_AUTHENTICATION_AESGCMGMACFAST_H_
