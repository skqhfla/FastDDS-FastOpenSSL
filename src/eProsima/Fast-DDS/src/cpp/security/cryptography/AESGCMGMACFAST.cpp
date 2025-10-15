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
 * @file AESGCMGMACFAST.cpp
 */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <security/cryptography/AESGCMGMACFAST.h>

using namespace eprosima::fastrtps::rtps::security;

AESGCMGMACFAST::AESGCMGMACFAST()
{
    m_cryptokeyexchange = new AESGCMGMACFAST_KeyExchange();
    m_cryptokeyfactory = std::make_shared<AESGCMGMACFAST_KeyFactory>();
    m_cryptotransform = new AESGCMGMACFAST_Transform();

    // Seed prng
    RAND_load_file("/dev/urandom", 32);
}

AESGCMGMACFAST_KeyExchange* AESGCMGMACFAST::keyexchange()
{
    return (AESGCMGMACFAST_KeyExchange*) m_cryptokeyexchange;
}

std::shared_ptr<AESGCMGMACFAST_KeyFactory> AESGCMGMACFAST::keyfactory()
{
    return m_cryptokeyfactory;
}

AESGCMGMACFAST_Transform* AESGCMGMACFAST::transform()
{
    return (AESGCMGMACFAST_Transform*) m_cryptotransform;
}

AESGCMGMACFAST::~AESGCMGMACFAST()
{
    delete m_cryptokeyexchange;
    delete m_cryptotransform;
}
