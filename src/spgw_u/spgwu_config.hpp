/*
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the Apache License, Version 2.0  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

/*! \file spgwu_config.hpp
* \brief
* \author Lionel Gauthier
* \company Eurecom
* \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_SPGWU_CONFIG_HPP_SEEN
#define FILE_SPGWU_CONFIG_HPP_SEEN

#include <libconfig.h++>
#include <mutex>
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <string>

namespace oai::cn::nf::spgwu {


#define SPGWU_CONFIG_STRING_SPGWU_CONFIG                          "S/P-GW-U"
#define SPGWU_CONFIG_STRING_PID_DIRECTORY                         "PID_DIRECTORY"
#define SPGWU_CONFIG_STRING_INSTANCE                              "INSTANCE"
#define SPGWU_CONFIG_STRING_INTERFACES                            "INTERFACES"
#define SPGWU_CONFIG_STRING_INTERFACE_NAME                        "INTERFACE_NAME"
#define SPGWU_CONFIG_STRING_IPV4_ADDRESS                          "IPV4_ADDRESS"
#define SPGWU_CONFIG_STRING_PORT                                  "PORT"
#define SPGWU_CONFIG_STRING_INTERFACE_SX                          "SX"
#define SPGWU_CONFIG_STRING_INTERFACE_S1U_S12_S4_UP               "S1U_S12_S4_UP"
#define SPGWU_CONFIG_STRING_INTERFACE_SGI                         "SGI"

#define SPGW_ABORT_ON_ERROR true
#define SPGW_WARN_ON_ERROR false

typedef struct interface_cfg_s {
  std::string     if_name;
  struct in_addr  addr4;
  struct in_addr  network4;
  struct in6_addr addr6;
  unsigned int    mtu;
  unsigned int    port;
} interface_cfg_t;

class spgwu_config {

private:

  int load_interface(const libconfig::Setting& if_cfg, interface_cfg_t& cfg);

public:

  /* Reader/writer lock for this configuration */
  std::mutex      m_rw_lock;
  std::string     pid_dir;
  unsigned int    instance;
  interface_cfg_t s1_up;
  interface_cfg_t sgi;
  interface_cfg_t sx;

  spgwu_config() : m_rw_lock() {
    pid_dir  = {};
    instance = 0;
    s1_up    = {};
    sgi      = {};
    sx       = {};
  };
  void lock() {m_rw_lock.lock();};
  void unlock() {m_rw_lock.unlock();};
  int load(const std::string& config_file);
  int execute();
  void display();
};
} // namespace spgwu

#endif /* FILE_SPGWU_CONFIG_HPP_SEEN */
