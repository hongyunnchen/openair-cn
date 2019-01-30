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

/*! \file s5s8.hpp
   \author  Lionel GAUTHIER
   \date 2018
   \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_PGW_SS5S8_HPP_SEEN
#define FILE_PGW_SS5S8_HPP_SEEN

#include "gtpv2c.hpp"
#include "itti_msg_s5s8.hpp"

#include <thread>

namespace oai::cn::nf::pgwc {

class pgw_s5s8 {
private:
  std::thread::id                      thread_id;
  std::thread                          thread;

public:
  pgw_s5s8();
  pgw_s5s8(pgw_s5s8 const&)    = delete;
  void operator=(pgw_s5s8 const&)     = delete;

  void handle_itti_msg (core::itti::itti_s5s8_create_session_request& m);
  void handle_itti_msg (core::itti::itti_s5s8_delete_session_request& m);
  void handle_itti_msg (core::itti::itti_s5s8_modify_bearer_request& m);

  void send_s5s8_msg(core::itti::itti_s5s8_create_session_response& m);
  void send_s5s8_msg(core::itti::itti_s5s8_delete_session_response& m);
  void send_s5s8_msg(core::itti::itti_s5s8_modify_bearer_response& m);

};
}
#endif /* FILE_PGW_SS5S8_HPP_SEEN */
