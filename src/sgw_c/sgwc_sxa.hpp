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

/*! \file sgwc_sxa.hpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_SGWC_SXA_HPP_SEEN
#define FILE_SGWC_SXA_HPP_SEEN

#include "pfcp.hpp"
#include "itti_msg_sxa.hpp"

#include <thread>

namespace oai::cn::nf::sgwc {

class sgwc_sxa  : public proto::pfcp::pfcp_l4_stack {
private:
  std::thread::id                      thread_id;
  std::thread                          thread;

public:
  sgwc_sxa();
  sgwc_sxa(sgwc_sxa const&)    = delete;
  void operator=(sgwc_sxa const&)     = delete;


  void handle_itti_msg (core::itti::itti_sxa_heartbeat_request& s) {};
  void handle_itti_msg (core::itti::itti_sxa_heartbeat_response& s) {};
  void handle_itti_msg (core::itti::itti_sxa_association_setup_request& s) {};
  void handle_itti_msg (core::itti::itti_sxa_association_setup_response& s) {};
  void handle_itti_msg (core::itti::itti_sxa_association_update_request& s) {};
  void handle_itti_msg (core::itti::itti_sxa_association_update_response& s) {};
  void handle_itti_msg (core::itti::itti_sxa_association_release_request& s) {};
  void handle_itti_msg (core::itti::itti_sxa_association_release_response& s) {};
  void handle_itti_msg (core::itti::itti_sxa_version_not_supported_response& s) {};
  void handle_itti_msg (core::itti::itti_sxa_node_report_response& s) {};
  void handle_itti_msg (core::itti::itti_sxa_session_set_deletion_request& s) {};
  void handle_itti_msg (core::itti::itti_sxa_session_establishment_request& s) {};
  void handle_itti_msg (core::itti::itti_sxa_session_modification_request& s) {};
  void handle_itti_msg (core::itti::itti_sxa_session_deletion_request& s) {};
  void handle_itti_msg (core::itti::itti_sxa_session_report_response& s) {};

  void send_sx_msg (core::itti::itti_sxa_heartbeat_request& s) {};
  void send_sx_msg (core::itti::itti_sxa_heartbeat_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_association_setup_request& s) {};
  void send_sx_msg (core::itti::itti_sxa_association_setup_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_association_update_request& s) {};
  void send_sx_msg (core::itti::itti_sxa_association_update_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_association_release_request& s) {};
  void send_sx_msg (core::itti::itti_sxa_association_release_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_version_not_supported_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_node_report_request& s) {};
  void send_sx_msg (core::itti::itti_sxa_session_set_deletion_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_session_establishment_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_session_modification_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_session_deletion_response& s) {};
  void send_sx_msg (core::itti::itti_sxa_session_report_request& s) {};

  void handle_receive_pfcp_msg( proto::pfcp::pfcp_msg& msg, const boost::asio::ip::udp::endpoint& remote_endpoint);
  void handle_receive(char* recv_buffer, const std::size_t bytes_transferred, boost::asio::ip::udp::endpoint& remote_endpoint);

  void time_out_itti_event(const uint32_t timer_id);
};
}
#endif /* FILE_SGWC_SXA_HPP_SEEN */
