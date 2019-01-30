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

/*! \file pgw_app.hpp
   \author  Lionel GAUTHIER
   \date 2018
   \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_PGW_APP_HPP_SEEN
#define FILE_PGW_APP_HPP_SEEN

#include "itti_msg_s5s8.hpp"
#include "pgw_config.hpp"
#include "pgw_context.hpp"
#include "pgw_pco.hpp"

#include <boost/atomic.hpp>

#include <map>
#include <set>
#include <string>
#include <thread>

namespace oai::cn::nf::pgwc {

//typedef std::pair<shared_ptr<pgw_context>,shared_ptr<pgw_pdn_connection>> zzz;

class pgw_app {
private:
  std::thread::id                      thread_id;
  std::thread                          thread;
  // teid generators (linear)
  boost::atomic<teid_t>                 teid_s5s8_cp;
  boost::atomic<teid_t>                 teid_s5s8_up;
  // key is remote teid
  std::map<imsi64_t, std::shared_ptr<pgw_context>> imsi2pgw_context;
  std::map<teid_t, std::shared_ptr<pgw_context>> s5s8lteid2pgw_context;
  std::set<teid_t> s5s8cplteid;
  std::set<teid_t> s5s8uplteid;

  // from config
  int              num_ue_pool;
  std::vector<struct in_addr> ipv4_pool_list[PGW_NUM_UE_POOL_MAX];

  int apply_config (const pgw_config& cfg);

  teid_t generate_s5s8_cp_teid();
  void free_s5s8c_teid(const teid_t& teid_s5s8_cp);
  bool is_s5s8c_teid_exist(teid_t& teid_s5s8_cp);
  teid_t generate_s5s8_up_teid();
  void free_s5s8u_teid(const teid_t& teid_s5s8_up);
  bool is_s5s8u_teid_exist(teid_t& teid_s5s8_up);

  // s5s8crteid2pgw_eps_bearer_context collection
  bool is_s5s8cpgw_fteid_2_pgw_context(core::fteid_t& ls5s8_fteid);
  bool is_imsi64_2_pgw_context(const imsi64_t& imsi64) const;
  std::shared_ptr<pgw_context> imsi64_2_pgw_context(const imsi64_t& imsi64) const;
  void set_imsi64_2_pgw_context(const imsi64_t& imsi64, std::shared_ptr<pgw_context> pc);

  int pco_push_protocol_or_container_id(core::protocol_configuration_options_t& pco, core::pco_protocol_or_container_id_t * const poc_id /* STOLEN_REF poc_id->contents*/);
  int process_pco_request_ipcp(core::protocol_configuration_options_t& pco_resp, const core::pco_protocol_or_container_id_t * const poc_id);
  int process_pco_dns_server_request(core::protocol_configuration_options_t& pco_resp, const core::pco_protocol_or_container_id_t * const poc_id);
  int process_pco_link_mtu_request(core::protocol_configuration_options_t& pco_resp, const core::pco_protocol_or_container_id_t * const poc_id);


public:
  pgw_app(const std::string& config_file);
  pgw_app(pgw_app const&)    = delete;
  void operator=(pgw_app const&)     = delete;

  void send_delete_session_response_cause_request_accepted (const uint64_t gtpc_tx_id, const teid_t teid, boost::asio::ip::udp::endpoint& r_endpoint) const;
  void send_delete_session_response_cause_context_not_found (const uint64_t gtpc_tx_id, const teid_t teid, boost::asio::ip::udp::endpoint& r_endpoint) const;

  core::fteid_t build_s5s8_cp_fteid(const struct in_addr ipv4_address, const teid_t teid);
  core::fteid_t generate_s5s8_cp_fteid(const struct in_addr ipv4_address);
  void free_s5s8_cp_fteid(const core::fteid_t& fteid);
  void set_s5s8cpgw_fteid_2_pgw_context(core::fteid_t& rs5s8_fteid, std::shared_ptr<pgw_context> spc);
  std::shared_ptr<pgw_context> s5s8cpgw_fteid_2_pgw_context(core::fteid_t& ls5s8_fteid);
  core::fteid_t build_s5s8_up_fteid(const struct in_addr ipv4_address, const teid_t teid);
  core::fteid_t generate_s5s8_up_fteid(const struct in_addr ipv4_address);
  void free_s5s8_up_fteid(const core::fteid_t& fteid);

  void delete_pgw_context(std::shared_ptr<pgw_context> spc);

  int static_paa_get_free_paa (const std::string& apn, core::paa_t& paa);
  int static_paa_release_address (const std::string& apn, struct in_addr& addr);
  int static_paa_get_num_ipv4_pool(void);
  int static_paa_get_ipv4_pool(const int pool_id, struct in_addr * const range_low, struct in_addr * const range_high, struct in_addr * const netaddr, struct in_addr * const netmask, std::vector<struct in_addr>::iterator& it_out_of_nw);
  int static_paa_get_pool_id(const struct in_addr& ue_addr);

  int process_pco_request(
    const core::protocol_configuration_options_t& pco_req,
    core::protocol_configuration_options_t& pco_resp,
    core::protocol_configuration_options_ids_t & pco_ids);


  void handle_itti_msg (core::itti::itti_s5s8_create_session_request& m);
  void handle_itti_msg (core::itti::itti_s5s8_delete_session_request& m);
  void handle_itti_msg (core::itti::itti_s5s8_modify_bearer_request& m);
};
}

#endif /* FILE_PGW_APP_HPP_SEEN */
