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

#include "common_defs.h"
#include "conversions.hpp"
#include "itti.hpp"
#include "itti_msg_sxa.hpp"
#include "logger.hpp"
#include "pgw_app.hpp"
#include "pgw_config.hpp"
#include "pgwc_procedure.hpp"
#include "pgw_context.hpp"

using namespace oai::cn::core;
using namespace oai::cn::core::itti;
using namespace oai::cn::proto::pfcp;
using namespace oai::cn::nf::pgwc;
using namespace std;

extern itti_mw *itti_inst;
extern pgw_app *pgw_app_inst;
extern pgw_config pgw_cfg;

uint64_t oai::cn::nf::pgwc::pgw_procedure::trxn_id_generator = 0;

//------------------------------------------------------------------------------
int session_establishment_procedure::run(std::shared_ptr<oai::cn::core::itti::itti_s5s8_create_session_request> req, std::shared_ptr<oai::cn::core::itti::itti_s5s8_create_session_response> resp)
{
  // TODO check if compatible with ongoing procedures if any
  s5_trigger = req;
  s5_triggered_pending = resp;
  ppc.get()->generate_seid();
  itti_sxab_session_establishment_request *sx_ser = new itti_sxab_session_establishment_request(TASK_PGWC_APP, TASK_PGWC_SX);
  sx_ser->seid = ppc.get()->seid;
  sx_ser->trxn_id = this->trxn_id;
  sx_ser->l_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(0xC0A8A064), 8805);
  sx_ser->r_endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4(0xC0A8A065), 8805);
  sx_triggered = std::shared_ptr<core::itti::itti_sxab_session_establishment_request>(sx_ser);

  //-------------------
  // IE node_id_t
  //-------------------
  core::pfcp::node_id_t node_id = {};
  pgw_cfg.get_pfcp_node_id(node_id);
  sx_ser->pfcp_ies.set(node_id);

  //-------------------
  // IE fseid_t
  //-------------------
  core::pfcp::fseid_t cp_fseid = {};
  pgw_cfg.get_pfcp_fseid(cp_fseid);
  cp_fseid.seid = ppc.get()->seid;
  sx_ser->pfcp_ies.set(cp_fseid);

  for (auto it : s5_trigger.get()->gtp_ies.bearer_contexts_to_be_created) {
    //*******************
    // UPLINK
    //*******************
    //-------------------
    // IE create_far
    //-------------------
    core::pfcp::create_far                  create_far = {};
    core::pfcp::far_id_t                    far_id = {};
    core::pfcp::apply_action_t              apply_action = {};
    core::pfcp::forwarding_parameters       forwarding_parameters = {};
//    core::pfcp::duplicating_parameters      duplicating_parameters = {};
//    core::pfcp::bar_id_t                    bar_id = {};

    // forwarding_parameters IEs
    core::pfcp::destination_interface_t     destination_interface = {};
    //core::pfcp::network_instance_t          network_instance = {};
    //core::pfcp::redirect_information_t      redirect_information = {};
    //core::pfcp::outer_header_creation_t     outer_header_creation = {};
    //core::pfcp::transport_level_marking_t   transport_level_marking = {};
    //core::pfcp::forwarding_policy_t         forwarding_policy = {};
    //core::pfcp::header_enrichment_t         header_enrichment = {};
    //core::pfcp::traffic_endpoint_id_t       linked_traffic_endpoint_id_t = {};
    //core::pfcp::proxying_t                  proxying = {};

    // DOIT simple ?
    far_id.far_id = it.eps_bearer_id.ebi | 0x1000; // TODO WARNING HARDCODED, 'Just for testing...'
    apply_action.forw = 1;

    destination_interface.interface_value = core::pfcp::INTERFACE_VALUE_CORE; // ACCESS is for downlink, CORE for uplink
    forwarding_parameters.set(destination_interface);

    create_far.set(far_id);
    create_far.set(apply_action);
    create_far.set(forwarding_parameters);
    //-------------------
    // IE create_pdr
    //-------------------
    core::pfcp::create_pdr                  create_pdr = {};
    core::pfcp::pdr_id_t                    prd_id = {};
    core::pfcp::precedence_t                precedence = {};
    core::pfcp::pdi                         pdi = {};
    core::pfcp::outer_header_removal_t      outer_header_removal = {};
//    core::pfcp::far_id_t                    far_id;
//    core::pfcp::urr_id_t                    urr_id;
//    core::pfcp::qer_id_t                    qer_id;
//    core::pfcp::activate_predefined_rules_t activate_predefined_rules;
    // pdi IEs
    core::pfcp::source_interface_t         source_interface = {};
    core::pfcp::fteid_t                    local_fteid = {};
    //core::pfcp::network_instance_t         network_instance = {};
    core::pfcp::ue_ip_address_t            ue_ip_address = {};
    //core::pfcp::traffic_endpoint_id_t      traffic_endpoint_id = {};
    core::pfcp::sdf_filter_t               sdf_filter = {};
    core::pfcp::application_id_t           application_id = {};
    //core::pfcp::ethernet_packet_filter     ethernet_packet_filter = {};
    core::pfcp::qfi_t                      qfi = {};
    //core::pfcp::framed_route_t             framed_route = {};
    //core::pfcp::framed_routing_t           framed_routing = {};
    //core::pfcp::framed_ipv6_route_t        framed_ipv6_route = {};
    source_interface.interface_value = core::pfcp::INTERFACE_VALUE_ACCESS;
    local_fteid.ch   = 1;
    //local_fteid.chid = 1;
    paa_to_pfcp_ue_ip_address(s5_triggered_pending.get()->gtp_ies.paa, ue_ip_address);

    // DOIT simple
    prd_id.rule_id = it.eps_bearer_id.ebi;
    precedence.precedence = it.bearer_level_qos.pl;

    pdi.set(source_interface);
    pdi.set(local_fteid);
    pdi.set(ue_ip_address);

    outer_header_removal.outer_header_removal_description = OUTER_HEADER_REMOVAL_GTPU_UDP_IPV4;

    create_pdr.set(prd_id);
    create_pdr.set(precedence);
    create_pdr.set(pdi);
    create_pdr.set(outer_header_removal);
    create_pdr.set(far_id);

    //-------------------
    // ADD IEs to message
    //-------------------
    sx_ser->pfcp_ies.add(create_pdr);
    sx_ser->pfcp_ies.add(create_far);
  }
  Logger::pgwc_app().info( "Sending ITTI message %s to task TASK_PGWC_SX", sx_ser->get_msg_name());
  int ret = itti_inst->send_msg(sx_triggered);
  if (RETURNok != ret) {
    Logger::pgwc_app().error( "Could not send ITTI message %s to task TASK_PGWC_SX", sx_ser->get_msg_name());
    return RETURNerror;
  }
  return RETURNok;
}

