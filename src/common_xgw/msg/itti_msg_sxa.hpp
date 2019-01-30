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

/*! \file itti_msg_sxa.hpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

#ifndef ITTI_MSG_SXA_HPP_INCLUDED_
#define ITTI_MSG_SXA_HPP_INCLUDED_

#include "3gpp_129.244.hpp"
#include "itti_msg.hpp"
#include "msg_pfcp.hpp"
#include <boost/asio.hpp>

namespace oai::cn::core::itti {

class itti_sxa_msg : public itti_msg {
public:
  itti_sxa_msg(const itti_msg_type_t  msg_type, const task_id_t origin, const task_id_t destination):
    itti_msg(msg_type, origin, destination) {
    l_endpoint = {};
    r_endpoint = {};
    seid = UNASSIGNED_SEID;
    pfcp_tx_id = 0;
  }
  itti_sxa_msg(const itti_sxa_msg& i) : itti_msg(i)  {
    l_endpoint = i.l_endpoint;
    r_endpoint = i.r_endpoint;
    seid = i.seid;
    pfcp_tx_id = i.pfcp_tx_id;
  }
  itti_sxa_msg(const itti_sxa_msg& i, const task_id_t orig, const task_id_t dest) : itti_sxa_msg(i)  {
    origin = orig;
    destination = dest;
  }

  boost::asio::ip::udp::endpoint l_endpoint;
  boost::asio::ip::udp::endpoint r_endpoint;
  seid_t                         seid;
  uint64_t                       pfcp_tx_id;
};

//-----------------------------------------------------------------------------
class itti_sxa_heartbeat_request : public itti_sxa_msg {
public:
  itti_sxa_heartbeat_request(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_HEARTBEAT_REQUEST, origin, destination) {  }
  itti_sxa_heartbeat_request(const itti_sxa_heartbeat_request& i) : itti_sxa_msg(i)  {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_heartbeat_request(const itti_sxa_heartbeat_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }

  const char* get_msg_name() {return typeid(itti_sxa_heartbeat_request).name();};

  cn::proto::pfcp::pfcp_heartbeat_request pfcp_ies;
};

//-----------------------------------------------------------------------------
class itti_sxa_heartbeat_response  : public itti_sxa_msg {
public:
  itti_sxa_heartbeat_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_HEARTBEAT_RESPONSE, origin, destination) {
  }
  itti_sxa_heartbeat_response(const itti_sxa_heartbeat_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_heartbeat_response(const itti_sxa_heartbeat_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_heartbeat_response).name();};

  cn::proto::pfcp::pfcp_heartbeat_response pfcp_ies;
};

//-----------------------------------------------------------------------------
class itti_sxa_association_setup_request   : public itti_sxa_msg {
public:
  itti_sxa_association_setup_request(const task_id_t origin, const task_id_t destination): itti_sxa_msg(SXA_ASSOCIATION_SETUP_REQUEST, origin, destination) {
  }
  itti_sxa_association_setup_request(const itti_sxa_association_setup_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_association_setup_request(const itti_sxa_association_setup_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_association_setup_request).name();};

  cn::proto::pfcp::pfcp_association_setup_request pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxa_association_setup_response   : public itti_sxa_msg {
public:
  itti_sxa_association_setup_response(const task_id_t origin, const task_id_t destination): itti_sxa_msg(SXA_ASSOCIATION_SETUP_RESPONSE, origin, destination) {
  }
  itti_sxa_association_setup_response(const itti_sxa_association_setup_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_association_setup_response(const itti_sxa_association_setup_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_association_setup_response).name();};

  cn::proto::pfcp::pfcp_association_setup_response pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxa_association_update_request   : public itti_sxa_msg {
public:
  itti_sxa_association_update_request(const task_id_t origin, const task_id_t destination): itti_sxa_msg(SXA_ASSOCIATION_UPDATE_REQUEST, origin, destination) {
  }
  itti_sxa_association_update_request(const itti_sxa_association_update_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_association_update_request(const itti_sxa_association_update_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_association_update_request).name();};

  cn::proto::pfcp::pfcp_association_update_request pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxa_association_update_response   : public itti_sxa_msg {
public:
  itti_sxa_association_update_response(const task_id_t origin, const task_id_t destination): itti_sxa_msg(SXA_ASSOCIATION_UPDATE_RESPONSE, origin, destination) {
  }
  itti_sxa_association_update_response(const itti_sxa_association_update_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_association_update_response(const itti_sxa_association_update_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_association_update_response).name();};

  cn::proto::pfcp::pfcp_association_update_response pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxa_association_release_request   : public itti_sxa_msg {
public:
  itti_sxa_association_release_request(const task_id_t origin, const task_id_t destination): itti_sxa_msg(SXA_ASSOCIATION_RELEASE_REQUEST, origin, destination) {
  }
  itti_sxa_association_release_request(const itti_sxa_association_release_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_association_release_request(const itti_sxa_association_release_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_association_release_request).name();};

  cn::proto::pfcp::pfcp_association_release_request pfcp_ies;
} ;


//-----------------------------------------------------------------------------
class itti_sxa_association_release_response   : public itti_sxa_msg {
public:
  itti_sxa_association_release_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_ASSOCIATION_RELEASE_RESPONSE, origin, destination) {
  }
  itti_sxa_association_release_response(const itti_sxa_association_release_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_association_release_response(const itti_sxa_association_release_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_association_release_response).name();};

  cn::proto::pfcp::pfcp_association_release_response pfcp_ies;
};

//-----------------------------------------------------------------------------
class itti_sxa_version_not_supported_response   : public itti_sxa_msg {
public:
  itti_sxa_version_not_supported_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_VERSION_NOT_SUPPORTED_RESPONSE, origin, destination) {
  }
  itti_sxa_version_not_supported_response(const itti_sxa_version_not_supported_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_version_not_supported_response(const itti_sxa_version_not_supported_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_version_not_supported_response).name();};

  cn::proto::pfcp::pfcp_version_not_supported_response pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxa_node_report_request   : public itti_sxa_msg {
public:
  itti_sxa_node_report_request(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_NODE_REPORT_REQUEST, origin, destination) {
  }
  itti_sxa_node_report_request(const itti_sxa_node_report_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_node_report_request(const itti_sxa_node_report_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_node_report_request).name();};

  cn::proto::pfcp::pfcp_node_report_request pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxa_node_report_response   : public itti_sxa_msg {
public:
  itti_sxa_node_report_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_NODE_REPORT_RESPONSE, origin, destination) {
  }
  itti_sxa_node_report_response(const itti_sxa_node_report_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_node_report_response(const itti_sxa_node_report_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_node_report_response).name();};

  cn::proto::pfcp::pfcp_node_report_response pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxa_session_set_deletion_request   : public itti_sxa_msg {
public:
  itti_sxa_session_set_deletion_request(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_SET_DELETION_REQUEST, origin, destination) {
  }
  itti_sxa_session_set_deletion_request(const itti_sxa_session_set_deletion_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_set_deletion_request(const itti_sxa_session_set_deletion_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_set_deletion_request).name();};

  cn::proto::pfcp::pfcp_session_set_deletion_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_set_deletion_response   : public itti_sxa_msg {
public:
  itti_sxa_session_set_deletion_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_SET_DELETION_RESPONSE, origin, destination) {
  }
  itti_sxa_session_set_deletion_response(const itti_sxa_session_set_deletion_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_set_deletion_response(const itti_sxa_session_set_deletion_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_set_deletion_response).name();};

  cn::proto::pfcp::pfcp_session_set_deletion_response pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_establishment_request   : public itti_sxa_msg {
public:
  itti_sxa_session_establishment_request(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_ESTABLISHMENT_REQUEST, origin, destination) {
  }
  itti_sxa_session_establishment_request(const itti_sxa_session_establishment_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_establishment_request(const itti_sxa_session_establishment_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_set_deletion_response).name();};

  cn::proto::pfcp::pfcp_session_establishment_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_establishment_response   : public itti_sxa_msg {
public:
  itti_sxa_session_establishment_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_ESTABLISHMENT_RESPONSE, origin, destination) {
  }
  itti_sxa_session_establishment_response(const itti_sxa_session_establishment_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_establishment_response(const itti_sxa_session_establishment_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_set_deletion_response).name();};

  cn::proto::pfcp::pfcp_session_establishment_response pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_modification_request   : public itti_sxa_msg {
public:
  itti_sxa_session_modification_request(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_MODIFICATION_REQUEST, origin, destination) {
  }
  itti_sxa_session_modification_request(const itti_sxa_session_modification_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_modification_request(const itti_sxa_session_modification_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_modification_request).name();};

  cn::proto::pfcp::pfcp_session_modification_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_modification_response   : public itti_sxa_msg {
public:
  itti_sxa_session_modification_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_MODIFICATION_RESPONSE, origin, destination) {
  }
  itti_sxa_session_modification_response(const itti_sxa_session_modification_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_modification_response(const itti_sxa_session_modification_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_modification_response).name();};

  cn::proto::pfcp::pfcp_session_modification_response pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_deletion_request   : public itti_sxa_msg {
public:
  itti_sxa_session_deletion_request(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_DELETION_REQUEST, origin, destination) {
  }
  itti_sxa_session_deletion_request(const itti_sxa_session_deletion_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_deletion_request(const itti_sxa_session_deletion_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_deletion_request).name();};

  cn::proto::pfcp::pfcp_session_deletion_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_deletion_response   : public itti_sxa_msg {
public:
  itti_sxa_session_deletion_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_DELETION_RESPONSE, origin, destination) {
  }
  itti_sxa_session_deletion_response(const itti_sxa_session_deletion_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_deletion_response(const itti_sxa_session_deletion_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_deletion_response).name();};

  cn::proto::pfcp::pfcp_session_deletion_response pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_report_request   : public itti_sxa_msg {
public:
  itti_sxa_session_report_request(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_REPORT_REQUEST, origin, destination) {
  }
  itti_sxa_session_report_request(const itti_sxa_session_report_request& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_report_request(const itti_sxa_session_report_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_deletion_request).name();};

  cn::proto::pfcp::pfcp_session_report_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxa_session_report_response   : public itti_sxa_msg {
public:
  itti_sxa_session_report_response(const task_id_t origin, const task_id_t destination):
    itti_sxa_msg(SXA_SESSION_REPORT_RESPONSE, origin, destination) {
  }
  itti_sxa_session_report_response(const itti_sxa_session_report_response& i) : itti_sxa_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxa_session_report_response(const itti_sxa_session_report_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxa_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxa_session_report_response).name();};

  cn::proto::pfcp::pfcp_session_report_response pfcp_ies;
} ;
} // namespace itti

#endif /* ITTI_MSG_SXA_HPP_INCLUDED_ */
