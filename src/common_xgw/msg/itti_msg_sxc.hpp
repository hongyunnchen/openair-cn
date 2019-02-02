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

/*! \file itti_msg_sxc.hpp
   \author  Lionel GAUTHIER
   \date 2019
   \email: lionel.gauthier@eurecom.fr
*/

#ifndef ITTI_MSG_SXC_HPP_INCLUDED_
#define ITTI_MSG_SXC_HPP_INCLUDED_

#include "3gpp_129.244.hpp"

#include "itti_msg.hpp"
#include "msg_pfcp.hpp"
#include <boost/asio.hpp>

namespace oai::cn::core::itti {

class itti_sxc_msg : public itti_msg {
public:
  itti_sxc_msg(const itti_msg_type_t  msg_type, const task_id_t origin, const task_id_t destination):
    itti_msg(msg_type, origin, destination) {
    l_endpoint = {};
    r_endpoint = {};
    seid = UNASSIGNED_SEID;
    trxn_id = 0;
  }
  itti_sxc_msg(const itti_sxc_msg& i) : itti_msg(i)  {
    l_endpoint = i.l_endpoint;
    r_endpoint = i.r_endpoint;
    seid = i.seid;
    trxn_id = i.trxn_id;
  }
  itti_sxc_msg(const itti_sxc_msg& i, const task_id_t orig, const task_id_t dest) : itti_sxc_msg(i)  {
    origin = orig;
    destination = dest;
  }

  boost::asio::ip::udp::endpoint l_endpoint;
  boost::asio::ip::udp::endpoint r_endpoint;
  seid_t                         seid;
  uint64_t                       trxn_id;
};

//-----------------------------------------------------------------------------
class itti_sxc_heartbeat_request : public itti_sxc_msg {
public:
  itti_sxc_heartbeat_request(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_HEARTBEAT_REQUEST, origin, destination) {  }
  itti_sxc_heartbeat_request(const itti_sxc_heartbeat_request& i) : itti_sxc_msg(i)  {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_heartbeat_request(const itti_sxc_heartbeat_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }

  const char* get_msg_name() {return typeid(itti_sxc_heartbeat_request).name();};

  pfcp::pfcp_heartbeat_request pfcp_ies;
};

//-----------------------------------------------------------------------------
class itti_sxc_heartbeat_response  : public itti_sxc_msg {
public:
  itti_sxc_heartbeat_response(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_HEARTBEAT_RESPONSE, origin, destination) {
  }
  itti_sxc_heartbeat_response(const itti_sxc_heartbeat_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_heartbeat_response(const itti_sxc_heartbeat_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_heartbeat_response).name();};

  pfcp::pfcp_heartbeat_response pfcp_ies;
};

//-----------------------------------------------------------------------------
class itti_sxc_pfcp_pfd_management_request   : public itti_sxc_msg {
public:
  itti_sxc_pfcp_pfd_management_request(const task_id_t origin, const task_id_t destination): itti_sxc_msg(SXC_PFCP_PFD_MANAGEMENT_REQUEST, origin, destination) {
  }
  itti_sxc_pfcp_pfd_management_request(const itti_sxc_pfcp_pfd_management_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_pfcp_pfd_management_request(const itti_sxc_pfcp_pfd_management_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_pfcp_pfd_management_request).name();};

  pfcp::pfcp_pfd_management_request pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxc_pfcp_pfd_management_response   : public itti_sxc_msg {
public:
  itti_sxc_pfcp_pfd_management_response(const task_id_t origin, const task_id_t destination): itti_sxc_msg(SXC_PFCP_PFD_MANAGEMENT_RESPONSE, origin, destination) {
  }
  itti_sxc_pfcp_pfd_management_response(const itti_sxc_pfcp_pfd_management_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_pfcp_pfd_management_response(const itti_sxc_pfcp_pfd_management_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_pfcp_pfd_management_response).name();};

  pfcp::pfcp_pfd_management_response pfcp_ies;
};


//-----------------------------------------------------------------------------
class itti_sxc_association_setup_request   : public itti_sxc_msg {
public:
  itti_sxc_association_setup_request(const task_id_t origin, const task_id_t destination): itti_sxc_msg(SXC_ASSOCIATION_SETUP_REQUEST, origin, destination) {
  }
  itti_sxc_association_setup_request(const itti_sxc_association_setup_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_association_setup_request(const itti_sxc_association_setup_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_association_setup_request).name();};

  pfcp::pfcp_association_setup_request pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxc_association_setup_response   : public itti_sxc_msg {
public:
  itti_sxc_association_setup_response(const task_id_t origin, const task_id_t destination): itti_sxc_msg(SXC_ASSOCIATION_SETUP_RESPONSE, origin, destination) {
  }
  itti_sxc_association_setup_response(const itti_sxc_association_setup_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_association_setup_response(const itti_sxc_association_setup_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_association_setup_response).name();};

  pfcp::pfcp_association_setup_response pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxc_association_update_request   : public itti_sxc_msg {
public:
  itti_sxc_association_update_request(const task_id_t origin, const task_id_t destination): itti_sxc_msg(SXC_ASSOCIATION_UPDATE_REQUEST, origin, destination) {
  }
  itti_sxc_association_update_request(const itti_sxc_association_update_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_association_update_request(const itti_sxc_association_update_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_association_update_request).name();};

  pfcp::pfcp_association_update_request pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxc_association_update_response   : public itti_sxc_msg {
public:
  itti_sxc_association_update_response(const task_id_t origin, const task_id_t destination): itti_sxc_msg(SXC_ASSOCIATION_UPDATE_RESPONSE, origin, destination) {
  }
  itti_sxc_association_update_response(const itti_sxc_association_update_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_association_update_response(const itti_sxc_association_update_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_association_update_response).name();};

  pfcp::pfcp_association_update_response pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxc_association_release_request   : public itti_sxc_msg {
public:
  itti_sxc_association_release_request(const task_id_t origin, const task_id_t destination): itti_sxc_msg(SXC_ASSOCIATION_RELEASE_REQUEST, origin, destination) {
  }
  itti_sxc_association_release_request(const itti_sxc_association_release_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_association_release_request(const itti_sxc_association_release_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_association_release_request).name();};

  pfcp::pfcp_association_release_request pfcp_ies;
} ;


//-----------------------------------------------------------------------------
class itti_sxc_association_release_response   : public itti_sxc_msg {
public:
  itti_sxc_association_release_response(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_ASSOCIATION_RELEASE_RESPONSE, origin, destination) {
  }
  itti_sxc_association_release_response(const itti_sxc_association_release_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_association_release_response(const itti_sxc_association_release_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_association_release_response).name();};

  pfcp::pfcp_association_release_response pfcp_ies;
};

//-----------------------------------------------------------------------------
class itti_sxc_version_not_supported_response   : public itti_sxc_msg {
public:
  itti_sxc_version_not_supported_response(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_VERSION_NOT_SUPPORTED_RESPONSE, origin, destination) {
  }
  itti_sxc_version_not_supported_response(const itti_sxc_version_not_supported_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_version_not_supported_response(const itti_sxc_version_not_supported_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_version_not_supported_response).name();};

  pfcp::pfcp_version_not_supported_response pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxc_node_report_request   : public itti_sxc_msg {
public:
  itti_sxc_node_report_request(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_NODE_REPORT_REQUEST, origin, destination) {
  }
  itti_sxc_node_report_request(const itti_sxc_node_report_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_node_report_request(const itti_sxc_node_report_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_node_report_request).name();};

  pfcp::pfcp_node_report_request pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxc_node_report_response   : public itti_sxc_msg {
public:
  itti_sxc_node_report_response(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_NODE_REPORT_RESPONSE, origin, destination) {
  }
  itti_sxc_node_report_response(const itti_sxc_node_report_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_node_report_response(const itti_sxc_node_report_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_node_report_response).name();};

  pfcp::pfcp_node_report_response pfcp_ies;
} ;

//-----------------------------------------------------------------------------
class itti_sxc_session_establishment_request   : public itti_sxc_msg {
public:
  itti_sxc_session_establishment_request(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_SESSION_ESTABLISHMENT_REQUEST, origin, destination) {
  }
  itti_sxc_session_establishment_request(const itti_sxc_session_establishment_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_session_establishment_request(const itti_sxc_session_establishment_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_session_set_deletion_response).name();};

  pfcp::pfcp_session_establishment_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxc_session_establishment_response   : public itti_sxc_msg {
public:
  itti_sxc_session_establishment_response(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_SESSION_ESTABLISHMENT_RESPONSE, origin, destination) {
  }
  itti_sxc_session_establishment_response(const itti_sxc_session_establishment_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_session_establishment_response(const itti_sxc_session_establishment_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_session_set_deletion_response).name();};

  pfcp::pfcp_session_establishment_response pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxc_session_modification_request   : public itti_sxc_msg {
public:
  itti_sxc_session_modification_request(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_SESSION_MODIFICATION_REQUEST, origin, destination) {
  }
  itti_sxc_session_modification_request(const itti_sxc_session_modification_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_session_modification_request(const itti_sxc_session_modification_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_session_modification_request).name();};

  pfcp::pfcp_session_modification_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxc_session_modification_response   : public itti_sxc_msg {
public:
  itti_sxc_session_modification_response(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_SESSION_MODIFICATION_RESPONSE, origin, destination) {
  }
  itti_sxc_session_modification_response(const itti_sxc_session_modification_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_session_modification_response(const itti_sxc_session_modification_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_session_modification_response).name();};

  pfcp::pfcp_session_modification_response pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxc_session_deletion_request   : public itti_sxc_msg {
public:
  itti_sxc_session_deletion_request(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_SESSION_DELETION_REQUEST, origin, destination) {
  }
  itti_sxc_session_deletion_request(const itti_sxc_session_deletion_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_session_deletion_request(const itti_sxc_session_deletion_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_session_deletion_request).name();};

  pfcp::pfcp_session_deletion_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxc_session_deletion_response   : public itti_sxc_msg {
public:
  itti_sxc_session_deletion_response(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_SESSION_DELETION_RESPONSE, origin, destination) {
  }
  itti_sxc_session_deletion_response(const itti_sxc_session_deletion_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_session_deletion_response(const itti_sxc_session_deletion_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_session_deletion_response).name();};

  pfcp::pfcp_session_deletion_response pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxc_session_report_request   : public itti_sxc_msg {
public:
  itti_sxc_session_report_request(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_SESSION_REPORT_REQUEST, origin, destination) {
  }
  itti_sxc_session_report_request(const itti_sxc_session_report_request& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_session_report_request(const itti_sxc_session_report_request& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_session_deletion_request).name();};

  pfcp::pcfp_session_report_request pfcp_ies;
} ;
//-----------------------------------------------------------------------------
class itti_sxc_session_report_response   : public itti_sxc_msg {
public:
  itti_sxc_session_report_response(const task_id_t origin, const task_id_t destination):
    itti_sxc_msg(SXC_SESSION_REPORT_RESPONSE, origin, destination) {
  }
  itti_sxc_session_report_response(const itti_sxc_session_report_response& i) : itti_sxc_msg(i) {
    pfcp_ies = i.pfcp_ies;
  }
  itti_sxc_session_report_response(const itti_sxc_session_report_response& i, const task_id_t orig, const task_id_t dest) :
    itti_sxc_msg(i, orig, dest)  {
    pfcp_ies = i.pfcp_ies;
  }
  const char* get_msg_name() {return typeid(itti_sxc_session_report_response).name();};

  pfcp::pfcp_session_report_response pfcp_ies;
} ;
} // namespace itti

#endif /* ITTI_MSG_SXC_HPP_INCLUDED_ */
