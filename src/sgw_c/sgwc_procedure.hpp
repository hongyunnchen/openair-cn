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
#ifndef FILE_SGWC_PROCEDURE_HPP_SEEN
#define FILE_SGWC_PROCEDURE_HPP_SEEN

/*! \file sgwc_procedure.hpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "itti_msg_s11.hpp"
#include "msg_gtpv2c.hpp"

#include <memory>
#include <list>

namespace oai::cn::nf::sgwc {

class sgw_eps_bearer_context;
class sgw_pdn_connection;

class sebc_procedure {
private:
  static uint64_t              gtpc_tx_id_generator;

  static uint64_t generate_gtpc_tx_id() {
    gtpc_tx_id_generator += 2;
    return gtpc_tx_id_generator;
  }

public:
  uint64_t              gtpc_tx_id;

  sebc_procedure(){gtpc_tx_id = generate_gtpc_tx_id();}
  sebc_procedure(uint64_t tx_id){gtpc_tx_id = tx_id;}
  virtual ~sebc_procedure(){}
  virtual core::itti::itti_msg_type_t get_procedure_type(){return core::itti::ITTI_MSG_TYPE_NONE;}
  virtual int run(std::shared_ptr<sgw_eps_bearer_context> ebc) {return RETURNerror;}
  virtual void handle_itti_msg (core::itti::itti_s5s8_create_session_response& csresp, std::shared_ptr<sgw_eps_bearer_context> ebc, std::shared_ptr<sgw_pdn_connection> spc) {}
  virtual void handle_itti_msg (core::itti::itti_s5s8_delete_session_response& dsresp, std::shared_ptr<sgw_eps_bearer_context> ebc, std::shared_ptr<sgw_pdn_connection> spc) {}
};


class sgw_eps_bearer_context;
class sgw_pdn_connection;

class create_session_request_procedure : public sebc_procedure {
public:
  create_session_request_procedure(core::itti::itti_s11_create_session_request& msg) : sebc_procedure(msg.gtpc_tx_id), msg(msg), ebc(nullptr) {}
  int run(std::shared_ptr<sgw_eps_bearer_context> ebc);
  void handle_itti_msg (core::itti::itti_s5s8_create_session_response& csresp, std::shared_ptr<sgw_eps_bearer_context> ebc, std::shared_ptr<sgw_pdn_connection> spc);

  core::itti::itti_s11_create_session_request msg;
  std::shared_ptr<sgw_eps_bearer_context> ebc;
};

//Assuming actually that only one pdn_connection per modify bearer request
class modify_bearer_request_procedure : public sebc_procedure {
public:
  modify_bearer_request_procedure(core::itti::itti_s11_modify_bearer_request& msg) : sebc_procedure(msg.gtpc_tx_id), msg(msg), ebc(nullptr) {
    to_be_modified = {};
    modified = {};
    to_be_removed = {};
    marked_for_removal = {};
  }
  int run(std::shared_ptr<sgw_eps_bearer_context> ebc);
  //void handle_itti_msg (core::itti::itti_sxa_xxx& resp, std::shared_ptr<sgw_eps_bearer_context> ebc, std::shared_ptr<sgw_pdn_connection> spc);

  core::itti::itti_s11_modify_bearer_request msg;
  std::shared_ptr<sgw_eps_bearer_context> ebc;
  std::shared_ptr<sgw_pdn_connection> pdn_connection;
  std::list<oai::cn::proto::gtpv2c::bearer_context_to_be_modified_within_modify_bearer_request> to_be_modified;
  std::list<oai::cn::proto::gtpv2c::bearer_context_modified_within_modify_bearer_response> modified;
  std::list<oai::cn::proto::gtpv2c::bearer_context_to_be_removed_within_modify_bearer_request> to_be_removed;
  std::list<oai::cn::proto::gtpv2c::bearer_contexts_marked_for_removal_within_modify_bearer_response> marked_for_removal;
};

class delete_session_request_procedure : public sebc_procedure {
public:
  delete_session_request_procedure(core::itti::itti_s11_delete_session_request& msg, std::shared_ptr<sgw_pdn_connection> pdn) : sebc_procedure(msg.gtpc_tx_id), msg(msg), pdn_connection(pdn), ebc(nullptr) {}
  int run(std::shared_ptr<sgw_eps_bearer_context> ebc);
  void handle_itti_msg (core::itti::itti_s5s8_delete_session_response& dsresp, std::shared_ptr<sgw_eps_bearer_context> ebc, std::shared_ptr<sgw_pdn_connection> spc);

  core::itti::itti_s11_delete_session_request msg;
  std::shared_ptr<sgw_eps_bearer_context> ebc;
  std::shared_ptr<sgw_pdn_connection> pdn_connection;
};
}
#include "sgwc_eps_bearer_context.hpp"

#endif
