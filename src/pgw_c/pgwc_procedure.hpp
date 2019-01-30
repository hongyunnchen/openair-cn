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
#ifndef FILE_PGWC_PROCEDURE_HPP_SEEN
#define FILE_PGWC_PROCEDURE_HPP_SEEN

/*! \file pgwc_procedure.hpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#include "itti_msg_sxab.hpp"
#include "msg_pfcp.hpp"

#include <memory>
#include <list>

namespace oai::cn::nf::pgwc {

class apn_context;
class pgw_pdn_connection;

class pgw_procedure {
private:
  static uint64_t              tx_id_generator;

  static uint64_t generate_tx_id() {
    tx_id_generator += 1;
    return tx_id_generator;
  }

public:
  uint64_t              tx_id;

  pgw_procedure(){tx_id = generate_tx_id();}
  pgw_procedure(uint64_t tx){tx_id = tx;}
  virtual ~pgw_procedure(){}
  virtual core::itti::itti_msg_type_t get_procedure_type(){return core::itti::ITTI_MSG_TYPE_NONE;}
  virtual int run(std::shared_ptr<pgw_pdn_connection> ppc) {return RETURNerror;}
  virtual void handle_itti_msg (core::itti::itti_sxab_session_establishment_response& resp, std::shared_ptr<apn_context> ebc, std::shared_ptr<pgw_pdn_connection> ppc) {}
};


class sgw_eps_bearer_context;
class sgw_pdn_connection;

class session_establishment_procedure : public pgw_procedure {
public:
  session_establishment_procedure(core::itti::itti_sxab_session_establishment_request& msg) : pgw_procedure(msg.tx_id), msg(msg), ebc(nullptr) {}
  int run(std::shared_ptr<pgw_pdn_connection> ppc);
  void handle_itti_msg (core::itti::itti_sxab_session_establishment_response& resp, std::shared_ptr<apn_context> ebc, std::shared_ptr<pgw_pdn_connection> ppc) {}

  core::itti::itti_sxab_session_establishment_request msg;
  std::shared_ptr<pgw_pdn_connection> ppc;
};

}
#include "pgw_context.hpp"

#endif
