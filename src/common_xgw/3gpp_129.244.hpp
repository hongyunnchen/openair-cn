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

/*! \file 3gpp_129.244.hpp
  \brief
  \author Lionel Gauthier
  \company Eurecom
  \email: lionel.gauthier@eurecom.fr
*/

#ifndef FILE_3GPP_129_244_HPP_SEEN
#define FILE_3GPP_129_244_HPP_SEEN

#include <arpa/inet.h>
#include <cstring>
#include <endian.h>
#include <exception>
//#include <fmt/format.h> conflicts with spdlog
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "3gpp_129.244.h"
#include "logger.hpp"
#include "msg_pfcp.hpp"
#include "serializable.hpp"


namespace oai::cn::proto::pfcp {

//------------------------------------------------------------------------------
class pfcp_tlv : public stream_serializable {
public:
  static const uint16_t tlv_ie_length = 4;
  uint16_t  type;
  uint16_t  length;
  uint16_t  enterprise_id;

  pfcp_tlv() {
    type = 0;
    length = 0;
    enterprise_id = 0;
  };

  pfcp_tlv(uint16_t t, uint16_t l = 0, uint16_t e = 0) {
    type = t;
    length = l;
    enterprise_id = e;
  };

  //~pfcp_tlv() {};

  void set_type(const uint16_t& t) {
    type = t;
  }

  uint16_t get_type() {
    return type;
  }

  void set_length(const uint16_t& l) {
    length = l;
  }

  void add_length(const uint16_t& l) {
    length += l;
  }

  uint16_t get_length() {
    return length ;
  }

  void set_enterprise_id(const uint16_t& e) {
    enterprise_id = e;
  }

  uint16_t get_enterprise_id() {
    return enterprise_id ;
  }

  void dump_to(std::ostream& os)  {
    auto ns_type = htobe16(type);
    os.write(reinterpret_cast<const char*>(&ns_type), sizeof(ns_type));
    auto ns_length = htobe16(length);
    os.write(reinterpret_cast<const char*>(&ns_length), sizeof(ns_length));
    if (type &0x8000) {
      auto ns_enterprise_id = htobe16(enterprise_id);
      os.write(reinterpret_cast<const char*>(&ns_enterprise_id), sizeof(ns_enterprise_id));
    }
  }

  void load_from(std::istream& is) {
    is.read(reinterpret_cast<char*>(&type), sizeof(type));
    type = be16toh(type);
    is.read(reinterpret_cast<char*>(&length), sizeof(length));
    length = be16toh(length);
    if (type &0x8000) {
      is.read(reinterpret_cast<char*>(&enterprise_id), sizeof(enterprise_id));
      enterprise_id = be16toh(enterprise_id);
    }
  }
};
//------------------------------------------------------------------------------
class pfcp_ie : public stream_serializable {
public:
  pfcp_tlv    tlv;

  pfcp_ie() {
    tlv = {0};
  }
  pfcp_ie(const pfcp_tlv& t) {
    tlv = t;
  }
  pfcp_ie(const uint8_t tlv_type) {
    tlv = {0};
    tlv.type = tlv_type;
  }
  
  virtual ~pfcp_ie() {};
  
  virtual void to_core_type(pfcp_ies_container& s) {throw pfcp_msg_illegal_ie_exception(s.msg_id, tlv.type);}

  virtual void dump_to(std::ostream& os) {
    tlv.dump_to(os);
  };

  virtual void load_from(std::istream& is) {throw pfcp_ie_unimplemented_exception(tlv.type); /* should not hapen of course*/};

  static pfcp_ie * new_pfcp_ie_from_stream(std::istream& is);
};
//------------------------------------------------------------------------------
class pfcp_grouped_ie : public pfcp_ie {
public:
  std::vector<std::shared_ptr<pfcp_ie>>  ies;

  pfcp_grouped_ie() : pfcp_ie() {
    ies = {};
  }
  pfcp_grouped_ie(const pfcp_grouped_ie& g) : pfcp_ie(g), ies(g.ies) {
  }

  pfcp_grouped_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    ies = {};
  }
  pfcp_grouped_ie(const uint8_t tlv_type) : pfcp_ie(tlv_type) {
    ies = {};
  }
  
  virtual ~pfcp_grouped_ie()
  {
    ies.clear();
  }

  virtual void to_core_type(pfcp_ies_container& s) {throw pfcp_msg_illegal_ie_exception(s.msg_id, tlv.type);}
  
  void add_ie(std::shared_ptr<pfcp_ie> ie) {
    ies.push_back(ie);
    tlv.length += (pfcp_tlv::tlv_ie_length + ie.get()->tlv.get_length());
  }

  virtual void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    for (auto sie : ies) {
      sie.get()->dump_to(os);
    }
  };

  virtual void load_from(std::istream& is) {
    //tlv.load_from(is);
    int32_t remaining_size = tlv.get_length();
    while (remaining_size > 0) {
      pfcp_ie *ie = new_pfcp_ie_from_stream(is);
      if (ie) {
        remaining_size -= (ie->tlv.get_length() + pfcp_tlv::tlv_ie_length);
        ies.push_back(std::shared_ptr<pfcp_ie>(ie)); // do not use add_ie()
      } else {
        throw pfcp_tlv_bad_length_exception(tlv.get_type(), tlv.get_length());
      }
    }
  };
};
//------------------------------------------------------------------------------
class pfcp_msg_header : public stream_serializable {
private:
#define PFCP_MSG_HEADER_MIN_SIZE        8
  union {
    struct {
      uint8_t                         s:1;
      uint8_t                         mp:1;
      uint8_t                         spare:3;
      uint8_t                         version:3;
    } bf;
    uint8_t b;
  } u1;
  uint8_t                         message_type;
  uint16_t                        message_length;
  uint64_t                        seid;
  uint32_t                        sequence_number;
  union {
    struct {
      uint8_t                         spare:4;
      uint8_t                         message_priority:4;
    } bf;
    uint8_t b;
  } u2;
    
public:

  pfcp_msg_header() {
    message_type = 0;
    message_length = 3 + 1; // sn + spare
    seid = 0;
    sequence_number = 0;
    u2.b = 0;
    u1.bf.version = 1;
  }

  pfcp_msg_header(const pfcp_msg_header& h) {
    u1.b = h.u1.b;
    message_type = h.message_type;
    message_length = h.message_length;
    seid = h.seid;
    sequence_number = h.sequence_number;
    u2.b = h.u2.b;
  }

  void set_seid(const uint64_t& s) {
   seid = s;
    if (u1.bf.s == 0) {
      u1.bf.s = 1;
      message_length += 8;
    }
  }
  
  bool has_seid() const {
    return (u1.bf.s == 1);
  }

  uint64_t get_seid() const {
    return seid;
  }

  void set_message_type(const uint8_t& t) {
    message_type = t;
  }

  uint8_t get_message_type() const {
    return message_type;
  }

  void set_message_length(const uint16_t& l) {
    message_length = l;
  }

  uint16_t get_message_length() const {
    return message_length;
  }

  void set_sequence_number(const uint32_t& s) {
    sequence_number = s & 0x00FFFFFF;
  }

  uint32_t get_sequence_number() const {
    return sequence_number;
  }

  virtual void dump_to(std::ostream& os) {
    // ! Control Plane GTP header length shall be a multiple of 4 octets.
    u1.bf.spare = 0;
    u2.bf.spare = 0;
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    os.write(reinterpret_cast<const char*>(&message_type), sizeof(message_type));
    auto ns_message_length = htobe16(message_length);
    os.write(reinterpret_cast<const char*>(&ns_message_length), sizeof(ns_message_length));
    if (u1.bf.s) {
      auto nl_seid = htobe64(seid);
      os.write(reinterpret_cast<const char*>(&nl_seid), sizeof(nl_seid));
    }

    uint8_t sn[3];
    uint32_t cp_sequence_number = sequence_number;
    sn[2] = cp_sequence_number & 0x000000FF;
    cp_sequence_number = cp_sequence_number >> 8;
    sn[1] = cp_sequence_number & 0x000000FF;
    cp_sequence_number = cp_sequence_number >> 8;
    sn[0] = cp_sequence_number & 0x000000FF;
    
    os.write(reinterpret_cast<const char*>(sn), 3);
    if (!u1.bf.mp) u2.bf.message_priority = 0;
    os.write(reinterpret_cast<const char*>(&u2.b), sizeof(u2.b));
  }
  virtual void load_from(std::istream& is) {
    // ! Control Plane GTP header length shall be a multiple of 4 octets.
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    is.read(reinterpret_cast<char*>(&message_type), sizeof(message_type));
    is.read(reinterpret_cast<char*>(&message_length), sizeof(message_length));
    message_length = be16toh(message_length);
    if (u1.bf.s) {
      is.read(reinterpret_cast<char*>(&seid), sizeof(seid));
      seid = be64toh(seid);
    } else {
      seid = 0;
    }
    uint8_t sn[3];
    is.read(reinterpret_cast<char*>(sn), 3);
    sequence_number = (((uint32_t)sn[0]) << 16) | (((uint32_t)sn[1]) << 8) | sn[2];
    is.read(reinterpret_cast<char*>(&u2.b), sizeof(u2.b));
  }
};
//------------------------------------------------------------------------------
class pfcp_msg : public pfcp_msg_header
{
public:
  uint16_t remote_port;
    
  std::vector<std::shared_ptr<pfcp_ie>>         ies;

  pfcp_msg() : pfcp_msg_header() {
    ies = {};
  }
  
  pfcp_msg(const pfcp_msg& m) : pfcp_msg_header(m) {
    ies = m.ies;
  }

  pfcp_msg(const pfcp_msg_header& hdr) : pfcp_msg_header(hdr) {
    ies = {};
  }

//  pfcp_msg(const pfcp_heartbeat_request& pfcp_ies);
//  pfcp_msg(const pfcp_heartbeat_response& pfcp_ies);
//  pfcp_msg(const pfcp_pfd_management_request& pfcp_ies);
//  pfcp_msg(const pfcp_pfd_management_response& pfcp_ies);
  pfcp_msg(const pfcp_association_setup_request& pfcp_ies);
//  pfcp_msg(const pfcp_association_setup_response& pfcp_ies);
//  pfcp_msg(const pfcp_association_update_request& pfcp_ies);
//  pfcp_msg(const pfcp_association_update_response& pfcp_ies);
//  pfcp_msg(const pfcp_association_release_request& pfcp_ies);
//  pfcp_msg(const pfcp_association_release_response& pfcp_ies);
//  pfcp_msg(const pfcp_version_not_supported_response& pfcp_ies);
//  pfcp_msg(const pfcp_node_report_request& pfcp_ies);
//  pfcp_msg(const pfcp_node_report_response& pfcp_ies);
  pfcp_msg(const pfcp_session_establishment_request& pfcp_ies);
//  pfcp_msg(const pfcp_session_establishment_response& pfcp_ies);
//  pfcp_msg(const pfcp_session_modification_request& pfcp_ies);
//  pfcp_msg(const pfcp_session_modification_response& pfcp_ies);
//  pfcp_msg(const pfcp_session_deletion_request& pfcp_ies);
//  pfcp_msg(const pfcp_session_deletion_response& pfcp_ies);
//  pfcp_msg(const pfcp_session_report_request& pfcp_ies);
//  pfcp_msg(const pfcp_session_report_response& pfcp_ies);


  ~pfcp_msg() {
    ies.clear();
  }

  void add_ie(std::shared_ptr<pfcp_ie> ie) {
    ies.push_back(ie);
    //std::cout << std::dec<< " add_ie   = " << get_message_length() << " -> "<< get_message_length() + pfcp_tlv::tlv_ie_length + ie.get()->tlv.get_length() << std::endl;
    set_message_length(get_message_length() + pfcp_tlv::tlv_ie_length + ie.get()->tlv.get_length());
  }
  
  void to_core_type(pfcp_heartbeat_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_heartbeat_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_pfd_management_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_pfd_management_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_association_setup_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_association_setup_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_association_update_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_association_update_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_association_release_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_association_release_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_version_not_supported_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_node_report_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_node_report_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_session_establishment_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_session_establishment_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_session_modification_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_session_modification_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_session_deletion_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_session_deletion_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_session_report_request& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }
  void to_core_type(pfcp_session_report_response& s) {
    for (auto i : ies) {
      i.get()->to_core_type(s);
    }
  }

  void dump_to(std::ostream& os)  {
    pfcp_msg_header::dump_to(os);
    for (auto i : ies) {
      i.get()->dump_to(os);
    }
  }
  void load_from(std::istream& is) {
    pfcp_msg_header::load_from(is);

    uint16_t check_msg_length = get_message_length() - 3 - 1; // sn + spare
    if (has_seid()) check_msg_length -= 8;
    pfcp_ie * ie = nullptr;
    uint16_t ies_length = 0;
    //std::cout << std::dec<< " check_msg_length  = " << check_msg_length << std::endl;
    do {
      ie = pfcp_ie::new_pfcp_ie_from_stream(is);
      if (ie) {
        ies_length += (pfcp_tlv::tlv_ie_length + ie->tlv.get_length());
        ies.push_back(std::shared_ptr<pfcp_ie>(ie));
        //std::cout << std::dec << " ies length  = " << ies_length << " IE length = " << ie->tlv.get_length() << std::endl;
      }
    } while((ie) && (ies_length < check_msg_length));

    if (ies_length != check_msg_length) {
      //std::cout << " check_msg_length  = " << check_msg_length << " ies_length  = " << ies_length << std::endl;
      throw pfcp_msg_bad_length_exception(get_message_type(), get_message_length());
    }
  }
};


inline void ipv6_address_dump_to(std::ostream& os, const struct in6_addr& ipv6_address) {
  os.write(reinterpret_cast<const char*>(ipv6_address.__in6_u.__u6_addr8), 16);
}

inline void ipv6_address_load_from(std::istream& is, struct in6_addr& ipv6_address) {
  is.read(reinterpret_cast<char*>(ipv6_address.__in6_u.__u6_addr8), 16);
}

inline void ipv4_address_dump_to(std::ostream& os, const struct in_addr& ipv4_address) {
  os.write(reinterpret_cast<const char*>(&ipv4_address.s_addr), sizeof(ipv4_address.s_addr));
}

inline void ipv4_address_load_from(std::istream& is, struct in_addr& ipv4_address) {
  is.read(reinterpret_cast<char*>(&ipv4_address.s_addr), sizeof(ipv4_address.s_addr));
}

//------------------------------------------------------------------------------
// NON GROUPED IEs
//------------------------------------------------------------------------------

//-------------------------------------
// IE CAUSE
class pfcp_cause_ie : public pfcp_ie {
public:
  uint8_t  cause_value;

  //--------
  pfcp_cause_ie(const core::pfcp::cause_t& b) : pfcp_ie(PFCP_IE_CAUSE){
    cause_value = b.cause_value;
    tlv.set_length(1);
  }
  //--------
  pfcp_cause_ie() : pfcp_ie(PFCP_IE_CAUSE){
    cause_value = core::pfcp::CAUSE_VALUE_RESERVED;
    tlv.set_length(1);
  }
  //--------
  pfcp_cause_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    cause_value = core::pfcp::CAUSE_VALUE_RESERVED;
  };
  //--------
  void to_core_type(core::pfcp::cause_t& b) {
    b.cause_value = cause_value;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&cause_value), sizeof(cause_value));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&cause_value), sizeof(cause_value));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::cause_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE SOURCE_INTERFACE
class pfcp_source_interface_ie : public pfcp_ie {
public:
  uint8_t  interface_value;

  //--------
  pfcp_source_interface_ie(const core::pfcp::source_interface_t& b) : pfcp_ie(PFCP_IE_SOURCE_INTERFACE){
    interface_value = b.interface_value;
    tlv.set_length(1);
  }
  //--------
  pfcp_source_interface_ie() : pfcp_ie(PFCP_IE_SOURCE_INTERFACE){
    interface_value = 255;
    tlv.set_length(1);
  }
  //--------
  pfcp_source_interface_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    interface_value = 255;
  };
  //--------
  void to_core_type(core::pfcp::source_interface_t& b) {
    b.interface_value = interface_value;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&interface_value), sizeof(interface_value));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&interface_value), sizeof(interface_value));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::source_interface_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE F_TEID
class pfcp_fteid_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t v4 :1;
      uint8_t v6 :1;
      uint8_t ch :1;
      uint8_t chid :1;
      uint8_t spare1 :4;
   } bf;
   uint8_t b;
  } u1;
  uint32_t teid;
  struct in_addr  ipv4_address;
  struct in6_addr ipv6_address;
  uint8_t choose_id;

  //--------
  pfcp_fteid_ie(const core::pfcp::fteid_t& b) : pfcp_ie(PFCP_IE_F_TEID){
    tlv.set_length(1);
    u1.b = 0;
    u1.bf.ch = b.ch;
    u1.bf.chid = b.chid;
    teid = b.teid;
    ipv4_address = b.ipv4_address;
    ipv6_address = b.ipv6_address;
    if (!u1.bf.ch) {
      tlv.add_length(4); // teid
      u1.bf.v4 = b.v4;
      u1.bf.v6 = b.v6;
      if (u1.bf.v4) {
        tlv.add_length(4);
      }
      if (u1.bf.v6) {
        tlv.add_length(16);
      }
    } else {
      ipv4_address.s_addr = INADDR_ANY;
      ipv6_address = in6addr_any;
      // else should clear v4 v6 bits
      if (u1.bf.chid) {
        choose_id = b.choose_id;
        tlv.add_length(1);
      }
    }
  }
  //--------
  pfcp_fteid_ie() : pfcp_ie(PFCP_IE_F_TEID){
    u1.b = 0;
    teid = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    choose_id = 0;
    tlv.set_length(1);
  }
  //--------
  pfcp_fteid_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    u1.b = 0;
    teid = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    choose_id = 0;
  };
  //--------
  void to_core_type(core::pfcp::fteid_t& f) {
    f = {0};
    f.v4 = u1.bf.v4;
    f.v6 = u1.bf.v6;
    f.teid = teid;
    f.ipv4_address = ipv4_address;
    f.ipv6_address = ipv6_address;
    f.choose_id = choose_id;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.set_length(1);
    if (!u1.bf.ch) {
      tlv.add_length(4); // teid
      if (u1.bf.v4) {
        tlv.add_length(4);
      }
      if (u1.bf.v6) {
        tlv.add_length(16);
      }
    } else {
      if (u1.bf.chid) {
        tlv.add_length(1);
      }
    }
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    if (!u1.bf.ch) {
      auto nl_teid = htobe32(teid);
      os.write(reinterpret_cast<const char*>(&nl_teid), sizeof(nl_teid));
      if (u1.bf.v4) {
        ipv4_address_dump_to(os, ipv4_address);
      }
      if (u1.bf.v6) {
        ipv6_address_dump_to(os, ipv6_address);
      }
    }
    if (u1.bf.chid) {
      os.write(reinterpret_cast<const char*>(&choose_id), sizeof(choose_id));
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    uint16_t check_length = 1;
    if (u1.bf.ch) {
      if (u1.bf.chid) {
        check_length += 1;
      }
      check_length += 1;
    } else {
      check_length += 4;
      if (u1.bf.v4) check_length += 4;
      if (u1.bf.v6) check_length += 16;
    }
    if (tlv.get_length() != check_length) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    if (!u1.bf.ch) {
      is.read(reinterpret_cast<char*>(&teid), sizeof(teid));
      teid = be32toh(teid);
      if (u1.bf.v4) {
        ipv4_address_load_from(is, ipv4_address);
      }
      if (u1.bf.v6) {
        ipv6_address_load_from(is, ipv6_address);
      }
    } else {
      if (u1.bf.chid) {
        is.read(reinterpret_cast<char*>(&choose_id), sizeof(choose_id));
      }
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::fteid_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE NETWORK_INSTANCE
class pfcp_network_instance_ie : public pfcp_ie {
public:
  std::string  network_instance;

  //--------
  pfcp_network_instance_ie(const core::pfcp::network_instance_t& b) : pfcp_ie(PFCP_IE_NETWORK_INSTANCE){
    network_instance = b.network_instance;
    tlv.set_length(network_instance.size());
  }
  //--------
  pfcp_network_instance_ie() : pfcp_ie(PFCP_IE_NETWORK_INSTANCE){
    tlv.set_length(0);
  }
  //--------
  pfcp_network_instance_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::network_instance_t& b) {
    b.network_instance = network_instance;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os << network_instance;
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    char e[tlv.get_length()];
    is.read(e, tlv.get_length());
    network_instance.assign(e, tlv.get_length());
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::network_instance_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE SDF_FILTER
class pfcp_sdf_filter_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t fd :1;
      uint8_t ttc :1;
      uint8_t spi :1;
      uint8_t fl :1;
      uint8_t bid :1;
      uint8_t spare1 :3;
   } bf;
   uint8_t b;
  } u1;
  uint16_t length_of_flow_description;
  std::string flow_description;
  std::string tos_traffic_class;        // 2 octets
  std::string security_parameter_index; // 4 octets
  std::string flow_label; // 3 octets
  uint32_t sdf_filter_id;

  //--------
  pfcp_sdf_filter_ie(const core::pfcp::sdf_filter_t& b) : pfcp_ie(PFCP_IE_SDF_FILTER){
    tlv.set_length(2);
    u1.b = 0;
    length_of_flow_description = 0;
    flow_description = {};
    tos_traffic_class = {};
    security_parameter_index = {};
    flow_label = {};
    sdf_filter_id = 0;
    u1.bf.fd = b.fd;
    u1.bf.ttc = b.ttc;
    u1.bf.spi = b.spi;
    u1.bf.fl = b.fl;
    u1.bf.bid = b.bid;
    if (u1.bf.fd) {
      length_of_flow_description = b.length_of_flow_description;
      flow_description = b.flow_description;
      tlv.add_length(sizeof(length_of_flow_description) + flow_description.size());
    }
    if (u1.bf.ttc) {
      if (b.tos_traffic_class.size() != 2) {
        throw pfcp_ie_value_exception(tlv.type, "tos_traffic_class");
      }
      tos_traffic_class = b.tos_traffic_class;
      tlv.add_length(2);
    }
    if (u1.bf.spi) {
      if (b.security_parameter_index.size() != 4) {
        throw pfcp_ie_value_exception(tlv.type, "security_parameter_index");
      }
      security_parameter_index = b.security_parameter_index;
      tlv.add_length(4);
    }
    if (u1.bf.fl) {
      if (b.flow_label.size() != 3) {
        throw pfcp_ie_value_exception(tlv.type, "flow_label");
      }
      flow_label = b.flow_label;
    }
    if (u1.bf.bid) {
      sdf_filter_id = b.sdf_filter_id;
    }
  }
  //--------
  pfcp_sdf_filter_ie() : pfcp_ie(PFCP_IE_SDF_FILTER){
    u1.b = 0;
    length_of_flow_description = 0;
    flow_description = {};
    tos_traffic_class = {};
    security_parameter_index = {};
    flow_label = {};
    sdf_filter_id = 0;
    tlv.set_length(2);
  }
  //--------
  pfcp_sdf_filter_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::sdf_filter_t& b) {
    b = {};
    b.fd = u1.bf.fd;
    b.ttc = u1.bf.ttc;
    b.spi = u1.bf.spi;
    b.fl = u1.bf.fl;
    b.bid = u1.bf.bid;

    if (u1.bf.fd) {
      b.length_of_flow_description = length_of_flow_description;
      b.flow_description = flow_description;
    }

    if (u1.bf.ttc) {
      b.tos_traffic_class = tos_traffic_class;
    }
    if (u1.bf.spi) {
      b.security_parameter_index = security_parameter_index;
    }
    if (u1.bf.fl) {
      b.flow_label = flow_label;
    }
    if (u1.bf.bid) {
      b.sdf_filter_id = sdf_filter_id;
    }
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    char spare = 0;
    os.write(reinterpret_cast<const char*>(&spare), sizeof(spare));
    if (u1.bf.fd) {
      auto be_length_of_flow_description = htobe16(length_of_flow_description);
      os.write(reinterpret_cast<const char*>(&be_length_of_flow_description), sizeof(be_length_of_flow_description));
      os << flow_description;
    }
    if (u1.bf.ttc) {
      os << tos_traffic_class;
    }
    if (u1.bf.spi) {
      os << security_parameter_index;
    }
    if (u1.bf.fl) {
      os << flow_label;
    }
    if (u1.bf.bid) {
      os << sdf_filter_id;
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    char spare = 0;
    is.read(reinterpret_cast<char*>(&spare), sizeof(spare));
    if (u1.bf.fd) {
      is.read(reinterpret_cast<char*>(&length_of_flow_description), sizeof(length_of_flow_description));
      length_of_flow_description = be16toh(length_of_flow_description);
      char e[length_of_flow_description];
      is.read(e, length_of_flow_description);
      flow_description.assign(e, length_of_flow_description);
    }
    if (u1.bf.ttc) {
      char e[2];
      is.read(e, 2);
      tos_traffic_class.assign(e, 2);
    }
    if (u1.bf.spi) {
      char e[4];
      is.read(e, 4);
      security_parameter_index.assign(e, 4);
    }
    if (u1.bf.fl) {
      char e[3];
      is.read(e, 3);
      flow_label.assign(e, 3);
    }
    if (u1.bf.bid) {
      is.read(reinterpret_cast<char*>(&sdf_filter_id), sizeof(sdf_filter_id));
      sdf_filter_id = be32toh(sdf_filter_id);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::sdf_filter_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE APPLICATION_ID
class pfcp_application_id_ie : public pfcp_ie {
public:
  std::string application_id;

  //--------
  pfcp_application_id_ie(const core::pfcp::application_id_t& b) : pfcp_ie(PFCP_IE_APPLICATION_ID){
    application_id = b.application_id;
    tlv.set_length(application_id.size());
  }
  //--------
  pfcp_application_id_ie() : pfcp_ie(PFCP_IE_APPLICATION_ID){
    application_id = {};
    tlv.set_length(0);
  }
  //--------
  pfcp_application_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::application_id_t& b) {
    b.application_id = application_id;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os << application_id;
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    uint16_t l = tlv.get_length();
    char e[l];
    is.read(e, l);
    application_id.assign(e, l);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::application_id_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE GATE_STATUS
class pfcp_gate_status_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t dl_gate :2;
      uint8_t ul_gate :2;
      uint8_t spare :4;
   } bf;
   uint8_t b;
  } u1;

  //--------
  pfcp_gate_status_ie(const core::pfcp::gate_status_t& b) : pfcp_ie(PFCP_IE_GATE_STATUS){
    u1.b = 0;
    u1.bf.ul_gate = b.ul_gate;
    u1.bf.dl_gate = b.dl_gate;
    tlv.set_length(1);
  }
  //--------
  pfcp_gate_status_ie() : pfcp_ie(PFCP_IE_GATE_STATUS){
    u1.b = 0;
    tlv.set_length(1);
  }
  //--------
  pfcp_gate_status_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::gate_status_t& b) {
    b.ul_gate = u1.bf.ul_gate;
    b.dl_gate = u1.bf.dl_gate;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::gate_status_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE MBR
class pfcp_mbr_ie : public pfcp_ie {
public:
  uint8_t ul_mbr[5];
  uint8_t dl_mbr[5];

  //--------
  pfcp_mbr_ie(const core::pfcp::mbr_t& b) : pfcp_ie(PFCP_IE_MBR){
    uint64_t uplink = b.ul_mbr & 0x000000FFFFFFFFFF;
    uint64_t downlink = b.dl_mbr & 0x000000FFFFFFFFFF;

    for (int i = 4; i >= 0; i--) {
      ul_mbr[i] = uplink & 0xFF;
      dl_mbr[i] = downlink & 0xFF;

      uplink = uplink >> 8;
      downlink = downlink >> 8;
    }
    tlv.set_length(10);
  }
  //--------
  pfcp_mbr_ie() : pfcp_ie(PFCP_IE_MBR){
    tlv.set_length(10);
  }
  //--------
  pfcp_mbr_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::mbr_t& b) {
    uint64_t uplink = 0;
    uint64_t downlink = 0;

    for (int i = 0; i < 5; i++) {
      uplink = uplink << 8;
      downlink = downlink << 8;
      uplink |= ul_mbr[i];
      downlink |= dl_mbr[i];
    }
    b.ul_mbr = uplink;
    b.dl_mbr = downlink;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(ul_mbr), 5);
    os.write(reinterpret_cast<const char*>(dl_mbr), 5);
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 10) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&ul_mbr), sizeof(ul_mbr));
    is.read(reinterpret_cast<char*>(&dl_mbr), sizeof(dl_mbr));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::mbr_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE GBR
class pfcp_gbr_ie : public pfcp_ie {
public:
  uint8_t ul_gbr[5];
  uint8_t dl_gbr[5];

  //--------
  pfcp_gbr_ie(const core::pfcp::gbr_t& b) : pfcp_ie(PFCP_IE_GBR){
    uint64_t uplink = b.ul_gbr & 0x000000FFFFFFFFFF;
    uint64_t downlink = b.dl_gbr & 0x000000FFFFFFFFFF;

    for (int i = 4; i >= 0; i--) {
      ul_gbr[i] = uplink & 0xFF;
      dl_gbr[i] = downlink & 0xFF;

      uplink = uplink >> 8;
      downlink = downlink >> 8;
    }
    tlv.set_length(10);
  }
  //--------
  pfcp_gbr_ie() : pfcp_ie(PFCP_IE_GBR){
    tlv.set_length(10);
  }
  //--------
  pfcp_gbr_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::gbr_t& b) {
    uint64_t uplink = 0;
    uint64_t downlink = 0;

    for (int i = 0; i < 5; i++) {
      uplink = uplink << 8;
      downlink = downlink << 8;
      uplink |= ul_gbr[i];
      downlink |= dl_gbr[i];
    }
    b.ul_gbr = uplink;
    b.dl_gbr = downlink;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(ul_gbr), 5);
    os.write(reinterpret_cast<const char*>(dl_gbr), 5);
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 10) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&ul_gbr), sizeof(ul_gbr));
    is.read(reinterpret_cast<char*>(&dl_gbr), sizeof(dl_gbr));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::gbr_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE QER_CORRELATION_ID
class pfcp_qer_correlation_id_ie : public pfcp_ie {
public:
  uint32_t qer_correlation_id;

  //--------
  pfcp_qer_correlation_id_ie(const core::pfcp::qer_correlation_id_t& b) : pfcp_ie(PFCP_IE_QER_CORRELATION_ID){
    qer_correlation_id = b.qer_correlation_id;
    tlv.set_length(sizeof(qer_correlation_id));
  }
  //--------
  pfcp_qer_correlation_id_ie() : pfcp_ie(PFCP_IE_QER_CORRELATION_ID){
    qer_correlation_id = 0;
    tlv.set_length(sizeof(qer_correlation_id));
  }
  //--------
  pfcp_qer_correlation_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::qer_correlation_id_t& b) {
    b.qer_correlation_id = qer_correlation_id;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_qer_correlation_id = htobe32(qer_correlation_id);
    os.write(reinterpret_cast<const char*>(&be_qer_correlation_id), sizeof(be_qer_correlation_id));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&qer_correlation_id), sizeof(qer_correlation_id));
    qer_correlation_id = be32toh(qer_correlation_id);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::qer_correlation_id_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE PRECEDENCE
class pfcp_precedence_ie : public pfcp_ie {
public:
  uint32_t precedence;

  //--------
  pfcp_precedence_ie(const core::pfcp::precedence_t& b) : pfcp_ie(PFCP_IE_PRECEDENCE){
    precedence = b.precedence;
    tlv.set_length(sizeof(precedence));
  }
  //--------
  pfcp_precedence_ie() : pfcp_ie(PFCP_IE_PRECEDENCE){
    precedence = 0;
    tlv.set_length(sizeof(precedence));
  }
  //--------
  pfcp_precedence_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::precedence_t& b) {
    b.precedence = precedence;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_precedence = htobe32(precedence);
    os.write(reinterpret_cast<const char*>(&be_precedence), sizeof(be_precedence));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(precedence)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&precedence), sizeof(precedence));
    precedence = be32toh(precedence);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::precedence_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE TRANSPORT_LEVEL_MARKING
class pfcp_transport_level_marking_ie : public pfcp_ie {
public:
  std::string transport_level_marking;

  //--------
  pfcp_transport_level_marking_ie(const core::pfcp::transport_level_marking_t& b) : pfcp_ie(PFCP_IE_TRANSPORT_LEVEL_MARKING){
    transport_level_marking = b.transport_level_marking;
    tlv.set_length(transport_level_marking.size());
  }
  //--------
  pfcp_transport_level_marking_ie() : pfcp_ie(PFCP_IE_TRANSPORT_LEVEL_MARKING){
    transport_level_marking = {};
    tlv.set_length(0);
  }
  //--------
  pfcp_transport_level_marking_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::transport_level_marking_t& b) {
    b.transport_level_marking = transport_level_marking;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    if (tlv.get_length() != 2) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    os << transport_level_marking;
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 2) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    char e[2];
    is.read(e, 2);
    transport_level_marking.assign(e, 2);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::transport_level_marking_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE VOLUME_THRESHOLD
class pfcp_volume_threshold_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t tovol :1;
      uint8_t ulvol :1;
      uint8_t dlvol :1;
      uint8_t spare :5;
   } bf;
   uint8_t b;
  } u1;
  uint64_t total_volume;
  uint64_t uplink_volume;
  uint64_t downlink_volume;
  //--------
  pfcp_volume_threshold_ie(const core::pfcp::volume_threshold_t& b) : pfcp_ie(PFCP_IE_VOLUME_THRESHOLD){
    tlv.set_length(1);
    u1.b = 0;
    u1.bf.tovol = b.tovol;
    u1.bf.ulvol = b.ulvol;
    u1.bf.dlvol = b.dlvol;
    if (u1.bf.tovol) {
      total_volume = b.total_volume;
      tlv.add_length(sizeof(total_volume));
    } else {
      total_volume = 0;
    }
    if (u1.bf.ulvol) {
      uplink_volume = b.uplink_volume;
      tlv.add_length(sizeof(uplink_volume));
    } else {
      uplink_volume = 0;
    }
    if (u1.bf.dlvol) {
      downlink_volume = b.downlink_volume;
      tlv.add_length(sizeof(downlink_volume));
    } else {
      downlink_volume = 0;
    }
  }
  //--------
  pfcp_volume_threshold_ie() : pfcp_ie(PFCP_IE_VOLUME_THRESHOLD){
    tlv.set_length(1);
    u1.b = 0;
    total_volume = 0;
    uplink_volume = 0;
    downlink_volume = 0;
  }
  //--------
  pfcp_volume_threshold_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::volume_threshold_t& b) {
    b = {};
    b.tovol = u1.bf.tovol;
    b.ulvol = u1.bf.ulvol;
    b.dlvol = u1.bf.dlvol;
    if (u1.bf.tovol) {
      b.total_volume = total_volume;
    }
    if (u1.bf.ulvol) {
      b.uplink_volume = uplink_volume;
    }
    if (u1.bf.dlvol) {
      b.downlink_volume = downlink_volume;
    }
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.set_length(1);
    if (u1.bf.tovol) {
      tlv.add_length(sizeof(total_volume));
    }
    if (u1.bf.ulvol) {
      tlv.add_length(sizeof(uplink_volume));
    }
    if (u1.bf.dlvol) {
      tlv.add_length(sizeof(downlink_volume));
    }

    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    if (u1.bf.tovol) {
      auto be_total_volume = htobe64(total_volume);
      os.write(reinterpret_cast<const char*>(&be_total_volume), sizeof(be_total_volume));
    }
    if (u1.bf.ulvol) {
      auto be_uplink_volume = htobe64(uplink_volume);
      os.write(reinterpret_cast<const char*>(&be_uplink_volume), sizeof(be_uplink_volume));
    }
    if (u1.bf.dlvol) {
      auto be_downlink_volume = htobe64(downlink_volume);
      os.write(reinterpret_cast<const char*>(&be_downlink_volume), sizeof(be_downlink_volume));
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() < 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    if (u1.bf.tovol) {
      is.read(reinterpret_cast<char*>(&total_volume), sizeof(total_volume));
      total_volume = be64toh(total_volume);
    }
    if (u1.bf.ulvol) {
      is.read(reinterpret_cast<char*>(&uplink_volume), sizeof(uplink_volume));
      total_volume = be64toh(uplink_volume);
    }
    if (u1.bf.dlvol) {
      is.read(reinterpret_cast<char*>(&downlink_volume), sizeof(downlink_volume));
      total_volume = be64toh(downlink_volume);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::volume_threshold_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE TIME_THRESHOLD
class pfcp_time_threshold_ie : public pfcp_ie {
public:
  uint32_t time_threshold;

  //--------
  pfcp_time_threshold_ie(const core::pfcp::time_threshold_t& b) : pfcp_ie(PFCP_IE_TIME_THRESHOLD){
    time_threshold = b.time_threshold;
    tlv.set_length(sizeof(time_threshold));
  }
  //--------
  pfcp_time_threshold_ie() : pfcp_ie(PFCP_IE_TIME_THRESHOLD){
    time_threshold = 0;
    tlv.set_length(sizeof(time_threshold));
  }
  //--------
  pfcp_time_threshold_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::time_threshold_t& b) {
    b.time_threshold = time_threshold;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_time_threshold = htobe32(time_threshold);
    os.write(reinterpret_cast<const char*>(&be_time_threshold), sizeof(be_time_threshold));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(time_threshold)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&time_threshold), sizeof(time_threshold));
    time_threshold = be32toh(time_threshold);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::time_threshold_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE MONITORING_TIME
class pfcp_monitoring_time_ie : public pfcp_ie {
public:
  uint32_t monitoring_time;

  //--------
  pfcp_monitoring_time_ie(const core::pfcp::monitoring_time_t& b) : pfcp_ie(PFCP_IE_MONITORING_TIME){
    monitoring_time = b.monitoring_time;
    tlv.set_length(sizeof(monitoring_time));
  }
  //--------
  pfcp_monitoring_time_ie() : pfcp_ie(PFCP_IE_MONITORING_TIME){
    monitoring_time = 0;
    tlv.set_length(sizeof(monitoring_time));
  }
  //--------
  pfcp_monitoring_time_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::monitoring_time_t& b) {
    b.monitoring_time = monitoring_time;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_monitoring_time = htobe32(monitoring_time);
    os.write(reinterpret_cast<const char*>(&be_monitoring_time), sizeof(be_monitoring_time));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(monitoring_time)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&monitoring_time), sizeof(monitoring_time));
    monitoring_time = be32toh(monitoring_time);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::monitoring_time_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE SUBSEQUENT_VOLUME_THRESHOLD
class pfcp_subsequent_volume_threshold_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t tovol :1;
      uint8_t ulvol :1;
      uint8_t dlvol :1;
      uint8_t spare :5;
   } bf;
   uint8_t b;
  } u1;
  uint64_t total_volume;
  uint64_t uplink_volume;
  uint64_t downlink_volume;
  //--------
  pfcp_subsequent_volume_threshold_ie(const core::pfcp::subsequent_volume_threshold_t& b) : pfcp_ie(PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD){
    tlv.set_length(1);
    u1.b = 0;
    u1.bf.tovol = b.tovol;
    u1.bf.ulvol = b.ulvol;
    u1.bf.dlvol = b.dlvol;
    if (u1.bf.tovol) {
      total_volume = b.total_volume;
      tlv.add_length(sizeof(total_volume));
    } else {
      total_volume = 0;
    }
    if (u1.bf.ulvol) {
      uplink_volume = b.uplink_volume;
      tlv.add_length(sizeof(uplink_volume));
    } else {
      uplink_volume = 0;
    }
    if (u1.bf.dlvol) {
      downlink_volume = b.downlink_volume;
      tlv.add_length(sizeof(downlink_volume));
    } else {
      downlink_volume = 0;
    }
  }
  //--------
  pfcp_subsequent_volume_threshold_ie() : pfcp_ie(PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD){
    tlv.set_length(1);
    u1.b = 0;
    total_volume = 0;
    uplink_volume = 0;
    downlink_volume = 0;
  }
  //--------
  pfcp_subsequent_volume_threshold_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::subsequent_volume_threshold_t& b) {
    b = {};
    b.tovol = u1.bf.tovol;
    b.ulvol = u1.bf.ulvol;
    b.dlvol = u1.bf.dlvol;
    if (u1.bf.tovol) {
      b.total_volume = total_volume;
    }
    if (u1.bf.ulvol) {
      b.uplink_volume = uplink_volume;
    }
    if (u1.bf.dlvol) {
      b.downlink_volume = downlink_volume;
    }
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.set_length(1);
    if (u1.bf.tovol) {
      tlv.add_length(sizeof(total_volume));
    }
    if (u1.bf.ulvol) {
      tlv.add_length(sizeof(uplink_volume));
    }
    if (u1.bf.dlvol) {
      tlv.add_length(sizeof(downlink_volume));
    }

    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    if (u1.bf.tovol) {
      auto be_total_volume = htobe64(total_volume);
      os.write(reinterpret_cast<const char*>(&be_total_volume), sizeof(be_total_volume));
    }
    if (u1.bf.ulvol) {
      auto be_uplink_volume = htobe64(uplink_volume);
      os.write(reinterpret_cast<const char*>(&be_uplink_volume), sizeof(be_uplink_volume));
    }
    if (u1.bf.dlvol) {
      auto be_downlink_volume = htobe64(downlink_volume);
      os.write(reinterpret_cast<const char*>(&be_downlink_volume), sizeof(be_downlink_volume));
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() < 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    if (u1.bf.tovol) {
      is.read(reinterpret_cast<char*>(&total_volume), sizeof(total_volume));
      total_volume = be64toh(total_volume);
    }
    if (u1.bf.ulvol) {
      is.read(reinterpret_cast<char*>(&uplink_volume), sizeof(uplink_volume));
      total_volume = be64toh(uplink_volume);
    }
    if (u1.bf.dlvol) {
      is.read(reinterpret_cast<char*>(&downlink_volume), sizeof(downlink_volume));
      total_volume = be64toh(downlink_volume);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::subsequent_volume_threshold_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE SUBSEQUENT_TIME_THRESHOLD
class pfcp_subsequent_time_threshold_ie : public pfcp_ie {
public:
  uint32_t subsequent_time_threshold;

  //--------
  pfcp_subsequent_time_threshold_ie(const core::pfcp::subsequent_time_threshold_t& b) : pfcp_ie(PFCP_IE_SUBSEQUENT_TIME_THRESHOLD){
    subsequent_time_threshold = b.subsequent_time_threshold;
    tlv.set_length(sizeof(subsequent_time_threshold));
  }
  //--------
  pfcp_subsequent_time_threshold_ie() : pfcp_ie(PFCP_IE_SUBSEQUENT_TIME_THRESHOLD){
    subsequent_time_threshold = 0;
    tlv.set_length(sizeof(subsequent_time_threshold));
  }
  //--------
  pfcp_subsequent_time_threshold_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::subsequent_time_threshold_t& b) {
    b.subsequent_time_threshold = subsequent_time_threshold;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_subsequent_time_threshold = htobe32(subsequent_time_threshold);
    os.write(reinterpret_cast<const char*>(&be_subsequent_time_threshold), sizeof(be_subsequent_time_threshold));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(subsequent_time_threshold)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&subsequent_time_threshold), sizeof(subsequent_time_threshold));
    subsequent_time_threshold = be32toh(subsequent_time_threshold);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::subsequent_time_threshold_t subsequent_time_threshold = {};
      to_core_type(subsequent_time_threshold);
      s.set(subsequent_time_threshold);
  }
};
//-------------------------------------
// IE INACTIVITY_DETECTION_TIME
class pfcp_inactivity_detection_time_ie : public pfcp_ie {
public:
  uint32_t inactivity_detection_time;

  //--------
  pfcp_inactivity_detection_time_ie(const core::pfcp::inactivity_detection_time_t& b) : pfcp_ie(PFCP_IE_INACTIVITY_DETECTION_TIME){
    inactivity_detection_time = b.inactivity_detection_time;
    tlv.set_length(sizeof(inactivity_detection_time));
  }
  //--------
  pfcp_inactivity_detection_time_ie() : pfcp_ie(PFCP_IE_INACTIVITY_DETECTION_TIME){
    inactivity_detection_time = 0;
    tlv.set_length(sizeof(inactivity_detection_time));
  }
  //--------
  pfcp_inactivity_detection_time_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::inactivity_detection_time_t& b) {
    b.inactivity_detection_time = inactivity_detection_time;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_inactivity_detection_time = htobe32(inactivity_detection_time);
    os.write(reinterpret_cast<const char*>(&be_inactivity_detection_time), sizeof(be_inactivity_detection_time));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(inactivity_detection_time)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&inactivity_detection_time), sizeof(inactivity_detection_time));
    inactivity_detection_time = be32toh(inactivity_detection_time);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::inactivity_detection_time_t inactivity_detection_time = {};
      to_core_type(inactivity_detection_time);
      s.set(inactivity_detection_time);
  }
};
//-------------------------------------
// IE REPORTING_TRIGGERS
class pfcp_reporting_triggers_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t perio:1;
      uint8_t volth:1;
      uint8_t timth:1;
      uint8_t quhti:1;
      uint8_t start:1;
      uint8_t stop:1;
      uint8_t droth:1;
      uint8_t liusa:1;
   } bf;
   uint8_t b;
  } u1;
  union {
    struct {
      uint8_t volqu:1;
      uint8_t timqu:1;
      uint8_t envcl:1;
      uint8_t macar:1;
      uint8_t eveth:1;
      uint8_t spare:3;
   } bf;
   uint8_t b;
  } u2;

  //--------
  pfcp_reporting_triggers_ie(const core::pfcp::reporting_triggers_t& b) : pfcp_ie(PFCP_IE_REPORTING_TRIGGERS){
    u1.b = 0;
    u2.b = 0;
    tlv.set_length(2);
    u1.bf.liusa = b.liusa;
    u1.bf.droth = b.droth;
    u1.bf.stop = b.stop;
    u1.bf.start = b.start;
    u1.bf.quhti = b.quhti;
    u1.bf.timth = b.timth;
    u1.bf.volth = b.volth;
    u1.bf.perio = b.perio;

    u2.bf.eveth = b.eveth;
    u2.bf.macar = b.macar;
    u2.bf.envcl = b.envcl;
    u2.bf.timqu = b.timqu;
    u2.bf.volqu = b.volqu;
  }
  //--------
  pfcp_reporting_triggers_ie() : pfcp_ie(PFCP_IE_REPORTING_TRIGGERS){
    u1.b = 0;
    u2.b = 0;
    tlv.set_length(2);
  }
  //--------
  pfcp_reporting_triggers_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::reporting_triggers_t& b) {
    b.liusa = u1.bf.liusa;
    b.droth = u1.bf.droth;
    b.stop = u1.bf.stop;
    b.start = u1.bf.start;
    b.quhti = u1.bf.quhti;
    b.timth = u1.bf.timth;
    b.volth = u1.bf.volth;
    b.perio = u1.bf.perio;

    b.eveth = u2.bf.eveth;
    b.macar = u2.bf.macar;
    b.envcl = u2.bf.envcl;
    b.timqu = u2.bf.timqu;
    b.volqu = u2.bf.volqu;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.set_length(2);
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    os.write(reinterpret_cast<const char*>(&u2.b), sizeof(u2.b));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 2) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    is.read(reinterpret_cast<char*>(&u2.b), sizeof(u2.b));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::reporting_triggers_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE REDIRECT_INFORMATION
//class pfcp_redirect_information_ie : public pfcp_ie {
//public:
//  union {
//    struct {
//      uint8_t redirect_address_type:4;
//      uint8_t spare:4;
//   } bf;
//   uint8_t b;
//  } u1;
//  uint16_t redirect_server_address_length;
//  std::string
//  //--------
//  pfcp_redirect_information_ie(const core::pfcp::redirect_information_t& b) : pfcp_ie(PFCP_IE_REDIRECT_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_redirect_information_ie() : pfcp_ie(PFCP_IE_REDIRECT_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_redirect_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::redirect_information_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::redirect_information_t redirect_information = {};
//      to_core_type(redirect_information);
//      s.set(redirect_information);
//  }
//};
////-------------------------------------
//// IE REPORT_TYPE
//class pfcp_report_type_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_report_type_ie(const core::pfcp::report_type_t& b) : pfcp_ie(PFCP_IE_REPORT_TYPE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_report_type_ie() : pfcp_ie(PFCP_IE_REPORT_TYPE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_report_type_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::report_type_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::report_type_t report_type = {};
//      to_core_type(report_type);
//      s.set(report_type);
//  }
//};
////-------------------------------------
//// IE OFFENDING_IE
//class pfcp_offending_ie_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_offending_ie_ie(const core::pfcp::offending_ie_t& b) : pfcp_ie(PFCP_IE_OFFENDING_IE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_offending_ie_ie() : pfcp_ie(PFCP_IE_OFFENDING_IE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_offending_ie_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::offending_ie_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::offending_ie_t offending_ie = {};
//      to_core_type(offending_ie);
//      s.set(offending_ie);
//  }
//};
//-------------------------------------
// IE FORWARDING_POLICY
class pfcp_forwarding_policy_ie : public pfcp_ie {
public:
  uint8_t forwarding_policy_identifier_length;
  std::string forwarding_policy_identifier; // max length 255 bytes

  //--------
  pfcp_forwarding_policy_ie(const core::pfcp::forwarding_policy_t& b) : pfcp_ie(PFCP_IE_FORWARDING_POLICY){
    forwarding_policy_identifier_length = b.forwarding_policy_identifier_length;
    forwarding_policy_identifier = b.forwarding_policy_identifier;
    tlv.set_length(1 + forwarding_policy_identifier.size());
  }
  //--------
  pfcp_forwarding_policy_ie() : pfcp_ie(PFCP_IE_FORWARDING_POLICY){
    forwarding_policy_identifier_length = 0;
    forwarding_policy_identifier = {};
    tlv.set_length(1);
  }
  //--------
  pfcp_forwarding_policy_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::forwarding_policy_t& b) {
    b.forwarding_policy_identifier_length = forwarding_policy_identifier_length;
    b.forwarding_policy_identifier = forwarding_policy_identifier;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&forwarding_policy_identifier_length), sizeof(forwarding_policy_identifier_length));
    os << forwarding_policy_identifier;
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() < 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&forwarding_policy_identifier_length), sizeof(forwarding_policy_identifier_length));
    if (tlv.get_length() != (1+forwarding_policy_identifier_length)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    char e[forwarding_policy_identifier_length];
    is.read(e, forwarding_policy_identifier_length);
    forwarding_policy_identifier.assign(e, forwarding_policy_identifier_length);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::forwarding_policy_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE DESTINATION_INTERFACE
class pfcp_destination_interface_ie : public pfcp_ie {
public:
  uint8_t  interface_value;

  //--------
  pfcp_destination_interface_ie(const core::pfcp::destination_interface_t& b) : pfcp_ie(PFCP_IE_DESTINATION_INTERFACE){
    interface_value = b.interface_value;
    tlv.set_length(1);
  }
  //--------
  pfcp_destination_interface_ie() : pfcp_ie(PFCP_IE_DESTINATION_INTERFACE){
    interface_value = 255;
    tlv.set_length(1);
  }
  //--------
  pfcp_destination_interface_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    interface_value = 255;
  };
  //--------
  void to_core_type(core::pfcp::destination_interface_t& b) {
    b.interface_value = interface_value;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&interface_value), sizeof(interface_value));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&interface_value), sizeof(interface_value));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::destination_interface_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE UP_FUNCTION_FEATURES
class pfcp_up_function_features_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t bucp:1;
      uint8_t ddnd:1;
      uint8_t dlbd:1;
      uint8_t trst:1;
      uint8_t ftup:1;
      uint8_t pfdm:1;
      uint8_t heeu:1;
      uint8_t treu:1;
   } bf;
   uint8_t b;
  } u1;
  union {
    struct {
      uint8_t empu:1;
      uint8_t pdiu:1;
      uint8_t udbc:1;
      uint8_t quoac:1;
      uint8_t trace:1;
      uint8_t frrt:1;
      uint8_t spare:2;
   } bf;
   uint8_t b;
  } u2;


  //--------
  pfcp_up_function_features_ie(const core::pfcp::up_function_features_t& b) : pfcp_ie(PFCP_IE_UP_FUNCTION_FEATURES){
    u2.b = 0;
    u1.bf.bucp = b.bucp;
    u1.bf.ddnd = b.ddnd;
    u1.bf.dlbd = b.dlbd;
    u1.bf.trst = b.trst;
    u1.bf.ftup = b.ftup;
    u1.bf.pfdm = b.pfdm;
    u1.bf.heeu = b.heeu;
    u1.bf.treu = b.treu;

    u2.bf.empu = b.empu;
    u2.bf.pdiu = b.pdiu;
    u2.bf.udbc = b.udbc;
    u2.bf.quoac = b.quoac;
    u2.bf.trace = b.trace;
    u2.bf.frrt = b.frrt;
    tlv.set_length(2);
  }
  //--------
  pfcp_up_function_features_ie() : pfcp_ie(PFCP_IE_UP_FUNCTION_FEATURES){
    u1.b = 0;
    u2.b = 0;
    tlv.set_length(2);
  }
  //--------
  pfcp_up_function_features_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    u1.b = 0;
    u2.b = 0;
  };
  //--------
  void to_core_type(core::pfcp::up_function_features_t& b) {
    b.bucp = u1.bf.bucp;
    b.ddnd = u1.bf.ddnd;
    b.dlbd = u1.bf.dlbd;
    b.trst = u1.bf.trst;
    b.ftup = u1.bf.ftup;
    b.pfdm = u1.bf.pfdm;
    b.heeu = u1.bf.heeu;
    b.treu = u1.bf.treu;

    b.empu = u2.bf.empu;
    b.pdiu = u2.bf.pdiu;
    b.udbc = u2.bf.udbc;
    b.quoac = u2.bf.quoac;
    b.trace = u2.bf.trace;
    b.frrt = u2.bf.frrt;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.set_length(2);
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    os.write(reinterpret_cast<const char*>(&u2.b), sizeof(u2.b));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 2) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    is.read(reinterpret_cast<char*>(&u2.b), sizeof(u2.b));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::up_function_features_t up_function_features = {};
      to_core_type(up_function_features);
      s.set(up_function_features);
  }
};
//-------------------------------------
// IE APPLY_ACTION
class pfcp_apply_action_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t drop:1;
      uint8_t forw:1;
      uint8_t buff:1;
      uint8_t nocp:1;
      uint8_t dupl:1;
      uint8_t spare:3;
   } bf;
   uint8_t b;
  } u1;

  //--------
  pfcp_apply_action_ie(const core::pfcp::apply_action_t& b) : pfcp_ie(PFCP_IE_APPLY_ACTION){
    tlv.set_length(1);
    u1.b = 0;
    u1.bf.drop = b.drop;
    u1.bf.forw = b.forw;
    u1.bf.buff = b.buff;
    u1.bf.nocp = b.nocp;
    u1.bf.dupl = b.dupl;
  }
  //--------
  pfcp_apply_action_ie() : pfcp_ie(PFCP_IE_APPLY_ACTION){
    u1.b = 0;
    tlv.set_length(1);
  }
  //--------
  pfcp_apply_action_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    u1.b = 0;
  };
  //--------
  void to_core_type(core::pfcp::apply_action_t& b) {
    b.drop = u1.bf.drop;
    b.forw = u1.bf.forw;
    b.buff = u1.bf.buff;
    b.nocp = u1.bf.nocp;
    b.dupl = u1.bf.dupl;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::apply_action_t apply_action = {};
      to_core_type(apply_action);
      s.set(apply_action);
  }
};
////-------------------------------------
//// IE DOWNLINK_DATA_SERVICE_INFORMATION
//class pfcp_downlink_data_service_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_downlink_data_service_information_ie(const core::pfcp::downlink_data_service_information_t& b) : pfcp_ie(PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_downlink_data_service_information_ie() : pfcp_ie(PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_downlink_data_service_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::downlink_data_service_information_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::downlink_data_service_information_t downlink_data_service_information = {};
//      to_core_type(downlink_data_service_information);
//      s.set(downlink_data_service_information);
//  }
//};
////-------------------------------------
//// IE DOWNLINK_DATA_NOTIFICATION_DELAY
//class pfcp_downlink_data_notification_delay_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_downlink_data_notification_delay_ie(const core::pfcp::downlink_data_notification_delay_t& b) : pfcp_ie(PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_downlink_data_notification_delay_ie() : pfcp_ie(PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_downlink_data_notification_delay_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::downlink_data_notification_delay_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::downlink_data_notification_delay_t downlink_data_notification_delay = {};
//      to_core_type(downlink_data_notification_delay);
//      s.set(downlink_data_notification_delay);
//  }
//};
////-------------------------------------
//// IE DL_BUFFERING_DURATION
//class pfcp_dl_buffering_duration_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_dl_buffering_duration_ie(const core::pfcp::dl_buffering_duration_t& b) : pfcp_ie(PFCP_IE_DL_BUFFERING_DURATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_dl_buffering_duration_ie() : pfcp_ie(PFCP_IE_DL_BUFFERING_DURATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_dl_buffering_duration_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::dl_buffering_duration_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::dl_buffering_duration_t dl_buffering_duration = {};
//      to_core_type(dl_buffering_duration);
//      s.set(dl_buffering_duration);
//  }
//};
////-------------------------------------
//// IE DL_BUFFERING_SUGGESTED_PACKET_COUNT
//class pfcp_dl_buffering_suggested_packet_count_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_dl_buffering_suggested_packet_count_ie(const core::pfcp::dl_buffering_suggested_packet_count_t& b) : pfcp_ie(PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_dl_buffering_suggested_packet_count_ie() : pfcp_ie(PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_dl_buffering_suggested_packet_count_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::dl_buffering_suggested_packet_count_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::dl_buffering_suggested_packet_count_t dl_buffering_suggested_packet_count = {};
//      to_core_type(dl_buffering_suggested_packet_count);
//      s.set(dl_buffering_suggested_packet_count);
//  }
//};
////-------------------------------------
//// IE PFCPSMREQ_FLAGS
//class pfcp_pfcpsmreq_flags_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_pfcpsmreq_flags_ie(const core::pfcp::pfcpsmreq_flags_t& b) : pfcp_ie(PFCP_IE_PFCPSMREQ_FLAGS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfcpsmreq_flags_ie() : pfcp_ie(PFCP_IE_PFCPSMREQ_FLAGS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfcpsmreq_flags_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::pfcpsmreq_flags_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::pfcpsmreq_flags_t pfcpsmreq_flags = {};
//      to_core_type(pfcpsmreq_flags);
//      s.set(pfcpsmreq_flags);
//  }
//};
////-------------------------------------
//// IE PFCPSRRSP_FLAGS
//class pfcp_pfcpsrrsp_flags_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_pfcpsrrsp_flags_ie(const core::pfcp::pfcpsrrsp_flags_t& b) : pfcp_ie(PFCP_IE_PFCPSRRSP_FLAGS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfcpsrrsp_flags_ie() : pfcp_ie(PFCP_IE_PFCPSRRSP_FLAGS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfcpsrrsp_flags_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::pfcpsrrsp_flags_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::pfcpsrrsp_flags_t pfcpsrrsp_flags = {};
//      to_core_type(pfcpsrrsp_flags);
//      s.set(pfcpsrrsp_flags);
//  }
//};
////-------------------------------------
//// IE LOAD_CONTROL_INFORMATION
//class pfcp_load_control_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_load_control_information_ie(const core::pfcp::load_control_information& b) : pfcp_ie(PFCP_IE_LOAD_CONTROL_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_load_control_information_ie() : pfcp_ie(PFCP_IE_LOAD_CONTROL_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_load_control_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::load_control_information& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::load_control_information load_control_information = {};
//      to_core_type(load_control_information);
//      s.set(load_control_information);
//  }
//};
////-------------------------------------
//// IE SEQUENCE_NUMBER
//class pfcp_sequence_number_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_sequence_number_ie(const core::pfcp::sequence_number_t& b) : pfcp_ie(PFCP_IE_SEQUENCE_NUMBER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_sequence_number_ie() : pfcp_ie(PFCP_IE_SEQUENCE_NUMBER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_sequence_number_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::sequence_number_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::sequence_number_t sequence_number = {};
//      to_core_type(sequence_number);
//      s.set(sequence_number);
//  }
//};
////-------------------------------------
//// IE METRIC
//class pfcp_metric_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_metric_ie(const core::pfcp::metric_t& b) : pfcp_ie(PFCP_IE_METRIC){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_metric_ie() : pfcp_ie(PFCP_IE_METRIC){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_metric_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::metric_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::metric_t metric = {};
//      to_core_type(metric);
//      s.set(metric);
//  }
//};
////-------------------------------------
//// IE OVERLOAD_CONTROL_INFORMATION
//class pfcp_overload_control_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_overload_control_information_ie(const core::pfcp::overload_control_information& b) : pfcp_ie(PFCP_IE_OVERLOAD_CONTROL_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_overload_control_information_ie() : pfcp_ie(PFCP_IE_OVERLOAD_CONTROL_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_overload_control_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::overload_control_information& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::overload_control_information overload_control_information = {};
//      to_core_type(overload_control_information);
//      s.set(overload_control_information);
//  }
//};
////-------------------------------------
//// IE TIMER
//class pfcp_timer_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_timer_ie(const core::pfcp::timer_t& b) : pfcp_ie(PFCP_IE_TIMER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_timer_ie() : pfcp_ie(PFCP_IE_TIMER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_timer_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::timer_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::timer_t timer = {};
//      to_core_type(timer);
//      s.set(timer);
//  }
//};
//-------------------------------------
// IE PACKET_DETECTION_RULE_ID PDR_ID
class pfcp_pdr_id_ie : public pfcp_ie {
public:
  uint16_t rule_id;

  //--------
  pfcp_pdr_id_ie(const core::pfcp::pdr_id_t& b) : pfcp_ie(PFCP_IE_PACKET_DETECTION_RULE_ID){
    rule_id = b.rule_id;
    tlv.set_length(sizeof(rule_id));
  }
  //--------
  pfcp_pdr_id_ie() : pfcp_ie(PFCP_IE_PACKET_DETECTION_RULE_ID){
    rule_id = 0;
    tlv.set_length(sizeof(rule_id));
  }
  //--------
  pfcp_pdr_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::pdr_id_t& b) {
    b.rule_id = rule_id;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_rule_id = htobe16(rule_id);
    os.write(reinterpret_cast<const char*>(&be_rule_id), sizeof(be_rule_id));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(rule_id)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&rule_id), sizeof(rule_id));
    rule_id = be16toh(rule_id);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::pdr_id_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE F_SEID
class pfcp_f_seid_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t  v6:1;
      uint8_t  v4:1;
      uint8_t  spare :6;
    } bf;
    uint8_t b;
  } u1;
  uint64_t seid;
  struct in_addr  ipv4_address;
  struct in6_addr ipv6_address;

  //--------
  pfcp_f_seid_ie(const core::pfcp::fseid_t& b) : pfcp_ie(PFCP_IE_F_SEID){
    u1.b = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    tlv.set_length(9);
    u1.bf.v4 = b.v4;
    u1.bf.v6 = b.v6;
    seid = b.seid;
    if (u1.bf.v4) {
      tlv.add_length(4);
      ipv4_address = b.ipv4_address;
    }
    if (u1.bf.v6) {
      tlv.add_length(16);
      ipv6_address = b.ipv6_address;
    }
  }
  //--------
  pfcp_f_seid_ie() : pfcp_ie(PFCP_IE_F_SEID){
    u1.b = 0;
    seid = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    tlv.set_length(9);
  }
  //--------
  pfcp_f_seid_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::fseid_t& b) {
    b = {};
    b.v4 = u1.bf.v4;
    b.v6 = u1.bf.v6;
    b.seid = seid;
    if (u1.bf.v4) {
      b.ipv4_address = ipv4_address;
    }
    if (u1.bf.v6) {
      b.ipv6_address = ipv6_address;
    }

  }
  //--------
  void dump_to(std::ostream& os) {
    uint16_t check_length = 9;
    if (u1.bf.v4) check_length += 4;
    if (u1.bf.v6) check_length += 16;
    tlv.set_length(check_length);
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    auto be_seid = htobe64(seid);
    os.write(reinterpret_cast<const char*>(&be_seid), sizeof(be_seid));
    if (u1.bf.v4) {
      ipv4_address_dump_to(os, ipv4_address);
    }
    if (u1.bf.v6) {
      ipv6_address_dump_to(os, ipv6_address);
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    uint16_t check_length = 9;
    if (u1.bf.v4) check_length += 4;
    if (u1.bf.v6) check_length += 16;
    if (tlv.get_length() != check_length) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&seid), sizeof(seid));
    seid = be64toh(seid);
    if (u1.bf.v4) {
      ipv4_address_load_from(is, ipv4_address);
    }
    if (u1.bf.v6) {
      ipv6_address_load_from(is, ipv6_address);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::fseid_t f_seid = {};
      to_core_type(f_seid);
      s.set(f_seid);
  }
};
////-------------------------------------
//// IE APPLICATION_IDS_PFDS
//class pfcp_application_ids_pfds_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_application_ids_pfds_ie(const core::pfcp::application_ids_pfds& b) : pfcp_ie(PFCP_IE_APPLICATION_IDS_PFDS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_application_ids_pfds_ie() : pfcp_ie(PFCP_IE_APPLICATION_IDS_PFDS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_application_ids_pfds_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::application_ids_pfds& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::application_ids_pfds application_ids_pfds = {};
//      to_core_type(application_ids_pfds);
//      s.set(application_ids_pfds);
//  }
//};
////-------------------------------------
//// IE PFD
//class pfcp_pfd_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_pfd_ie(const core::pfcp::pfd& b) : pfcp_ie(PFCP_IE_PFD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfd_ie() : pfcp_ie(PFCP_IE_PFD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfd_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::pfd& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::pfd pfd = {};
//      to_core_type(pfd);
//      s.set(pfd);
//  }
//};
//-------------------------------------
// IE NODE_ID
class pfcp_node_id_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t node_id_type :4;
      uint8_t spare1 :4;
   } bf;
   uint8_t b;
  } u1;

  struct in_addr  ipv4_address;
  struct in6_addr ipv6_address;
  std::string fqdn;

  //--------
  pfcp_node_id_ie(const core::pfcp::node_id_t& b) : pfcp_ie(PFCP_IE_NODE_ID){
    u1.b = 0;
    tlv.set_length(1);
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    fqdn = {};

    u1.bf.node_id_type = b.node_id_type;
    switch (u1.bf.node_id_type) {
    case core::pfcp::NODE_ID_TYPE_IPV4_ADDRESS:
      tlv.add_length(4);
      ipv4_address = b.u1.ipv4_address;
      break;
    case core::pfcp::NODE_ID_TYPE_IPV6_ADDRESS:
      tlv.add_length(16);
      ipv6_address = b.u1.ipv6_address;
      break;
    case core::pfcp::NODE_ID_TYPE_FQDN:
      tlv.add_length(sizeof(b.fqdn));
      fqdn = b.fqdn;
      break;
    default:;
    }
  }
  //--------
  pfcp_node_id_ie() : pfcp_ie(PFCP_IE_NODE_ID){
    u1.b = 0;
    tlv.set_length(1);
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    fqdn = {};
  }
  //--------
  pfcp_node_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::node_id_t& b) {
    b.node_id_type = u1.bf.node_id_type;
    switch (u1.bf.node_id_type) {
    case core::pfcp::NODE_ID_TYPE_IPV4_ADDRESS:
      b.u1.ipv4_address = ipv4_address;
      break;
    case core::pfcp::NODE_ID_TYPE_IPV6_ADDRESS:
      b.u1.ipv6_address = ipv6_address;
      break;
    case core::pfcp::NODE_ID_TYPE_FQDN:
      b.fqdn = fqdn;
      break;
    default:
      ;
    }
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    switch (u1.bf.node_id_type) {
    case core::pfcp::NODE_ID_TYPE_IPV4_ADDRESS:
      ipv4_address_dump_to(os, ipv4_address);
      break;
    case core::pfcp::NODE_ID_TYPE_IPV6_ADDRESS:
      ipv6_address_dump_to(os, ipv6_address);
      break;
    case core::pfcp::NODE_ID_TYPE_FQDN:
      os << fqdn;
      break;
    default:
      ;
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    uint16_t check_length = tlv.get_length() - 1;
    switch (u1.bf.node_id_type) {
    case core::pfcp::NODE_ID_TYPE_IPV4_ADDRESS:
      if (check_length != 4) {
        throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
      }
      ipv4_address_load_from(is, ipv4_address);
      break;
    case core::pfcp::NODE_ID_TYPE_IPV6_ADDRESS:
      if (check_length != 16) {
        throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
      }
      ipv6_address_load_from(is, ipv6_address);
      break;
    case core::pfcp::NODE_ID_TYPE_FQDN: {
        if (check_length == 0) {
          throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
        }
        char e[check_length];
        is.read(e, check_length);
        fqdn.assign(e, check_length);
      }
      break;
    default:
      ;
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::node_id_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE PFD_CONTENTS
//class pfcp_pfd_contents_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_pfd_contents_ie(const core::pfcp::pfd_contents_t& b) : pfcp_ie(PFCP_IE_PFD_CONTENTS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfd_contents_ie() : pfcp_ie(PFCP_IE_PFD_CONTENTS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfd_contents_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::pfd_contents_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::pfd_contents_t pfd_contents = {};
//      to_core_type(pfd_contents);
//      s.set(pfd_contents);
//  }
//};
////-------------------------------------
//// IE MEASUREMENT_METHOD
//class pfcp_measurement_method_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_measurement_method_ie(const core::pfcp::measurement_method_t& b) : pfcp_ie(PFCP_IE_MEASUREMENT_METHOD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_measurement_method_ie() : pfcp_ie(PFCP_IE_MEASUREMENT_METHOD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_measurement_method_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::measurement_method_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::measurement_method_t measurement_method = {};
//      to_core_type(measurement_method);
//      s.set(measurement_method);
//  }
//};
////-------------------------------------
//// IE USAGE_REPORT_TRIGGER
//class pfcp_usage_report_trigger_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_usage_report_trigger_ie(const core::pfcp::usage_report_trigger_t& b) : pfcp_ie(PFCP_IE_USAGE_REPORT_TRIGGER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_report_trigger_ie() : pfcp_ie(PFCP_IE_USAGE_REPORT_TRIGGER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_report_trigger_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::usage_report_trigger_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::usage_report_trigger_t usage_report_trigger = {};
//      to_core_type(usage_report_trigger);
//      s.set(usage_report_trigger);
//  }
//};
////-------------------------------------
//// IE MEASUREMENT_PERIOD
//class pfcp_measurement_period_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_measurement_period_ie(const core::pfcp::measurement_period_t& b) : pfcp_ie(PFCP_IE_MEASUREMENT_PERIOD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_measurement_period_ie() : pfcp_ie(PFCP_IE_MEASUREMENT_PERIOD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_measurement_period_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::measurement_period_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::measurement_period_t measurement_period = {};
//      to_core_type(measurement_period);
//      s.set(measurement_period);
//  }
//};
////-------------------------------------
//// IE FQ_CSID
//class pfcp_fq_csid_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_fq_csid_ie(const core::pfcp::fq_csid_t& b) : pfcp_ie(PFCP_IE_FQ_CSID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_fq_csid_ie() : pfcp_ie(PFCP_IE_FQ_CSID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_fq_csid_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::fq_csid_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::fq_csid_t fq_csid = {};
//      to_core_type(fq_csid);
//      s.set(fq_csid);
//  }
//};
////-------------------------------------
//// IE VOLUME_MEASUREMENT
//class pfcp_volume_measurement_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_volume_measurement_ie(const core::pfcp::volume_measurement_t& b) : pfcp_ie(PFCP_IE_VOLUME_MEASUREMENT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_volume_measurement_ie() : pfcp_ie(PFCP_IE_VOLUME_MEASUREMENT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_volume_measurement_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::volume_measurement_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::volume_measurement_t volume_measurement = {};
//      to_core_type(volume_measurement);
//      s.set(volume_measurement);
//  }
//};
////-------------------------------------
//// IE DURATION_MEASUREMENT
//class pfcp_duration_measurement_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_duration_measurement_ie(const core::pfcp::duration_measurement_t& b) : pfcp_ie(PFCP_IE_DURATION_MEASUREMENT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_duration_measurement_ie() : pfcp_ie(PFCP_IE_DURATION_MEASUREMENT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_duration_measurement_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::duration_measurement_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::duration_measurement_t duration_measurement = {};
//      to_core_type(duration_measurement);
//      s.set(duration_measurement);
//  }
//};
////-------------------------------------
//// IE APPLICATION_DETECTION_INFORMATION
//class pfcp_application_detection_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_application_detection_information_ie(const core::pfcp::application_detection_information& b) : pfcp_ie(PFCP_IE_APPLICATION_DETECTION_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_application_detection_information_ie() : pfcp_ie(PFCP_IE_APPLICATION_DETECTION_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_application_detection_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::application_detection_information& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::application_detection_information application_detection_information = {};
//      to_core_type(application_detection_information);
//      s.set(application_detection_information);
//  }
//};
////-------------------------------------
//// IE TIME_OF_FIRST_PACKET
//class pfcp_time_of_first_packet_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_time_of_first_packet_ie(const core::pfcp::time_of_first_packet_t& b) : pfcp_ie(PFCP_IE_TIME_OF_FIRST_PACKET){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_time_of_first_packet_ie() : pfcp_ie(PFCP_IE_TIME_OF_FIRST_PACKET){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_time_of_first_packet_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::time_of_first_packet_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::time_of_first_packet_t time_of_first_packet = {};
//      to_core_type(time_of_first_packet);
//      s.set(time_of_first_packet);
//  }
//};
////-------------------------------------
//// IE TIME_OF_LAST_PACKET
//class pfcp_time_of_last_packet_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_time_of_last_packet_ie(const core::pfcp::time_of_last_packet_t& b) : pfcp_ie(PFCP_IE_TIME_OF_LAST_PACKET){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_time_of_last_packet_ie() : pfcp_ie(PFCP_IE_TIME_OF_LAST_PACKET){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_time_of_last_packet_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::time_of_last_packet_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::time_of_last_packet_t time_of_last_packet = {};
//      to_core_type(time_of_last_packet);
//      s.set(time_of_last_packet);
//  }
//};
////-------------------------------------
//// IE QUOTA_HOLDING_TIME
//class pfcp_quota_holding_time_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_quota_holding_time_ie(const core::pfcp::quota_holding_time_t& b) : pfcp_ie(PFCP_IE_QUOTA_HOLDING_TIME){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_quota_holding_time_ie() : pfcp_ie(PFCP_IE_QUOTA_HOLDING_TIME){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_quota_holding_time_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::quota_holding_time_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::quota_holding_time_t quota_holding_time = {};
//      to_core_type(quota_holding_time);
//      s.set(quota_holding_time);
//  }
//};
////-------------------------------------
//// IE DROPPED_DL_TRAFFIC_THRESHOLD
//class pfcp_dropped_dl_traffic_threshold_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_dropped_dl_traffic_threshold_ie(const core::pfcp::dropped_dl_traffic_threshold_t& b) : pfcp_ie(PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_dropped_dl_traffic_threshold_ie() : pfcp_ie(PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_dropped_dl_traffic_threshold_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::dropped_dl_traffic_threshold_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::dropped_dl_traffic_threshold_t dropped_dl_traffic_threshold = {};
//      to_core_type(dropped_dl_traffic_threshold);
//      s.set(dropped_dl_traffic_threshold);
//  }
//};
////-------------------------------------
//// IE VOLUME_QUOTA
//class pfcp_volume_quota_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_volume_quota_ie(const core::pfcp::volume_quota_t& b) : pfcp_ie(PFCP_IE_VOLUME_QUOTA){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_volume_quota_ie() : pfcp_ie(PFCP_IE_VOLUME_QUOTA){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_volume_quota_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::volume_quota_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::volume_quota_t volume_quota = {};
//      to_core_type(volume_quota);
//      s.set(volume_quota);
//  }
//};
////-------------------------------------
//// IE TIME_QUOTA
//class pfcp_time_quota_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_time_quota_ie(const core::pfcp::time_quota_t& b) : pfcp_ie(PFCP_IE_TIME_QUOTA){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_time_quota_ie() : pfcp_ie(PFCP_IE_TIME_QUOTA){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_time_quota_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::time_quota_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::time_quota_t time_quota = {};
//      to_core_type(time_quota);
//      s.set(time_quota);
//  }
//};
////-------------------------------------
//// IE START_TIME
//class pfcp_start_time_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_start_time_ie(const core::pfcp::start_time_t& b) : pfcp_ie(PFCP_IE_START_TIME){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_start_time_ie() : pfcp_ie(PFCP_IE_START_TIME){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_start_time_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::start_time_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::start_time_t start_time = {};
//      to_core_type(start_time);
//      s.set(start_time);
//  }
//};
////-------------------------------------
//// IE END_TIME
//class pfcp_end_time_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_end_time_ie(const core::pfcp::end_time_t& b) : pfcp_ie(PFCP_IE_END_TIME){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_end_time_ie() : pfcp_ie(PFCP_IE_END_TIME){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_end_time_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::end_time_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::end_time_t end_time = {};
//      to_core_type(end_time);
//      s.set(end_time);
//  }
//};
////-------------------------------------
//// IE QUERY_URR
//class pfcp_query_urr_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_query_urr_ie(const core::pfcp::query_urr& b) : pfcp_ie(PFCP_IE_QUERY_URR){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_query_urr_ie() : pfcp_ie(PFCP_IE_QUERY_URR){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_query_urr_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::query_urr& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::query_urr query_urr = {};
//      to_core_type(query_urr);
//      s.set(query_urr);
//  }
//};
////-------------------------------------
//// IE USAGE_REPORT_WITHIN_SESSION_MODIFICATION_RESPONSE
//class pfcp_usage_report_within_session_modification_response_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_usage_report_within_session_modification_response_ie(const core::pfcp::usage_report_within_pfcp_session_modification_response& b) : pfcp_ie(PFCP_IE_USAGE_REPORT_WITHIN_SESSION_MODIFICATION_RESPONSE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_report_within_session_modification_response_ie() : pfcp_ie(PFCP_IE_USAGE_REPORT_WITHIN_SESSION_MODIFICATION_RESPONSE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_report_within_session_modification_response_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::usage_report_within_pfcp_session_modification_response& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::usage_report_within_pfcp_session_modification_response usage_report_within_session_modification_response = {};
//      to_core_type(usage_report_within_session_modification_response);
//      s.set(usage_report_within_session_modification_response);
//  }
//};
////-------------------------------------
//// IE USAGE_REPORT_WITHIN_SESSION_DELETION_RESPONSE
//class pfcp_usage_report_within_session_deletion_response_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_usage_report_within_session_deletion_response_ie(const core::pfcp::usage_report_within_pfcp_session_deletion_response& b) : pfcp_ie(PFCP_IE_USAGE_REPORT_WITHIN_SESSION_DELETION_RESPONSE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_report_within_session_deletion_response_ie() : pfcp_ie(PFCP_IE_USAGE_REPORT_WITHIN_SESSION_DELETION_RESPONSE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_report_within_session_deletion_response_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::usage_report_within_pfcp_session_deletion_response& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::usage_report_within_pfcp_session_deletion_response usage_report_within_session_deletion_response = {};
//      to_core_type(usage_report_within_session_deletion_response);
//      s.set(usage_report_within_session_deletion_response);
//  }
//};
////-------------------------------------
//// IE USAGE_REPORT_WITHIN_SESSION_REPORT_REQUEST
//class pfcp_usage_report_within_session_report_request_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_usage_report_within_session_report_request_ie(const core::pfcp::usage_report_within_pfcp_session_report_request& b) : pfcp_ie(PFCP_IE_USAGE_REPORT_WITHIN_SESSION_REPORT_REQUEST){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_report_within_session_report_request_ie() : pfcp_ie(PFCP_IE_USAGE_REPORT_WITHIN_SESSION_REPORT_REQUEST){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_report_within_session_report_request_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::usage_report_within_pfcp_session_report_request& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::usage_report_within_pfcp_session_report_request usage_report_within_session_report_request = {};
//      to_core_type(usage_report_within_session_report_request);
//      s.set(usage_report_within_session_report_request);
//  }
//};
//-------------------------------------
// IE URR_ID
class pfcp_urr_id_ie : public pfcp_ie {
public:
  uint32_t urr_id;

  //--------
  pfcp_urr_id_ie(const core::pfcp::urr_id_t& b) : pfcp_ie(PFCP_IE_URR_ID){
    urr_id = b.urr_id;
    tlv.set_length(sizeof(urr_id));
  }
  //--------
  pfcp_urr_id_ie() : pfcp_ie(PFCP_IE_URR_ID){
    urr_id = 0;
    tlv.set_length(sizeof(urr_id));
  }
  //--------
  pfcp_urr_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::urr_id_t& b) {
    b.urr_id = urr_id;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_urr_id = htobe32(urr_id);
    os.write(reinterpret_cast<const char*>(&urr_id), sizeof(urr_id));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(urr_id)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&urr_id), sizeof(urr_id));
    urr_id = be32toh(urr_id);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::urr_id_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE LINKED_URR_ID
//class pfcp_linked_urr_id_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_linked_urr_id_ie(const core::pfcp::linked_urr_id_t& b) : pfcp_ie(PFCP_IE_LINKED_URR_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_linked_urr_id_ie() : pfcp_ie(PFCP_IE_LINKED_URR_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_linked_urr_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::linked_urr_id_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::linked_urr_id_t linked_urr_id = {};
//      to_core_type(linked_urr_id);
//      s.set(linked_urr_id);
//  }
//};
////-------------------------------------
//// IE DOWNLINK_DATA_REPORT
//class pfcp_downlink_data_report_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_downlink_data_report_ie(const core::pfcp::downlink_data_report& b) : pfcp_ie(PFCP_IE_DOWNLINK_DATA_REPORT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_downlink_data_report_ie() : pfcp_ie(PFCP_IE_DOWNLINK_DATA_REPORT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_downlink_data_report_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::downlink_data_report& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::downlink_data_report downlink_data_report = {};
//      to_core_type(downlink_data_report);
//      s.set(downlink_data_report);
//  }
//};
//-------------------------------------
// IE OUTER_HEADER_CREATION
class pfcp_outer_header_creation_ie : public pfcp_ie {
public:
  uint16_t  outer_header_creation_description;
  uint32_t  teid;
  struct in_addr  ipv4_address;
  struct in6_addr ipv6_address;
  uint16_t  port_number;
  //--------
  pfcp_outer_header_creation_ie(const core::pfcp::outer_header_creation_t& b) : pfcp_ie(PFCP_IE_OUTER_HEADER_CREATION){
    teid = {};
    ipv4_address = {};
    ipv6_address = {};
    port_number = {};

    outer_header_creation_description = b.outer_header_creation_description;
    tlv.set_length(1);
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV4 | OUTER_HEADER_CREATION_GTPU_UDP_IPV6)) {
      teid = b.teid;
      tlv.add_length(sizeof(teid));
    }
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV4 | OUTER_HEADER_CREATION_UDP_IPV4)) {
      ipv4_address = b.ipv4_address;
      tlv.add_length(sizeof(ipv4_address.s_addr));
    }
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV6 | OUTER_HEADER_CREATION_UDP_IPV6)) {
      ipv6_address = b.ipv6_address;
      tlv.add_length(sizeof(ipv6_address.__in6_u.__u6_addr8));
    }
    if (outer_header_creation_description & OUTER_HEADER_CREATION_UDP_IPV4) {
      port_number = b.port_number;
      tlv.add_length(sizeof(port_number));
    }
  }
  //--------
  pfcp_outer_header_creation_ie() : pfcp_ie(PFCP_IE_OUTER_HEADER_CREATION){
    outer_header_creation_description = {};
    teid = {};
    ipv4_address = {};
    ipv6_address = {};
    port_number = {};
    tlv.set_length(0);
  }
  //--------
  pfcp_outer_header_creation_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::outer_header_creation_t& b) {
    b.outer_header_creation_description = outer_header_creation_description;
    b.teid         = teid;
    b.ipv4_address = ipv4_address;
    b.ipv6_address = ipv6_address;
    b.port_number  = port_number;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_outer_header_creation_description = htobe16(outer_header_creation_description);
    os.write(reinterpret_cast<const char*>(&be_outer_header_creation_description), sizeof(be_outer_header_creation_description));
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV4 | OUTER_HEADER_CREATION_GTPU_UDP_IPV6)) {
      auto be_teid = htobe32(teid);
      os.write(reinterpret_cast<const char*>(&be_teid), sizeof(be_teid));
    }
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV4 | OUTER_HEADER_CREATION_UDP_IPV4)) {
      ipv4_address_dump_to(os, ipv4_address);
    }
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV6 | OUTER_HEADER_CREATION_UDP_IPV6)) {
      ipv6_address_dump_to(os, ipv6_address);
    }
    if (outer_header_creation_description & OUTER_HEADER_CREATION_UDP_IPV4) {
      auto be_port_number = htobe16(port_number);
      os.write(reinterpret_cast<const char*>(&be_port_number), sizeof(be_port_number));
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() < 4) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&outer_header_creation_description), sizeof(outer_header_creation_description));
    outer_header_creation_description = be16toh(outer_header_creation_description);
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV4 | OUTER_HEADER_CREATION_GTPU_UDP_IPV6)) {
      is.read(reinterpret_cast<char*>(&teid), sizeof(teid));
      teid = be32toh(teid);
    }
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV4 | OUTER_HEADER_CREATION_UDP_IPV4)) {
      ipv4_address_load_from(is, ipv4_address);
    }
    if (outer_header_creation_description & (OUTER_HEADER_CREATION_GTPU_UDP_IPV6 | OUTER_HEADER_CREATION_UDP_IPV6)) {
      ipv6_address_load_from(is, ipv6_address);
    }
    if (outer_header_creation_description & OUTER_HEADER_CREATION_UDP_IPV4) {
      is.read(reinterpret_cast<char*>(&port_number), sizeof(port_number));
      port_number = be16toh(port_number);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::outer_header_creation_t outer_header_creation = {};
      to_core_type(outer_header_creation);
      s.set(outer_header_creation);
  }
};
////-------------------------------------
//// IE CREATE_BAR
//class pfcp_create_bar_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_create_bar_ie(const core::pfcp::create_bar& b) : pfcp_ie(PFCP_IE_CREATE_BAR){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_create_bar_ie() : pfcp_ie(PFCP_IE_CREATE_BAR){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_create_bar_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::create_bar& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::create_bar create_bar = {};
//      to_core_type(create_bar);
//      s.set(create_bar);
//  }
//};
////-------------------------------------
//// IE UPDATE_BAR_WITHIN_SESSION_MODIFICATION_REQUEST
//class pfcp_update_bar_within_session_modification_request_ie : public pfcp_grouped_ie {
//public:
//
//  //--------
//  pfcp_update_bar_within_session_modification_request_ie(const core::pfcp::update_bar_within_pfcp_session_modification_request& b) : pfcp_grouped_ie(PFCP_IE_UPDATE_BAR_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST){
//    tlv.set_length(0);
//  }
//  //--------
//  pfcp_update_bar_within_session_modification_request_ie() : pfcp_grouped_ie(PFCP_IE_UPDATE_BAR_WITHIN_PFCP_SESSION_MODIFICATION_REQUEST){
//  }
//  //--------
//  void to_core_type(core::pfcp::update_bar_within_pfcp_session_modification_request& c) {
//    for (auto sie : ies) {
//      sie.get()->to_core_type(c);
//    }
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//    core::pfcp::update_bar_within_pfcp_session_modification_request i = {};
//    to_core_type(i);
//    s.set(i);
//  }
//};
//
////-------------------------------------
//// IE REMOVE_BAR
//class pfcp_remove_bar_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_remove_bar_ie(const core::pfcp::remove_bar& b) : pfcp_ie(PFCP_IE_REMOVE_BAR){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_remove_bar_ie() : pfcp_ie(PFCP_IE_REMOVE_BAR){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_remove_bar_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::remove_bar& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::remove_bar remove_bar = {};
//      to_core_type(remove_bar);
//      s.set(remove_bar);
//  }
//};
//-------------------------------------
// IE BAR_ID
class pfcp_bar_id_ie : public pfcp_ie {
public:
  uint8_t bar_id;

  //--------
  pfcp_bar_id_ie(const core::pfcp::bar_id_t& b) : pfcp_ie(PFCP_IE_BAR_ID){
    bar_id = b.bar_id;
    tlv.set_length(1);
  }
  //--------
  pfcp_bar_id_ie() : pfcp_ie(PFCP_IE_BAR_ID){
    bar_id = 0;
    tlv.set_length(1);
  }
  //--------
  pfcp_bar_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    bar_id = 0;
  };
  //--------
  void to_core_type(core::pfcp::bar_id_t& b) {
    b.bar_id = bar_id;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&bar_id), sizeof(bar_id));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&bar_id), sizeof(bar_id));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::bar_id_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE CP_FUNCTION_FEATURES
class pfcp_cp_function_features_ie : public pfcp_ie {
public:

  union {
    struct {
      uint8_t load:1;
      uint8_t ovrl:1;
      uint8_t spare1 :6;
   } bf;
   uint8_t b;
  } u1;


  //--------
  pfcp_cp_function_features_ie(const core::pfcp::cp_function_features_t& b) : pfcp_ie(PFCP_IE_CP_FUNCTION_FEATURES){
    u1.b = 0;
    u1.bf.load = b.load;
    u1.bf.ovrl = b.ovrl;
    tlv.set_length(1);
  }
  //--------
  pfcp_cp_function_features_ie() : pfcp_ie(PFCP_IE_CP_FUNCTION_FEATURES){
    u1.b = 0;
    tlv.set_length(1);
  }
  //--------
  pfcp_cp_function_features_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    u1.b = 0;
  };
  //--------
  void to_core_type(core::pfcp::cp_function_features_t& b) {
    b.load = u1.bf.load;
    b.ovrl = u1.bf.ovrl;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::cp_function_features_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE USAGE_INFORMATION
//class pfcp_usage_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_usage_information_ie(const core::pfcp::usage_information_t& b) : pfcp_ie(PFCP_IE_USAGE_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_information_ie() : pfcp_ie(PFCP_IE_USAGE_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_usage_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::usage_information_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::usage_information_t usage_information = {};
//      to_core_type(usage_information);
//      s.set(usage_information);
//  }
//};
////-------------------------------------
//// IE APPLICATION_INSTANCE_ID
//class pfcp_application_instance_id_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_application_instance_id_ie(const core::pfcp::application_instance_id_t& b) : pfcp_ie(PFCP_IE_APPLICATION_INSTANCE_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_application_instance_id_ie() : pfcp_ie(PFCP_IE_APPLICATION_INSTANCE_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_application_instance_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::application_instance_id_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::application_instance_id_t application_instance_id = {};
//      to_core_type(application_instance_id);
//      s.set(application_instance_id);
//  }
//};
////-------------------------------------
//// IE FLOW_INFORMATION
//class pfcp_flow_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_flow_information_ie(const core::pfcp::flow_information_t& b) : pfcp_ie(PFCP_IE_FLOW_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_flow_information_ie() : pfcp_ie(PFCP_IE_FLOW_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_flow_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::flow_information_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::flow_information_t flow_information = {};
//      to_core_type(flow_information);
//      s.set(flow_information);
//  }
//};
//-------------------------------------
// IE UE_IP_ADDRESS
class pfcp_ue_ip_address_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t v6 :1;
      uint8_t v4 :1;
      uint8_t sd :1;
      uint8_t ipv6d :1;
      uint8_t spare1 :4;
   } bf;
   uint8_t b;
  } u1;
  struct in_addr  ipv4_address;
  struct in6_addr ipv6_address;
  uint8_t         ipv6_prefix_delegation_bits;

  //--------
  pfcp_ue_ip_address_ie(const core::pfcp::ue_ip_address_t& b) : pfcp_ie(PFCP_IE_UE_IP_ADDRESS){
    u1.b = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    ipv6_prefix_delegation_bits = 0;
    tlv.set_length(1);
    u1.bf.sd = b.sd;
    u1.bf.v4 = b.v4;
    u1.bf.v6 = b.v6;
    if (u1.bf.v4) {
      ipv4_address = b.ipv4_address;
      tlv.add_length(4);
    }
    if (u1.bf.v6) {
      ipv6_address = b.ipv6_address;
      u1.bf.ipv6d = b.ipv6d;
      tlv.add_length(16);
      if (u1.bf.ipv6d) {
        ipv6_prefix_delegation_bits = b.ipv6_prefix_delegation_bits;
        tlv.add_length(1);
      }
    }
  }
  //--------
  pfcp_ue_ip_address_ie() : pfcp_ie(PFCP_IE_UE_IP_ADDRESS){
    u1.b = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    ipv6_prefix_delegation_bits = 0;
    tlv.set_length(1);
  }
  //--------
  pfcp_ue_ip_address_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::ue_ip_address_t& b) {
    b.sd = u1.bf.sd;
    b.v4 = u1.bf.v4;
    b.v6 = u1.bf.v6;
    if (u1.bf.v4) {
      b.ipv4_address = ipv4_address;
    }
    if (u1.bf.v6) {
      b.ipv6_address = ipv6_address;
      b.ipv6d = u1.bf.ipv6d;
      if (u1.bf.ipv6d) {
        b.ipv6_prefix_delegation_bits = ipv6_prefix_delegation_bits;
      }
    }
  }
  //--------
  void dump_to(std::ostream& os) {
    uint16_t length = 1;
    if (u1.bf.v4) {
      length += 4;
    }
    if (u1.bf.v6) {
      length += 16;
      if (u1.bf.ipv6d) {
        length += 1;
      }
    }
    tlv.set_length(length);
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    if (u1.bf.v4) {
      ipv4_address_dump_to(os, ipv4_address);
    }
    if (u1.bf.v6) {
      ipv6_address_dump_to(os, ipv6_address);
      if (u1.bf.ipv6d) {
        os.write(reinterpret_cast<const char*>(&ipv6_prefix_delegation_bits), sizeof(ipv6_prefix_delegation_bits));
      }
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    uint16_t check_length = 1;
    if (u1.bf.v4) {
      check_length += 4;
    }
    if (u1.bf.v6) {
      check_length += 16;
      if (u1.bf.ipv6d) {
        check_length += 1;
      }
    }
    if (tlv.get_length() != check_length) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    if (u1.bf.v4) {
      ipv4_address_load_from(is, ipv4_address);
    }
    if (u1.bf.v6) {
      ipv6_address_load_from(is, ipv6_address);
      if (u1.bf.ipv6d) {
        is.read(reinterpret_cast<char*>(&ipv6_prefix_delegation_bits), sizeof(ipv6_prefix_delegation_bits));
      }
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::ue_ip_address_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE PACKET_RATE
//class pfcp_packet_rate_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_packet_rate_ie(const core::pfcp::packet_rate_t& b) : pfcp_ie(PFCP_IE_PACKET_RATE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_packet_rate_ie() : pfcp_ie(PFCP_IE_PACKET_RATE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_packet_rate_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::packet_rate_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::packet_rate_t packet_rate = {};
//      to_core_type(packet_rate);
//      s.set(packet_rate);
//  }
//};
//-------------------------------------
// IE OUTER_HEADER_REMOVAL
class pfcp_outer_header_removal_ie : public pfcp_ie {
public:
  uint8_t  outer_header_removal_description;

  //--------
  pfcp_outer_header_removal_ie(const core::pfcp::outer_header_removal_t& b) : pfcp_ie(PFCP_IE_OUTER_HEADER_REMOVAL){
    outer_header_removal_description = b.outer_header_removal_description;
    tlv.set_length(sizeof(outer_header_removal_description));
  }
  //--------
  pfcp_outer_header_removal_ie() : pfcp_ie(PFCP_IE_OUTER_HEADER_REMOVAL){
    outer_header_removal_description = 0;
    tlv.set_length(sizeof(outer_header_removal_description));
  }
  //--------
  pfcp_outer_header_removal_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::outer_header_removal_t& b) {
    b.outer_header_removal_description = outer_header_removal_description;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.set_length(sizeof(outer_header_removal_description));
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&outer_header_removal_description), sizeof(outer_header_removal_description));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(outer_header_removal_description)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&outer_header_removal_description), sizeof(outer_header_removal_description));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::outer_header_removal_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE RECOVERY_TIME_STAMP
class pfcp_recovery_time_stamp_ie : public pfcp_ie {
public:
  uint32_t     recovery_time_stamp;

  //--------
  pfcp_recovery_time_stamp_ie(const core::pfcp::recovery_time_stamp_t& b) : pfcp_ie(PFCP_IE_RECOVERY_TIME_STAMP){
    recovery_time_stamp = b.recovery_time_stamp;
    tlv.set_length(sizeof(recovery_time_stamp));
  }
  //--------
  pfcp_recovery_time_stamp_ie() : pfcp_ie(PFCP_IE_RECOVERY_TIME_STAMP){
    recovery_time_stamp = 0;
    tlv.set_length(sizeof(recovery_time_stamp));
  }
  //--------
  pfcp_recovery_time_stamp_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    recovery_time_stamp = 0;
  };
  //--------
  void to_core_type(core::pfcp::recovery_time_stamp_t& b) {
    b.recovery_time_stamp = recovery_time_stamp;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_recovery_time_stamp = htobe32(recovery_time_stamp);
    os.write(reinterpret_cast<const char*>(&be_recovery_time_stamp), sizeof(be_recovery_time_stamp));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&recovery_time_stamp), sizeof(recovery_time_stamp));
    recovery_time_stamp = be32toh(recovery_time_stamp);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::recovery_time_stamp_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE DL_FLOW_LEVEL_MARKING
//class pfcp_dl_flow_level_marking_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_dl_flow_level_marking_ie(const core::pfcp::dl_flow_level_marking_t& b) : pfcp_ie(PFCP_IE_DL_FLOW_LEVEL_MARKING){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_dl_flow_level_marking_ie() : pfcp_ie(PFCP_IE_DL_FLOW_LEVEL_MARKING){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_dl_flow_level_marking_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::dl_flow_level_marking_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::dl_flow_level_marking_t dl_flow_level_marking = {};
//      to_core_type(dl_flow_level_marking);
//      s.set(dl_flow_level_marking);
//  }
//};
////-------------------------------------
//// IE HEADER_ENRICHMENT
//class pfcp_header_enrichment_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_header_enrichment_ie(const core::pfcp::header_enrichment_t& b) : pfcp_ie(PFCP_IE_HEADER_ENRICHMENT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_header_enrichment_ie() : pfcp_ie(PFCP_IE_HEADER_ENRICHMENT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_header_enrichment_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::header_enrichment_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::header_enrichment_t header_enrichment = {};
//      to_core_type(header_enrichment);
//      s.set(header_enrichment);
//  }
//};
////-------------------------------------
//// IE ERROR_INDICATION_REPORT
//class pfcp_error_indication_report_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_error_indication_report_ie(const core::pfcp::error_indication_report& b) : pfcp_ie(PFCP_IE_ERROR_INDICATION_REPORT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_error_indication_report_ie() : pfcp_ie(PFCP_IE_ERROR_INDICATION_REPORT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_error_indication_report_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::error_indication_report& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::error_indication_report error_indication_report = {};
//      to_core_type(error_indication_report);
//      s.set(error_indication_report);
//  }
//};
////-------------------------------------
//// IE MEASUREMENT_INFORMATION
//class pfcp_measurement_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_measurement_information_ie(const core::pfcp::measurement_information_t& b) : pfcp_ie(PFCP_IE_MEASUREMENT_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_measurement_information_ie() : pfcp_ie(PFCP_IE_MEASUREMENT_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_measurement_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::measurement_information_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::measurement_information_t measurement_information = {};
//      to_core_type(measurement_information);
//      s.set(measurement_information);
//  }
//};
////-------------------------------------
//// IE NODE_REPORT_TYPE
//class pfcp_node_report_type_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_node_report_type_ie(const core::pfcp::node_report_type_t& b) : pfcp_ie(PFCP_IE_NODE_REPORT_TYPE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_node_report_type_ie() : pfcp_ie(PFCP_IE_NODE_REPORT_TYPE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_node_report_type_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::node_report_type_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::node_report_type_t node_report_type = {};
//      to_core_type(node_report_type);
//      s.set(node_report_type);
//  }
//};
////-------------------------------------
//// IE USER_PLANE_PATH_FAILURE_REPORT
//class pfcp_user_plane_path_failure_report_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_user_plane_path_failure_report_ie(const core::pfcp::user_plane_path_failure_report& b) : pfcp_ie(PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_user_plane_path_failure_report_ie() : pfcp_ie(PFCP_IE_USER_PLANE_PATH_FAILURE_REPORT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_user_plane_path_failure_report_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::user_plane_path_failure_report& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::user_plane_path_failure_report v = {};
//      to_core_type(v);
//      s.set(v);
//  }
//};
////-------------------------------------
//// IE REMOTE_GTP_U_PEER
//class pfcp_remote_gtp_u_peer_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_remote_gtp_u_peer_ie(const core::pfcp::remote_gtp_u_peer_t& b) : pfcp_ie(PFCP_IE_REMOTE_GTP_U_PEER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_remote_gtp_u_peer_ie() : pfcp_ie(PFCP_IE_REMOTE_GTP_U_PEER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_remote_gtp_u_peer_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::remote_gtp_u_peer_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::remote_gtp_u_peer_t v = {};
//      to_core_type(v);
//      s.set(v);
//  }
//};
////-------------------------------------
//// IE UR_SEQN
//class pfcp_ur_seqn_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_ur_seqn_ie(const core::pfcp::ur_seqn_t& b) : pfcp_ie(PFCP_IE_UR_SEQN){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ur_seqn_ie() : pfcp_ie(PFCP_IE_UR_SEQN){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ur_seqn_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::ur_seqn_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::ur_seqn_t ur_seqn = {};
//      to_core_type(ur_seqn);
//      s.set(ur_seqn);
//  }
//};
////-------------------------------------
//// IE UPDATE_DUPLICATING_PARAMETERS
//class pfcp_update_duplicating_parameters_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_update_duplicating_parameters_ie(const core::pfcp::update_duplicating_parameters& b) : pfcp_ie(PFCP_IE_UPDATE_DUPLICATING_PARAMETERS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_update_duplicating_parameters_ie() : pfcp_ie(PFCP_IE_UPDATE_DUPLICATING_PARAMETERS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_update_duplicating_parameters_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::update_duplicating_parameters& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::update_duplicating_parameters update_duplicating_parameters = {};
//      to_core_type(update_duplicating_parameters);
//      s.set(update_duplicating_parameters);
//  }
//};
//-------------------------------------
// IE ACTIVATE_PREDEFINED_RULES
class pfcp_activate_predefined_rules_ie : public pfcp_ie {
public:
  std::string      predefined_rules_name;

  //--------
  pfcp_activate_predefined_rules_ie(const core::pfcp::activate_predefined_rules_t& b) : pfcp_ie(PFCP_IE_ACTIVATE_PREDEFINED_RULES){
    predefined_rules_name = b.predefined_rules_name;
    tlv.set_length(predefined_rules_name.size());
  }
  //--------
  pfcp_activate_predefined_rules_ie() : pfcp_ie(PFCP_IE_ACTIVATE_PREDEFINED_RULES){
    predefined_rules_name = {};
    tlv.set_length(0);
  }
  //--------
  pfcp_activate_predefined_rules_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::activate_predefined_rules_t& b) {
    b.predefined_rules_name = predefined_rules_name;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.set_length(predefined_rules_name.size());
    tlv.dump_to(os);
    os << predefined_rules_name;
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() == 0) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    char e[tlv.get_length()];
    is.read(e, tlv.get_length());
    predefined_rules_name.assign(e, tlv.get_length());
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::activate_predefined_rules_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE DEACTIVATE_PREDEFINED_RULES
class pfcp_deactivate_predefined_rules_ie : public pfcp_ie {
public:
  std::string      predefined_rules_name;

  //--------
  pfcp_deactivate_predefined_rules_ie(const core::pfcp::deactivate_predefined_rules_t& b) : pfcp_ie(PFCP_IE_DEACTIVATE_PREDEFINED_RULES){
    predefined_rules_name = b.predefined_rules_name;
    tlv.set_length(predefined_rules_name.size());
  }
  //--------
  pfcp_deactivate_predefined_rules_ie() : pfcp_ie(PFCP_IE_DEACTIVATE_PREDEFINED_RULES){
    predefined_rules_name = {};
    tlv.set_length(0);
  }
  //--------
  pfcp_deactivate_predefined_rules_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::deactivate_predefined_rules_t& b) {
    b.predefined_rules_name = predefined_rules_name;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.set_length(predefined_rules_name.size());
    tlv.dump_to(os);
    os << predefined_rules_name;
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() == 0) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    char e[tlv.get_length()];
    is.read(e, tlv.get_length());
    predefined_rules_name.assign(e, tlv.get_length());
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::deactivate_predefined_rules_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE FAR_ID
class pfcp_far_id_ie : public pfcp_ie {
public:
  uint32_t far_id;

  //--------
  pfcp_far_id_ie(const core::pfcp::far_id_t& b) : pfcp_ie(PFCP_IE_FAR_ID){
    far_id = b.far_id;
    tlv.set_length(sizeof(far_id));
  }
  //--------
  pfcp_far_id_ie() : pfcp_ie(PFCP_IE_FAR_ID){
    far_id = 0;
    tlv.set_length(sizeof(far_id));
  }
  //--------
  pfcp_far_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::far_id_t& b) {
    b.far_id = far_id;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_far_id = htobe32(far_id);
    os.write(reinterpret_cast<const char*>(&be_far_id), sizeof(be_far_id));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(far_id)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&far_id), sizeof(far_id));
    far_id = be32toh(far_id);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::far_id_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE QER_ID
class pfcp_qer_id_ie : public pfcp_ie {
public:
  uint32_t qer_id;

  //--------
  pfcp_qer_id_ie(const core::pfcp::qer_id_t& b) : pfcp_ie(PFCP_IE_QER_ID){
    qer_id = b.qer_id;
    tlv.set_length(sizeof(qer_id));
  }
  //--------
  pfcp_qer_id_ie() : pfcp_ie(PFCP_IE_QER_ID){
    qer_id = 0;
    tlv.set_length(sizeof(qer_id));
  }
  //--------
  pfcp_qer_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::qer_id_t& b) {
    b.qer_id = qer_id;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_qer_id = htobe32(qer_id);
    os.write(reinterpret_cast<const char*>(&be_qer_id), sizeof(be_qer_id));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(qer_id)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&qer_id), sizeof(qer_id));
    qer_id = be32toh(qer_id);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::qer_id_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE OCI_FLAGS
//class pfcp_oci_flags_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_oci_flags_ie(const core::pfcp::oci_flags_t& b) : pfcp_ie(PFCP_IE_OCI_FLAGS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_oci_flags_ie() : pfcp_ie(PFCP_IE_OCI_FLAGS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_oci_flags_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::oci_flags_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::oci_flags_t oci_flags = {};
//      to_core_type(oci_flags);
//      s.set(oci_flags);
//  }
//};
////-------------------------------------
//// IE PFCP_ASSOCIATION_RELEASE_REQUEST
//class pfcp_pfcp_association_release_request_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_pfcp_association_release_request_ie(const core::pfcp::pfcp_association_release_request_t& b) : pfcp_ie(PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfcp_association_release_request_ie() : pfcp_ie(PFCP_IE_PFCP_ASSOCIATION_RELEASE_REQUEST){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pfcp_association_release_request_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::pfcp_association_release_request_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::pfcp_association_release_request_t pfcp_association_release_request = {};
//      to_core_type(pfcp_association_release_request);
//      s.set(pfcp_association_release_request);
//  }
//};
////-------------------------------------
//// IE GRACEFUL_RELEASE_PERIOD
//class pfcp_graceful_release_period_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_graceful_release_period_ie(const core::pfcp::graceful_release_period_t& b) : pfcp_ie(PFCP_IE_GRACEFUL_RELEASE_PERIOD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_graceful_release_period_ie() : pfcp_ie(PFCP_IE_GRACEFUL_RELEASE_PERIOD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_graceful_release_period_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::graceful_release_period_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::graceful_release_period_t graceful_release_period = {};
//      to_core_type(graceful_release_period);
//      s.set(graceful_release_period);
//  }
//};
////-------------------------------------
//// IE PDN_TYPE
//class pfcp_pdn_type_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_pdn_type_ie(const core::pfcp::pdn_type_t& b) : pfcp_ie(PFCP_IE_PDN_TYPE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pdn_type_ie() : pfcp_ie(PFCP_IE_PDN_TYPE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_pdn_type_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::pdn_type_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::pdn_type_t pdn_type = {};
//      to_core_type(pdn_type);
//      s.set(pdn_type);
//  }
//};
////-------------------------------------
//// IE FAILED_RULE_ID
//class pfcp_failed_rule_id_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_failed_rule_id_ie(const core::pfcp::failed_rule_id_t& b) : pfcp_ie(PFCP_IE_FAILED_RULE_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_failed_rule_id_ie() : pfcp_ie(PFCP_IE_FAILED_RULE_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_failed_rule_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::failed_rule_id_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::failed_rule_id_t failed_rule_id = {};
//      to_core_type(failed_rule_id);
//      s.set(failed_rule_id);
//  }
//};
////-------------------------------------
//// IE TIME_QUOTA_MECHANISM
//class pfcp_time_quota_mechanism_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_time_quota_mechanism_ie(const core::pfcp::time_quota_mechanism_t& b) : pfcp_ie(PFCP_IE_TIME_QUOTA_MECHANISM){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_time_quota_mechanism_ie() : pfcp_ie(PFCP_IE_TIME_QUOTA_MECHANISM){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_time_quota_mechanism_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::time_quota_mechanism_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::time_quota_mechanism_t time_quota_mechanism = {};
//      to_core_type(time_quota_mechanism);
//      s.set(time_quota_mechanism);
//  }
//};
//-------------------------------------
// IE USER_PLANE_IP_RESOURCE_INFORMATION
class pfcp_user_plane_ip_resource_information_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t v4:1;
      uint8_t v6:1;
      uint8_t teidri:3;
      uint8_t assoni:1;
      uint8_t assosi:1;
      uint8_t spare1 :1;
   } bf;
   uint8_t b;
  } u1;
  uint8_t         teid_range;
  struct in_addr  ipv4_address;
  struct in6_addr ipv6_address;
  uint16_t        network_instance;
  union {
    struct {
      uint8_t source_interface:4;
      uint8_t spare2 :4;
   } bf;
   uint8_t b;
  } u2;
  //--------
  pfcp_user_plane_ip_resource_information_ie(const core::pfcp::user_plane_ip_resource_information_t& b) : pfcp_ie(PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION){
    u1.b = 0;
    u2.b = 0;
    teid_range = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    network_instance = 0;
    tlv.set_length(1);

    u1.bf.v4 = b.v4;
    u1.bf.v6 = b.v6;
    u1.bf.teidri = b.teidri;
    u1.bf.assoni = b.assoni;
    u1.bf.assosi = b.assosi;
    teid_range = b.teid_range;
    if (u1.bf.v4) {
      ipv4_address = b.ipv4_address;
      tlv.add_length(4);
    }
    if (u1.bf.v6) {
      ipv6_address = b.ipv6_address;
      tlv.add_length(16);
    }
    if (u1.bf.assoni) {
      network_instance = b.network_instance;
      tlv.add_length(2);
    }
    if (u1.bf.assosi) {
      u2.bf.source_interface = b.source_interface;
      tlv.add_length(1);
    }
  }
  //--------
  pfcp_user_plane_ip_resource_information_ie() : pfcp_ie(PFCP_IE_USER_PLANE_IP_RESOURCE_INFORMATION){
    u1.b = 0;
    u2.b = 0;
    teid_range = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    network_instance = 0;
    tlv.set_length(1);
  }
  //--------
  pfcp_user_plane_ip_resource_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
    u1.b = 0;
    u2.b = 0;
    teid_range = 0;
    ipv4_address.s_addr = INADDR_ANY;
    ipv6_address = in6addr_any;
    network_instance = 0;
  };
  //--------
  void to_core_type(core::pfcp::user_plane_ip_resource_information_t& b) {
    b = {};
    b.v4 = u1.bf.v4;
    b.v6 = u1.bf.v6;
    b.teidri = u1.bf.teidri;
    b.assoni = u1.bf.assoni;
    b.assosi = u1.bf.assosi;
    b.teid_range = teid_range;
    if (u1.bf.v4) {
      b.ipv4_address = ipv4_address;
    }
    if (u1.bf.v6) {
      b.ipv6_address = ipv6_address;
    }
    if (u1.bf.assoni) {
      b.network_instance = network_instance;
    }
    if (u1.bf.assosi) {
      b.source_interface = u2.bf.source_interface;
    }
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    auto be_teid_range = htobe32(teid_range);
    os.write(reinterpret_cast<const char*>(&be_teid_range), sizeof(be_teid_range));
    if (u1.bf.v4) {
      ipv4_address_dump_to(os, ipv4_address);
    }
    if (u1.bf.v6) {
      ipv6_address_dump_to(os, ipv6_address);
    }
    if (u1.bf.assoni) {
      auto be_network_instance = htobe32(network_instance);
      os.write(reinterpret_cast<const char*>(&be_network_instance), sizeof(be_network_instance));
    }
    if (u1.bf.assosi) {
      os.write(reinterpret_cast<const char*>(&u2.b), sizeof(u2.b));
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() < 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    is.read(reinterpret_cast<char*>(&teid_range), sizeof(teid_range));
    teid_range = be32toh(teid_range);
    if (u1.bf.v4) {
      ipv4_address_load_from(is, ipv4_address);
    }
    if (u1.bf.v6) {
      ipv6_address_load_from(is, ipv6_address);
    }
    if (u1.bf.assoni) {
      is.read(reinterpret_cast<char*>(&network_instance), sizeof(network_instance));
      network_instance = be16toh(network_instance);
    }
    if (u1.bf.assosi) {
      is.read(reinterpret_cast<char*>(&u2.b), sizeof(u2.b));
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::user_plane_ip_resource_information_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
//-------------------------------------
// IE USER_PLANE_INACTIVITY_TIMER
class pfcp_user_plane_inactivity_timer_ie : public pfcp_ie {
public:
  uint32_t  user_plane_inactivity_timer;

  //--------
  pfcp_user_plane_inactivity_timer_ie(const core::pfcp::user_plane_inactivity_timer_t& b) : pfcp_ie(PFCP_IE_USER_PLANE_INACTIVITY_TIMER){
    user_plane_inactivity_timer = b.user_plane_inactivity_timer;
    tlv.set_length(sizeof(user_plane_inactivity_timer));
  }
  //--------
  pfcp_user_plane_inactivity_timer_ie() : pfcp_ie(PFCP_IE_USER_PLANE_INACTIVITY_TIMER){
    user_plane_inactivity_timer = 0;
    tlv.set_length(sizeof(user_plane_inactivity_timer));
  }
  //--------
  pfcp_user_plane_inactivity_timer_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::user_plane_inactivity_timer_t& b) {
    b.user_plane_inactivity_timer = user_plane_inactivity_timer;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    auto be_user_plane_inactivity_timer = htobe32(user_plane_inactivity_timer);
    os.write(reinterpret_cast<const char*>(&be_user_plane_inactivity_timer), sizeof(be_user_plane_inactivity_timer));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != sizeof(user_plane_inactivity_timer)) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&user_plane_inactivity_timer), sizeof(user_plane_inactivity_timer));
    user_plane_inactivity_timer = be32toh(user_plane_inactivity_timer);
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::user_plane_inactivity_timer_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE AGGREGATED_URRS
//class pfcp_aggregated_urrs_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_aggregated_urrs_ie(const core::pfcp::aggregated_urrs& b) : pfcp_ie(PFCP_IE_AGGREGATED_URRS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_aggregated_urrs_ie() : pfcp_ie(PFCP_IE_AGGREGATED_URRS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_aggregated_urrs_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::aggregated_urrs& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::aggregated_urrs aggregated_urrs = {};
//      to_core_type(aggregated_urrs);
//      s.set(aggregated_urrs);
//  }
//};
////-------------------------------------
//// IE MULTIPLIER
//class pfcp_multiplier_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_multiplier_ie(const core::pfcp::multiplier_t& b) : pfcp_ie(PFCP_IE_MULTIPLIER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_multiplier_ie() : pfcp_ie(PFCP_IE_MULTIPLIER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_multiplier_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::multiplier_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::multiplier_t multiplier = {};
//      to_core_type(multiplier);
//      s.set(multiplier);
//  }
//};
////-------------------------------------
//// IE AGGREGATED_URR_ID
//class pfcp_aggregated_urr_id_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_aggregated_urr_id_ie(const core::pfcp::aggregated_urr_id_t& b) : pfcp_ie(PFCP_IE_AGGREGATED_URR_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_aggregated_urr_id_ie() : pfcp_ie(PFCP_IE_AGGREGATED_URR_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_aggregated_urr_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::aggregated_urr_id_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::aggregated_urr_id_t aggregated_urr_id = {};
//      to_core_type(aggregated_urr_id);
//      s.set(aggregated_urr_id);
//  }
//};
////-------------------------------------
//// IE SUBSEQUENT_VOLUME_QUOTA
//class pfcp_subsequent_volume_quota_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_subsequent_volume_quota_ie(const core::pfcp::subsequent_volume_quota_t& b) : pfcp_ie(PFCP_IE_SUBSEQUENT_VOLUME_QUOTA){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_subsequent_volume_quota_ie() : pfcp_ie(PFCP_IE_SUBSEQUENT_VOLUME_QUOTA){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_subsequent_volume_quota_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::subsequent_volume_quota_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::subsequent_volume_quota_t subsequent_volume_quota = {};
//      to_core_type(subsequent_volume_quota);
//      s.set(subsequent_volume_quota);
//  }
//};
////-------------------------------------
//// IE SUBSEQUENT_TIME_QUOTA
//class pfcp_subsequent_time_quota_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_subsequent_time_quota_ie(const core::pfcp::subsequent_time_quota_t& b) : pfcp_ie(PFCP_IE_SUBSEQUENT_TIME_QUOTA){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_subsequent_time_quota_ie() : pfcp_ie(PFCP_IE_SUBSEQUENT_TIME_QUOTA){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_subsequent_time_quota_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::subsequent_time_quota_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::subsequent_time_quota_t subsequent_time_quota = {};
//      to_core_type(subsequent_time_quota);
//      s.set(subsequent_time_quota);
//  }
//};
////-------------------------------------
//// IE RQI
//class pfcp_rqi_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_rqi_ie(const core::pfcp::rqi_t& b) : pfcp_ie(PFCP_IE_RQI){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_rqi_ie() : pfcp_ie(PFCP_IE_RQI){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_rqi_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::rqi_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::rqi_t rqi = {};
//      to_core_type(rqi);
//      s.set(rqi);
//  }
//};
//-------------------------------------
// IE QFI
class pfcp_qfi_ie : public pfcp_ie {
public:
  union {
    struct {
      uint8_t  qfi:6;
      uint8_t spare :2;
   } bf;
   uint8_t b;
  } u1;

  //--------
  pfcp_qfi_ie(const core::pfcp::qfi_t& b) : pfcp_ie(PFCP_IE_QFI){
    u1.b = 0;
    u1.bf.qfi = b.qfi;
    tlv.set_length(1);
  }
  //--------
  pfcp_qfi_ie() : pfcp_ie(PFCP_IE_QFI){
    u1.b = 0;
    tlv.set_length(1);
  }
  //--------
  pfcp_qfi_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::qfi_t& b) {
    b.qfi = u1.bf.qfi;
  }
  //--------
  void dump_to(std::ostream& os) {
    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::qfi_t v = {};
      to_core_type(v);
      s.set(v);
  }
};
////-------------------------------------
//// IE QUERY_URR_REFERENCE
//class pfcp_query_urr_reference_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_query_urr_reference_ie(const core::pfcp::query_urr_reference_t& b) : pfcp_ie(PFCP_IE_QUERY_URR_REFERENCE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_query_urr_reference_ie() : pfcp_ie(PFCP_IE_QUERY_URR_REFERENCE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_query_urr_reference_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::query_urr_reference_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::query_urr_reference_t query_urr_reference = {};
//      to_core_type(query_urr_reference);
//      s.set(query_urr_reference);
//  }
//};
////-------------------------------------
//// IE ADDITIONAL_USAGE_REPORTS_INFORMATION
//class pfcp_additional_usage_reports_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_additional_usage_reports_information_ie(const core::pfcp::additional_usage_reports_information_t& b) : pfcp_ie(PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_additional_usage_reports_information_ie() : pfcp_ie(PFCP_IE_ADDITIONAL_USAGE_REPORTS_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_additional_usage_reports_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::additional_usage_reports_information_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::additional_usage_reports_information_t additional_usage_reports_information = {};
//      to_core_type(additional_usage_reports_information);
//      s.set(additional_usage_reports_information);
//  }
//};
////-------------------------------------
//// IE CREATE_TRAFFIC_ENDPOINT
//class pfcp_create_traffic_endpoint_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_create_traffic_endpoint_ie(const core::pfcp::create_traffic_endpoint& b) : pfcp_ie(PFCP_IE_CREATE_TRAFFIC_ENDPOINT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_create_traffic_endpoint_ie() : pfcp_ie(PFCP_IE_CREATE_TRAFFIC_ENDPOINT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_create_traffic_endpoint_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::create_traffic_endpoint& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::create_traffic_endpoint create_traffic_endpoint = {};
//      to_core_type(create_traffic_endpoint);
//      s.set(create_traffic_endpoint);
//  }
//};
////-------------------------------------
//// IE CREATED_TRAFFIC_ENDPOINT
//class pfcp_created_traffic_endpoint_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_created_traffic_endpoint_ie(const core::pfcp::created_traffic_endpoint& b) : pfcp_ie(PFCP_IE_CREATED_TRAFFIC_ENDPOINT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_created_traffic_endpoint_ie() : pfcp_ie(PFCP_IE_CREATED_TRAFFIC_ENDPOINT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_created_traffic_endpoint_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::created_traffic_endpoint& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::created_traffic_endpoint created_traffic_endpoint = {};
//      to_core_type(created_traffic_endpoint);
//      s.set(created_traffic_endpoint);
//  }
//};
////-------------------------------------
//// IE UPDATE_TRAFFIC_ENDPOINT
//class pfcp_update_traffic_endpoint_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_update_traffic_endpoint_ie(const core::pfcp::update_traffic_endpoint& b) : pfcp_ie(PFCP_IE_UPDATE_TRAFFIC_ENDPOINT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_update_traffic_endpoint_ie() : pfcp_ie(PFCP_IE_UPDATE_TRAFFIC_ENDPOINT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_update_traffic_endpoint_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::update_traffic_endpoint& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::update_traffic_endpoint update_traffic_endpoint = {};
//      to_core_type(update_traffic_endpoint);
//      s.set(update_traffic_endpoint);
//  }
//};
////-------------------------------------
//// IE REMOVE_TRAFFIC_ENDPOINT
//class pfcp_remove_traffic_endpoint_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_remove_traffic_endpoint_ie(const core::pfcp::remove_traffic_endpoint& b) : pfcp_ie(PFCP_IE_REMOVE_TRAFFIC_ENDPOINT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_remove_traffic_endpoint_ie() : pfcp_ie(PFCP_IE_REMOVE_TRAFFIC_ENDPOINT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_remove_traffic_endpoint_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::remove_traffic_endpoint& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::remove_traffic_endpoint remove_traffic_endpoint = {};
//      to_core_type(remove_traffic_endpoint);
//      s.set(remove_traffic_endpoint);
//  }
//};
////-------------------------------------
//// IE TRAFFIC_ENDPOINT_ID
//class pfcp_traffic_endpoint_id_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_traffic_endpoint_id_ie(const core::pfcp::traffic_endpoint_id_t& b) : pfcp_ie(PFCP_IE_TRAFFIC_ENDPOINT_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_traffic_endpoint_id_ie() : pfcp_ie(PFCP_IE_TRAFFIC_ENDPOINT_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_traffic_endpoint_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::traffic_endpoint_id_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::traffic_endpoint_id_t traffic_endpoint_id = {};
//      to_core_type(traffic_endpoint_id);
//      s.set(traffic_endpoint_id);
//  }
//};
////-------------------------------------
//// IE ETHERNET_PACKET_FILTER
//class pfcp_ethernet_packet_filter_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_ethernet_packet_filter_ie(const core::pfcp::ethernet_packet_filter& b) : pfcp_ie(PFCP_IE_ETHERNET_PACKET_FILTER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_packet_filter_ie() : pfcp_ie(PFCP_IE_ETHERNET_PACKET_FILTER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_packet_filter_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::ethernet_packet_filter& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::ethernet_packet_filter ethernet_packet_filter = {};
//      to_core_type(ethernet_packet_filter);
//      s.set(ethernet_packet_filter);
//  }
//};
////-------------------------------------
//// IE MAC_ADDRESS
//class pfcp_mac_address_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_mac_address_ie(const core::pfcp::mac_address_t& b) : pfcp_ie(PFCP_IE_MAC_ADDRESS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_mac_address_ie() : pfcp_ie(PFCP_IE_MAC_ADDRESS){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_mac_address_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::mac_address_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::mac_address_t mac_address = {};
//      to_core_type(mac_address);
//      s.set(mac_address);
//  }
//};
////-------------------------------------
//// IE C_TAG
//class pfcp_c_tag_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_c_tag_ie(const core::pfcp::c_tag_t& b) : pfcp_ie(PFCP_IE_C_TAG){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_c_tag_ie() : pfcp_ie(PFCP_IE_C_TAG){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_c_tag_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::c_tag_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::c_tag_t c_tag = {};
//      to_core_type(c_tag);
//      s.set(c_tag);
//  }
//};
////-------------------------------------
//// IE S_TAG
//class pfcp_s_tag_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_s_tag_ie(const core::pfcp::s_tag_t& b) : pfcp_ie(PFCP_IE_S_TAG){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_s_tag_ie() : pfcp_ie(PFCP_IE_S_TAG){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_s_tag_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::s_tag_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::s_tag_t s_tag = {};
//      to_core_type(s_tag);
//      s.set(s_tag);
//  }
//};
////-------------------------------------
//// IE ETHERTYPE
//class pfcp_ethertype_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_ethertype_ie(const core::pfcp::ethertype_t& b) : pfcp_ie(PFCP_IE_ETHERTYPE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethertype_ie() : pfcp_ie(PFCP_IE_ETHERTYPE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethertype_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::ethertype_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::ethertype_t ethertype = {};
//      to_core_type(ethertype);
//      s.set(ethertype);
//  }
//};
////-------------------------------------
//// IE PROXYING
//class pfcp_proxying_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_proxying_ie(const core::pfcp::proxying_t& b) : pfcp_ie(PFCP_IE_PROXYING){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_proxying_ie() : pfcp_ie(PFCP_IE_PROXYING){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_proxying_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::proxying_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::proxying_t proxying = {};
//      to_core_type(proxying);
//      s.set(proxying);
//  }
//};
////-------------------------------------
//// IE ETHERNET_FILTER_ID
//class pfcp_ethernet_filter_id_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_ethernet_filter_id_ie(const core::pfcp::ethernet_filter_id_t& b) : pfcp_ie(PFCP_IE_ETHERNET_FILTER_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_filter_id_ie() : pfcp_ie(PFCP_IE_ETHERNET_FILTER_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_filter_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::ethernet_filter_id_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::ethernet_filter_id_t ethernet_filter_id = {};
//      to_core_type(ethernet_filter_id);
//      s.set(ethernet_filter_id);
//  }
//};
////-------------------------------------
//// IE ETHERNET_FILTER_PROPERTIES
//class pfcp_ethernet_filter_properties_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_ethernet_filter_properties_ie(const core::pfcp::ethernet_filter_properties_t& b) : pfcp_ie(PFCP_IE_ETHERNET_FILTER_PROPERTIES){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_filter_properties_ie() : pfcp_ie(PFCP_IE_ETHERNET_FILTER_PROPERTIES){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_filter_properties_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::ethernet_filter_properties_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::ethernet_filter_properties_t ethernet_filter_properties = {};
//      to_core_type(ethernet_filter_properties);
//      s.set(ethernet_filter_properties);
//  }
//};
////-------------------------------------
//// IE SUGGESTED_BUFFERING_PACKETS_COUNT
//class pfcp_suggested_buffering_packets_count_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_suggested_buffering_packets_count_ie(const core::pfcp::suggested_buffering_packets_count_t& b) : pfcp_ie(PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_suggested_buffering_packets_count_ie() : pfcp_ie(PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_suggested_buffering_packets_count_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::suggested_buffering_packets_count_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::suggested_buffering_packets_count_t suggested_buffering_packets_count = {};
//      to_core_type(suggested_buffering_packets_count);
//      s.set(suggested_buffering_packets_count);
//  }
//};
//-------------------------------------
// IE USER_ID
class pfcp_user_id_ie : public pfcp_ie {
public:

  union {
    struct {
      uint8_t imsif:1;
      uint8_t imeif:1;
      uint8_t msisdnf:1;
      uint8_t naif:1;
      uint8_t spare:4;
   } bf;
   uint8_t b;
  } u1;

  uint8_t length_of_imsi;
  core::imsi_t imsi;
  uint8_t length_of_imei;
  std::string imei;
  uint8_t length_of_msisdn;
  core::msisdn_t msisdn;;
  uint8_t length_of_nai;
  std::string nai;

  //--------
  pfcp_user_id_ie(const core::pfcp::user_id_t& b) : pfcp_ie(PFCP_IE_USER_ID){
    u1.b = 0;
    length_of_imsi = 0;
    length_of_imei = 0;
    length_of_msisdn = 0;
    length_of_nai = 0;
    imsi = {};
    imei = {};
    msisdn = {};
    nai = {};
    tlv.set_length(1);

    u1.bf.naif = b.naif;
    u1.bf.msisdnf = b.msisdnf;
    u1.bf.imeif = b.imeif;
    u1.bf.imsif = b.imsif;
    if (u1.bf.imsif) {
      length_of_imsi = b.length_of_imsi;
      imsi = b.imsi;
      tlv.add_length(1+length_of_imsi);
    }
    if (u1.bf.imeif) {
      length_of_imei = b.length_of_imei;
      imei = b.imei;
      tlv.add_length(1+length_of_imei);
    }
    if (u1.bf.msisdnf) {
      length_of_msisdn = b.length_of_msisdn;
      msisdn = b.msisdn;
      tlv.add_length(1+length_of_msisdn);
    }
    if (u1.bf.naif) {
      length_of_nai = b.length_of_nai;
      nai = b.nai;
      tlv.add_length(1+length_of_nai);
    }
  }
  //--------
  pfcp_user_id_ie() : pfcp_ie(PFCP_IE_USER_ID){
    u1.b = 0;
    length_of_imsi = 0;
    length_of_imei = 0;
    length_of_msisdn = 0;
    length_of_nai = 0;
    imsi = {};
    imei = {};
    msisdn = {};
    nai = {};
    tlv.set_length(1);
  }
  //--------
  pfcp_user_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
  };
  //--------
  void to_core_type(core::pfcp::user_id_t& b) {
    b.naif = u1.bf.naif;
    b.msisdnf = u1.bf.msisdnf;
    b.imeif = u1.bf.imeif;
    b.imsif = u1.bf.imsif;
    if (u1.bf.imsif) {
      b.length_of_imsi = length_of_imsi;
      b.imsi = imsi;
    }
    if (u1.bf.imeif) {
      b.length_of_imei = length_of_imei;
      b.imei = imei;
    }
    if (u1.bf.msisdnf) {
      b.length_of_msisdn = length_of_msisdn;
      b.msisdn = msisdn;
    }
    if (u1.bf.naif) {
      b.length_of_nai = length_of_nai;
      b.nai = nai;
    }
  }
  //--------
  void dump_to(std::ostream& os) {
    if (u1.bf.imsif) {
      if (imsi.num_digits > 15) imsi.num_digits = 15;
      length_of_imsi = imsi.num_digits / 2;
      if (imsi.num_digits & 1) {
        imsi.u1.b[length_of_imsi] |= 0xF0;
        length_of_imsi++;
      }
      tlv.add_length(1+length_of_imsi);
    }
    if (u1.bf.imeif) {
      tlv.add_length(1+length_of_imei);
    }
    if (u1.bf.msisdnf) {
      if (msisdn.num_digits > 15) msisdn.num_digits = 15;
      length_of_msisdn = msisdn.num_digits / 2;
      if (msisdn.num_digits & 1) {
        msisdn.u1.b[length_of_msisdn] |= 0xF0;
        length_of_msisdn++;
      }
      tlv.add_length(1+length_of_msisdn);
    }
    if (u1.bf.naif) {
      tlv.add_length(1+length_of_nai);
    }

    tlv.dump_to(os);
    os.write(reinterpret_cast<const char*>(&u1.b), sizeof(u1.b));
    if (u1.bf.imsif) {
      os.write(reinterpret_cast<const char*>(&length_of_imsi), sizeof(length_of_imsi));
      os.write(reinterpret_cast<const char*>(&imsi.u1.b[0]), length_of_imsi);
    }
    if (u1.bf.imeif) {
      os.write(reinterpret_cast<const char*>(&length_of_imei), sizeof(length_of_imei));
      os << imei;
    }
    if (u1.bf.msisdnf) {
      os.write(reinterpret_cast<const char*>(&length_of_msisdn), sizeof(length_of_msisdn));
      os.write(reinterpret_cast<const char*>(&msisdn.u1.b[0]), length_of_msisdn);
    }
    if (u1.bf.naif) {
      os.write(reinterpret_cast<const char*>(&length_of_nai), sizeof(length_of_nai));
      os << nai;
    }
  }
  //--------
  void load_from(std::istream& is) {
    //tlv.load_from(is);
    if (tlv.get_length() != 1) {
      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
    }
    is.read(reinterpret_cast<char*>(&u1.b), sizeof(u1.b));
    if (u1.bf.imsif) {
      is.read(reinterpret_cast<char*>(&length_of_imsi), sizeof(length_of_imsi));
      is.read(reinterpret_cast<char*>(imsi.u1.b), length_of_imsi);
      imsi.num_digits = length_of_imsi*2;
      if ((imsi.u1.b[length_of_imsi-1] & 0xF0) == 0xF0) {
        imsi.num_digits -= 1;
      }
      if (imsi.num_digits > 15) imsi.num_digits = 15; // should not happen
    }
    if (u1.bf.imeif) {
      is.read(reinterpret_cast<char*>(&length_of_imei), sizeof(length_of_imei));
      char e[length_of_imei];
      is.read(e, length_of_imei);
      imei.assign(e, length_of_imei);
    }
    if (u1.bf.msisdnf) {
      is.read(reinterpret_cast<char*>(&length_of_msisdn), sizeof(length_of_msisdn));
      is.read(reinterpret_cast<char*>(msisdn.u1.b), length_of_msisdn);
      msisdn.num_digits = length_of_msisdn*2;
      if ((msisdn.u1.b[length_of_msisdn-1] & 0xF0) == 0xF0) {
        msisdn.num_digits -= 1;
      }
    }
    if (u1.bf.naif) {
      is.read(reinterpret_cast<char*>(&length_of_nai), sizeof(length_of_nai));
      char e[length_of_nai];
      is.read(e, length_of_nai);
      nai.assign(e, length_of_nai);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
      core::pfcp::user_id_t user_id = {};
      to_core_type(user_id);
      s.set(user_id);
  }
};
////-------------------------------------
//// IE ETHERNET_PDU_SESSION_INFORMATION
//class pfcp_ethernet_pdu_session_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_ethernet_pdu_session_information_ie(const core::pfcp::ethernet_pdu_session_information_t& b) : pfcp_ie(PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_pdu_session_information_ie() : pfcp_ie(PFCP_IE_ETHERNET_PDU_SESSION_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_pdu_session_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::ethernet_pdu_session_information_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::ethernet_pdu_session_information_t ethernet_pdu_session_information = {};
//      to_core_type(ethernet_pdu_session_information);
//      s.set(ethernet_pdu_session_information);
//  }
//};
////-------------------------------------
//// IE ETHERNET_TRAFFIC_INFORMATION
//class pfcp_ethernet_traffic_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_ethernet_traffic_information_ie(const core::pfcp::ethernet_traffic_information& b) : pfcp_ie(PFCP_IE_ETHERNET_TRAFFIC_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_traffic_information_ie() : pfcp_ie(PFCP_IE_ETHERNET_TRAFFIC_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_traffic_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::ethernet_traffic_information& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::ethernet_traffic_information ethernet_traffic_information = {};
//      to_core_type(ethernet_traffic_information);
//      s.set(ethernet_traffic_information);
//  }
//};
////-------------------------------------
//// IE MAC_ADDRESSES_DETECTED
//class pfcp_mac_addresses_detected_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_mac_addresses_detected_ie(const core::pfcp::mac_addresses_detected_t& b) : pfcp_ie(PFCP_IE_MAC_ADDRESSES_DETECTED){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_mac_addresses_detected_ie() : pfcp_ie(PFCP_IE_MAC_ADDRESSES_DETECTED){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_mac_addresses_detected_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::mac_addresses_detected_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::mac_addresses_detected_t mac_addresses_detected = {};
//      to_core_type(mac_addresses_detected);
//      s.set(mac_addresses_detected);
//  }
//};
////-------------------------------------
//// IE MAC_ADDRESSES_REMOVED
//class pfcp_mac_addresses_removed_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_mac_addresses_removed_ie(const core::pfcp::mac_addresses_removed_t& b) : pfcp_ie(PFCP_IE_MAC_ADDRESSES_REMOVED){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_mac_addresses_removed_ie() : pfcp_ie(PFCP_IE_MAC_ADDRESSES_REMOVED){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_mac_addresses_removed_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::mac_addresses_removed_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::mac_addresses_removed_t mac_addresses_removed = {};
//      to_core_type(mac_addresses_removed);
//      s.set(mac_addresses_removed);
//  }
//};
////-------------------------------------
//// IE ETHERNET_INACTIVITY_TIMER
//class pfcp_ethernet_inactivity_timer_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_ethernet_inactivity_timer_ie(const core::pfcp::ethernet_inactivity_timer_t& b) : pfcp_ie(PFCP_IE_ETHERNET_INACTIVITY_TIMER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_inactivity_timer_ie() : pfcp_ie(PFCP_IE_ETHERNET_INACTIVITY_TIMER){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_ethernet_inactivity_timer_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::ethernet_inactivity_timer_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::ethernet_inactivity_timer_t ethernet_inactivity_timer = {};
//      to_core_type(ethernet_inactivity_timer);
//      s.set(ethernet_inactivity_timer);
//  }
//};
////-------------------------------------
//// IE ADDITIONAL_MONITORING_TIME
//class pfcp_additional_monitoring_time_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_additional_monitoring_time_ie(const core::pfcp::additional_monitoring_time& b) : pfcp_ie(PFCP_IE_ADDITIONAL_MONITORING_TIME){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_additional_monitoring_time_ie() : pfcp_ie(PFCP_IE_ADDITIONAL_MONITORING_TIME){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_additional_monitoring_time_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::additional_monitoring_time& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::additional_monitoring_time additional_monitoring_time = {};
//      to_core_type(additional_monitoring_time);
//      s.set(additional_monitoring_time);
//  }
//};
////-------------------------------------
//// IE EVENT_INFORMATION
//class pfcp_event_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_event_information_ie(const core::pfcp::event_information& b) : pfcp_ie(PFCP_IE_EVENT_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_event_information_ie() : pfcp_ie(PFCP_IE_EVENT_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_event_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::event_information& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::event_information event_information = {};
//      to_core_type(event_information);
//      s.set(event_information);
//  }
//};
////-------------------------------------
//// IE EVENT_REPORTING
//class pfcp_event_reporting_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_event_reporting_ie(const core::pfcp::event_reporting& b) : pfcp_ie(PFCP_IE_EVENT_REPORTING){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_event_reporting_ie() : pfcp_ie(PFCP_IE_EVENT_REPORTING){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_event_reporting_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::event_reporting& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::event_reporting event_reporting = {};
//      to_core_type(event_reporting);
//      s.set(event_reporting);
//  }
//};
////-------------------------------------
//// IE EVENT_ID
//class pfcp_event_id_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_event_id_ie(const core::pfcp::event_id_t& b) : pfcp_ie(PFCP_IE_EVENT_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_event_id_ie() : pfcp_ie(PFCP_IE_EVENT_ID){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_event_id_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::event_id_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::event_id_t event_id = {};
//      to_core_type(event_id);
//      s.set(event_id);
//  }
//};
////-------------------------------------
//// IE EVENT_THRESHOLD
//class pfcp_event_threshold_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_event_threshold_ie(const core::pfcp::event_threshold_t& b) : pfcp_ie(PFCP_IE_EVENT_THRESHOLD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_event_threshold_ie() : pfcp_ie(PFCP_IE_EVENT_THRESHOLD){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_event_threshold_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::event_threshold_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::event_threshold_t event_threshold = {};
//      to_core_type(event_threshold);
//      s.set(event_threshold);
//  }
//};
////-------------------------------------
//// IE TRACE_INFORMATION
//class pfcp_trace_information_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_trace_information_ie(const core::pfcp::trace_information_t& b) : pfcp_ie(PFCP_IE_TRACE_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_trace_information_ie() : pfcp_ie(PFCP_IE_TRACE_INFORMATION){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_trace_information_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::trace_information_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::trace_information_t trace_information = {};
//      to_core_type(trace_information);
//      s.set(trace_information);
//  }
//};
////-------------------------------------
//// IE FRAMED_ROUTE
//class pfcp_framed_route_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_framed_route_ie(const core::pfcp::framed_route_t& b) : pfcp_ie(PFCP_IE_FRAMED_ROUTE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_framed_route_ie() : pfcp_ie(PFCP_IE_FRAMED_ROUTE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_framed_route_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::framed_route_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::framed_route_t framed_route = {};
//      to_core_type(framed_route);
//      s.set(framed_route);
//  }
//};
////-------------------------------------
//// IE FRAMED_ROUTING
//class pfcp_framed_routing_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_framed_routing_ie(const core::pfcp::framed_routing_t& b) : pfcp_ie(PFCP_IE_FRAMED_ROUTING){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_framed_routing_ie() : pfcp_ie(PFCP_IE_FRAMED_ROUTING){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_framed_routing_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::framed_routing_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::framed_routing_t framed_routing = {};
//      to_core_type(framed_routing);
//      s.set(framed_routing);
//  }
//};
////-------------------------------------
//// IE FRAMED_IPV6_ROUTE
//class pfcp_framed_ipv6_route_ie : public pfcp_ie {
//public:
//  uint8_t todo;
//
//  //--------
//  pfcp_framed_ipv6_route_ie(const core::pfcp::framed_ipv6_route_t& b) : pfcp_ie(PFCP_IE_FRAMED_IPV6_ROUTE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_framed_ipv6_route_ie() : pfcp_ie(PFCP_IE_FRAMED_IPV6_ROUTE){
//    todo = 0;
//    tlv.set_length(1);
//  }
//  //--------
//  pfcp_framed_ipv6_route_ie(const pfcp_tlv& t) : pfcp_ie(t) {
//    todo = 0;
//  };
//  //--------
//  void to_core_type(core::pfcp::framed_ipv6_route_t& b) {
//    b.todo = todo;
//  }
//  //--------
//  void dump_to(std::ostream& os) {
//    tlv.dump_to(os);
//    os.write(reinterpret_cast<const char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void load_from(std::istream& is) {
//    //tlv.load_from(is);
//    if (tlv.get_length() != 1) {
//      throw pfcp_tlv_bad_length_exception(tlv.type, tlv.get_length());
//    }
//    is.read(reinterpret_cast<char*>(&todo), sizeof(todo));
//  }
//  //--------
//  void to_core_type(pfcp_ies_container& s) {
//      core::pfcp::framed_ipv6_route_t framed_ipv6_route = {};
//      to_core_type(framed_ipv6_route);
//      s.set(framed_ipv6_route);
//  }
//};

//-------------------------------------
// IE PDI
class pfcp_pdi_ie : public pfcp_grouped_ie {
public:
  //--------
  pfcp_pdi_ie(const core::pfcp::pdi& b) : pfcp_grouped_ie(PFCP_IE_PDI){
    tlv.set_length(0);
    if (b.source_interface.first) {std::shared_ptr<pfcp_source_interface_ie> sie(new pfcp_source_interface_ie(b.source_interface.second)); add_ie(sie);}
    if (b.local_fteid.first) {std::shared_ptr<pfcp_fteid_ie> sie(new pfcp_fteid_ie(b.local_fteid.second)); add_ie(sie);}
    if (b.network_instance.first) {std::shared_ptr<pfcp_network_instance_ie> sie(new pfcp_network_instance_ie(b.network_instance.second)); add_ie(sie);}
    if (b.ue_ip_address.first) {std::shared_ptr<pfcp_ue_ip_address_ie> sie(new pfcp_ue_ip_address_ie(b.ue_ip_address.second)); add_ie(sie);}
    //if (b.traffic_endpoint_id.first) {std::shared_ptr<pfcp_traffic_endpoint_id_ie> sie(new pfcp_traffic_endpoint_id_ie(b.traffic_endpoint_id.second)); add_ie(sie);}
    if (b.sdf_filter.first) {std::shared_ptr<pfcp_sdf_filter_ie> sie(new pfcp_sdf_filter_ie(b.sdf_filter.second)); add_ie(sie);}
    if (b.application_id.first) {std::shared_ptr<pfcp_application_id_ie> sie(new pfcp_application_id_ie(b.application_id.second)); add_ie(sie);}
    //if (b.ethernet_packet_filter.first) {std::shared_ptr<pfcp_ethernet_packet_filter_ie> sie(new pfcp_ethernet_packet_filter_ie(b.ethernet_packet_filter.second)); add_ie(sie);}
    if (b.qfi.first) {std::shared_ptr<pfcp_qfi_ie> sie(new pfcp_qfi_ie(b.qfi.second)); add_ie(sie);}
    //if (b.framed_route.first) {std::shared_ptr<pfcp_framed_route_ie> sie(new pfcp_framed_route_ie(b.framed_route.second)); add_ie(sie);}
    //if (b.framed_routing.first) {std::shared_ptr<pfcp_framed_routing_ie> sie(new pfcp_framed_routing_ie(b.framed_routing.second)); add_ie(sie);}
    //if (b.framed_ipv6_route.first) {std::shared_ptr<pfcp_framed_ipv6_route_ie> sie(new pfcp_framed_ipv6_route_ie(b.framed_ipv6_route.second)); add_ie(sie);}
  }
  //--------
  pfcp_pdi_ie() : pfcp_grouped_ie(PFCP_IE_PDI){
  }
  //--------
  pfcp_pdi_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::pdi& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::pdi i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE FORWARDING_PARAMETERS
class pfcp_forwarding_parameters_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_forwarding_parameters_ie(const core::pfcp::forwarding_parameters& b) : pfcp_grouped_ie(PFCP_IE_FORWARDING_PARAMETERS){
    tlv.set_length(0);
    if (b.destination_interface.first) {std::shared_ptr<pfcp_destination_interface_ie> sie(new pfcp_destination_interface_ie(b.destination_interface.second)); add_ie(sie);}
    if (b.network_instance.first) {std::shared_ptr<pfcp_network_instance_ie> sie(new pfcp_network_instance_ie(b.network_instance.second)); add_ie(sie);}
    //if (b.redirect_information.first) {std::shared_ptr<pfcp_redirect_information_ie> sie(new pfcp_redirect_information_ie(b.redirect_information.second)); add_ie(sie);}
    if (b.outer_header_creation.first) {std::shared_ptr<pfcp_outer_header_creation_ie> sie(new pfcp_outer_header_creation_ie(b.outer_header_creation.second)); add_ie(sie);}
    if (b.transport_level_marking.first) {std::shared_ptr<pfcp_transport_level_marking_ie> sie(new pfcp_transport_level_marking_ie(b.transport_level_marking.second)); add_ie(sie);}
    if (b.forwarding_policy.first) {std::shared_ptr<pfcp_forwarding_policy_ie> sie(new pfcp_forwarding_policy_ie(b.forwarding_policy.second)); add_ie(sie);}
    //if (b.header_enrichment.first) {std::shared_ptr<pfcp_header_enrichment_ie> sie(new pfcp_header_enrichment_ie(b.header_enrichment.second)); add_ie(sie);}
    //if (b.linked_traffic_endpoint_id_t.first) {std::shared_ptr<pfcp_linked_traffic_endpoint_id_t_ie> sie(new pfcp_linked_traffic_endpoint_id_t_ie(b.linked_traffic_endpoint_id_t.second)); add_ie(sie);}
    //if (b.proxying.first) {std::shared_ptr<pfcp_proxying_ie> sie(new pfcp_proxying_ie(b.proxying.second)); add_ie(sie);}
  }
  //--------
  pfcp_forwarding_parameters_ie() : pfcp_grouped_ie(PFCP_IE_FORWARDING_PARAMETERS){
  }
  //--------
  pfcp_forwarding_parameters_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::forwarding_parameters& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::forwarding_parameters v = {};
    to_core_type(v);
    s.set(v);
  }
};
//-------------------------------------
// IE DUPLICATING_PARAMETERS
class pfcp_duplicating_parameters_ie : public pfcp_grouped_ie {
public:
  //--------
  pfcp_duplicating_parameters_ie(const core::pfcp::duplicating_parameters& b) : pfcp_grouped_ie(PFCP_IE_DUPLICATING_PARAMETERS){
    tlv.set_length(0);
  }
  //--------
  pfcp_duplicating_parameters_ie() : pfcp_grouped_ie(PFCP_IE_DUPLICATING_PARAMETERS){
  }
  //--------
  pfcp_duplicating_parameters_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::duplicating_parameters& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::duplicating_parameters i = {};
    to_core_type(i);
    s.set(i);
  }
};

//-------------------------------------
// IE CREATE_PDR
class pfcp_create_pdr_ie : public pfcp_grouped_ie {
public:


  //--------
  pfcp_create_pdr_ie(const core::pfcp::create_pdr& b) : pfcp_grouped_ie(PFCP_IE_CREATE_PDR) {
    tlv.set_length(0);
    if (b.pdr_id.first) {std::shared_ptr<pfcp_pdr_id_ie> sie(new pfcp_pdr_id_ie(b.pdr_id.second)); add_ie(sie);}
    if (b.precedence.first) {std::shared_ptr<pfcp_precedence_ie> sie(new pfcp_precedence_ie(b.precedence.second)); add_ie(sie);}
    if (b.pdi.first) {std::shared_ptr<pfcp_pdi_ie> sie(new pfcp_pdi_ie(b.pdi.second)); add_ie(sie);}
    if (b.outer_header_removal.first) {std::shared_ptr<pfcp_outer_header_removal_ie> sie(new pfcp_outer_header_removal_ie(b.outer_header_removal.second)); add_ie(sie);}
    if (b.far_id.first) {std::shared_ptr<pfcp_far_id_ie> sie(new pfcp_far_id_ie(b.far_id.second)); add_ie(sie);}
    if (b.urr_id.first) {std::shared_ptr<pfcp_urr_id_ie> sie(new pfcp_urr_id_ie(b.urr_id.second)); add_ie(sie);}
    if (b.qer_id.first) {std::shared_ptr<pfcp_qer_id_ie> sie(new pfcp_qer_id_ie(b.qer_id.second)); add_ie(sie);}
    if (b.activate_predefined_rules.first) {std::shared_ptr<pfcp_activate_predefined_rules_ie> sie(new pfcp_activate_predefined_rules_ie(b.activate_predefined_rules.second)); add_ie(sie);}
  }
  //--------
  pfcp_create_pdr_ie() : pfcp_grouped_ie(PFCP_IE_CREATE_PDR){
  }
  //--------
  pfcp_create_pdr_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::create_pdr& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::create_pdr i = {};
    to_core_type(i);
    s.add(i);
  }
};
//-------------------------------------
// IE CREATE_FAR
class pfcp_create_far_ie : public pfcp_grouped_ie {
public:
  //--------
  pfcp_create_far_ie(const core::pfcp::create_far& b) : pfcp_grouped_ie(PFCP_IE_CREATE_FAR){
    tlv.set_length(0);
    if (b.far_id.first) {std::shared_ptr<pfcp_far_id_ie> sie(new pfcp_far_id_ie(b.far_id.second)); add_ie(sie);}
    if (b.apply_action.first) {std::shared_ptr<pfcp_apply_action_ie> sie(new pfcp_apply_action_ie(b.apply_action.second)); add_ie(sie);}
    if (b.forwarding_parameters.first) {std::shared_ptr<pfcp_forwarding_parameters_ie> sie(new pfcp_forwarding_parameters_ie(b.forwarding_parameters.second)); add_ie(sie);}
    if (b.duplicating_parameters.first) {std::shared_ptr<pfcp_duplicating_parameters_ie> sie(new pfcp_duplicating_parameters_ie(b.duplicating_parameters.second)); add_ie(sie);}
    if (b.bar_id.first) {std::shared_ptr<pfcp_bar_id_ie> sie(new pfcp_bar_id_ie(b.bar_id.second)); add_ie(sie);}
  }
  //--------
  pfcp_create_far_ie() : pfcp_grouped_ie(PFCP_IE_CREATE_FAR){
  }
  //--------
  pfcp_create_far_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::create_far& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::create_far i = {};
    to_core_type(i);
    s.add(i);
  }
};
//-------------------------------------
// IE CREATE_URR
class pfcp_create_urr_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_create_urr_ie(const core::pfcp::create_urr& b) : pfcp_grouped_ie(PFCP_IE_CREATE_URR){
    tlv.set_length(0);
  }
  //--------
  pfcp_create_urr_ie() : pfcp_grouped_ie(PFCP_IE_CREATE_URR){
  }
  //--------
  pfcp_create_urr_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::duplicating_parameters& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::create_urr i = {};
    to_core_type(i);
    s.add(i);
  }
};
//-------------------------------------
// IE CREATE_QER
class pfcp_create_qer_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_create_qer_ie(const core::pfcp::create_qer& b) : pfcp_grouped_ie(PFCP_IE_CREATE_QER){
    tlv.set_length(0);
  }
  //--------
  pfcp_create_qer_ie() : pfcp_grouped_ie(PFCP_IE_CREATE_QER){
  }
  //--------
  pfcp_create_qer_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::create_qer& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::create_qer i = {};
    to_core_type(i);
    s.add(i);
  }
};
//-------------------------------------
// IE CREATED_PDR
class pfcp_created_pdr_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_created_pdr_ie(const core::pfcp::created_pdr& b) : pfcp_grouped_ie(PFCP_IE_CREATED_PDR){
    tlv.set_length(0);
  }
  //--------
  pfcp_created_pdr_ie() : pfcp_grouped_ie(PFCP_IE_CREATED_PDR){
  }
  //--------
  pfcp_created_pdr_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::created_pdr& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::created_pdr i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE UPDATE_PDR
class pfcp_update_pdr_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_update_pdr_ie(const core::pfcp::update_pdr& b) : pfcp_grouped_ie(PFCP_IE_UPDATE_PDR){
    tlv.set_length(0);
  }
  //--------
  pfcp_update_pdr_ie() : pfcp_grouped_ie(PFCP_IE_UPDATE_PDR){
  }
  //--------
  pfcp_update_pdr_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::update_pdr& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::update_pdr i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE UPDATE_FAR
class pfcp_update_far_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_update_far_ie(const core::pfcp::update_far& b) : pfcp_grouped_ie(PFCP_IE_UPDATE_FAR){
    tlv.set_length(0);
  }
  //--------
  pfcp_update_far_ie() : pfcp_grouped_ie(PFCP_IE_UPDATE_FAR){
  }
  //--------
  pfcp_update_far_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::update_far& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::update_far i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE UPDATE_FORWARDING_PARAMETERS
class pfcp_update_forwarding_parameters_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_update_forwarding_parameters_ie(const core::pfcp::update_forwarding_parameters& b) :
        pfcp_grouped_ie(PFCP_IE_UPDATE_FORWARDING_PARAMETERS){
    tlv.set_length(0);
  }
  //--------
  pfcp_update_forwarding_parameters_ie() : pfcp_grouped_ie(PFCP_IE_UPDATE_FORWARDING_PARAMETERS){
  }
  //--------
  pfcp_update_forwarding_parameters_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::update_forwarding_parameters& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::update_forwarding_parameters i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE UPDATE_BAR_WITHIN_SESSION_MODIFICATION_REQUEST
class pfcp_update_bar_within_pfcp_session_report_response_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_update_bar_within_pfcp_session_report_response_ie(const core::pfcp::update_bar_within_pfcp_session_report_response& b) : pfcp_grouped_ie(PFCP_IE_UPDATE_BAR_WITHIN_PFCP_SESSION_REPORT_RESPONSE){
    tlv.set_length(0);
  }
  //--------
  pfcp_update_bar_within_pfcp_session_report_response_ie() : pfcp_grouped_ie(PFCP_IE_UPDATE_BAR_WITHIN_PFCP_SESSION_REPORT_RESPONSE){
  }
  //--------
  pfcp_update_bar_within_pfcp_session_report_response_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::update_bar_within_pfcp_session_report_response& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::update_bar_within_pfcp_session_report_response i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE UPDATE_URR
class pfcp_update_urr_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_update_urr_ie(const core::pfcp::update_urr& b) : pfcp_grouped_ie(PFCP_IE_UPDATE_URR){
    tlv.set_length(0);
  }
  //--------
  pfcp_update_urr_ie() : pfcp_grouped_ie(PFCP_IE_UPDATE_URR){
  }
  //--------
  pfcp_update_urr_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::update_urr& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::update_urr i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE UPDATE_QER
class pfcp_update_qer_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_update_qer_ie(const core::pfcp::update_qer& b) : pfcp_grouped_ie(PFCP_IE_UPDATE_QER){
    tlv.set_length(0);
  }
  //--------
  pfcp_update_qer_ie() : pfcp_grouped_ie(PFCP_IE_UPDATE_QER){
  }
  //--------
  pfcp_update_qer_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::update_qer& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::update_qer i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE REMOVE_PDR
class pfcp_remove_pdr_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_remove_pdr_ie(const core::pfcp::remove_pdr& b) : pfcp_grouped_ie(PFCP_IE_REMOVE_PDR){
    tlv.set_length(0);
  }
  //--------
  pfcp_remove_pdr_ie() : pfcp_grouped_ie(PFCP_IE_REMOVE_PDR){
  }
  //--------
  pfcp_remove_pdr_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::remove_pdr& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::remove_pdr i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE REMOVE_FAR
class pfcp_remove_far_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_remove_far_ie(const core::pfcp::remove_far& b) : pfcp_grouped_ie(PFCP_IE_REMOVE_FAR){
    tlv.set_length(0);
  }
  //--------
  pfcp_remove_far_ie() : pfcp_grouped_ie(PFCP_IE_REMOVE_FAR){
  }
  //--------
  pfcp_remove_far_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::remove_far& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::remove_far i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE REMOVE_URR
class pfcp_remove_urr_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_remove_urr_ie(const core::pfcp::remove_urr& b) : pfcp_grouped_ie(PFCP_IE_REMOVE_URR){
    tlv.set_length(0);
  }
  //--------
  pfcp_remove_urr_ie() : pfcp_grouped_ie(PFCP_IE_REMOVE_URR){
  }
  //--------
  pfcp_remove_urr_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::remove_urr& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::remove_urr i = {};
    to_core_type(i);
    s.set(i);
  }
};
//-------------------------------------
// IE REMOVE_QER
class pfcp_remove_qer_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_remove_qer_ie(const core::pfcp::remove_qer& b) : pfcp_grouped_ie(PFCP_IE_REMOVE_QER){
    tlv.set_length(0);
  }
  //--------
  pfcp_remove_qer_ie() : pfcp_grouped_ie(PFCP_IE_REMOVE_QER){
  }
  //--------
  pfcp_remove_qer_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::remove_qer& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::remove_qer i = {};
    to_core_type(i);
    s.set(i);
  }
};

//-------------------------------------
// IE CREATE_TRAFFIC_ENDPOINT
class pfcp_create_traffic_endpoint_ie : public pfcp_grouped_ie {
public:

  //--------
  pfcp_create_traffic_endpoint_ie(const core::pfcp::create_traffic_endpoint& b) : pfcp_grouped_ie(PFCP_IE_CREATE_TRAFFIC_ENDPOINT){
    tlv.set_length(0);
  }
  //--------
  pfcp_create_traffic_endpoint_ie() : pfcp_grouped_ie(PFCP_IE_CREATE_TRAFFIC_ENDPOINT){
  }
  //--------
  pfcp_create_traffic_endpoint_ie(const pfcp_tlv& t) : pfcp_grouped_ie(t){
  }
  //--------
  void to_core_type(core::pfcp::create_traffic_endpoint& c) {
    for (auto sie : ies) {
      sie.get()->to_core_type(c);
    }
  }
  //--------
  void to_core_type(pfcp_ies_container& s) {
    core::pfcp::create_traffic_endpoint i = {};
    to_core_type(i);
    s.set(i);
  }
};


} // namespace pfcp

#endif /* FILE_3GPP_129_244_HPP_SEEN */
