/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <core.p4>
#include <v1model.p4>

// CPU_PORT specifies the P4 port number associated to controller packet-in and
// packet-out. All packets forwarded via this port will be delivered to the
// controller as P4Runtime PacketIn messages. Similarly, PacketOut messages from
// the controller will be seen by the P4 pipeline as coming from the CPU_PORT.
#define CPU_PORT 255
#define MY_MULTICAST_LOGICAL_PORT 233
// CPU_CLONE_SESSION_ID specifies the mirroring session for packets to be cloned
// to the CPU port. Packets associated with this session ID will be cloned to
// the CPU_PORT as well as being transmitted via their egress port (set by the
// bridging/routing/acl table). For cloning to work, the P4Runtime controller
// needs first to insert a CloneSessionEntry that maps this session ID to the
// CPU_PORT.
#define CPU_CLONE_SESSION_ID 99

// Maximum number of hops supported when using SRv6.
// Required for Exercise 7.
#define SRV6_MAX_HOPS 4

/* CONSTANTS */
#define NUM_PORTS 6
#define NUM_BATCHES 2

#define REGISTER_SIZE_TOTAL 6144 //256
#define REGISTER_BATCH_SIZE REGISTER_SIZE_TOTAL/NUM_BATCHES
#define REGISTER_PORT_SIZE REGISTER_BATCH_SIZE/NUM_PORTS

#define REGISTER_CELL_WIDTH 128

#define LOSS_CHANGE_OF_BATCH 0x1234

typedef bit<9>   port_num_t;
typedef bit<48>  mac_addr_t;
typedef bit<16>  mcast_group_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;
typedef bit<16>  l4_port_t;

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_PROBE = 0x0812;

const bit<8> IP_PROTO_ICMP   = 1;
const bit<8> IP_PROTO_TCP    = 6;
const bit<8> IP_PROTO_UDP    = 17;
const bit<8> IP_PROTO_SRV6   = 43;
const bit<8> IP_PROTO_ICMPV6 = 58;
const bit<8> TYPE_LOSS = 0xFC;

const mac_addr_t IPV6_MCAST_01 = 0x33_33_00_00_00_01;

const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;

const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;

const bit<32> NDP_FLAG_ROUTER    = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;
const bit<32> NDP_FLAG_OVERRIDE  = 0x20000000;


//------------------------------------------------------------------------------
// HEADER DEFINITIONS
//------------------------------------------------------------------------------

header ethernet_t {
    mac_addr_t  dst_addr;
    mac_addr_t  src_addr;
    bit<16>     ether_type;
}

header link_qual_t {
    bit<32> throughput;

}
header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header loss_t {

    bit<1> batch_id;
    bit<7> padding; // to be able to add 2 bytes to the IP header length
    bit<8> nextProtocol;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    traffic_class;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr;
    bit<8>    hop_limit;
    bit<128>  src_addr;
    bit<128>  dst_addr;
}

header srv6h_t {
    bit<8>   next_hdr;
    bit<8>   hdr_ext_len;
    bit<8>   routing_type;
    bit<8>   segment_left;
    bit<8>   last_entry;
    bit<8>   flags;
    bit<16>  tag;
}

header srv6_list_t {
    bit<128>  segment_id;
}

header tcp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<3>   res;
    bit<3>   ecn;
    bit<6>   ctrl;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header icmp_t {
    bit<8>   type;
    bit<8>   icmp_code;
    bit<16>  checksum;
    bit<16>  identifier;
    bit<16>  sequence_number;
    bit<64>  timestamp;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_t {
    bit<32>      flags;
    ipv6_addr_t  target_ipv6_addr;
    // NDP option.
    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}

// fill metadata in it
header probe_t {

}

// Packet-in header. Prepended to packets sent to the CPU_PORT and used by the
// P4Runtime server (Stratum) to populate the PacketIn message metadata fields.
// Here we use it to carry the original ingress port where the packet was
// received.
@controller_header("packet_in")
header cpu_in_header_t {
    port_num_t  ingress_port;
    bit<7>      _pad;
}

// Packet-out header. Prepended to packets received from the CPU_PORT. Fields of
// this header are populated by the P4Runtime server based on the P4Runtime
// PacketOut metadata fields. Here we use it to inform the P4 pipeline on which
// port this packet-out should be transmitted.
@controller_header("packet_out")
header cpu_out_header_t {
    port_num_t  egress_port;
    bit<7>      _pad;
}


struct parsed_headers_t {
    cpu_out_header_t cpu_out;
    cpu_in_header_t cpu_in;
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv6_t ipv6;
    srv6h_t srv6h;
    srv6_list_t[SRV6_MAX_HOPS] srv6_list;
    loss_t loss;
    tcp_t tcp;
    udp_t udp;
    icmp_t icmp;
    icmpv6_t icmpv6;
    ndp_t ndp;
}

struct local_metadata_t {
    l4_port_t   l4_src_port;
    l4_port_t   l4_dst_port;
    bool        is_multicast;
    ipv6_addr_t next_srv6_sid;
    bit<8>      ip_proto;
    bit<8>      icmp_type;
    bit<9>      original_ingress_port;
    bit<32> slice_id;
    bit<32> priority;

    bit<16> tmp_src_port;
    bit<16> tmp_dst_port;
    bit<16> um_h1;
    bit<16> um_h2;
    bit<16> um_h3;
    bit<16> dm_h1;
    bit<16> dm_h2;
    bit<16> dm_h3;
    bit<128> tmp_ip_src;
    bit<128> tmp_ip_dst;
    bit<128> tmp_ports_proto;
    bit<128> tmp_counter;
    bit<16> previous_batch_id;
    bit<16> batch_id;
    bit<16> last_local_batch_id;
    bit<1> dont_execute_um;
    bit<1> dont_execute_dm;
    bit<32> meter_tag;
}


//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   inout local_metadata_t local_metadata,
                   inout standard_metadata_t standard_metadata)
{
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.cpu_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        local_metadata.ip_proto = hdr.ipv4.protocol;
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        local_metadata.ip_proto = hdr.ipv6.next_hdr;
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            IP_PROTO_SRV6: parse_srv6;
            TYPE_LOSS: parse_loss;
            default: accept;
        }
    }
    
    state parse_loss {
        packet.extract(hdr.loss);
        transition select(hdr.loss.nextProtocol){
            IP_PROTO_TCP : parse_tcp;
            IP_PROTO_UDP : parse_udp;
            default: accept;
        }
    }
    
    state parse_tcp {
        packet.extract(hdr.tcp);
        local_metadata.l4_src_port = hdr.tcp.src_port;
        local_metadata.l4_dst_port = hdr.tcp.dst_port;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        local_metadata.l4_src_port = hdr.udp.src_port;
        local_metadata.l4_dst_port = hdr.udp.dst_port;
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        local_metadata.icmp_type = hdr.icmp.type;
        transition accept;
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        local_metadata.icmp_type = hdr.icmpv6.type;
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition accept;
    }

    state parse_srv6 {
        packet.extract(hdr.srv6h);
        transition parse_srv6_list;
    }

    state parse_srv6_list {
        packet.extract(hdr.srv6_list.next);
        bool next_segment = (bit<32>)hdr.srv6h.segment_left - 1 == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(next_segment) {
            true: mark_current_srv6;
            default: check_last_srv6;
        }
    }

    state mark_current_srv6 {
        local_metadata.next_srv6_sid = hdr.srv6_list.last.segment_id;
        transition check_last_srv6;
    }

    state check_last_srv6 {
        // working with bit<8> and int<32> which cannot be cast directly; using
        // bit<32> as common intermediate type for comparision
        bool last_segment = (bit<32>)hdr.srv6h.last_entry == (bit<32>)hdr.srv6_list.lastIndex;
        transition select(last_segment) {
           true: parse_srv6_next_hdr;
           false: parse_srv6_list;
        }
    }

    state parse_srv6_next_hdr {
        transition select(hdr.srv6h.next_hdr) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }
}

control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta)
{
    // Not used here. We assume all packets have valid checksum, if not, we let
    // the end hosts detect errors.
    apply { /* EMPTY */ }
}


control IngressPipeImpl (inout parsed_headers_t    hdr,
                         inout local_metadata_t    local_metadata,
                         inout standard_metadata_t standard_metadata) {

    register<bit<16>>(1) last_batch_id;

    // 128 + 128 + 48 = 304
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) um_ip_src;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) um_ip_dst;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) um_ports_proto; // 16 + 16 + 16 = 48
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) um_counter;

    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) dm_ip_src;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) dm_ip_dst;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) dm_ports_proto;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) dm_counter;

    action compute_hash_indexes(){

         // Compute hash indexes for upstream meter
        hash(local_metadata.um_h1, HashAlgorithm.crc32_custom, ((local_metadata.batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.egress_spec-1)*REGISTER_PORT_SIZE))), {hdr.ipv6.src_addr,  hdr.ipv6.dst_addr,
         local_metadata.tmp_src_port, local_metadata.tmp_dst_port, hdr.loss.nextProtocol}, (bit<16>)REGISTER_PORT_SIZE);
        hash(local_metadata.um_h2, HashAlgorithm.crc32_custom, ((local_metadata.batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.egress_spec-1)*REGISTER_PORT_SIZE))), {hdr.ipv6.src_addr,  hdr.ipv6.dst_addr,
         local_metadata.tmp_src_port, local_metadata.tmp_dst_port, hdr.loss.nextProtocol}, (bit<16>)REGISTER_PORT_SIZE);
        hash(local_metadata.um_h3, HashAlgorithm.crc32_custom, ((local_metadata.batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.egress_spec-1)*REGISTER_PORT_SIZE))), {hdr.ipv6.src_addr,  hdr.ipv6.dst_addr,
         local_metadata.tmp_src_port, local_metadata.tmp_dst_port, hdr.loss.nextProtocol}, (bit<16>)REGISTER_PORT_SIZE);

        // Compute hash indexes for downstream meter
        hash(local_metadata.dm_h1, HashAlgorithm.crc32_custom, ((local_metadata.previous_batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.ingress_port-1)*REGISTER_PORT_SIZE))), {hdr.ipv6.src_addr,  hdr.ipv6.dst_addr,
         local_metadata.tmp_src_port, local_metadata.tmp_dst_port, hdr.loss.nextProtocol}, (bit<16>)REGISTER_PORT_SIZE);
        hash(local_metadata.dm_h2, HashAlgorithm.crc32_custom, ((local_metadata.previous_batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.ingress_port-1)*REGISTER_PORT_SIZE))), {hdr.ipv6.src_addr,  hdr.ipv6.dst_addr,
         local_metadata.tmp_src_port, local_metadata.tmp_dst_port, hdr.loss.nextProtocol}, (bit<16>)REGISTER_PORT_SIZE);
        hash(local_metadata.dm_h3, HashAlgorithm.crc32_custom, ((local_metadata.previous_batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.ingress_port-1)*REGISTER_PORT_SIZE))), {hdr.ipv6.src_addr,  hdr.ipv6.dst_addr,
         local_metadata.tmp_src_port, local_metadata.tmp_dst_port, hdr.loss.nextProtocol}, (bit<16>)REGISTER_PORT_SIZE);
    }

    action apply_um_meter(){

        // ip src
        //hash1
        bit<128> tmp = hdr.ipv6.src_addr;
        um_ip_src.read(local_metadata.tmp_ip_src, (bit<32>)local_metadata.um_h1);
        local_metadata.tmp_ip_src = local_metadata.tmp_ip_src ^ (tmp);
        um_ip_src.write((bit<32>)local_metadata.um_h1, local_metadata.tmp_ip_src);

        //hash2
        um_ip_src.read(local_metadata.tmp_ip_src, (bit<32>)local_metadata.um_h2);
        local_metadata.tmp_ip_src = local_metadata.tmp_ip_src ^ (tmp);
        um_ip_src.write((bit<32>)local_metadata.um_h2, local_metadata.tmp_ip_src);

        //hash3
        um_ip_src.read(local_metadata.tmp_ip_src, (bit<32>)local_metadata.um_h3);
        local_metadata.tmp_ip_src = local_metadata.tmp_ip_src ^ (tmp);
        um_ip_src.write((bit<32>)local_metadata.um_h3, local_metadata.tmp_ip_src);

        // ip dst
        tmp = hdr.ipv6.dst_addr;
        um_ip_dst.read(local_metadata.tmp_ip_dst, (bit<32>)local_metadata.um_h1);
        local_metadata.tmp_ip_dst = local_metadata.tmp_ip_dst ^ (tmp);
        um_ip_dst.write((bit<32>)local_metadata.um_h1, local_metadata.tmp_ip_dst);

        //hash2
        um_ip_dst.read(local_metadata.tmp_ip_dst, (bit<32>)local_metadata.um_h2);
        local_metadata.tmp_ip_dst = local_metadata.tmp_ip_dst ^ (tmp);
        um_ip_dst.write((bit<32>)local_metadata.um_h2, local_metadata.tmp_ip_dst);

        //hash3
        um_ip_dst.read(local_metadata.tmp_ip_dst, (bit<32>)local_metadata.um_h3);
        local_metadata.tmp_ip_dst = local_metadata.tmp_ip_dst ^ (tmp);
        um_ip_dst.write((bit<32>)local_metadata.um_h3, local_metadata.tmp_ip_dst);

        // misc fields
        // hash1
        tmp = (bit<128>)((bit<8>)0 ++ local_metadata.tmp_src_port ++ local_metadata.tmp_dst_port ++ hdr.loss.nextProtocol);
        um_ports_proto.read(local_metadata.tmp_ports_proto, (bit<32>)local_metadata.um_h1);
        local_metadata.tmp_ports_proto = local_metadata.tmp_ports_proto ^ (tmp);
        um_ports_proto.write((bit<32>)local_metadata.um_h1, local_metadata.tmp_ports_proto);

        //hash2
        um_ports_proto.read(local_metadata.tmp_ports_proto, (bit<32>)local_metadata.um_h2);
        local_metadata.tmp_ports_proto = local_metadata.tmp_ports_proto ^ (tmp);
        um_ports_proto.write((bit<32>)local_metadata.um_h2, local_metadata.tmp_ports_proto);

        //hash3
        um_ports_proto.read(local_metadata.tmp_ports_proto, (bit<32>)local_metadata.um_h3);
        local_metadata.tmp_ports_proto = local_metadata.tmp_ports_proto ^ (tmp);
        um_ports_proto.write((bit<32>)local_metadata.um_h3, local_metadata.tmp_ports_proto);

        // counter
        //hash1
        um_counter.read(local_metadata.tmp_counter, (bit<32>)local_metadata.um_h1);
        local_metadata.tmp_counter = local_metadata.tmp_counter + 1;
        um_counter.write((bit<32>)local_metadata.um_h1, local_metadata.tmp_counter);

        //hash2
        um_counter.read(local_metadata.tmp_counter, (bit<32>)local_metadata.um_h2);
        local_metadata.tmp_counter = local_metadata.tmp_counter + 1;
        um_counter.write((bit<32>)local_metadata.um_h2, local_metadata.tmp_counter);

        //hash3
        um_counter.read(local_metadata.tmp_counter, (bit<32>)local_metadata.um_h3);
        local_metadata.tmp_counter = local_metadata.tmp_counter + 1;
        um_counter.write((bit<32>)local_metadata.um_h3, local_metadata.tmp_counter);
    }

    action apply_dm_meter(){

        // ip src
        //hash1
        bit<128> tmp = hdr.ipv6.src_addr;
        dm_ip_src.read(local_metadata.tmp_ip_src, (bit<32>)local_metadata.dm_h1);
        local_metadata.tmp_ip_src = local_metadata.tmp_ip_src ^ (tmp);
        dm_ip_src.write((bit<32>)local_metadata.dm_h1, local_metadata.tmp_ip_src);

        //hash2
        dm_ip_src.read(local_metadata.tmp_ip_src, (bit<32>)local_metadata.dm_h2);
        local_metadata.tmp_ip_src = local_metadata.tmp_ip_src ^ (tmp);
        dm_ip_src.write((bit<32>)local_metadata.dm_h2, local_metadata.tmp_ip_src);

        //hash3
        dm_ip_src.read(local_metadata.tmp_ip_src, (bit<32>)local_metadata.dm_h3);
        local_metadata.tmp_ip_src = local_metadata.tmp_ip_src ^ (tmp);
        dm_ip_src.write((bit<32>)local_metadata.dm_h3, local_metadata.tmp_ip_src);

        // ip dst
        tmp = hdr.ipv6.dst_addr;
        dm_ip_dst.read(local_metadata.tmp_ip_dst, (bit<32>)local_metadata.dm_h1);
        local_metadata.tmp_ip_dst = local_metadata.tmp_ip_dst ^ (tmp);
        dm_ip_dst.write((bit<32>)local_metadata.dm_h1, local_metadata.tmp_ip_dst);

        //hash2
        dm_ip_dst.read(local_metadata.tmp_ip_dst, (bit<32>)local_metadata.dm_h2);
        local_metadata.tmp_ip_dst = local_metadata.tmp_ip_dst ^ (tmp);
        dm_ip_dst.write((bit<32>)local_metadata.dm_h2, local_metadata.tmp_ip_dst);

        //hash3
        dm_ip_dst.read(local_metadata.tmp_ip_dst, (bit<32>)local_metadata.dm_h3);
        local_metadata.tmp_ip_dst = local_metadata.tmp_ip_dst ^ (tmp);
        dm_ip_dst.write((bit<32>)local_metadata.dm_h3, local_metadata.tmp_ip_dst);

        // misc fields
        //hash1
        tmp = (bit<128>)((bit<8>)0 ++ local_metadata.tmp_src_port ++ local_metadata.tmp_dst_port ++ hdr.loss.nextProtocol);
        dm_ports_proto.read(local_metadata.tmp_ports_proto, (bit<32>)local_metadata.dm_h1);
        local_metadata.tmp_ports_proto = local_metadata.tmp_ports_proto ^ (tmp);
        dm_ports_proto.write((bit<32>)local_metadata.dm_h1, local_metadata.tmp_ports_proto);

        //hash2
        dm_ports_proto.read(local_metadata.tmp_ports_proto, (bit<32>)local_metadata.dm_h2);
        local_metadata.tmp_ports_proto = local_metadata.tmp_ports_proto ^ (tmp);
        dm_ports_proto.write((bit<32>)local_metadata.dm_h2, local_metadata.tmp_ports_proto);

        //hash3
        dm_ports_proto.read(local_metadata.tmp_ports_proto, (bit<32>)local_metadata.dm_h3);
        local_metadata.tmp_ports_proto = local_metadata.tmp_ports_proto ^ (tmp);
        dm_ports_proto.write((bit<32>)local_metadata.dm_h3, local_metadata.tmp_ports_proto);

        // counter
        //hash1
        dm_counter.read(local_metadata.tmp_counter, (bit<32>)local_metadata.dm_h1);
        local_metadata.tmp_counter = local_metadata.tmp_counter + 1;
        dm_counter.write((bit<32>)local_metadata.dm_h1, local_metadata.tmp_counter);

        //hash2
        dm_counter.read(local_metadata.tmp_counter, (bit<32>)local_metadata.dm_h2);
        local_metadata.tmp_counter = local_metadata.tmp_counter + 1;
        dm_counter.write((bit<32>)local_metadata.dm_h2, local_metadata.tmp_counter);

        //hash3
        dm_counter.read(local_metadata.tmp_counter, (bit<32>)local_metadata.dm_h3);
        local_metadata.tmp_counter = local_metadata.tmp_counter + 1;
        dm_counter.write((bit<32>)local_metadata.dm_h3, local_metadata.tmp_counter);

    }

    action remove_header (){
        bit<8> protocol = hdr.loss.nextProtocol;
        hdr.loss.setInvalid();
        hdr.ipv6.next_hdr = protocol;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len - 2;
        local_metadata.dont_execute_um = 1;
    }

    table remove_loss_header {
        key = {
            standard_metadata.egress_spec: exact;
        }

        actions = {
            remove_header;
            NoAction;
        }
        size=64;
        default_action = NoAction;
    }

   meter(32w16384, MeterType.bytes) my_meter;

   action drop() {
       mark_to_drop(standard_metadata);
   }

   // set color
   action m_action(bit<32> meter_index) {
       my_meter.execute_meter<bit<32>>(meter_index, local_metadata.meter_tag);
   }


   action set_slice_id(bit<32> slice_id) {
        local_metadata.slice_id = slice_id;
   }

   table m_classify {
       key = {
           hdr.ipv6.src_addr: exact;
           hdr.ipv6.dst_addr: exact;
           local_metadata.l4_src_port: exact;
           local_metadata.l4_dst_port: exact;
           hdr.ipv6.next_hdr: exact;
       }
       actions = {
           set_slice_id;
       }
       default_action = NoAction;
       size = 2048;
   }

   table m_read {
        key = {
            local_metadata.slice_id: exact;
        }
        actions = {
            // set_color
            m_action;
            // set_uncolored
            NoAction;
        }
        default_action = NoAction;
        size = 16384;

   }

   action set_priority(bit<32> pri) {
        local_metadata.priority = pri;
   }

   table m_filter {
       key = {
           local_metadata.meter_tag: exact;
       }
       actions = {
           set_priority;
           drop;
       }
       default_action = drop;
       size = 16;
   }

    action set_egress_port(port_num_t port_num) {
        standard_metadata.egress_spec = port_num;
    }

    table l2_exact_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = {
            set_egress_port;
            @defaultonly drop;
        }
        const default_action = drop;
        @name("l2_exact_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- l2_ternary_table (for broadcast/multicast entries) ------------------

    action set_multicast_group(mcast_group_id_t gid) {
        // gid will be used by the Packet Replication Engine (PRE) in the
        // Traffic Manager--located right after the ingress pipeline, to
        // replicate a packet to multiple egress ports, specified by the control
        // plane by means of P4Runtime MulticastGroupEntry messages.
        standard_metadata.mcast_grp = gid;
        local_metadata.is_multicast = true;
    }

    table l2_ternary_table {
        key = {
            hdr.ethernet.dst_addr: ternary;
        }
        actions = {
            set_multicast_group;
            @defaultonly drop;
        }
        const default_action = drop;
        @name("l2_ternary_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    action ndp_ns_to_na(mac_addr_t target_mac) {
        hdr.ethernet.src_addr = target_mac;
        hdr.ethernet.dst_addr = IPV6_MCAST_01;
        ipv6_addr_t host_ipv6_tmp = hdr.ipv6.src_addr;
        hdr.ipv6.src_addr = hdr.ndp.target_ipv6_addr;
        hdr.ipv6.dst_addr = host_ipv6_tmp;
        hdr.ipv6.next_hdr = IP_PROTO_ICMPV6;
        hdr.icmpv6.type = ICMP6_TYPE_NA;
        hdr.ndp.flags = NDP_FLAG_ROUTER | NDP_FLAG_OVERRIDE;
        hdr.ndp.type = NDP_OPT_TARGET_LL_ADDR;
        hdr.ndp.length = 1;
        hdr.ndp.target_mac_addr = target_mac;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table ndp_reply_table {
        key = {
            hdr.ndp.target_ipv6_addr: exact;
        }
        actions = {
            ndp_ns_to_na;
        }
        @name("ndp_reply_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- my_station_table ---------------------------------------------------

    table my_station_table {
        key = {
            hdr.ethernet.dst_addr: exact;
        }
        actions = { NoAction; }
        @name("my_station_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    // --- routing_v6_table ----------------------------------------------------

    action_selector(HashAlgorithm.crc16, 32w1024, 32w16) ecmp_selector;

    action set_next_hop(mac_addr_t dmac) {
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dmac;
        // Decrement TTL
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }
    table routing_v6_table {
      key = {
          hdr.ipv6.dst_addr:          lpm;
          // The following fields are not used for matching, but as input to the
          // ecmp_selector hash function.
          hdr.ipv6.dst_addr:          selector;
          hdr.ipv6.src_addr:          selector;
          hdr.ipv6.flow_label:        selector;
          // The rest of the 5-tuple is optional per RFC6438
          hdr.ipv6.next_hdr:          selector;
          local_metadata.l4_src_port: selector;
          local_metadata.l4_dst_port: selector;
      }
      actions = {
          set_next_hop;
      }
      implementation = ecmp_selector;
      @name("routing_v6_table_counter")
      counters = direct_counter(CounterType.packets_and_bytes);
    }

    // *** TODO EXERCISE 6 (SRV6)
    //
    // Implement tables to provide SRV6 logic.

    // --- srv6_my_sid----------------------------------------------------------

    // Process the packet if the destination IP is the segemnt Id(sid) of this
    // device. This table will decrement the "segment left" field from the Srv6
    // header and set destination IP address to next segment.

    action srv6_end() {
        hdr.srv6h.segment_left = hdr.srv6h.segment_left - 1;
        hdr.ipv6.dst_addr = local_metadata.next_srv6_sid;
    }

    direct_counter(CounterType.packets_and_bytes) srv6_my_sid_table_counter;
    table srv6_my_sid {
      key = {
          hdr.ipv6.dst_addr: lpm;
      }
      actions = {
          srv6_end;
      }
      counters = srv6_my_sid_table_counter;
    }

    // --- srv6_transit --------------------------------------------------------

    // Inserts the SRv6 header to the IPv6 header of the packet based on the
    // destination IP address.


    action insert_srv6h_header(bit<8> num_segments) {
        hdr.srv6h.setValid();
        hdr.srv6h.next_hdr = hdr.ipv6.next_hdr;
        hdr.srv6h.hdr_ext_len =  num_segments * 2;
        hdr.srv6h.routing_type = 4;
        hdr.srv6h.segment_left = num_segments - 1;
        hdr.srv6h.last_entry = num_segments - 1;
        hdr.srv6h.flags = 0;
        hdr.srv6h.tag = 0;
        hdr.ipv6.next_hdr = IP_PROTO_SRV6;
    }

    /*
       Single segment header doesn't make sense given PSP
       i.e. we will pop the SRv6 header when segments_left reaches 0
     */

    action srv6_t_insert_2(ipv6_addr_t s1, ipv6_addr_t s2) {
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 40;
        insert_srv6h_header(2);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s2;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s1;
    }

    action srv6_t_insert_3(ipv6_addr_t s1, ipv6_addr_t s2, ipv6_addr_t s3) {
        hdr.ipv6.dst_addr = s1;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + 56;
        insert_srv6h_header(3);
        hdr.srv6_list[0].setValid();
        hdr.srv6_list[0].segment_id = s3;
        hdr.srv6_list[1].setValid();
        hdr.srv6_list[1].segment_id = s2;
        hdr.srv6_list[2].setValid();
        hdr.srv6_list[2].segment_id = s1;
    }

    direct_counter(CounterType.packets_and_bytes) srv6_transit_table_counter;
    table srv6_transit {
      key = {
          hdr.ipv6.dst_addr: lpm;
          // TODO: what other fields do we want to match?
      }
      actions = {
          srv6_t_insert_2;
          srv6_t_insert_3;
          // Extra credit: set a metadata field, then push label stack in egress
      }
      counters = srv6_transit_table_counter;
    }

    // Called directly in the apply block.
    action srv6_pop() {
      hdr.ipv6.next_hdr = hdr.srv6h.next_hdr;
      // SRv6 header is 8 bytes
      // SRv6 list entry is 16 bytes each
      // (((bit<16>)hdr.srv6h.last_entry + 1) * 16) + 8;
      bit<16> srv6h_size = (((bit<16>)hdr.srv6h.last_entry + 1) << 4) + 8;
      hdr.ipv6.payload_len = hdr.ipv6.payload_len - srv6h_size;

      hdr.srv6h.setInvalid();
      // Need to set MAX_HOPS headers invalid
      hdr.srv6_list[0].setInvalid();
      hdr.srv6_list[1].setInvalid();
      hdr.srv6_list[2].setInvalid();
    }

    // *** ACL
    //
    // Provides ways to override a previous forwarding decision, for example
    // requiring that a packet is cloned/sent to the CPU, or dropped.
    //
    // We use this table to clone all NDP packets to the control plane, so to
    // enable host discovery. When the location of a new host is discovered, the
    // controller is expected to update the L2 and L3 tables with the
    // correspionding brinding and routing entries.

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    // packet clone_to_cpu equals to from ingress to egress directly
    // our probe packet need it's function, and ONOS can put it as p4 entry
    action clone_to_cpu() {
        // if change here, the packet_out directly send back to onos will not be affected !
        clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, { standard_metadata.ingress_port });
    }

    table probe_table {
        key = {
            hdr.ethernet.ether_type: exact;
        }
        actions = {
            clone_to_cpu;
            NoAction;
        }
        default_action = NoAction;
        @name("probe_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }
    table acl_table {
        key = {
            standard_metadata.ingress_port: ternary;
            hdr.ethernet.dst_addr:          ternary;
            hdr.ethernet.src_addr:          ternary;
            hdr.ethernet.ether_type:        ternary;
            local_metadata.ip_proto:        ternary;
            local_metadata.icmp_type:       ternary;
            local_metadata.l4_src_port:     ternary;
            local_metadata.l4_dst_port:     ternary;
        }
        actions = {
            send_to_cpu;
            clone_to_cpu;
            drop;
        }
        @name("acl_table_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    table ipv6_multicast_table {
        key = {
            hdr.ipv6.dst_addr: exact;
        }
        actions = {
            NoAction;
            // set_multicast_group;
        }

        @name("ipv6_multicast_counter")
        counters = direct_counter(CounterType.packets_and_bytes);
    }

    apply {

        if (m_classify.apply().hit) {
            m_read.apply();
            m_filter.apply();
        }
        // limit throughput before doing l2_l3_forward
        // Check meter
        m_read.apply();

        // Filter based on meter status
        m_filter.apply();

        if (hdr.tcp.isValid())
        {
            meta.tmp_src_port = hdr.tcp.srcPort;
            meta.tmp_dst_port = hdr.tcp.dstPort;
        }
        else if (hdr.udp.isValid())
        {
            meta.tmp_src_port = hdr.udp.srcPort;
            meta.tmp_dst_port = hdr.udp.dstPort;
        }

        bool do_acl = true;
        if (hdr.cpu_out.isValid()) {
            if (hdr.cpu_out.egress_port == MY_MULTICAST_LOGICAL_PORT) {
                // if egress_port = 233, then multicast
                standard_metadata.mcast_grp = 0xfe;
                exit;
            } else {
                 standard_metadata.egress_spec = hdr.cpu_out.egress_port;
                 hdr.cpu_out.setInvalid();
                 exit;
            }
        }

        // probe_table.apply();

        bool do_l3_l2 = true;

        if (hdr.icmpv6.isValid() && hdr.icmpv6.type == ICMP6_TYPE_NS) {

            if (ndp_reply_table.apply().hit) {
                do_l3_l2 = false;
            }
        }

        if (do_l3_l2) {

            if (hdr.ipv6.isValid() && my_station_table.apply().hit) {

                if (srv6_my_sid.apply().hit) {
                    // PSP logic -- enabled for all packets
                    if (hdr.srv6h.isValid() && hdr.srv6h.segment_left == 0) {
                        srv6_pop();
                    }
                } else {
                    srv6_transit.apply();
                }
                if (ipv6_multicast_table.apply().hit) {
                    standard_metadata.mcast_grp = 0x72;
                    exit;
                }

                routing_v6_table.apply();

                // Check TTL, drop packet if necessary to avoid loops.
                if(hdr.ipv6.hop_limit == 0) { drop(); }
            }

            // L2 bridging logic. Apply the exact table first...
            if (!l2_exact_table.apply().hit) {
                // ...if an entry is NOT found, apply the ternary one in case
                // this is a multicast/broadcast NDP NS packet.
                l2_ternary_table.apply();
            }
        }

        // TODO:
        // Lastly, apply the ACL table.
        // if a switch get "portAll" and do forward
        // then the ether_type = 0x0812 will hit acl_table and clone_to_cpu
        // but at this time, the ingress_port is CPU_PORT
        // we want to change it to the next hop's ingress_port
        // the reason is that, standard_metadata.ingress_port that send to cpu
        // is always the first hop's CPU_PORT
        if (hdr.ethernet.ether_type == 0x0812) {

        }
        if (do_acl) {
            acl_table.apply();
        }
        // Assumes that the comunication is not host -- switch -- host, otherwise we
        // would have to check that too
        if (!hdr.loss.isValid())
        {
           hdr.loss.setValid();
           hdr.loss.nextProtocol = hdr.ipv6.next_hdr;
           hdr.ipv6.payload_len = hdr.ipv6.payload_len + 2;
           hdr.ipv6.next_hdr = TYPE_LOSS;

           local_metadata.dont_execute_dm = 1;
        }
        else
        {
           local_metadata.previous_batch_id = (bit<16>)hdr.loss.batch_id;
        }
        // Compute local batch
        local_metadata.batch_id = (bit<16>)((standard_metadata.ingress_global_timestamp >> 21) % 2);
        last_batch_id.read(local_metadata.last_local_batch_id, (bit<32>)0);
        last_batch_id.write((bit<32>)0, local_metadata.batch_id);

        // Only works if there is enough traffic. For example
        // if there is 1 packet every 1 second it can happen
        // that the batch id never changes
        if (local_metadata.batch_id != local_metadata.last_local_batch_id)
        {
            // comment it
            clone3(CloneType.I2E, 99, local_metadata);
        }

        // Update the header batch id with the current one
        hdr.loss.batch_id = (bit<1>)local_metadata.batch_id;

        compute_hash_indexes();
        remove_loss_header.apply();

        if (local_metadata.dont_execute_um == 0)
        {
           apply_um_meter();
        }

        if (local_metadata.dont_execute_dm == 0)
        {
           apply_dm_meter();
        }
    }


control EgressPipeImpl (inout parsed_headers_t hdr,
                        inout local_metadata_t local_metadata,
                        inout standard_metadata_t standard_metadata) {
    apply {

        // If ingress clone
        if (standard_metadata.instance_type == 1){
            hdr.loss.setValid();
            hdr.ipv6.setInvalid();
            hdr.loss.batch_id = (bit<1>)meta.last_local_batch_id;
            hdr.loss.padding = (bit<7>)0;
            hdr.loss.nextProtocol = (bit<8>)0;
            hdr.ethernet.etherType = LOSS_CHANGE_OF_BATCH;
            truncate((bit<32>)16); //ether+loss header
        }

        if (standard_metadata.egress_port == CPU_PORT) {
            hdr.cpu_in.setValid();

            if (hdr.ethernet.ether_type == 233) {
                // ADD EXTRA LINK METRICS
            }
            hdr.cpu_in.ingress_port = standard_metadata.ingress_port;
            exit;
        }

        // If this is a multicast packet (flag set by l2_ternary_table), make
        // sure we are not replicating the packet on the same port where it was
        // received. This is useful to avoid broadcasting NDP requests on the
        // ingress port.
        if (local_metadata.is_multicast == true &&
              standard_metadata.ingress_port == standard_metadata.egress_port) {
            mark_to_drop(standard_metadata);
        }
    }
}


control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t local_metadata)
{
    apply {
        // The following is used to update the ICMPv6 checksum of NDP
        // NA packets generated by the ndp reply table in the ingress pipeline.
        // This function is executed only if the NDP header is present.
        update_checksum(hdr.ndp.isValid(),
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                hdr.ipv6.payload_len,
                8w0,
                hdr.ipv6.next_hdr,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.flags,
                hdr.ndp.target_ipv6_addr,
                hdr.ndp.type,
                hdr.ndp.length,
                hdr.ndp.target_mac_addr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}


control DeparserImpl(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.cpu_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.srv6h);
        packet.emit(hdr.srv6_list);
        // comment it
        packet.emit(hdr.loss);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.ndp);
    }
}


V1Switch(
    ParserImpl(),
    VerifyChecksumImpl(),
    IngressPipeImpl(),
    EgressPipeImpl(),
    ComputeChecksumImpl(),
    DeparserImpl()
) main;