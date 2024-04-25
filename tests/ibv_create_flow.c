struct raw_eth_flow_attr {
               struct ibv_flow_attr            attr;
               struct ibv_flow_spec_eth        spec_eth;
               struct ibv_flow_spec_ipv4       spec_ipv4;
       } __attribute__((packed));

       struct raw_eth_flow_attr flow_attr = {
                       .attr = {
                               .comp_mask      = 0,
                               .type           = IBV_FLOW_ATTR_NORMAL,
                               .size           = sizeof(flow_attr),
                               .priority       = 0,
                               .num_of_specs   = 2,
                               .port           = 1,
                               .flags          = 0,
                       },
                       .spec_eth = {
                               .type   = IBV_FLOW_SPEC_ETH,
                               .size   = sizeof(struct ibv_flow_spec_eth),
                               .val = {
                                       .dst_mac = {0x66, 0x11, 0x22, 0x33, 0x44, 0x55},
                                       .src_mac = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                                       .ether_type = 0,
                                       .vlan_tag = 0,
                               },
                               .mask = {
                                       .dst_mac = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                                       .src_mac = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
                                       .ether_type = 0,
                                       .vlan_tag = 0,
                               }
                       },
                       .spec_ipv4 = {
                               .type   = IBV_FLOW_SPEC_IPV4,
                               .size   = sizeof(struct ibv_flow_spec_ipv4),
                               .val = {
                                       .src_ip = 0x0B86C806,
                                       .dst_ip = 0,
                               },
                               .mask = {
                                       .src_ip = 0xFFFFFFFF,
                                       .dst_ip = 0,
                               }
                       }
       };

       