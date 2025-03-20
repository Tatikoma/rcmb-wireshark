--------------------------------------------------------------------------------
-- Redis Cluster bus dissector with reassembly indication
--------------------------------------------------------------------------------

rcmb_protocol = Proto("RCmb", "RCmb Protocol")

--------------------------------------------------------------------------------
-- Protocol fields

local length_F            = ProtoField.uint32("rcmb.length",             "Length")
local version_F           = ProtoField.uint16("rcmb.version",            "Version")
local port_F              = ProtoField.uint16("rcmb.port",               "Port")
local type_F              = ProtoField.string("rcmb.type",               "Type")
local count_F             = ProtoField.uint16("rcmb.count",              "Count")
local currentEpoch_F      = ProtoField.uint64("rcmb.current_epoch",      "CurrentEpoch")
local configEpoch_F       = ProtoField.uint64("rcmb.config_epoch",       "ConfigEpoch")
local replicationOffset_F = ProtoField.uint64("rcmb.replication_offset", "ReplicationOffset")
local sender_F            = ProtoField.string("rcmb.sender",            "Sender")
local hashSlots_F         = ProtoField.string("rcmb.hash_slots",        "HashSlots")
local slaveOf_F           = ProtoField.string("rcmb.slave_of",          "SlaveOf")
local myip_F              = ProtoField.string("rcmb.my_ip",             "MyIP")
local notused1_F          = ProtoField.bytes("rcmb.reserved",           "Reserved")
local pport_F             = ProtoField.uint16("rcmb.pport",             "SecondaryPort")
local cport_F             = ProtoField.uint16("rcmb.cport",             "ClusterBusPort")
local flags_F             = ProtoField.string("rcmb.flags",             "Flags")
local state_F             = ProtoField.string("rcmb.state",             "ClusterState")
local mflags_F            = ProtoField.string("rcmb.mflags",            "MessageFlags")

-- Gossip-specific fields
local nodeName_F          = ProtoField.string("rcmb.node_name",          "NodeName")
local pingSent_F          = ProtoField.uint32("rcmb.ping_sent",         "PingSent")
local pingReceived_F      = ProtoField.uint32("rcmb.pong_received",     "PingReceived")
local gossipIP_F          = ProtoField.string("rcmb.gossip_ip",         "GossipIP")
local gossipPort_F        = ProtoField.uint16("rcmb.gossip_port",       "GossipPort")
local gossipCport_F       = ProtoField.uint16("rcmb.gossip_cport",      "GossipClusterPort")
local gossipFlags_F       = ProtoField.string("rcmb.gossip_flags",      "GossipFlags")
local gossipPport_F       = ProtoField.uint16("rcmb.gossip_pport",      "GossipPport")
local gossipNotused1_F    = ProtoField.uint16("rcmb.gossip_notused1",    "GossipNotused1")

-- For PUBLISH, FAIL, etc.
local channel_F           = ProtoField.string("rcmb.channel",           "Channel")
local message_F           = ProtoField.string("rcmb.message",           "Message")

rcmb_protocol.fields = {
    length_F, version_F, port_F, type_F, count_F,
    currentEpoch_F, configEpoch_F, replicationOffset_F,
    sender_F, hashSlots_F, slaveOf_F,
    myip_F, notused1_F, pport_F, cport_F,
    flags_F, state_F, mflags_F,
    nodeName_F, pingSent_F, pingReceived_F,
    gossipIP_F, gossipPort_F, gossipCport_F, gossipFlags_F,
    gossipPport_F, gossipNotused1_F,
    channel_F, message_F
}

--------------------------------------------------------------------------------
-- Constants for message types, node flags, etc.

local CLUSTERMSG_TYPE_PING   = 0
local CLUSTERMSG_TYPE_PONG   = 1
local CLUSTERMSG_TYPE_MEET   = 2
local CLUSTERMSG_TYPE_FAIL   = 3
local CLUSTERMSG_TYPE_PUBLISH= 4
local CLUSTERMSG_TYPE_FAILOVER_AUTH_REQUEST = 5
local CLUSTERMSG_TYPE_FAILOVER_AUTH_ACK     = 6
local CLUSTERMSG_TYPE_UPDATE = 7
local CLUSTERMSG_TYPE_MFSTART= 8
local CLUSTERMSG_TYPE_MODULE = 9
local CLUSTERMSG_TYPE_PUBLISHSHARD = 10
local CLUSTERMSG_TYPE_COUNT  = 11

local CLUSTER_NODE_MASTER     = 1
local CLUSTER_NODE_SLAVE      = 2
local CLUSTER_NODE_PFAIL      = 4
local CLUSTER_NODE_FAIL       = 8
local CLUSTER_NODE_MYSELF     = 16
local CLUSTER_NODE_HANDSHAKE  = 32
local CLUSTER_NODE_NOADDR     = 64
local CLUSTER_NODE_MEET       = 128
local CLUSTER_NODE_MIGRATE_TO = 256
local CLUSTER_NODE_NOFAILOVER = 512

local CLUSTERMSG_FLAG0_PAUSED   = 1
local CLUSTERMSG_FLAG0_FORCEACK = 2
local CLUSTERMSG_FLAG0_EXT_DATA = 4

local msg_types = {
    [CLUSTERMSG_TYPE_PING]   = "PING",
    [CLUSTERMSG_TYPE_PONG]   = "PONG",
    [CLUSTERMSG_TYPE_MEET]   = "MEET",
    [CLUSTERMSG_TYPE_FAIL]   = "FAIL",
    [CLUSTERMSG_TYPE_PUBLISH]= "PUBLISH",
    [CLUSTERMSG_TYPE_FAILOVER_AUTH_REQUEST] = "FAILOVER_AUTH_REQUEST",
    [CLUSTERMSG_TYPE_FAILOVER_AUTH_ACK]     = "FAILOVER_AUTH_ACK",
    [CLUSTERMSG_TYPE_UPDATE] = "UPDATE",
    [CLUSTERMSG_TYPE_MFSTART]= "MFSTART",
    [CLUSTERMSG_TYPE_MODULE] = "MODULE",
    [CLUSTERMSG_TYPE_PUBLISHSHARD] = "PUBLISHSHARD",
    [CLUSTERMSG_TYPE_COUNT]  = "COUNT"
}

--------------------------------------------------------------------------------
-- Helper funcs: decode flags, mflags, hashslots

local function flags_to_string(f)
    local t = {}
    if bit.band(f,CLUSTER_NODE_MASTER)     ~=0 then table.insert(t,"MASTER") end
    if bit.band(f,CLUSTER_NODE_SLAVE)      ~=0 then table.insert(t,"SLAVE")  end
    if bit.band(f,CLUSTER_NODE_PFAIL)      ~=0 then table.insert(t,"PFAIL")  end
    if bit.band(f,CLUSTER_NODE_FAIL)       ~=0 then table.insert(t,"FAIL")   end
    if bit.band(f,CLUSTER_NODE_MYSELF)     ~=0 then table.insert(t,"MYSELF") end
    if bit.band(f,CLUSTER_NODE_HANDSHAKE)  ~=0 then table.insert(t,"HANDSHAKE") end
    if bit.band(f,CLUSTER_NODE_NOADDR)     ~=0 then table.insert(t,"NOADDR") end
    if bit.band(f,CLUSTER_NODE_MEET)       ~=0 then table.insert(t,"MEET")   end
    if bit.band(f,CLUSTER_NODE_MIGRATE_TO) ~=0 then table.insert(t,"MIGRATE_TO") end
    if bit.band(f,CLUSTER_NODE_NOFAILOVER) ~=0 then table.insert(t,"NOFAILOVER") end
    local s = table.concat(t," | ")
    return string.format("0x%04X (%s)",f, #s>0 and s or "")
end

local function mflags_to_string(mf)
    local t = {}
    if bit.band(mf, CLUSTERMSG_FLAG0_PAUSED)   ~= 0 then table.insert(t,"PAUSED")   end
    if bit.band(mf, CLUSTERMSG_FLAG0_FORCEACK) ~= 0 then table.insert(t,"FORCEACK") end
    if bit.band(mf, CLUSTERMSG_FLAG0_EXT_DATA) ~= 0 then table.insert(t,"EXT_DATA") end
    local s = table.concat(t," | ")
    if #s>0 then
        return string.format("0x%02X (%s)",mf,s)
    else
        return string.format("0x%02X",mf)
    end
end

local hashSlotsCache = {}
local function hash_slots_to_string(slots)
    local key = slots:tohex()
    if hashSlotsCache[key] then
        return hashSlotsCache[key]
    end
    local s,e = -1,-1
    local parts = {}
    for i=0,16384 do
        local in_slot = false
        if i<16384 then
            local b = slots:get_index(bit.rshift(i,3))
            if b and bit.band(b, bit.lshift(1, i%8))~=0 then
                in_slot = true
            end
        end
        if in_slot then
            if s<0 then s=i e=i else e=i end
        else
            if s>=0 then
                if s==e then
                    table.insert(parts, tostring(s))
                else
                    table.insert(parts, s.."-"..e)
                end
                s,e=-1,-1
            end
        end
    end
    local r = "["..table.concat(parts,", ").."]"
    hashSlotsCache[key] = r
    return r
end

--------------------------------------------------------------------------------
-- We track "src port -> cluster cport" to annotate the info column

local sourcePortToClusterPort = {}

--------------------------------------------------------------------------------
-- Take tcp.srcport / tcp.dstport fields
local tcp_src_f = Field.new("tcp.srcport")
local tcp_dst_f = Field.new("tcp.dstport")

--------------------------------------------------------------------------------
-- Dissect a single RCmb message (already skipping "RCmb" + length =8 bytes)

local function dissect_rcmb_message(buf_range, pinfo, tree)
    local offset = 0

    -- version (2)
    tree:add(version_F, buf_range(offset,2))
    offset = offset + 2

    -- port (2)
    tree:add(port_F, buf_range(offset,2))
    local base_port_val = buf_range(offset,2):uint()
    offset = offset + 2

    -- type (2)
    local tval = buf_range(offset,2):uint()
    local tstr = msg_types[tval] or ("TYPE_"..tostring(tval))
    tree:add(type_F, buf_range(offset,2), tstr)
    offset = offset + 2

    -- count (2)
    local cnt = buf_range(offset,2):uint()
    tree:add(count_F, buf_range(offset,2))
    offset = offset + 2

    -- currentEpoch (8)
    local cur_ep = buf_range(offset,8):uint64()
    tree:add(currentEpoch_F, buf_range(offset,8))
    offset = offset + 8

    -- configEpoch (8)
    local cfg_ep = buf_range(offset,8):uint64()
    tree:add(configEpoch_F, buf_range(offset,8))
    offset = offset + 8

    -- replicationOffset (8)
    tree:add(replicationOffset_F, buf_range(offset,8))
    offset = offset + 8

    -- sender (40)
    local snd = buf_range(offset,40):string()
    tree:add(sender_F, buf_range(offset,40), snd)
    offset = offset + 40

    -- hashSlots (2048)
    local hs_str = hash_slots_to_string(buf_range(offset,2048):bytes())
    tree:add(hashSlots_F, buf_range(offset,2048), hs_str)
    offset = offset + 2048

    -- slaveOf (40)
    local slv = buf_range(offset,40):string()
    tree:add(slaveOf_F, buf_range(offset,40), slv)
    offset = offset + 40

    -- myip (46)
    local myip_str = buf_range(offset,46):string()
    tree:add(myip_F, buf_range(offset,46), myip_str)
    offset = offset + 46

    -- notused1 (32)
    tree:add(notused1_F, buf_range(offset,32))
    offset = offset + 32

    -- pport (2)
    local ppv = buf_range(offset,2):uint()
    tree:add(pport_F, buf_range(offset,2))
    offset = offset + 2

    -- cport (2)
    local cpv = buf_range(offset,2):uint()
    tree:add(cport_F, buf_range(offset,2))
    offset = offset + 2

    if tval == CLUSTERMSG_TYPE_PING then
        sourcePortToClusterPort[tostring(tcp_src_f())] = cpv
    end

    -- flags (2)
    local fl = buf_range(offset,2):uint()
    local fl_str = flags_to_string(fl)
    tree:add(flags_F, buf_range(offset,2), fl_str)
    offset = offset + 2

    -- state (1) 0=OK, 1=FAIL
    local st = buf_range(offset,1):uint()
    local st_str = (st==1) and "FAIL" or "OK"
    tree:add(state_F, buf_range(offset,1), st_str)
    offset = offset + 1

    -- mflags (3)
    local mf_b = buf_range(offset+1,1):uint()
    tree:add(mflags_F, buf_range(offset,3), mflags_to_string(mf_b))
    offset = offset + 3

    -- If count=0 but type is neither PING/PONG/MEET => set count=1
    if cnt==0 and (tval~=CLUSTERMSG_TYPE_PING and tval~=CLUSTERMSG_TYPE_PONG and tval~=CLUSTERMSG_TYPE_MEET) then
        cnt = 1
    end

    local is_master = bit.band(fl, CLUSTER_NODE_MASTER) ~=0
    local is_slave  = bit.band(fl, CLUSTER_NODE_SLAVE ) ~=0

    for i=1,cnt do
        if tval==CLUSTERMSG_TYPE_PING or tval==CLUSTERMSG_TYPE_PONG or tval==CLUSTERMSG_TYPE_MEET then
            -- Gossip (104)
            local gossip_len = 104
            local gossip_tree = tree:add(buf_range(offset,gossip_len),
                    "MsgDataGossip (#"..i..")")

            gossip_tree:add(nodeName_F, buf_range(offset,40))
            offset = offset + 40

            gossip_tree:add(pingSent_F, buf_range(offset,4))
            offset = offset + 4

            gossip_tree:add(pingReceived_F, buf_range(offset,4))
            offset = offset + 4

            local g_ip_str = buf_range(offset,46):string()
            gossip_tree:add(gossipIP_F, buf_range(offset,46), g_ip_str)
            offset = offset + 46

            gossip_tree:add(gossipPort_F, buf_range(offset,2))
            offset = offset + 2

            gossip_tree:add(gossipCport_F, buf_range(offset,2))
            offset = offset + 2

            local gfv = buf_range(offset,2):uint()
            gossip_tree:add(gossipFlags_F, buf_range(offset,2), flags_to_string(gfv))
            offset = offset + 2

            gossip_tree:add(gossipPport_F, buf_range(offset,2))
            offset = offset + 2

            gossip_tree:add(gossipNotused1_F, buf_range(offset,2))
            offset = offset + 2

        elseif tval==CLUSTERMSG_TYPE_FAIL then
            local fail_tree = tree:add(buf_range(offset,40), "MsgDataFail (#"..i..")")
            fail_tree:add(nodeName_F, buf_range(offset,40))
            offset = offset + 40

        elseif tval==CLUSTERMSG_TYPE_PUBLISH or tval==CLUSTERMSG_TYPE_PUBLISHSHARD then
            local ch_len = buf_range(offset,4):uint()
            local ms_len = buf_range(offset+4,4):uint()
            local data_len = 8 + ch_len + ms_len
            local pub_tree = tree:add(buf_range(offset,data_len),
                    "MsgDataPublish (#"..i..")")
            offset = offset + 8

            pub_tree:add(channel_F, buf_range(offset, ch_len))
            offset = offset + ch_len

            pub_tree:add(message_F, buf_range(offset, ms_len))
            offset = offset + ms_len

        elseif tval==CLUSTERMSG_TYPE_UPDATE then
            local upd_len = 8 + 40 + 2048
            local upd_tree = tree:add(buf_range(offset,upd_len),
                    "MsgDataUpdate (#"..i..")")
            upd_tree:add(configEpoch_F, buf_range(offset,8))
            offset = offset + 8

            upd_tree:add(nodeName_F, buf_range(offset,40))
            offset = offset + 40

            local u_hs_str = hash_slots_to_string(buf_range(offset,2048):bytes())
            upd_tree:add(hashSlots_F, buf_range(offset,2048), u_hs_str)
            offset = offset + 2048

        elseif tval==CLUSTERMSG_TYPE_MODULE then
            local mod_len = 19
            local mod_tree = tree:add(buf_range(offset,mod_len),
                    "MsgModule (#"..i..")")
            offset = offset + mod_len
        else
            -- Unknown or not implemented
        end
    end

    local src_p = tostring(tcp_src_f())
    local dst_p = tostring(tcp_dst_f())

    if tostring(cpv) ~= src_p then
        src_p = src_p.."["..cpv.."]"
    end
    local dst_cpv = sourcePortToClusterPort[tostring(tcp_dst_f())]
    if dst_cpv then
        dst_p = dst_p.."["..dst_cpv.."]"
    end

    local info_str = tstr.." ("..src_p.."->"..dst_p..")"
            .. " CurrentEpoch="..tostring(cur_ep)
            .. " ConfigEpoch="..tostring(cfg_ep)

    if is_master then
        info_str = info_str.." MASTER"
    elseif is_slave then
        info_str = info_str.." SLAVE"
    end
    pinfo.cols.info = info_str
end

--------------------------------------------------------------------------------
-- Main dissector (with reassembly indication)

function rcmb_protocol.dissector(buffer, pinfo, tree)
    pinfo.can_desegment = 2  -- enable reassembly

    local buf_len = buffer:len()
    local offset = 0
    local reassembled_flag = false

    while offset < buf_len do
        -- Ensure we have at least 8 bytes for "RCmb" + length
        if (buf_len - offset) < 8 then
            -- Not enough data to read header
            if pinfo.desegment_len == 0 then
                pinfo.cols.info:append(" [need more for header]")
            end
            pinfo.desegment_offset = offset
            pinfo.desegment_len    = 8 - (buf_len - offset)
            return
        end

        if buffer(offset,4):string() ~= "RCmb" then
            -- Not our protocol
            return
        end

        local msg_len = buffer(offset+4,4):uint()
        if (buf_len - offset) < msg_len then
            -- Not enough data for the full RCmb packet
            pinfo.desegment_offset = offset
            pinfo.desegment_len    = msg_len - (buf_len - offset)
            pinfo.cols.info:append(" (need reassembly: full len="..msg_len..")")
            return
        end

        -- If we get here => we have full packet
        pinfo.cols.protocol = "RCmb"

        -- If reassembly was used, offset is nonzero or we set desegment before
        if pinfo.desegment_offset ~= 0 then
            reassembled_flag = true
        end

        local subtree = tree:add(rcmb_protocol, buffer(offset,msg_len),
                "RCmb Protocol Data")
        subtree:add(length_F, buffer(offset+4,4))

        local start = offset
        offset = offset + 8

        local subrange = buffer(offset, msg_len-8)
        dissect_rcmb_message(subrange, pinfo, subtree)

        offset = start + msg_len
    end

    -- If we found we used reassembly at least once
    if reassembled_flag then
        pinfo.cols.info:append(" (reassembled)")
    end
end

-- Register on known cluster bus ports
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(16379, rcmb_protocol)
tcp_table:add(17000, rcmb_protocol)
tcp_table:add(17001, rcmb_protocol)
tcp_table:add(17002, rcmb_protocol)
tcp_table:add(17003, rcmb_protocol)
tcp_table:add(17004, rcmb_protocol)
tcp_table:add(17005, rcmb_protocol)
