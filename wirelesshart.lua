-- WirelessHART (IEC 62591) dissector for Wireshark.
--
-- Originally from Sam Roberts' post on wireshark-dev
-- (https://www.wireshark.org/lists/wireshark-dev/201107/msg00040.html),
-- packaged by Reid Wightman.
--
-- WirelessHART frames are IEEE 802.15.4 frames. Wireshark's built-in
-- 802.15.4 ("wpan") dissector decodes the MAC header (sequence number,
-- network ID, addresses) and the FCS when present; this plugin decodes what wpan
-- hands over as payload:
--
--   [DLPDU specifier (1)] [DLPDU payload (n)] [MIC (4)]
--
-- so it works with any standard 802.15.4 sniffer (link types 195, 230, 283).
--
-- Byte order: the 802.15.4 header is little-endian (handled by wpan); the
-- WirelessHART fields below are big-endian.

local wihart = Proto("wihart", "WirelessHART")

local MIC_LEN = 4
local NPDU_MIN = 10 -- control, ttl, asn(2), graph id(2), dst(2), src(2)

-- Bit extraction without the `&` operator, so the plugin loads on both
-- Lua 5.2 (Wireshark <= 4.2) and Lua 5.4 (Wireshark >= 4.4).
local function bits(v, shift, width)
    return math.floor(v / 2^shift % 2^width)
end

local f = wihart.fields

-- The WirelessHART Network ID is carried in the 802.15.4 PAN ID field, which
-- wpan decodes (shown there in hex). Re-exposed here in decimal, the way
-- gateways display it.
local wpan_dst_pan = Field.new("wpan.dst_pan")

local eui64 = { [0] = "no", "yes" }
local priority = { [0] = "alarm", "normal", "process data", "command" }
local netkey = { [0] = "false", "true" }
local pkttype = { [0] = "ack", "advertise", "keep alive", "disconnect", [7] = "data" }
-- Well-known WirelessHART nicknames
local nickname = { [0xF980] = "Network Manager", [0xF981] = "Gateway" }

-- Channel map: little-endian bitmap, bit 0 = channel 11 ... bit 14 = channel 25
-- (bit 15 would be channel 26, which WirelessHART does not use). Inferred from
-- captures: all 15 channels reads ff7f; channels 13-21 only reads fc07.
-- Returns e.g. "13-21" or "11-13, 15, 17-25".
local function channel_list(tvb, off, n)
    local chans = {}
    for i = 0, n - 1 do
        local b = tvb(off + i, 1):uint()
        for bit = 0, 7 do
            if bits(b, bit, 1) == 1 then chans[#chans + 1] = 11 + i * 8 + bit end
        end
    end
    if #chans == 0 then return "none" end
    local parts, first = {}, 1
    for i = 1, #chans do
        if i == #chans or chans[i + 1] ~= chans[i] + 1 then
            parts[#parts + 1] = (i == first) and tostring(chans[i])
                or (chans[first] .. "-" .. chans[i])
            first = i + 1
        end
    end
    return table.concat(parts, ", ")
end

f.netid                = ProtoField.uint16("wihart.netid", "Network ID", base.DEC)
f.dlpduspec            = ProtoField.uint8("wihart.dlpduspec", "DLPDU specifier", base.HEX)
f.dlpduspec_priority   = ProtoField.uint8("wihart.dlpduspec.priority", "priority", base.HEX, priority, 0x30)
f.dlpduspec_netkey     = ProtoField.uint8("wihart.dlpduspec.netkey", "network key", base.DEC, netkey, 0x08)
f.dlpduspec_type       = ProtoField.uint8("wihart.dlpduspec.pkttype", "packet type", base.HEX, pkttype, 0x07)
f.dlpdudata            = ProtoField.bytes("wihart.dlpdudata", "dlpdudata")
f.mic                  = ProtoField.uint32("wihart.mic", "message integrity code", base.HEX)

-- advertise
f.adv_slot             = ProtoField.uint64("wihart.advertise.slot", "absolute slot number", base.DEC)
f.adv_joinctl          = ProtoField.uint8("wihart.advertise.joinctl", "join control", base.HEX)
f.adv_mapsz            = ProtoField.uint8("wihart.advertise.chanmapsz", "active channels", base.DEC)
f.adv_map              = ProtoField.bytes("wihart.advertise.chanmap", "channel map")
f.adv_graphid          = ProtoField.uint16("wihart.advertise.graphid", "graph id", base.HEX)
f.adv_framecnt         = ProtoField.uint8("wihart.advertise.superframecount", "number of superframes", base.DEC)
f.adv_frameid          = ProtoField.uint8("wihart.advertise.frameid", "superframe id", base.DEC)
f.adv_framesz          = ProtoField.uint16("wihart.advertise.framesz", "superframe number of slots", base.DEC)
f.adv_linkcnt          = ProtoField.uint8("wihart.advertise.linkcnt", "number of links", base.DEC)
f.adv_linkjoinslot     = ProtoField.uint16("wihart.advertise.linkslot", "link join slot", base.DEC)
f.adv_linkjoinbits     = ProtoField.uint8("wihart.advertise.linkbits", "link join bits(6:xmit,5-0:chanoffset)", base.HEX)

-- ack
local ackcodes = {
     [0] = "success",
    [61] = "no buffers available",
    [62] = "no alarm/event buffers available",
    [63] = "priority too low",
}

f.ack_code             = ProtoField.uint8("wihart.ack.code", "response code", base.DEC, ackcodes)
f.ack_timeadj          = ProtoField.int16("wihart.ack.timeadj", "time adjustment (usec)", base.DEC)

-- data => network layer PDU
f.nwk_control          = ProtoField.uint8("wihart.nwk.control", "control field", base.HEX)
f.nwk_control_dst64    = ProtoField.uint8("wihart.nwk.control.dst64", "dst64", base.DEC, eui64, 0x80)
f.nwk_control_src64    = ProtoField.uint8("wihart.nwk.control.src64", "src64", base.DEC, eui64, 0x40)
f.nwk_ttl              = ProtoField.uint8("wihart.nwk.ttl", "time to live hop count", base.DEC)
f.nwk_asn              = ProtoField.uint16("wihart.nwk.asn", "snippet of abs slot number", base.HEX)
f.nwk_graphid          = ProtoField.uint16("wihart.nwk.graphid", "graph id", base.HEX)
f.nwk_dstaddr          = ProtoField.uint16("wihart.nwk.dstaddr", "dstaddr", base.HEX, nickname)
f.nwk_dstaddr64        = ProtoField.uint64("wihart.nwk.dstaddr64", "dstaddr", base.HEX)
f.nwk_srcaddr          = ProtoField.uint16("wihart.nwk.srcaddr", "srcaddr", base.HEX, nickname)
f.nwk_srcaddr64        = ProtoField.uint64("wihart.nwk.srcaddr64", "srcaddr", base.HEX)

-- Length of an advertise body starting at `off`, with a channel map of
-- `mapsz` bytes, or nil if it does not fit in `avail` bytes.
local function advertise_len(tvb, off, avail, mapsz)
    local p = off
    local function fits(n) return p + n <= off + avail end
    if not fits(7) then return nil end
    p = p + 7 -- absolute slot number (5) + join control (1) + active channels (1)
    if not fits(mapsz + 3) then return nil end
    p = p + mapsz + 2 -- channel map + graph id
    local nframes = tvb(p, 1):uint()
    p = p + 1
    for _ = 1, nframes do
        if not fits(4) then return nil end
        local nlinks = tvb(p + 3, 1):uint()
        p = p + 4 -- superframe id (1) + slots (2) + link count (1)
        if not fits(nlinks * 3) then return nil end
        p = p + nlinks * 3
    end
    return p - off
end

-- Channel map size in bytes for the advertise body at `off`, or nil if the
-- body does not add up. The byte before the map is the number of ACTIVE
-- channels (9 with map fc07 = channels 13-21, 15 with ff7f), not a length, so
-- the map is most likely a fixed 16 bits. Try 2 bytes first, then the older
-- ceil(count / 8) reading, and keep whichever makes the frame add up.
local function advertise_mapsz(tvb, off, avail)
    if avail < 7 then return nil end
    local count = tvb(off + 6, 1):uint()
    for _, mapsz in ipairs({ 2, math.ceil(count / 8) }) do
        if advertise_len(tvb, off, avail, mapsz) == avail then return mapsz end
    end
    return nil
end

-- Structural check used by the heuristic: does this 802.15.4 payload have
-- the exact shape of a WirelessHART DLPDU?
local function looks_like_wihart(tvb)
    local len = tvb:len()
    if len < 1 + MIC_LEN then return false end
    local spec = tvb(0, 1):uint()
    if bits(spec, 6, 2) ~= 0 then return false end -- reserved bits
    local name = pkttype[bits(spec, 0, 3)]
    local body = len - 1 - MIC_LEN
    if name == "ack" then return body == 3 end
    if name == "keep alive" or name == "disconnect" then return body == 0 end
    if name == "advertise" then return advertise_mapsz(tvb, 1, body) ~= nil end
    if name == "data" then
        if body < NPDU_MIN then return false end
        local control = tvb(1, 1):uint()
        local need = NPDU_MIN + 6 * bits(control, 7, 1) + 6 * bits(control, 6, 1)
        return body >= need
    end
    return false
end

function wihart.dissector(tvb, pinfo, tree)
    local len = tvb:len()
    if len < 1 + MIC_LEN then return 0 end

    pinfo.cols.protocol = "WiHART"

    local spec = tvb(0, 1):uint()
    local pduname = pkttype[bits(spec, 0, 3)] or "unknown"
    pinfo.cols.info = pduname

    local subtree = tree:add(wihart, tvb(), "WirelessHART DLPDU")
    local pan = wpan_dst_pan()
    if pan then
        -- Bytes live in the wpan header, not this payload: add as generated.
        subtree:add(f.netid, tvb(0, 0), pan.value):set_generated()
    end
    local spectree = subtree:add(f.dlpduspec, tvb(0, 1))
    spectree:add(f.dlpduspec_priority, tvb(0, 1))
    spectree:add(f.dlpduspec_netkey, tvb(0, 1))
    spectree:add(f.dlpduspec_type, tvb(0, 1))

    local datalen = len - 1 - MIC_LEN
    if datalen > 0 then
        subtree:add(f.dlpdudata, tvb(1, datalen))
    end
    subtree:add(f.mic, tvb(len - MIC_LEN, MIC_LEN))

    local pos = 1
    local function add(t, field, size)
        local item = t:add(field, tvb(pos, size))
        pos = pos + size
        return item
    end

    if pduname == "ack" then
        local acktree = subtree:add(wihart, tvb(1, datalen), "WirelessHART ACK")
        add(acktree, f.ack_code, 1)
        add(acktree, f.ack_timeadj, 2)

    elseif pduname == "advertise" then
        local advtree = subtree:add(wihart, tvb(1, datalen), "WirelessHART ADVERTISE")
        add(advtree, f.adv_slot, 5)
        add(advtree, f.adv_joinctl, 1)
        -- Malformed frame (neither size fits): show it with the older rule.
        local mapsz = advertise_mapsz(tvb, 1, datalen) or math.ceil(tvb(pos, 1):uint() / 8)
        add(advtree, f.adv_mapsz, 1)
        local mapitem = add(advtree, f.adv_map, mapsz)
        if mapsz > 0 then
            mapitem:append_text(" (channels " .. channel_list(tvb, pos - mapsz, mapsz) .. ")")
        end
        add(advtree, f.adv_graphid, 2)
        local framecnt = tvb(pos, 1):uint()
        add(advtree, f.adv_framecnt, 1)
        for _ = 1, framecnt do
            add(advtree, f.adv_frameid, 1)
            add(advtree, f.adv_framesz, 2)
            local linkcnt = tvb(pos, 1):uint()
            add(advtree, f.adv_linkcnt, 1)
            for _ = 1, linkcnt do
                add(advtree, f.adv_linkjoinslot, 2)
                add(advtree, f.adv_linkjoinbits, 1)
            end
        end

    elseif pduname == "data" then
        local nwktree = subtree:add(wihart, tvb(1, datalen), "WirelessHART NPDU")
        local control = tvb(pos, 1):uint()
        local ctltree = add(nwktree, f.nwk_control, 1)
        ctltree:add(f.nwk_control_dst64, tvb(pos - 1, 1))
        ctltree:add(f.nwk_control_src64, tvb(pos - 1, 1))
        add(nwktree, f.nwk_ttl, 1)
        add(nwktree, f.nwk_asn, 2)
        add(nwktree, f.nwk_graphid, 2)
        if bits(control, 7, 1) == 1 then
            add(nwktree, f.nwk_dstaddr64, 8)
        else
            add(nwktree, f.nwk_dstaddr, 2)
        end
        if bits(control, 6, 1) == 1 then
            add(nwktree, f.nwk_srcaddr64, 8)
        else
            add(nwktree, f.nwk_srcaddr, 2)
        end
    end

    return len
end

-- Automatic detection on any 802.15.4 capture. Can be switched off under
-- Analyze > Enabled Protocols (wihart_wpan).
wihart:register_heuristic("wpan", function(tvb, pinfo, tree)
    if not looks_like_wihart(tvb) then return false end
    wihart.dissector(tvb, pinfo, tree)
    return true
end)

-- Manual fallback: Analyze > Decode As... > "IEEE 802.15.4 PANID" > WIHART.
DissectorTable.get("wpan.panid"):add_for_decode_as(wihart)
