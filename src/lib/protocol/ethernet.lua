module(..., package.seeall)
local ffi = require("ffi")
local C = ffi.C
local lib = require("core.lib")
local bitfield = lib.bitfield
local header = require("lib.protocol.header")
local ipv6 = require("lib.protocol.ipv6")
local band = require("bit").band
local ntohs, htons = lib.ntohs, lib.htons

local mac_addr_t = ffi.typeof("uint8_t[6]")
local ethernet = subClass(header)

-- Class variables
ethernet._name = "ethernet"
ethernet._ulp = {
   class_map = {
                  [0x0800] = "lib.protocol.ipv4",
                  [0x86dd] = "lib.protocol.ipv6",
                  [0x0806] = "lib.protocol.arp",
                },
   method    = 'type' }
ethernet:init(
   {
      [1] = ffi.typeof[[
            struct {
               uint8_t  ether_dhost[6];
               uint8_t  ether_shost[6];
               uint16_t ether_type;
            } __attribute__((packed))
      ]],
      
      -- 802.1q
      [2] = ffi.typeof[[
            struct {
               uint8_t  ether_dhost[6];
               uint8_t  ether_shost[6];
               uint16_t tpid;
               uint16_t tci; /* tag control information: priority, cfi, vlan_id */
               uint16_t ether_type;
            } __attribute__((packed))
      ]],
      
      -- QinQ
      [3] = ffi.typeof[[
            struct {
               uint8_t  ether_dhost[6];
               uint8_t  ether_shost[6];
               uint16_t outer_tpid;
               uint16_t outer_tci; /* tag control information: priority, cfi, vlan_id */
               uint16_t inner_tpid;
               uint16_t inner_tci; /* tag control information: priority, cfi, vlan_id */
               uint16_t ether_type;
            } __attribute__((packed))
      ]],
   })

local types = { untagged = 1, dot1q = 2, qinq = 3, }

-- Class methods

function ethernet:new(config)
   local o = ethernet:superClass().new(self)
   local vlan_type = config.vlan_type or 1 -- default is untagged
   
   if (vlan_type ~= 1) then
      local header = o._headers[vlan_type]
      o._header = header
      local data = header.data
      header.box[0] = ffi.cast(header.ptr_t, data)
      ffi.fill(data, ffi.sizeof(data))
   end

   o.vlan_type = vlan_type
   o:dst(config.dst)
   o:src(config.src)
   o:type(config.type)

   if (vlan_type ~= 1) then
      local h = o:header()
   
      -- tci
      --    3 bit  - prioroty
      --    1 bit  - cfi (0 - canonical ethernet)
      --    12 bit - vlan id
      
      if (config.vlan_header_bits ~= nil) then   
         if (vlan_type == 2) then
            -- dot1q
            bitfield(16, h, 'tci', 0, 3, config.priority) -- priority
            bitfield(16, h, 'tci', 3, 1, 0) -- cfi
            bitfield(16, h, 'tci', 4, 12, config.vid) -- vlan id
         elseif (vlan_type == 3) then 
            -- qinq
            bitfield(16, h, 'outer_tci', 0, 3, config.outer_priority) -- priority
            bitfield(16, h, 'outer_tci', 3, 1, 0) -- cfi
            bitfield(16, h, 'outer_tci', 4, 12, config.outer_vid) -- vlan id
            
            bitfield(16, h, 'inner_tci', 0, 3, config.inner_priority) -- priority
            bitfield(16, h, 'inner_tci', 3, 1, 0) -- cfi
            bitfield(16, h, 'inner_tci', 4, 12, config.inner_vid) -- vlan id
         end
      elseif (config.proto_pkt ~= nil) then
         local proto_pkt = config.proto_pkt
         local proto_h = proto_pkt:header()
         
         if (vlan_type == 2) then
            -- dot1q
            h.tci = proto_h.tci;
            h.tpid = proto_h.tpid;
         elseif (vlan_type == 3) then 
            -- qinq
            h.outer_tci = proto_h.outer_tci;
            h.outer_tpid = proto_h.outer_tpid;
            h.inner_tci = proto_h.inner_tci;
            h.inner_tpid = proto_h.inner_tpid;
         end
      end
   end
      
   return o
end

function ethernet:new_from_mem (mem, size, config)
   local o = ethernet:superClass().new_from_mem(self, mem, size)
   local header = o._header
   local data = header.box[0]
   local ether_type = lib.htons(data.ether_type)
   local vlan_type
   
   if (ether_type == 0x8000) then 
      vlan_type = 1 -- untagged 
   elseif (ether_type == config.qinq_tpid) then
      vlan_type = 3 -- qinq
   elseif (ether_type == 0x8100) then
      vlan_type = 2 -- dot1q
   else 
      vlan_type = 1 -- untagged
   end
   
   o.vlan_type = vlan_type
   
   local header = o._headers[vlan_type]
   header.box[0] = ffi.cast(header.ptr_t, mem)
   o._header = header
   
   return o
end

-- Convert printable address to numeric
function ethernet:pton (p)
   local result = mac_addr_t()
   local i = 0
   for v in p:split(":") do
      if string.match(v:lower(), '^[0-9a-f][0-9a-f]$') then
         result[i] = tonumber("0x"..v)
      else
         error("invalid mac address "..p)
      end
      i = i+1
   end
   assert(i == 6, "invalid mac address "..p)
   return result
end

-- Convert numeric address to printable
function ethernet:ntop (n)
   local p = {}
   for i = 0, 5, 1 do
      table.insert(p, string.format("%02x", n[i]))
   end
   return table.concat(p, ":")
end

-- Mapping of an IPv6 multicast address to a MAC address per RFC2464,
-- section 7
function ethernet:ipv6_mcast(ip)
   local result = self:pton("33:33:00:00:00:00")
   local n = ffi.cast("uint8_t *", ip)
   assert(n[0] == 0xff, "invalid multiast address: "..ipv6:ntop(ip))
   ffi.copy(ffi.cast("uint8_t *", result)+2, n+12, 4)
   return result
end

-- Check whether a MAC address has its group bit set
function ethernet:is_mcast (addr)
   return band(addr[0], 0x01) ~= 0
end

-- Instance methods

function ethernet:src (a)
   local h = self:header()
   if a ~= nil then
      ffi.copy(h.ether_shost, a, 6)
   else
      return h.ether_shost
   end
end

function ethernet:src_eq (a)
   return C.memcmp(a, self:header().ether_shost, 6) == 0
end

function ethernet:dst (a)
   local h = self:header()
   if a ~= nil then
      ffi.copy(h.ether_dhost, a, 6)
   else
      return h.ether_dhost
   end
end

function ethernet:dst_eq (a)
   return C.memcmp(a, self:header().ether_dhost, 6) == 0
end

function ethernet:swap ()
   local tmp = mac_addr_t()
   local h = self:header()
   ffi.copy(tmp, h.ether_dhost, 6)
   ffi.copy(h.ether_dhost, h.ether_shost,6)
   ffi.copy(h.ether_shost, tmp, 6)
end

function ethernet:type (t)
   local h = self:header()
   if t ~= nil then
      h.ether_type = htons(t)
   else
      return(ntohs(h.ether_type))
   end
end

function ethernet:get_field(name)
   local h = self:header()
   return ntohs(h[name])
end

function ethernet:set_field(name, v)
   local h = self:header()
   h[name] = htons(v)
end

-- tpid

function ethernet:get_tpid()
   return self:get_field('tpid')
end

function ethernet:set_tpid(v)
   self:set_field('tpid', v)
end

function ethernet:get_outer_tpid()
   return self:get_field('outer_tpid')
end

function ethernet:set_outer_tpid(v)
   self:set_field('outer_tpid', v)
end

function ethernet:get_inner_tpid()
   return self:get_field('inner_tpid')
end

function ethernet:set_inner_tpid(v)
   self:set_field('inner_tpid', v)
end

-- prio

function ethernet:get_prio()
   local h = self:header()
   return bitfield(16, h, 'tci', 0, 3)
end

function ethernet:set_prio(v)
   local h = self:header()
   bitfield(16, h, 'tci', 0, 3, v)
end

function ethernet:get_outer_prio()
   local h = self:header()
   return bitfield(16, h, 'outer_tci', 0, 3)
end

function ethernet:set_outer_prio(v)
   local h = self:header()
   bitfield(16, h, 'outer_tci', 0, 3, v)
end

function ethernet:get_inner_prio()
   local h = self:header()
   return bitfield(16, h, 'inner_tci', 0, 3)
end

function ethernet:set_inner_prio(v)
   local h = self:header()
   bitfield(16, h, 'inner_tci', 0, 3, v)
end

-- vid

function ethernet:get_vid()
   local h = self:header()
   return bitfield(16, h, 'tci', 4, 12)
end

function ethernet:set_vid(v)
   local h = self:header()
   bitfield(16, h, 'tci', 4, 12, v)
end

function ethernet:get_outer_vid()
   local h = self:header()
   return bitfield(16, h, 'outer_tci', 4, 12)
end

function ethernet:set_outer_vid(v)
   local h = self:header()
   bitfield(16, h, 'outer_tci', 4, 12, v)
end

function ethernet:get_inner_vid()
   local h = self:header()
   return bitfield(16, h, 'inner_tci', 4, 12)
end

function ethernet:set_inner_vid(v)
   local h = self:header()
   bitfield(16, h, 'inner_tci', 4, 12, v)
end

return ethernet

