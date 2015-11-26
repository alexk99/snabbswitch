module(..., package.seeall)
local ffi = require("ffi")
local C = ffi.C
local lib = require("core.lib")
local bitfield = lib.bitfield
local header = require("lib.protocol.header")
local band = require("bit").band
local ntohs, htons = lib.ntohs, lib.htons
local mac_addr_t = ffi.typeof("uint8_t[6]")
local arp = subClass(header)

-- Class variables
arp._name = "arp" -- ipv4 ethernet arp
arp._ulp = {
   class_map = {},
   method    = nil 
}

arp:init(
   {  [1] = ffi.typeof[[
            struct {
               uint16_t htype;   // Hardware type
               uint16_t ptype;   // Protocol type
               uint8_t hlen;     // Hardware address length 
               uint8_t plen;     // Protocol address length
               uint16_t oper;    // operation
               uint8_t sha[6];   // sender hardware address
               uint8_t spa[4];   // sender protocol address
               uint8_t tha[6];   // target hardware address
               uint8_t tpa[4];   // target protocol address
            }
      ]],
   }
)

local types = { base = 1, }

-- Class methods
function arp:new(config)
   local o = arp:superClass().new(self)
   local h = o:header();
   
   h.htype = htons(1) -- ethernet
   h.ptype = htons(0x800) -- ipv4
   h.hlen = 6 -- ethernet mac size
   h.plen = 4 -- ipv4 addr size
   h.oper = htons(config.oper)
   
   ffi.copy(h.sha, config.sha, 6)
   ffi.copy(h.spa, config.spa, 4)   
   ffi.copy(h.tha, config.tha, 6)
   ffi.copy(h.tpa, config.tpa, 4)   
   
   return o
end

function arp:get_oper()
   local h = self:header()
   return ntohs(h['oper'])
end


return arp

