module(..., package.seeall)

local ffi = require("ffi")
local lib = require("core.lib")
local packet = require("core.packet")
local link = require("core.link")
local ethernet = require("lib.protocol.ethernet")
local arp = require("lib.protocol.arp")
local ipv4 = require("lib.protocol.ipv4")
local datagram = require("lib.protocol.datagram")

local empty, receive, transmit = link.empty, link.receive, link.transmit
local clone = packet.clone

local ipv4_addr_t = ffi.typeof("uint8_t[4]")
local ipv4_addr_t_size = ffi.sizeof(ipv4_addr_t)


router = subClass(nil)
router._name = "ipv4 router"

function router.d_print(v)
   return
   -- print (v)
end

local d_print = router.d_print

function router:new(arg)
   local o = router:superClass().new(self, arg)
   
   local conf = arg and config.parse_app_arg(arg) or {}
   assert(conf.ports, self._name..": invalid configuration")

   -- config
   o.conf = conf

   return o
end

function router:pkt_vid_key(pkt, port)
   local key

   d_print ("pkt vlan_type: " .. pkt.vlan_type)
   
   if (pkt.vlan_type == 1) then
      key = self.conf.ports[port.name].native_vlan
   elseif (pkt.vlan_type == 2) then
      key = pkt.vid
   elseif (pkt.vlan_type == 3) then 
      key = pkt.outer_vid * 4096 + pkt.inner_vid
   else
      key = nil
   end
   
   return key
end

function router:post_config()
   assert(self.input and self.output)
   
   local port_name
   for port_name, port in pairs(self.conf.ports) do
      port.input_link = self.input[port_name]
      port.output_link = self.output[port_name]
   end

   local conf = self.conf

   -- physical ports
   self.port_by_dev = {}
   local port
   for _, port in pairs(conf.ports) do
      d_print('port by dev ' .. port.dev)
      self.port_by_dev[port.dev] = port
   end

   
   -- vif
   local key, vif_name, vlan_type

   local vif_by_key = {}
   self.vif_by_key= vif_by_key

   local vif_by_name = {}
   self.vif_by_name= vif_by_name
  
   for _, vif in ipairs(conf.vif) do
   
      if (vif.eth_type == "qinq") then
         key = vif.outer_vid * 4096 + vif.inner_vid
         vlan_type = 3
      elseif (vif.eth_type == "dot1q") then
         key = vif.vid
         vlan_type = 2
      elseif (vif.eth_type == "untagged") then 
         key = vif.native_vlan
         vlan_type = 1
      else
         -- todo 
         -- syslog the error
      end
   
      vif_by_key[key] = vif
      d_print ("key: " .. key)
      
      vif.c_ip = ipv4:pton(vif.ip_addr)
      vif.c_mac = ethernet:pton(vif.mac_addr)
      vif.vlan_type = vlan_type
      
      vif.counters = {
         rpf_dropped = 0,
      };
      
      port = self.port_by_dev[vif.physical_dev]
      vif.port = port
      
      d_print ('vif_by_name: ' .. vif.name)
      vif_by_name[vif.name] = vif
   end
   
   -- debug
   self.ip_4_2_10 = ipv4:pton('10.4.2.10')
   self.ip_3_2_2 = ipv4:pton('10.3.2.2')

   self.eth_a = ethernet:pton('00:0c:29:aa:88:cf')
   self.eth_b = ethernet:pton('00:0c:29:43:12:49')
   
   
   d_print "post_config(): end"
end

function router.cmp_ip(ip1, ip2)
   return ffi.C.memcmp(ip1, ip2, ipv4_addr_t_size) == 0
end

function router:ip_reachable(ip) 
   return true
end

function router:process_arp(port, pkt, eth_pkt, inp_vif)
   local eth_pkt_size = ffi.sizeof(eth_pkt:ctype())

   local arp_pkt = arp:new_from_mem(
      pkt.data + eth_pkt_size,
      pkt.length - eth_pkt_size)
   
   d_print ("eth pkt size: " .. eth_pkt_size)
   d_print ("inp_vif: " .. inp_vif.name)
   
   local eth_h = eth_pkt:header()
   local arp_h = arp_pkt:header()
   
   if (arp_pkt:get_oper() == 1) then -- request
      d_print "arp request"
   
      local request_h = arp_h
           
      if ((inp_vif.proxy_arp == true and router:ip_reachable(request_h.tpa)) or
            router.cmp_ip(inp_vif.c_ip, request_h.tpa)) then
      
         local arp_reply = arp:new({
            oper = 2, -- reply
            sha = inp_vif.c_mac,
            spa = request_h.tpa,
            tha = request_h.sha,
            tpa = request_h.spa,
         })
         
         -- construct reply
         local ether = ethernet:new({
            src = inp_vif.c_mac,
            dst = eth_h.ether_shost,
            vlan_type = eth_pkt.vlan_type,
            proto_pkt = eth_pkt,
            type = 0x0806, -- arp
         })

         d_print ("reply.smac: " .. ether:ntop(ether:src()))
         d_print ("reply.dmac: " .. ether:ntop(ether:dst()))
                 
         local p = packet.allocate()
         local dgram = datagram:new(p)
         dgram:push(arp_reply)
         dgram:push(ether)
        
         link.transmit(port.output_link, p)
   end
   elseif (arp_h.oper == 2) then -- reply
      
   end
end

function router:fib_lookup(ipv4_pkt) 
   local ip_addr = ipv4_pkt:dst()
   d_print ("fib ip: " .. ipv4:ntop(ip_addr))

   if (router.cmp_ip(ip_addr, self.ip_4_2_10)) then
      return {
         prefix = '10.4.2.0',
         mask = 24,
         out_vif = self.vif_by_name['vlan4.2'],
         next_hop = nil,
         unreachable = false
      }
   elseif (router.cmp_ip(ip_addr, self.ip_3_2_2)) then
      return {
         prefix = '10.3.2.0',
         mask = 24,
         out_vif = self.vif_by_name['vlan3.2'],
         next_hop = nil,
         unreachable = false
      }
   end
end

function router:arp_lookup(ip_addr)
   d_print ("arp ip: " .. ipv4:ntop(ip_addr))

   if (router.cmp_ip(ip_addr, self.ip_4_2_10)) then
      return {
         addr = self.eth_a
      }
   elseif (router.cmp_ip(ip_addr, self.ip_3_2_2)) then
      return {
         addr = self.eth_b
      }
   end
end


function router:input_ipv4(port, pkt, eth_pkt, ipv4_pkt, inp_vif)
end

function router:forward_ipv4(port, pkt, eth_pkt, ipv4_pkt, inp_vif)
   local fib_rec = self:fib_lookup(ipv4_pkt)
   
   -- route not found
   if (not fib_rec) then
      -- drop packet
      packet.free(pkt)
      -- todo: update statistic counters
      return
   end
   
   -- unreachable
   if (fib_rec.unreachable) then
      -- drop packet
      packet.free(pkt)
      -- todo: update statistic counters
      return
   end

   -- decrement ttl
   local ttl = ipv4_pkt:ttl()
   ttl = ttl - 1
   if (ttl == 0) then
      -- drop packet
      packet.free(pkt)
      -- todo: update statistic counters
      return
   end
   ipv4_pkt:ttl(ttl)

   -- arp lookup
   local arp_rec = self:arp_lookup(ipv4_pkt:dst())
   if (not arp_rec or not arp_rec.addr) then
      -- ethernet destination address unknown
      -- drop packet
      packet.free(pkt)
      
      -- todo: arp request
      
      -- todo: update statistic counters
      d_print('drop packet')
      return
   end
   local dst_mac_addr = arp_rec.addr
  
   -- set new ethernet headers
   eth_pkt:src(inp_vif.c_mac)
   eth_pkt:dst(dst_mac_addr)
   
   -- set new vlan headers
   local out_vif = fib_rec.out_vif
   if (out_vif.vlan_type == 3) then
      -- tpid
      -- use outgoing interface tpid
      eth_pkt:set_outer_tpid(out_vif.qinq_tpid)
      eth_pkt:set_inner_tpid(0x8100)

      -- vlan id
      -- use outgoing 
      eth_pkt:set_outer_vid(out_vif.outer_vid)
      eth_pkt:set_inner_vid(out_vif.inner_vid)

      -- prio
      -- overwrite packets outer and inner priorities
      -- only if priorities are defined in the outgoing interface
      if (out_vif.outer_prio) then
         eth_pkt:set_outer_prio(out_vif.outer_prio)
      end
      
      if (out_vif.inner_prio) then
         eth_pkt:set_inner_prio(out_vif.inner_prio)
      end
   elseif (vif.vlan_type == 2) then
      -- tpid
      eth_pkt:set_tpid(out_vif.qinq_tpid)

      -- vlan id
      eth_pkt:set_vid(out_vif.outer_vid)

      -- prio
      -- overwrite packets outer and inner priorities
      -- only if priorities are defined in the outgoing interface
      if (out_vif.prio) then
         eth_pkt:set_inner_prio(out_vif.prio)
      end
   end
   
   -- recompute checksum
   ipv4_pkt:header().checksum = 0
   ipv4_pkt:checksum()
   
   -- send packet
   link.transmit(out_vif.port.output_link, pkt)
end

function router:process_ipv4(port, pkt, eth_pkt, inp_vif)
   local eth_pkt_size = ffi.sizeof(eth_pkt:ctype())

   local ipv4_pkt = ipv4:new_from_mem(
      pkt.data + eth_pkt_size,
      pkt.length - eth_pkt_size)
   
   d_print ("eth pkt size: " .. eth_pkt_size)
   d_print ("inp_vif: " .. inp_vif.name)
   
   local ipv4_pkt_h = ipv4_pkt:header()
   
   if (router.cmp_ip(ipv4_pkt_h.dst_ip, inp_vif.c_ip)) then
      d_print('INPUT')
      -- INPUT
      -- this packet is for this router
  
      -- Reverse Path Filtering
      if (inp_vif.rpf) then
         local fib_rec = self:fib_lookup(ipv4_pkt)
         if (not fib_rec or fib_rec.out_if ~= inp_vif) then
            -- drop packet
            -- increment rpf dropped packets counter
            vif.couters.rpf_dropped = vif.couters.rpf_dropped + 1
         end
      end
      
      self:input_ipv4(port, pkt, eth_pkt, ipv4_pkt, inp_vif)
   else
      -- FORWARD
      d_print('FORWARD')
      self:forward_ipv4(port, pkt, eth_pkt, ipv4_pkt, inp_vif)
   end
end

function router:push()
   local port
   local input_link
   local output_link
   
   for _, port in pairs(self.conf.ports) do
      input_link = port.input_link
      output_link = port.output_link
   
      while not empty(input_link) do
         local pkt = receive(input_link)
         
         local eth_pkt = ethernet:new_from_mem(pkt.data, pkt.length, { qinq_tpid = 0x8100 })
         local eth_pkt_h = eth_pkt:header()
         
         d_print ("eth_type: " .. eth_pkt:type())
         -- d_print ("tpid: " .. eth:tpid())
         -- d_print ("vid: " .. eth:vid())
         d_print ("outer_tpid: " .. eth_pkt:get_outer_tpid())
         d_print ("inner_tpid: " .. eth_pkt:get_inner_tpid())
         d_print ("outer_vid: " .. eth_pkt:get_outer_vid())
         d_print ("inner_vid: " .. eth_pkt:get_inner_vid())
         d_print ("outer_prio: " .. eth_pkt:get_outer_prio())
         d_print ("inner_prio: " .. eth_pkt:get_inner_prio())
         
         -- ind virtual interface
         if (eth_pkt.vlan_type == 1) then
            -- untagged frame
         elseif (eth_pkt.vlan_type == 2) then
            -- dot1q
         elseif (eth_pkt.vlan_type == 3) then
            -- qinq
            eth_pkt.inner_vid = eth_pkt:get_inner_vid()
            eth_pkt.outer_vid = eth_pkt:get_outer_vid()
         end
   
         local key = self:pkt_vid_key(eth_pkt, port);
         d_print ("key: " .. key)
         local inp_vif = self.vif_by_key[key]
         -- assert(inp_vif)
         local eth_type = eth_pkt:type()
        
         if (eth_type == 0x0806) then -- arp
            self:process_arp(port, pkt, eth_pkt, inp_vif)
         elseif (eth_type == 0x800) then -- ipv4
            self:process_ipv4(port, pkt, eth_pkt, inp_vif)
         end      
      end
   end   
   
--      elseif (eth_type == xxx) then -- icmp
         -- todo
         -- icmp packets might be fragmented.
         -- so first packet fragmentation must be implemented
      
--         local reply = router:process_icmp(pkt, eth_pkt, inp_vif)
--         if reply ~= nil then
--            link.transmit(output_link, reply)
--         end
--      end
   
end
