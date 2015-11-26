module(..., package.seeall)

local raw = require("apps.socket.raw")
local router = require("apps.router.router")

function run (parameters)
   local conf = { 
      ports = {
         port1 = {
            native_vlan = 10,
            dev = 'eth1'
         },
         
         port2 = {
            native_vlan = 11,
            dev = 'eth2'   
         }
      },

      -- virtual interfaces
      vif = {
         {
            name           = 'vlan3.2',
            physical_dev   = 'eth1',
            eth_type       = 'qinq', -- qinq, dot1q, untagged
            qinq_tpid      = 0x8100,
            
            outer_vid      = 3,
            inner_vid      = 2,
            outer_prio     = 1,
            inner_prio     = 1,
            
            ip_addr        = '10.3.2.1',
            mask           = 24,
            --mac_addr       = '00:0c:29:01:01:f1',
            mac_addr       = '00:0c:29:4d:31:f4',
            proxy_arp      = false,
         },
         
         {
            name           = 'vlan4.2',
            physical_dev   = 'eth2',
            eth_type       = 'qinq', -- qinq, dot1q, untagged
            qinq_tpid      = 0x8100,
            outer_vid      = 4,
            inner_vid      = 2,
            outer_prio     = 1,
            inner_prio     = 1,
            ip_addr        = '10.4.2.1',
            mask           = 24,
            -- mac_addr       = '00:0c:29:01:01:f2',
            mac_addr       = '00:0c:29:4d:31:fe',
            proxy_arp      = false,
         },
      },
   }

   local c = config.new()
   config.app(c, "r1", router.router, conf)
   local socket_name, port, port_name, link_name
   
   local port_name, port
   for port_name, port in pairs(conf.ports) do
      socket_name = "socket_" .. port_name
      config.app(c, socket_name, raw.RawSocket, {ifname = port.dev, auxdata = 1})
      
      link_name = socket_name .. '.tx -> r1.' .. port_name
      config.link(c, link_name)
      print(link_name)
      
      link_name = 'r1.' .. port_name .. ' -> ' .. socket_name .. '.rx'
      config.link(c, link_name)
      print(link_name)
   end
   
   engine.configure(c)
   engine.app_table.r1:post_config();
   engine.main({duration=6000, report = {showlinks=true}})
end
