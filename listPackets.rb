#!/usr/bin/env ruby
require 'packetfu'

interface = ARGV[0]
unless( interface )
	puts "USAGE: #{__FILE__} <interface name>"
	exit(0)
end

unless( Process.euid.zero? )
	puts "Packet sniffing requires root permission."
	exit(0)
end

capture = PacketFu::Capture.new(:iface => interface, :start => true, :filter => "ip")
capture.stream.each do |pkt|
	p = PacketFu::Packet.parse(pkt)
	if( p.is_ip? )
		(src, dst, size, type) = [p.ip_saddr, p.ip_daddr, p.size, p.proto.last]
		printf("%-15s -> %-15s %s (%d bytes)\n", src, dst, type, size)
	end
end
