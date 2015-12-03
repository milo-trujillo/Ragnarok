#!/usr/bin/env ruby
require 'packetfu'
require 'set'

interface = ARGV[0]
unless( interface )
	puts "USAGE: #{__FILE__} <interface name>"
	exit(0)
end

unless( Process.euid.zero? )
	puts "Packet sniffing requires root permission."
	exit(0)
end

sources = Set.new

capture = PacketFu::Capture.new(:iface => interface, :start => true, :filter => "ip")
capture.stream.each do |pkt|
	packet = PacketFu::Packet.parse(pkt)
	source = packet.ip_saddr
	alreadySeen = sources.add?(source)
	if( alreadySeen != nil )
		puts "Received packet from new host #{source}"
	end
end
