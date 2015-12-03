#!/usr/bin/env ruby
require 'packetfu'

=begin
	This utility sends one single packet, from any address to any address.
	It's mostly for testing how devices in the pool react when they impersonate
	one another.
=end

unless( ARGV.size == 6 )
	puts "USAGE:"
	puts "  #{__FILE__} <interface> <sourceIP> <destIP> <sourcePort> <destPort> <msg>"
	exit(0)
end
(interface, src, dst, srcPort, dstPort, payload) = ARGV

unless( Process.euid.zero? )
	puts "Low level packet generation requires root permission."
	exit(0)
end

packet = PacketFu::TCPPacket.new
packet.payload = payload
packet.ip_saddr = src
packet.ip_daddr = dst
packet.tcp_sport = srcPort
packet.tcp_dport = dstPort
packet.recalc
puts "Packet created"

config = PacketFu::Config.new(PacketFu::Utils.whoami?(:iface=> interface)).config
injector = PacketFu::Inject.new(:iface => interface, :config => config, :promisc => false)
injector.array_to_wire(:array => [packet.to_s])
puts "Packet sent"
