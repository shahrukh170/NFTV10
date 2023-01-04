import argparse
from core.util import getIfaceNameByAddr
from core.handlers import gatewayFilterPacketsHandler, staticFilterPacketsHandler

def cliArgumentsToConfiguration(args):
	""" Takes in CLI arguments and returns a dictionary of configurations.
	"""
	
	parser = argparse.ArgumentParser('Flow-Based Filter CLI')
	parser.add_argument('-i', '--ingress-ip', action='store', dest='ingress_ip', required=True, type=str, help='Input IP Address')
	parser.add_argument('-o', '--egress-ip', action='store', dest='egress_ip', required=True, type=str, help='Output IP Address')

	sub_parsers = parser.add_subparsers(dest='subCommands')
	gateway_args = sub_parsers.add_parser('gateway', help='Mode 0 - Gateway filter')

	static_filter_args = sub_parsers.add_parser('static', help='Mode 1 - Static Filter')
	static_filter_args.add_argument(
		'-pl', 
		'--packet-based-rules', 
		action='store', 
		dest='packet_based_rules', 
		required=True, 
		type=str,
		help='specify a list of Packet Based Filter rules, separated by \",\" e.g 2,3,4')
	static_filter_args.add_argument(
		'-fl', 
		'--flow-based-rules', 
		action='store', 
		dest='flow_based_rules', 
		required=False, 
		type=str,
		help='specify a list of Flow Based Filter rules, separated by \",\" e.g 2,3,4')
	

	result = parser.parse_args(args)
	ingress_ip, egress_ip = result.ingress_ip, result.egress_ip
	ingress_iface, egress_iface = getIfaceNameByAddr(ingress_ip), getIfaceNameByAddr(egress_ip)

	filter_mode_name = result.subCommands
	packets_handler  = None
	conf = {
		'ingress_ip': ingress_ip, 
		'egress_ip': egress_ip, 
		'ingress_iface': ingress_iface, 
		'egress_iface': egress_iface
	}

	if filter_mode_name:
		if filter_mode_name == 'gateway':
			conf['handler'] = gatewayFilterPacketsHandler
		elif filter_mode_name == 'static':
			conf['handler'] = staticFilterPacketsHandler
			packet_based_rules = result.packet_based_rules if(result.packet_based_rules) else ''
			packet_based_rules = packet_based_rules.strip(',').split(',')
			conf['pbf_rule_numbers'] = [int(i) for i in packet_based_rules if i.isdigit()]
			flow_based_rules = result.flow_based_rules if(result.flow_based_rules) else ''
			flow_based_rules = flow_based_rules.strip(',').split(',')
			conf['fbf_rule_numbers'] = [int(i) for i in flow_based_rules if i.isdigit()]
		else:
			parser.print_help()
			parser.exit()
	else:
		parser.print_help()
		parser.exit()

	return conf

