#!/usr/bin/env python2
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), '../../utils/'))

import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def rules1(p4info_helper, sw):
    #1
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.swtrace",
        default_action=True,
        action_name="MyEgress.add_swtrace",
        action_params={
            "swid": 1
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name
    
    #2
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ("10.0.1.1", 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": "00:00:00:00:01:01",
            "port": 2
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

    #3
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ("10.0.1.11", 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": "00:00:00:02:04:00",
            "port": 1
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

    #4
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ("10.0.2.2", 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": "00:00:00:02:03:00",
            "port": 3
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

    #5
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ("10.0.2.22", 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": "00:00:00:02:04:00",
            "port": 4
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

def rules2(p4info_helper, sw):
    #1
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.swtrace",
        default_action=True,
        action_name="MyEgress.add_swtrace",
        action_params={
            "swid": 2
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name
    
    #2
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ("10.0.2.2", 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": "00:00:00:00:02:02",
            "port": 2
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

    #3
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ("10.0.2.22", 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": "00:00:00:00:02:16",
            "port": 1
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

    #4
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ("10.0.1.1", 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": "00:00:00:01:03:00",
            "port": 3
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

    #5
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": ("10.0.1.11", 32)
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": "00:00:00:01:04:00",
            "port": 4
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name
##########################

def rules1cc(p4info_helper, sw):
    #1
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.swtrace",
        default_action=True,
        action_name="MyEgress.add_swtrace",
        action_params={
            "swid": 1
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name

def rules2cc(p4info_helper, sw):
    #1
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyEgress.swtrace",
        default_action=True,
        action_name="MyEgress.add_swtrace",
        action_params={
            "swid": 2
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ingress tunnel rule on %s" % sw.name
##########################

def readTableRules(p4info_helper, sw):
    """
    Reads the table entries from all tables on the switch.

    :param p4info_helper: the P4Info helper
    :param sw: the switch connection
    """
    print '\n----- Reading tables rules for %s -----' % sw.name
    for response in sw.ReadTableEntries():
        for entity in response.entities:
            entry = entity.table_entry
            # TODO For extra credit, you can use the p4info_helper to translate
            #      the IDs in the entry to names
            table_name = p4info_helper.get_tables_name(entry.table_id)
            print '%s: ' % table_name,
            for m in entry.match:
                print p4info_helper.get_match_field_name(table_name, m.field_id),
                print '%r' % (p4info_helper.get_match_field_value(m),),
            action = entry.action.action
            action_name = p4info_helper.get_actions_name(action.action_id)
            print '->', action_name,
            for p in action.params:
                print p4info_helper.get_action_param_name(action_name, p.param_id),
                print '%r' % p.value,
            print

def printGrpcError(e):
    print "gRPC Error:", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    traceback = sys.exc_info()[2]
    print "[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def printCounter(p4info_helper, sw, counter_name, index):
    """
    Reads the specified counter at the specified index from the switch. In our
    program, the index is the tunnel ID. If the index is 0, it will return all
    values from the counter.

    :param p4info_helper: the P4Info helper
    :param sw:  the switch connection
    :param counter_name: the name of the counter from the P4 program
    :param index: the counter index (in our case, the tunnel ID)
    """
    for response in sw.ReadCounters(p4info_helper.get_counters_id(counter_name), index):
        for entity in response.entities:
            counter = entity.counter_entry
            print "%s %s %d: %d packets (%d bytes)" % (
                sw.name, counter_name, index,
                counter.data.packet_count, counter.data.byte_count
            )
            return counter.data.packet_count

def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)

    try:
        ###########################################################################
        ############################# Setting Setting #############################
        ########################################################################### 
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s1"
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                       bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForwardingPipelineConfig on s2"

        ###########################################################################
        ############################ Install all rules ############################
        ###########################################################################
        rules1(p4info_helper, s1)
        rules2(p4info_helper, s2)

        readTableRules(p4info_helper, s1)
        readTableRules(p4info_helper, s2)

        while True:
            sleep(2)
            print '\n----- Reading tunnel counters -----'
            x = printCounter(p4info_helper, s1, "MyIngress.cca", 0)
            y = printCounter(p4info_helper, s1, "MyIngress.ccb", 1)
        ###########################################################################
        ############################# End End End End #############################
        ###########################################################################
    except KeyboardInterrupt:
        print " Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()



if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.p4info')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/mri.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nHave you run 'make'?" % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
