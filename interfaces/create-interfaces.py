#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Sample code for creating interfaces
# for a single host in NetBox, vm or hardware.
# See --help for usage.
#
# Could also be used for deleting/updating interfaces.
#
# Basic Usage:
#   create-interfaces.py -H https://netbox.example -T <TOKEN> <HOSTNAME> <INTERFACE_NAME> [<INTERFACE_NAME>...]
#   create-interfaces.py -H https://netbox.example -T <TOKEN> --csv ifaces.csv <HOSTNAME>
#
# Pass '-k' to disable TLS checks.
#

import argparse
import csv
import os
import sys

import requests
import urllib3
import pynetbox


def check_iface_config(iface_config):
    # <STUB>
    return bool(iface_config.get("name", None))
# --- end of check_iface_config (...) ---


def main(prog, argv):
    arg_parser = get_argument_parser(prog)
    arg_config = arg_parser.parse_args()

    # create http(s) session
    session = requests.Session()
    if arg_config.insecure:
        session.verify = False
        # disable warnings
        urllib3.disable_warnings()

    # init api endpoint
    api = pynetbox.api(
        arg_config.api_host,
        token=arg_config.api_token,
    )

    # bind http(s) session to api endpoint
    api.http_session = session

    # build up wanted interfaces
    #  a mapping name => interface config
    #
    #  interface config is a dictionary containing
    #  keys that will be passed as parameters
    #  when creating/editing interfaces, for instance:
    #    - name [required]
    #    - (type)
    #    - mtu
    #    - mac_address
    #    - description
    #    - mgmt_only
    #    - mode
    #    - untagged_vlan
    #    - tagged_vlans
    #
    # Attributes other than <name> require
    # somehow structured input (example code for CSV below).
    #
    wanted_interfaces = {}
    
    # from cmdline
    for iface_arg in arg_config.interface:
        # XXX: name only
        # could also use a more advanced "name[,mac[,...]]" format
        iface_config = {'name': iface_arg}

        wanted_interfaces[iface_config['name']] = iface_config
    # --

    # possibly from csv, json, ...
    # <STUB>
    if arg_config.csv:
        for iface_config in load_csv_vars_file(arg_config.csv):
            wanted_interfaces[iface_config['name']] = iface_config
        # --
    # --

    # validate - not properly implemented, checks name only
    invalid_interface_config = [
        name for name, iface_config in wanted_interfaces.items()
        if not check_iface_config(iface_config)
    ]

    if invalid_interface_config:
        raise RuntimeError("invalid iface config", invalid_interface_config)
    # --

    return main_create_interface(
        arg_config, api,
        arg_config.hostname,
        wanted_interfaces,
        arg_config.is_vm
    )
# --- end of main (...) ---


def main_create_interface(
    arg_config, api, hostname, wanted_interfaces, is_vm
):
    # API calls differ depending on whether the requested
    # host is a virtual machine or real hardware
    if is_vm:
        api_device = api.virtualization.virtual_machines
        api_interface = api.virtualization.interfaces
        api_ckey_iface = 'virtual_machine'
    else:
        api_device = api.dcim.devices
        api_interface = api.dcim.interfaces
        api_ckey_iface = 'device'
    # --
    api_qkey_iface = f'{api_ckey_iface}_id'

    # get device/vm info -- need device id
    dev_info = api_device.get(name=hostname)

    # lookup may fail..
    if dev_info is None:
        # XXX: proper exception
        sys.stderr.write(f"machine not found: {hostname}\n")
        return False
    # -- end if device not found

    # build common options for interacting with interfaces
    #   - device id
    iface_query_opts = {api_qkey_iface: dev_info.id}

    # get a list of interfaces for the requested hostname
    iface_info_list = list(api_interface.filter(**iface_query_opts))

    # build a mapping : interface name => interface info,
    # assuming that interface names are unique
    iface_info_map = {o.name: o for o in iface_info_list}

    # create a set of interface names
    # for both iface_info_map and wanted_interfaces
    iface_info_names = set(iface_info_map)
    wanted_iface_names = set(wanted_interfaces)

    # determine what would need to be done:
    #   - new   (interface does not exist yet)
    #       -> api_interface.create()
    #   - old   (interface should not exist)                  [NOT IMPLEMENTED]
    #       -> <iface_info>.delete()
    #   - keep  (interface exists - may have different info)  [NOT IMPLEMENTED]
    #       -> <iface_info>.put()/.patch()
    #
    ifaces_new = (wanted_iface_names - iface_info_names)
    ## ifaces_old  = (iface_info_names - wanted_iface_names),
    ## ifaces_keep = (wanted_iface_names & iface_info_names),
    ## XXX: depending on detail info, would have to compare 'keep'
    ##      whether mac, IP, (un)tagged VLAN, ... changed

    # print diff, lazy loop
    for key, names in [('new', ifaces_new)]:
        sys.stdout.write(
            "{host} : {key:<4} : {names}\n".format(
                host=hostname,
                key=key.upper(),
                names=(', '.join(sorted(names)) if names else '<none>'),
            )
        )
    # --

    if arg_config.dry_run:
        # dry run mode - bail out w/ success status
        return True
    # -- end if dry run mode?

    for iface_name in ifaces_new:
        # copy iface config from wanted_interfaces, add device id
        iface_opts = {}
        iface_opts.update(wanted_interfaces[iface_name])
        iface_opts[api_ckey_iface] = dev_info.id

        reply = api_interface.create(**iface_opts)

        if reply is None:
            sys.stderr.write(
                f"Failed to create interface {iface_name} for {hostname}!\n"
            )
            return False

        sys.stdout.write(f"reply = {reply!s}\n")
    # -- end for create interface

    return True
# --- end of main_create_interface (...) ---


def get_argument_parser(prog):
    prog_name = os.path.splitext(os.path.basename(prog))[0]

    arg_parser = argparse.ArgumentParser(
        prog = prog_name
    )

    arg_parser.add_argument(
        "-H", "--api-host",
        metavar="<url>",
        required=True,
        help="api endpoint (example: http://localhost:8000)"
    )

    arg_parser.add_argument(
        "-T", "--api-token",
        metavar="<token>",
        required=True,
        help="api token"
    )

    arg_parser.add_argument(
        "-k", "--insecure",
        default=False,
        action='store_true',
        help="disable TLS verification",
    )

    arg_parser.add_argument(
        "-n", "--dry-run",
        default=False,
        action='store_true',
        help="just show what would be done",
    )

    arg_parser.add_argument(
        "--vm",
        default=False,
        action='store_true',
        dest="is_vm",
        help="whether <hostname> is a virtual machine"
    )

    arg_parser.add_argument(
        "-C", "--csv",
        help="load interfaces from CSV file (UNSAFE / not validated properly)"
    )

    arg_parser.add_argument(
        "hostname",
        help="host name for which interfaces should be created"
    )

    arg_parser.add_argument(
        "interface",
        nargs="*",
        help="interface name(s)"
    )

    return arg_parser
# --- end of get_argument_parser (...) ---


def load_csv_vars_file(filepath):
    # lazy copy-paste
    sniffer = csv.Sniffer()
    
    with open(filepath, newline='') as fh:
        sample = fh.read(2**14)
        dialect = sniffer.sniff(sample)
        has_header = sniffer.has_header(sample)

        # rewind
        fh.seek(0)
        if has_header:
            reader = csv.DictReader(fh, dialect=dialect)
        else:
            #reader = csv.reader(fh, dialect=dialect)
            raise RuntimeError("dict header expected!", filepath)
        # --

        data = list(reader)
    # -- end with

    return data
# --- end of load_csv_vars_file (...) ---


if __name__ == '__main__':
    os_ex_ok = getattr(os, 'EX_OK', 0)

    try:
        exit_code = main(sys.argv[0], sys.argv[1:])

    except KeyboardInterrupt:
        exit_code = os_ex_ok ^ 130

    else:
        if exit_code is True or exit_code is None:
            exit_code = os_ex_ok
        elif exit_code is False:
            exit_code = os_ex_ok ^ 1
    # --

    sys.exit(exit_code)
# --
