#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
:url: https://github.com/allenta/zabbix-template-for-varnish-cache
:copyright: (c) 2015 by Allenta Consulting S.L. <info@allenta.com>.
:license: BSD, see LICENSE.txt for more details.
'''

from __future__ import absolute_import
import json
import re
import subprocess
import sys
import time
from argparse import ArgumentParser

ITEMS = re.compile(
    r'^(?:'
    r'uptime|'
    r'sess_conn|'
    r'sess_drop|'
    r'sess_fail|'
    r'client_req_400|'
    r'client_req_417|'
    r'client_req|'
    r'cache_hit|'
    r'cache_hitpass|'
    r'cache_miss|'
    r'backend_conn|'
    r'backend_unhealthy|'
    r'backend_busy|'
    r'backend_fail|'
    r'backend_reuse|'
    r'backend_recycle|'
    r'backend_retry|'
    r'fetch_head|'
    r'fetch_length|'
    r'fetch_chunked|'
    r'fetch_eof|'
    r'fetch_bad|'
    r'fetch_none|'
    r'fetch_1xx|'
    r'fetch_204|'
    r'fetch_304|'
    r'fetch_failed|'
    r'fetch_no_thread|'
    r'threads|'
    r'threads_limited|'
    r'threads_created|'
    r'threads_destroyed|'
    r'threads_failed|'
    r'thread_queue_len|'
    r'busy_sleep|'
    r'busy_wakeup|'
    r'busy_killed|'
    r'sess_queued|'
    r'sess_dropped|'
    r'n_object|'
    r'n_objectcore|'
    r'n_objecthead|'
    r'n_backend|'
    r'n_expired|'
    r'n_lru_nuked|'
    r'bans_obj_killed|'
    r'bans_lurker_obj_killed|'
    r'losthdr|'
    r's_sess|'
    r's_req|'
    r's_pipe|'
    r's_pass|'
    r's_fetch|'
    r's_synth|'
    r's_req_hdrbytes|'
    r's_req_bodybytes|'
    r's_resp_hdrbytes|'
    r's_resp_bodybytes|'
    r's_pipe_hdrbytes|'
    r's_pipe_in|'
    r's_pipe_out|'
    r'sess_closed|'
    r'sess_closed_err|'
    r'sess_readahead|'
    r'backend_req|'
    r'bans|'
    r'n_purges|'
    r'n_obj_purged|'
    r'esi_errors|'
    r'esi_warnings|'
    r'n_gzip|'
    r'n_gunzip|'
    r'uptime|'
    r'SMA\..+\.(?:c_fail|g_bytes|g_space)|'
    r'VBE\..+\.(?:happy|bereq_hdrbytes|bereq_bodybytes|beresp_hdrbytes|beresp_bodybytes|pipe_hdrbytes|pipe_out|pipe_in|conn|req)'
    r')$')

SUBJECTS = {
    'backends': re.compile(r'^VBE\.(boot\.default|[^\()]+\([^\)]+\))\..*$'),
    'storages': re.compile(r'^SMA\.([^\.]+)\..*$'),
}


###############################################################################
## 'send' COMMAND
###############################################################################

def send(options):
    # Initializations.
    now = int(time.time())
    items = stats(options.varnish_name)

    # Build Zabbix sender input.
    rows = ''
    for name, item in items.items():
        row = '- varnish.stat[%(key)s] %(tst)d %(value)d\n' % {
            'key': str2key(name),
            'tst': now,
            'value': item['value'],
        }
        sys.stdout.write(row)
        rows += row

    # Submit metrics.
    rc, output = execute('zabbix_sender -T -r -i - %(config)s %(server)s %(port)s %(host)s' % {
        'config':
            '-c "%s"' % options.zabbix_config
            if options.zabbix_config is not None else '',
        'server':
            '-z "%s"' % options.zabbix_server
            if options.zabbix_server is not None else '',
        'port':
            '-p %d' % options.zabbix_port
            if options.zabbix_port is not None else '',
        'host':
            '-s "%s"' % options.zabbix_host
            if options.zabbix_host is not None else '',
    }, stdin=rows)

    # Check return code.
    if rc == 0:
        sys.stdout.write(output)
    else:
        sys.stderr.write(output)
        sys.exit(1)


###############################################################################
## 'discover' COMMAND
###############################################################################

def discover(options):
    # Initializations.
    items = stats(options.varnish_name)

    # Build Zabbix discovery input.
    ids = set()
    discovery = {
        'data': [],
    }
    for name in items.iterkeys():
        match = SUBJECTS[options.subject].match(name)
        if match is not None and match.group(1) not in ids:
            discovery['data'].append({
                '{#NAME}': match.group(1),
                '{#ID}': str2key(match.group(1)),
            })
            ids.add(match.group(1))

    # Render output.
    sys.stdout.write(json.dumps(discovery, sort_keys=True, indent=2))


###############################################################################
## HELPERS
###############################################################################

def stats(name=None):
    # Fetch stats through varnishstat.
    rc, output = execute('varnishstat -1 -j %(name)s' % {
        'name': '-n "%s"' % name if name is not None else '',
    })

    # Check return code & filter / normalize output.
    if rc == 0:
        result = {}
        for name, item in json.loads(output).items():
            if 'value' in item:
                if ITEMS.match(name) is not None:
                    result[name] = {
                        'type': item.get('type'),
                        'ident': item.get('ident'),
                        'flag': item.get('flag'),
                        'description': item.get('description'),
                        'value': item['value'],
                    }
        return result
    else:
        sys.stderr.write(output)
        sys.exit(1)


def str2key(name):
    result = name
    for char in ['(', ')', ',']:
        result = result.replace(char, '\\' + char)
    return result


def execute(command, stdin=None):
    child = subprocess.Popen(
        command,
        shell=True,
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    output = child.communicate(input=stdin)[0]
    return child.returncode, output


###############################################################################
## MAIN
###############################################################################

def main():
    # Set up the base command line parser.
    parser = ArgumentParser()
    parser.add_argument(
        '-n', '--varnish-name', dest='varnish_name',
        type=str, required=False, default=None,
        help='the varnishd instance to get stats from')
    subparsers = parser.add_subparsers(dest='command')

    # Set up 'send' command.
    subparser = subparsers.add_parser(
        'send',
        help='submit varnishstat output through Zabbix sender')
    subparser.add_argument(
        '-c', '--zabbix-config', dest='zabbix_config',
        type=str, required=False, default=None,
        help='the Zabbix agent configuration file to fetch the configuration '
             'from')
    subparser.add_argument(
        '-z', '--zabbix-server', dest='zabbix_server',
        type=str, required=False, default=None,
        help='hostname or IP address of the Zabbix server / Zabbix proxy')
    subparser.add_argument(
        '-p', '--zabbix-port', dest='zabbix_port',
        type=int, required=False, default=None,
        help='port number of server trapper running on the Zabbix server / '
             'Zabbix proxy')
    subparser.add_argument(
        '-s', '--zabbix-host', dest='zabbix_host',
        type=str, required=False, default=None,
        help='host name as registered in the Zabbix frontend')

    # Set up 'discover' command.
    subparser = subparsers.add_parser(
        'discover',
        help='generate Zabbix discovery schema')
    subparser.add_argument(
        'subject', type=str, choices=SUBJECTS.keys(),
        help="dynamic resources to be discovered")

    # Parse command line arguments.
    options = parser.parse_args()

    # Check required arguments.
    if options.command == 'send':
        if options.zabbix_config is None and options.zabbix_server is None:
            parser.print_help()
            sys.exit(1)

    # Execute command.
    globals()[options.command](options)
    sys.exit(0)

if __name__ == '__main__':
    main()
