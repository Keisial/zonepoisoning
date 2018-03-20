#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#
# Copyright © 2018  Ángel González
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

'''Verifies that your domain servers are not vulnerable to Zone Poisoned
as described on "Zone Poisoning: The How and Where of Non-Secure DNS Dynamic
Updates", Maciej Korczynski, Michal Krol, and Michel van Eeten, ACM SIGCOMM
Internet Measurement Conference (IMC'16), pages 271-278, Santa Monica,
November 2016" - http://mkorczynski.com/IMC16Korczynski.pdf
'''

import sys
import argparse

import dns.resolver
import dns.update
import dns.query
import dns.rdtypes.ANY.TXT
from dns.resolver import NXDOMAIN
from dns.rdatatype import A, AAAA, NS, TXT

VERBOSE_LEVEL = 1
DEFAULT_RECORD_TEXT = 'Domain vulnerable to Zone Poisoning, see http://mkorczynski.com/IMC16Korczynski.pdf'

def nameserver_addresses(domain, rdtype=A):
    '''Returns the IP addresses of the nameservers for the given domain'''
    nameservers = dns.resolver.query(domain, NS, raise_on_no_answer=False)

    if VERBOSE_LEVEL >= 1:
        print("Nameservers of {}: {}".format(
            domain,
            ", ".join([ns.to_text().rstrip('.') for ns in nameservers])
        ))

    if rdtype is None:
        for nameserver in nameservers:
            yield nameserver.to_text().rstrip('.')
        return

    for nameserver in nameservers:
        answers = dns.resolver.query(nameserver.target, rdtype)

        if VERBOSE_LEVEL >= 2:
            print(" - {}: {}".format(
                nameserver.to_text().rstrip('.'),
                ", ".join([answer.to_text() for answer in answers])))

        for answer in answers:
            yield (nameserver.to_text(), answer.address)

    if VERBOSE_LEVEL >= 2:
        print("")

    return


def query_record(resolver, test_record):
    '''Queries the test record and returns wether it exists'''
    try:
        resolver.query(test_record, TXT)
        if VERBOSE_LEVEL >= 1:
            print("Test record is present!")
        return True
    except NXDOMAIN:
        if VERBOSE_LEVEL >= 2:
            print("Test record is missing")
    except dns.resolver.NoNameservers as dnsexception:
        if VERBOSE_LEVEL >= 1:
            print("Failure fetching test record: {}".format(dnsexception.kwargs['errors'][0][3]))
    except dns.exception.DNSException as dnsexception:
        if VERBOSE_LEVEL >= 1:
            print("Failure fetching test record: {}".format(dnsexception))

    return False


def poisonable_zone(zone_name, ipver=A, server=None, timeout=5, entry="zone-is-poisonable", text=DEFAULT_RECORD_TEXT, vulnerable_nameservers=None):
    '''Checks the zone for poisonability'''
    nameservers = {}
    dns.resolver.get_default_resolver().lifetime = timeout

    if server is not None:
        nameservers[server] = ''
    else:
        try:
            for nameserver, address in nameserver_addresses(zone_name, ipver):
                nameservers[address] = " ({})".format(nameserver.rstrip('.'))
        except NXDOMAIN:
            print("NOT VULNERABLE: Domain {} does not exist".format(zone_name))
            return False

    vulnerable = False
    resolver = dns.resolver.Resolver(configure=False)
    resolver.lifetime = timeout

    for ns_address in nameservers:
        if VERBOSE_LEVEL >= 1:
            print("Checking zone {} on server {}{}".format(
                zone_name, ns_address, nameservers[ns_address]
                ))

        if vulnerable_nameservers and ns_address in vulnerable_nameservers:
            if vulnerable_nameservers[ns_address]:
                vulnerable = True
                print("ASSUMED VULNERABLE: Assuming zone {} on server {}{} to be vulnerable based on prior results".format(zone_name, ns_address, nameservers[ns_address]))
            else:
                print("ASSUMED NOT VULNERABLE: Assuming zone {} on server {}{} not to be vulnerable based on prior results".format(zone_name, ns_address, nameservers[ns_address]))
            continue

        resolver.nameservers = [ns_address]
        test_record = "{}.{}".format(entry, zone_name)

        added = False
        deleted = False
        missing = not query_record(resolver, test_record)

        test_data = dns.rdtypes.ANY.TXT.TXT(dns.rdataclass.IN, TXT, [text.encode('utf-8')])
        if missing:
            if VERBOSE_LEVEL >= 1:
                print("Attempting to add test record to server {}{}".format(
                    ns_address, nameservers[ns_address]
                ))

            update = dns.update.Update(zone_name)
            update.add(entry, 60, test_data)

            try:
                dns.query.udp(update, ns_address, timeout=timeout)
            except dns.exception.DNSException as dnsexception:
                print("Server refused the update attempt: {}".format(dnsexception))
            added = query_record(resolver, test_record)

        if added or not missing:
            if VERBOSE_LEVEL >= 1:
                print("Attempting to delete test record from server {}{}".format(ns_address, nameservers[ns_address]))
            update = dns.update.Update(zone_name)
            update.delete(entry, test_data)

            try:
                dns.query.udp(update, ns_address, timeout=timeout)
            except dns.exception.DNSException as dnsexception:
                print("Server refused the deletion attempt: {}".format(dnsexception))
            deleted = not query_record(resolver, test_record)

        if added or deleted:
            vulnerable = True
            if vulnerable_nameservers is not None:
                vulnerable_nameservers[ns_address] = True

            print("VULNERABLE: server {}{} accepted a dynamic update on zone {}".format(
                ns_address, nameservers[ns_address], zone_name))
        else:
            if vulnerable_nameservers is not None:
                vulnerable_nameservers[ns_address] = False
            print("NOT VULNERABLE: server {}{}".format(ns_address, nameservers[ns_address]))


        if VERBOSE_LEVEL >= 1:
            print("")

    return vulnerable

def main():
    '''main function'''
    global VERBOSE_LEVEL

    parser = argparse.ArgumentParser(description="Checks if a domain is vulnerable to Zone Poisoning")
    parser.add_argument("domain", nargs='+')
    parser.add_argument("-4", dest='ipver', const=A, action='store_const', required=False, help="Use IPv4")
    parser.add_argument("-6", dest='ipver', const=AAAA, action='store_const', required=False, help="Use IPv6")
    parser.add_argument("--timeout", default=5, type=int, action='store', required=False, help="DNS timeout")
    parser.add_argument("--server", nargs='?', action='store', required=False, help="Nameserver to be tested")
    parser.add_argument("--quick", action='store_true', required=False, help="Scan quicker by assuming that a single nameserver will always be either vulnerable or not")
    parser.add_argument("--entry", default='zone-is-poisonable', action='store', required=False, help="Record name used on the test")
    parser.add_argument("--message", action='store', required=False, help="Message used on the test record")
    parser.add_argument("--quiet", dest='verbose', const=0, action='store_const', required=False)
    parser.add_argument("--verbose", dest='verbose', const=2, action='store_const', required=False)
    args = parser.parse_args()

    if args.verbose is not None:
        VERBOSE_LEVEL = args.verbose

    vulnerable_domains = 0
    vulnerable_nameservers = {} if args.quick else None

    for domain in args.domain:
        vulnerable = poisonable_zone(
            domain,
            args.ipver or A,
            args.server,
            args.timeout,
            args.entry,
            args.message or DEFAULT_RECORD_TEXT,
            vulnerable_nameservers
        )

        if vulnerable:
            vulnerable_domains += 1

    print("{} out of {} domains were vulnerable.".format(vulnerable_domains, len(args.domain)))
    sys.exit(vulnerable_domains != 0)

if __name__ == '__main__':
    main()
