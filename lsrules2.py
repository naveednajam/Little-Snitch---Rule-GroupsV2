

import os
import json
from glob import glob
from functools import partial  # for rawincount function which counts lines in a file
import urllib.parse
from updateSources import update_all_sources
from timeit import default_timer as timer
import logging
import logger

# setup logger
logger.setup(__name__)
log = logging.getLogger(__name__)

# Project Settings
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))


def get_default():
    return {
        "destinationpath": os.path.join(BASEDIR_PATH, "rulegroups"),
        "sourcespath": os.path.join(BASEDIR_PATH, "sources"),
        "sourcedatafilename": "update.json",
        "sources": [],
    }


def get_default_hostnames():
    return {"localhost", "localhost.localdomain", "local", "broadcasthost", "localhost4",
            "localhost4.localdomain4",
            "localhost6", "localhost4.localdomain6", "ip6-localnet", "ip6-localhost", "ip6-loopback",
            "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts"}


# Global Variables
duplicates = 0
settings = get_default()
hostnames = get_default_hostnames()

# Constants
DOMAIN_NAME = "dl.rulegroups.com"


def main():
    os.chdir(BASEDIR_PATH)
    log.info("Current Working Directory: %s",os.getcwd())

    global settings
    global hostnames
    # settings = get_default()
    # hostnames = get_default_hostnames()

    # update all source files
    update_all_sources()

    if not os.path.exists(settings["destinationpath"]):
        os.makedirs(settings["destinationpath"])

    create_rulegroups(settings["destinationpath"])

    log.info("Detected duplicates during rule creation  = %s", duplicates)
    log.info("Total Unique Domains are %d", len(hostnames))


def get_sources_sorted():
    global settings
    sources_path = settings["sourcespath"]
    source_data_filename = settings["sourcedatafilename"]
    sources = glob(sources_path + "/**/" + source_data_filename, recursive=True)
    final_sources = {}
    for source_file_url in sources:
        with open(source_file_url, "r", encoding='utf-8') as info_file:
            update_data = json.load(info_file)
        final_sources[source_file_url] = int(update_data["numberofrules"])

    sources = {}
    sorted_d = sorted((value, key) for (key, value) in final_sources.items())
    for rules, path in sorted_d:
        sources[path] = rules

    return sources


def create_rulegroups(outputpath):
    global settings
    sources_path = settings["sourcespath"]
    source_data_filename = settings["sourcedatafilename"]

    # cleanup hosts file and get domains and subdomains
    hosts_catalog = []
    # get list of all sources files sorted by number of rules. default source file name is update.json
    settings["sources"] = get_sources_sorted()

    for file in settings["sources"]:
        domain_file_url = os.path.join(os.path.dirname(file), "domains")
        ipv4_file_url = os.path.join(os.path.dirname(file), "ipv4")
        ipv6_file_url = os.path.join(os.path.dirname(file), "ipv6")
        source_file_url = file
        try:
            if os.path.exists(domain_file_url):
                #domain_count, file_count = convert_to_lsrules(domain_file_url, source_file_url, "domain", outputpath)
                domain_count, file_count = convert_to_ruleset(file_url=domain_file_url,update_file_url=source_file_url,type="domain",destination_path=outputpath)
               # domain_count, file_count = convert_to_ruleset_unified(file_url=domain_file_url, update_file_url=source_file_url,type="domain", destination_path=outputpath)
                item = update_hosts_catalog(source_file_url, domain_count, file_count)
                hosts_catalog.append(item)
            elif os.path.exists(ipv4_file_url):
                log.info("converting ipv4 file")
                ipv4_count, file_count = convert_ipv4_to_lsrules(ipv4_file_url, source_file_url, type="ip", destination_path=outputpath,direction="incomming")
                item = update_hosts_catalog(source_file_url, ipv4_count, file_count,"incoming")
                hosts_catalog.append(item)
        except Exception as err:
            log.error("Error while converting to lsrules %s", err)
            log.exception("Error while converting to lsrules")
            domain_count = 0
            file_count = 0
            pass

        # save converted files information in hosts_catalog.json file
    with open(os.path.join(outputpath, "hosts_catalog.json"), "w", encoding='utf-8') as catalog:
        json.dump(hosts_catalog, catalog)


def update_hosts_catalog(source_file_url, item_count, file_count,direction="outgoing"):
    with open(source_file_url, "r", encoding='utf-8') as info_file:
        update_json = json.load(info_file)

    parent_dir = os.path.basename(os.path.split(os.path.split(source_file_url)[0])[0])

    if not ("sources" in parent_dir):
        rule_file_name = parent_dir + "_" + os.path.basename(os.path.split(source_file_url)[0])
        category = parent_dir
    else:
        rule_file_name = os.path.basename(os.path.split(source_file_url)[0])
        category = "Malware / Adware / Tracking"

    # if category information exist in update.json then use that info. otherwise use generic info
    if ("catagory" not in update_json.keys()):
        category = update_json["category"]

    # output converted files information in json format
    item = {"name": update_json["name"], "category": category, "homeurl": update_json["homeurl"],
            "hostsurl": update_json["url"], "unique_domains": item_count, "lastupdate": update_json["lastupdate"],"direction":direction,"type":update_json["type"]}
    if (item_count > 200000) and (file_count > 0):
        rules = []
        for x in range(file_count + 1):
            rules.append("x-littlesnitch:subscribe-rules?url=" + urllib.parse.quote(
                "https://" + DOMAIN_NAME + "/index.php?origin=rulegroups&rulegroup=" + rule_file_name + str(
                    x) + ".lsrules"))

        item["rulegroup"] = rules
    else:
        item["rulegroup"] = "x-littlesnitch:subscribe-rules?url=" + urllib.parse.quote(
            "https://" + DOMAIN_NAME + "/index.php?origin=rulegroups&rulegroup=" + rule_file_name + ".lsrules")

    return item


def convert_to_lsrules(domain_file_url, source_file_url, type="domain",destination_path="."):
    global hostnames
    global duplicates

    rule = {"description": "Date and Time Info of last update", "name": "hosts list",
            }
    if type == "domain":
        key = "denied-remote-domains"
    elif type == "ip":
        key = "denied-remote-addresses"
    elif type == "host":
        key = "denied-remote-hosts"

    domains = []

    with open(domain_file_url, encoding='utf-8') as file_data:
        # alternate method to achieve same results
        # domains = list(map(extract_hostname,[line.strip() if not re.search(r'^[w]{3}\.', line) else re.sub(r'^[w]{3}\.', "", line.strip()) for line in file_data.readlines()]))
        for domain in file_data.readlines():
            # domain = extract_hostname(line)
            domain = domain.strip()

            if (domain not in hostnames):
                domains.append(domain)
                hostnames.add(domain)
            else:
                duplicates += 1

    parent_dir = os.path.basename(os.path.split(os.path.split(domain_file_url)[0])[0])
    # drive output file name
    if not ("sources" in parent_dir):
        rule_file_name = parent_dir + "_" + os.path.basename(os.path.split(domain_file_url)[0])
    else:
        rule_file_name = os.path.basename(os.path.split(domain_file_url)[0])

    with open(source_file_url, "r", encoding='utf-8') as info_file:
        update_json = json.load(info_file)

    file_count = 0
    start = 0
    max_domain_limit = 200000
    total_domains = len(domains)

    if (total_domains > max_domain_limit):
        domain_count = total_domains

        while (domain_count > max_domain_limit):
            rule["name"] = rule_file_name + str(file_count)
            rule["description"] = "Source: " + update_json["url"] + " | Unique Domains: " + str(
                len(domains)) + " |  Last Update: " + update_json["lastupdate"]
            rule["priority"] = "regular"
            rule[key] = domains[start:(start + max_domain_limit)]
            lsrules = json.dumps(rule, indent=4)

            if (destination_path != ".") and (len(rule[key])):
                with open(os.path.join(destination_path, rule["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                    lsfile.write(lsrules)
            elif len(rule[key]):
                with open(os.path.join(os.path.split(domain_file_url)[0], rule["name"] + ".lsrules"), "w",
                          encoding='utf-8') as lsfile:
                    lsfile.write(lsrules)

            file_count += 1
            domain_count = domain_count - max_domain_limit
            start = start + max_domain_limit

        rule["name"] = rule_file_name + str(file_count)
        rule["description"] = "Source: " + update_json["url"] + " | Unique Domains: " + str(
            len(domains)) + " |  Last Update: " + update_json["lastupdate"]
        rule["priority"] = "regular"
        rule[key] = domains[start:]
        lsrules = json.dumps(rule, indent=4)
        if (destination_path != ".") and (len(rule[key])):
            with open(os.path.join(destination_path, rule["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
        elif len(rule[key]):
            with open(os.path.join(os.path.split(domain_file_url)[0], rule["name"] + ".lsrules"), "w",
                      encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
    else:
        rule["name"] = rule_file_name
        rule["description"] = "Source: " + update_json["url"] + " | Unique Domains: " + str(
            len(domains)) + " |  Last Update: " + update_json["lastupdate"]
        rule["priority"] = "regular"
        rule[key] = domains
        lsrules = json.dumps(rule, indent=4)

        if (destination_path != ".") and (len(domains)):
            with open(os.path.join(destination_path, rule["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
        elif len(domains):
            with open(os.path.join(os.path.split(domain_file_url)[0], rule["name"] + ".lsrules"), "w",
                      encoding='utf-8') as lsfile:
                lsfile.write(lsrules)

    # crete iptables rule files - For Future use
    #createiptablesrules(domains, rule_file_name, destination_path)

    # return number of domains converted to rule group format
    return total_domains, file_count


def convert_ipv4_to_lsrules(ip_file_url, source_file_url, type="ip", destination_path=".", direction="incoming"):
    rulegroup = {
        "description": "Date and Time Info of last update", "name": "ip list",
        "rules": []
        }

    domains = []
    #read ipv4 file
    with open(ip_file_url, encoding='utf-8') as file_data:
        for ip in file_data.readlines():
            domains.append(ip.strip())


    parent_dir = os.path.basename(os.path.split(os.path.split(ip_file_url)[0])[0])
    # drive output file name
    if not ("sources" in parent_dir):
        rule_file_name = parent_dir + "_" + os.path.basename(os.path.split(ip_file_url)[0])
    else:
        rule_file_name = os.path.basename(os.path.split(ip_file_url)[0])

    with open(source_file_url, "r", encoding='utf-8') as info_file:
        update_json = json.load(info_file)

    file_count = 0
    start = 0
    max_domain_limit = 200000
    total_domains = len(domains)

    if (total_domains > max_domain_limit):
        domain_count = total_domains

        while (domain_count > max_domain_limit):
            rulegroup["name"] = rule_file_name + str(file_count)
            rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
                len(domains)) + " |  Last Update: " + update_json["lastupdate"]

            remote_addresses = domains[start:(start + max_domain_limit)]
            rule = {"action": "deny",
                    "direction": "incoming",
                    "priority": "regular",
                    "process": "any",
                    "remote-addresses": ",".join(remote_addresses)
                    }

            rulegroup["rules"].append(rule)
            lsrules = json.dumps(rulegroup, indent=4)

            if (destination_path != ".") and (len(remote_addresses)):
                with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                    lsfile.write(lsrules)
            elif len(remote_addresses):
                with open(os.path.join(os.path.split(ip_file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                          encoding='utf-8') as lsfile:
                    lsfile.write(lsrules)

            file_count += 1
            domain_count = domain_count - max_domain_limit
            start = start + max_domain_limit

        rulegroup["name"] = rule_file_name + str(file_count)
        rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
            len(domains)) + " |  Last Update: " + update_json["lastupdate"]

        remote_addresses = domains[start:]
        rule = {"action": "deny",
                "direction": "incoming",
                "priority": "regular",
                "process": "any",
                "remote-addresses": ",".join(remote_addresses)
                }

        rulegroup["rules"].append(rule)
        lsrules = json.dumps(rulegroup, indent=4)
        if (destination_path != ".") and (len(remote_addresses)):
            with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
        elif len(remote_addresses):
            with open(os.path.join(os.path.split(ip_file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                      encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
    else:
        rulegroup["name"] = rule_file_name
        rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
        len(domains)) + " |  Last Update: " + update_json["lastupdate"]

        rule = {"action": "deny",
                "direction": "incoming",
                "priority": "regular",
                "process": "any",
                "remote-addresses": ",".join(domains)
                }

        rulegroup["rules"].append(rule)

        lsrules = json.dumps(rulegroup, indent=4)

        if (destination_path != ".") and (len(domains)):
            with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
        elif len(domains):
            with open(os.path.join(os.path.split(ip_file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                      encoding='utf-8') as lsfile:
                lsfile.write(lsrules)

    # crete iptables rule files - For Future use
    # createiptablesrules(domains, rule_file_name, destination_path)

    # return number of domains converted to rule group format
    return total_domains, file_count


def convert_to_ruleset(file_url, update_file_url, type="domain", destination_path="."):
    global hostnames
    global duplicates

    rulegroup = {
        "description": "Date and Time Info of last update", "name": "ip list",
        "rules": []
        }
    # to block ip address
    # to block ip address
    if type == "domain":
        key = "remote-domains"
    elif type == "ip":
        key = "remote-addresses"
    elif type == "host":
        key = "remote-hosts"

    domains = []
    if type == "domain" or type == "host":
        with open(file_url, encoding='utf-8') as file_data:
            # alternate method to achieve same results
            # domains = list(map(extract_hostname,[line.strip() if not re.search(r'^[w]{3}\.', line) else re.sub(r'^[w]{3}\.', "", line.strip()) for line in file_data.readlines()]))
            for domain in file_data.readlines():
                # domain = extract_hostname(line)
                domain = domain.strip()

                if (domain not in hostnames):
                    domains.append(domain)
                    hostnames.add(domain)
                else:
                    duplicates += 1
    elif type == "ip":
        #read ipv4 file
        with open(file_url, encoding='utf-8') as file_data:
            for ip in file_data.readlines():
                domains.append(ip.strip())


    parent_dir = os.path.basename(os.path.split(os.path.split(file_url)[0])[0])
    # drive output file name
    if not ("sources" in parent_dir):
        rule_file_name = parent_dir + "_" + os.path.basename(os.path.split(file_url)[0])
    else:
        rule_file_name = os.path.basename(os.path.split(file_url)[0])

    with open(update_file_url, "r", encoding='utf-8') as info_file:
        update_json = json.load(info_file)
        try:
            direction = update_json["direction"]
        except KeyError:
            direction = "outgoing"
            pass

    file_count = 0
    start = 0
    max_domain_limit = 200000
    total_domains = len(domains)

    if (total_domains > max_domain_limit):
        domain_count = total_domains

        while (domain_count > max_domain_limit):
            rulegroup["name"] = rule_file_name + str(file_count)
            rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
                len(domains)) + " |  Last Update: " + update_json["lastupdate"]

            remote_addresses = domains[start:(start + max_domain_limit)]
            rulegroup["rules"] = rule_list(remote_addresses,"deny",direction=direction,priority="regular",key=key)

            lsrules = json.dumps(rulegroup, indent=4)

            if (destination_path != ".") and (len(remote_addresses)):
                with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                    lsfile.write(lsrules)
            elif len(remote_addresses):
                with open(os.path.join(os.path.split(file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                          encoding='utf-8') as lsfile:
                    lsfile.write(lsrules)

            file_count += 1
            domain_count = domain_count - max_domain_limit
            start = start + max_domain_limit

        rulegroup["name"] = rule_file_name + str(file_count)
        rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
            len(domains)) + " |  Last Update: " + update_json["lastupdate"]

        remote_addresses = domains[start:]
        rulegroup["rules"] = rule_list(remote_addresses, "deny", direction=direction, priority="regular", key=key)

        lsrules = json.dumps(rulegroup, indent=4)
        if (destination_path != ".") and (len(remote_addresses)):
            with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
        elif len(remote_addresses):
            with open(os.path.join(os.path.split(file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                      encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
    else:
        rulegroup["name"] = rule_file_name
        rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
        len(domains)) + " |  Last Update: " + update_json["lastupdate"]

        rulegroup["rules"] = rule_list(domains,"deny",direction=direction,priority="regular",key=key)

        lsrules = json.dumps(rulegroup, indent=4)

        if (destination_path != ".") and (len(domains)):
            with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
        elif len(domains):
            with open(os.path.join(os.path.split(file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                      encoding='utf-8') as lsfile:
                lsfile.write(lsrules)

    # crete iptables rule files - For Future use
    # createiptablesrules(domains, rule_file_name, destination_path)

    # return number of domains converted to rule group format
    return total_domains, file_count


def convert_to_ruleset_unified(file_url, update_file_url, type="domain", destination_path="."):
    global hostnames
    global duplicates

    rulegroup = {
        "description": "Date and Time Info of last update", "name": "ip list",
        "rules": []
        }
    # to block ip address
    # to block ip address
    if type == "domain":
        key = "remote-domains"
    elif type == "ip":
        key = "remote-addresses"
    elif type == "host":
        key = "remote-hosts"

    domains = []
    if type == "domain" or type == "host":
        with open(file_url, encoding='utf-8') as file_data:
            # alternate method to achieve same results
            # domains = list(map(extract_hostname,[line.strip() if not re.search(r'^[w]{3}\.', line) else re.sub(r'^[w]{3}\.', "", line.strip()) for line in file_data.readlines()]))
            for domain in file_data.readlines():
                # domain = extract_hostname(line)
                domain = domain.strip()

                if (domain not in hostnames):
                    domains.append(domain)
                    hostnames.add(domain)
                else:
                    duplicates += 1
    elif type == "ip":
        #read ipv4 file
        with open(file_url, encoding='utf-8') as file_data:
            for ip in file_data.readlines():
                domains.append(ip.strip())


    parent_dir = os.path.basename(os.path.split(os.path.split(file_url)[0])[0])
    # drive output file name
    if not ("sources" in parent_dir):
        rule_file_name = parent_dir + "_" + os.path.basename(os.path.split(file_url)[0])
    else:
        rule_file_name = os.path.basename(os.path.split(file_url)[0])

    with open(update_file_url, "r", encoding='utf-8') as info_file:
        update_json = json.load(info_file)
        try:
            direction = update_json["direction"]
        except KeyError:
            direction = "outgoing"
            pass

    file_count = 0
    start = 0
    max_domain_limit = 200000
    total_domains = len(domains)

    if (total_domains > max_domain_limit):
        domain_count = total_domains

        while (domain_count > max_domain_limit):
            rulegroup["name"] = rule_file_name + str(file_count)
            rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
                len(domains)) + " |  Last Update: " + update_json["lastupdate"]

            remote_addresses = domains[start:(start + max_domain_limit)]
            rule = {"action": "deny",
                    "direction": direction,
                    "priority": "regular",
                    "process": "any",
                    key: ",".join(remote_addresses)
                    }
            rulegroup["rules"].append(rule)

            lsrules = json.dumps(rulegroup, indent=4)

            if (destination_path != ".") and (len(remote_addresses)):
                with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                    lsfile.write(lsrules)
            elif len(remote_addresses):
                with open(os.path.join(os.path.split(file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                          encoding='utf-8') as lsfile:
                    lsfile.write(lsrules)

            file_count += 1
            domain_count = domain_count - max_domain_limit
            start = start + max_domain_limit

        rulegroup["name"] = rule_file_name + str(file_count)
        rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
            len(domains)) + " |  Last Update: " + update_json["lastupdate"]

        remote_addresses = domains[start:]
        rule = {"action": "deny",
                "direction": direction,
                "priority": "regular",
                "process": "any",
                key: ",".join(remote_addresses)
                }
        rulegroup["rules"].append(rule)

        lsrules = json.dumps(rulegroup, indent=4)
        if (destination_path != ".") and (len(remote_addresses)):
            with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
        elif len(remote_addresses):
            with open(os.path.join(os.path.split(file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                      encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
    else:
        rulegroup["name"] = rule_file_name
        rulegroup["description"] = "Source: " + update_json["url"] + " | Unique IP Ranges: " + str(
        len(domains)) + " |  Last Update: " + update_json["lastupdate"]

        rule = {"action": "deny",
                "direction": direction,
                "priority": "regular",
                "process": "any",
                key: ",".join(domains)
                }
        rulegroup["rules"].append(rule)

        lsrules = json.dumps(rulegroup, indent=4)

        if (destination_path != ".") and (len(domains)):
            with open(os.path.join(destination_path, rulegroup["name"] + ".lsrules"), "w", encoding='utf-8') as lsfile:
                lsfile.write(lsrules)
        elif len(domains):
            with open(os.path.join(os.path.split(file_url)[0], rulegroup["name"] + ".lsrules"), "w",
                      encoding='utf-8') as lsfile:
                lsfile.write(lsrules)

    # crete iptables rule files - For Future use
    # createiptablesrules(domains, rule_file_name, destination_path)

    # return number of domains converted to rule group format
    return total_domains, file_count



# convert domains to iptables rule format and write to file with .rules extension in the output directory
def createiptablesrules(domains, rule_file_name, destination_path):
    '''
    :param domains:
    :param rule_file_name:
    :param destination_path:
    :return:
    '''
    destination_path = os.path.join(destination_path, "iptable_rules")
    if not os.path.exists(destination_path):
        os.mkdir(destination_path)

    if (destination_path != ".") and (len(domains)):
        with open(os.path.join(destination_path, rule_file_name + ".rules"), "w", encoding='utf-8') as iptablesrulefile:
            table_name = '*filter\n'
            chain_name = ':' + rule_file_name + ' - [0:0]\n'
            rules = set()
            # Write header to file
            iptablesrulefile.write(table_name)
            iptablesrulefile.write(chain_name)

            # write rules to chains in the file
            for domain in domains:
                if len(domain) < 129:
                    iptablesrulefile.write(
                        '-A ' + rule_file_name + ' -m string --string "' + domain + '" --algo kmp --from 40 --to 512 -g LOGGING\n')
                else:
                    iptablesrulefile.write(
                        '-A ' + rule_file_name + ' -m string --string "' + domain[:(
                        len(domain) - 128)] + ' -m string --string "' + domain[(len(
                        domain) - 128):] + '" --algo kmp --from 40 --to 512 -g LOGGING\n')
                    log.debug(domain[(len(domain) - 128):])

            # Write footer
            iptablesrulefile.write("-A ADBLOCK -j " + rule_file_name + '\n')
            iptablesrulefile.write("COMMIT\n")

    log.info("domains are=%s and file_name=%s and path=%s", str(len(domains)), rule_file_name, destination_path)


# Extra functions
# fast method to count number of lines in a file
def rawincount(filename):
    f = open(filename, 'rb')
    bufgen = iter(partial(f.raw.read, 1024 * 1024), b'')
    return sum(buf.count(b'\n') for buf in bufgen)


def unique(mylist):
    # insert the list to the set
    list_set = set(mylist)
    # convert the set to the list
    unique_list = (list(list_set))
    return unique_list

def rule_list(addresses,action="deny",direction="outgoing",priority="regular",key="remote-domains"):
    rules = []
    for address in addresses:
        rules.append({"action": action,
                "direction": direction,
                "priority": priority,
                "process": "any",
                key: address
            })
    return rules


if __name__ == '__main__':
    main()
