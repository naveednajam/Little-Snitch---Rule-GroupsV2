
import gzip
import logging
import logger
import json
import os
import sys
import re
import random
import string
import tempfile
from glob import glob
from timeit import default_timer as timer
from datetime import datetime
import shutil
from functools import partial
import libarchive.public
from subprocess import Popen, PIPE
'''
The Ubuntu libarchive package maintainer only provides a “libarchive.so” symlink in the dev package so you’ll have to install the libarchive-dev package.
'''

# setup logger
logger.setup(__name__)
log = logging.getLogger(__name__)

# Detecting Python 3 for version-dependent implementations
PY3 = sys.version_info >= (3, 0)

if PY3:
    from urllib.request import urlopen
    from urllib.request import Request
else:
    raise Exception("We only support python3.")

# Project Settings
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))


# decorator to calculate duration
# taken by any function.
def calculate_time(func):
    # added arguments inside the inner1,
    # if function takes any arguments,
    # can be added like this.
    def inner1(*args, **kwargs):
        # storing time before function execution
        begin = timer()

        func(*args, **kwargs)

        # storing time after function execution
        end = timer()
        log.info("Total Time taken %f", (end - begin))

    return inner1


def get_defaults():
    """
    Helper method for getting the default settings.

    Returns
    -------
    default_settings : dict
        A dictionary of the default settings when updating host information.
    """
    return {
        "numberofrules": 0,
        "duplicates": 0,
        "sourcespath": os.path.join(BASEDIR_PATH, "sources"),
        "sources": [],
        "hostfilename": "hosts",
        "domainfilename": "domains",
        "ipv4filename": "ipv4",
        "ipv6filename": "ipv6",
        "bogonsfilename": os.path.join(BASEDIR_PATH, "bogons"),
        "bogonsurl": "http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt", # "http://www.cidr-report.org/bogons/freespace-prefix.txt", # Alternate bogon address https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
        "sourcedatafilename": "update.json",
        "sourcesdata": [],
        "whitelist": set(),
        "whitelistfile": os.path.join(BASEDIR_PATH, "whitelist"),
        "whitelisturl": "https://raw.githubusercontent.com/Ultimate-Hosts-Blacklist/whitelist/master/domains.list",
        "hostnames": {"localhost", "localhost.localdomain", "local", "broadcasthost", "localhost4",
                      "localhost4.localdomain4",
                      "localhost6", "localhost4.localdomain6", "ip6-localnet", "ip6-localhost", "ip6-loopback",
                      "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts"},
        "ipv4": set(),
        "ipv6": set(),
        "bogons": set(),
        "exclude_ipv4":set(),
        "tldsurl":"https://data.iana.org/TLD/tlds-alpha-by-domain.txt",
        "tldsfilename":"tlds-alpha-by-domain.txt",
        "tlds":set()
    }


# global Variables
settings = get_defaults()
localhosts = {}

def main():
    #change to script directory
    os.chdir(BASEDIR_PATH)
    log.info("Current Working Directory: %s", os.getcwd())

    update_all_sources()


@calculate_time
def update_all_sources():
    global settings
    global localhosts

    #settings = get_defaults()

    # remove localhosts from all sources
    localhosts = {"localhost", "localhost.localdomain", "local", "broadcasthost", "localhost4",
                  "localhost4.localdomain4",
                  "localhost6", "localhost4.localdomain6", "ip6-localnet", "ip6-localhost", "ip6-loopback",
                  "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts"}

    if get_whitelist(settings["whitelisturl"]):
        # load whitelist
        if os.path.exists(settings["whitelistfile"]) and os.path.isfile(settings["whitelistfile"]):
            with open(settings["whitelistfile"], "r", encoding="UTF-8") as whitelistfile:
                # settings["whitelist"] = list(((line) for line in whitelistfile.readlines()))
                settings["whitelist"] = [item.strip() for item in whitelistfile.readlines() if not re.search(
                    r'^\s*#|^\s*$|^\s*::1|^\s*fe80::1|^\s*ff0|^\s*0.0.0.0 0.0.0.0|^\s*255.255.255.255|^\s*127.0.1.1',
                    item)]
        # log whilelist
        log.debug("Whitelist: %s", settings["whitelist"])

    #download update bogons
    getfile(settings["bogonsurl"], settings["bogonsfilename"])

    # download updated TLDs
    getfile(settings["tldsurl"],settings["tldsfilename"])

    # loading TLDs
    if os.path.exists(settings["tldsfilename"]) and os.path.isfile(settings["tldsfilename"]):
        with open(settings["tldsfilename"], "r", encoding="UTF-8") as tldslist:
            # settings["whitelist"] = list(((line) for line in whitelistfile.readlines()))
            settings["tlds"] = set(item.strip() for item in tldslist.readlines())
        # log whilelist
        log.debug("TLDs: %s", settings["tlds"])



    sources_path = settings["sourcespath"]
    source_data_filename = settings["sourcedatafilename"]  # update.json
    # settings["sources"] = glob(sources_path + "/**/" + source_data_filename, recursive=True)  # list of all sub director of sources
    settings["sources"] = get_sources_sorted()
    domain_filename = settings["domainfilename"]
    ipv4_filename = settings["ipv4filename"]
    ipv6_filename = settings["ipv6filename"]

    for source in settings["sources"]:

        # reset unique number of rules per source
        settings["numberofrules"] = 0

        # load update.json file and get source file url
        update_file = open(source, "r", encoding="UTF-8")
        update_data = json.load(update_file)
        update_file.close()
        update_url = update_data["url"]
        secondary_url = False
        try:
            if update_data["url2"]:
                update_url = update_data["url2"]
                secondary_url=True
        except:
            pass
        # check if source file is compressed
        try:
            if update_data["compressed"]:
                compressed = True
                update_url = update_data["url"]
            else:
                compressed = False
        except:
            compressed = False
            pass

        # check compressed file name
        try:
            if update_data["filename"]:
                filename=update_data["filename"]
            else:
                filename=None
        except:
            filename = None
            pass

        log.info("Updating source %s from %s", os.path.dirname(source), update_url)
        #url form second source
        status,f = fetchurl(update_url,compressed,filename)
        if status != 200 and compressed is False and secondary_url is True:   # when second source fails try to fetch from first url update_data["url"]
            status, f = fetchurl(update_data["url"], compressed,filename)

        if status == 200:
            if (compressed == True):
                lines = list(map(extract_hostname, ((line.strip()) for line in f.readlines())))
            else:
                lines = list(map(extract_hostname, ((line.decode("utf-8").strip()) for line in f.readlines())))

            # Close http socket or file handle
            f.close()

            if str(type(f)) != "<class 'http.client.HTTPResponse'>":
                os.unlink(f.name)

            if update_data["type"] == "domain":
                domains = list(set(filter(checkdomain, lines)) - settings["tlds"])

                if len(domains):
                    with open(os.path.join(os.path.dirname(source), domain_filename), "w", encoding="UTF-8") as d:
                        d.writelines("\n".join(domains))
                    # update source file with numberofrules
                    try:
                        with open(source, "w", encoding="UTF-8") as update_file:
                            update_data["numberofrules"] = len(domains)
                            update_data["lastupdate"] = datetime.now().strftime("%d/%m/%Y %H:%M") + " UTC+8"
                            update_file.write(json.dumps(update_data, indent=4))
                    except Exception as err2:
                        log.error("When type=domain Exception while updating source file %s with Error %s", source,
                                  err2)

            elif update_data["type"] == "ipv4":
                ipv4 = list(filter(checkipv4, lines))
                target_file = os.path.join(os.path.dirname(source), ipv4_filename)
                if len(ipv4):
                    with open(target_file, "w", encoding="UTF-8") as d:
                        d.writelines("\n".join(ipv4))

                    #clean up bogons from ipv4 files
                    if os.path.isfile("/usr/bin/iprange"):
                        output = tempfile.TemporaryFile()
                        # create Popen object to optimize target file and exclude fullbogon and previoulsy downloaded ipv4 lists
                        #p1 = Popen(["iprange", "--optimize", target_file, "--exclude-next",settings["bogonsfilename"]]+list(settings["exclude_ipv4"]) + ["--print-ranges"], stdout=output)
                        p1 = Popen(
                            ["iprange", "--optimize", target_file, "--exclude-next", settings["bogonsfilename"]] + ["--print-ranges"], stdout=output)
                        # Execute p1 command object
                        p1.communicate()
                        with open(target_file, "wb") as destination_file:
                            output.seek(0)
                            shutil.copyfileobj(output, destination_file)
                            output.close()

                    if os.path.exists(target_file):
                        # add ipv4 file path to settings["exclude_ipv4"] set to exclude it from future ipv4 list
                        # it is to remove duplicate ipranges among all lists
                        settings["exclude_ipv4"].add(target_file)

                    # update source file with numberofrules
                    try:
                        with open(source, "w", encoding="UTF-8") as update_file:
                            update_data["numberofrules"] = rawincount(os.path.join(os.path.dirname(source), ipv4_filename))
                            update_data["lastupdate"] = datetime.now().strftime("%d/%m/%Y %H:%M") + " UTC+8"
                            update_file.write(json.dumps(update_data, indent=4))
                    except Exception as err2:
                        log.error("When type=ipv4 Exception while updating source file %s with Error %s", source,
                                  err2)

            elif update_data["type"] == "ipv6":
                ipv6 = list(filter(checkipv6, lines))
                if len(ipv6):
                    with open(os.path.join(os.path.dirname(source), ipv6_filename), "w", encoding="UTF-8") as d:
                        d.writelines("\n".join(ipv6))

                    # update source file with numberofrules
                    try:
                        with open(source, "w", encoding="UTF-8") as update_file:
                            update_data["numberofrules"] = len(ipv6)
                            update_data["lastupdate"] = datetime.now().strftime("%d/%m/%Y %H:%M") + " UTC+8"
                            update_file.write(json.dumps(update_data, indent=4))
                    except Exception as err2:
                        log.error("When type=ipv6 Exception while updating source file %s with Error %s", source,
                                  err2)
    log.info("Removed duplicates during source updated= %s", settings["duplicates"])


def extract_hostname(rule_line):
    # get settings
    global settings

    if re.search(
            r'^\s*#|^\s*$|^\s*::1|^\s*fe80::1|^\s*ff0|^\s*0.0.0.0 0.0.0.0|^\s*255.255.255.255|^\s*127.0.1.1|^@@|^!|^&|^\+|^\[.*\]$|^-|^\.|^_|^=|^/|^\|\w.*|^\?|^:|^%|^\^|^\$|^,|^;|^~|^\*|^@|^\\|^\|\.',
            rule_line) is None:
        """
            first try: IP followed by domain and inline comment
        """
        log.debug("[extract_hostname]:first try:")

        # regular expression to detect IP followed by domain
        regex = r"^\s*((\d{1,3}\.){3}\d{1,3})\s+([\w\.-]+[a-zA-Z])(.*)"
        result = re.search(regex, rule_line.strip())

        if result:
            target_ip, hostname, rule_comment = result.group(1, 3, 4)
            hostname = get_domain_complement(hostname)
            hostname = domain2idna(hostname)
            if (hostname not in settings["hostnames"]) and (hostname not in settings["whitelist"]):
                settings["hostnames"].add(hostname)
                return hostname
            else:
                settings["duplicates"]+=1
                return None  # return none if duplicate entry

        """
            Second try: IP followed by host ip and inline comment
        """
        log.debug("[extract_hostname]:second try:")

        # regular expression to detect IP address followed by host IP address
        regex = r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(.*)"
        result = re.search(regex, rule_line.strip())
        if result:
            target_ip, host_ip, rule_comment = result.group(1, 2, 3)
            host_ip = host_ip.strip()
            if (host_ip not in settings["ipv4"]) and (host_ip not in settings["whitelist"]):
                settings["ipv4"].add(host_ip)
                return host_ip
            else:
                settings["duplicates"] += 1
                return None

        """
            Third detect domains followed by comment
        """

        log.debug("[extract_hostname]:third try:")

        regex = r"^\s*([\w\.-]+[a-zA-Z])(.*)"
        result = re.search(regex, rule_line.strip())

        if result:
            hostname, rule_comment = result.group(1, 2)
            hostname = get_domain_complement(hostname)
            hostname = domain2idna(hostname)
            if (hostname not in settings["hostnames"]) and (hostname not in settings["whitelist"]):
                settings["hostnames"].add(hostname)
                return hostname
            else:
                settings["duplicates"] += 1
                return None

        """
                    4th try: only IPv4 
        """
        log.debug("[extract_hostname]:fourth try:")

        # regular expression to detect IPv4 address followed by comment
        # regex = r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*(.*)"
        regex = r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/\d{1,2})?\s*(.*)"
        result = re.search(regex, rule_line.strip())
        if result:
            host_ip, cidr, rule_comment = result.group(1, 2, 3)
            host_ip = host_ip.strip()
            if cidr:
                host_ip = host_ip + cidr.strip()

            if (host_ip not in settings["ipv4"]) and (host_ip not in settings["whitelist"]):
                settings["ipv4"].add(host_ip)
                return host_ip
            else:
                settings["duplicates"] += 1
                return None

        """
                            5th try: only IPv6 
        """
        log.debug("[extract_hostname]:fifth try:")

        # regular expression to detect IPv6 address followed by comment
        regex = r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*(.*)$"
        result = re.search(regex, rule_line.strip())
        if result:
            host_ip, rule_comment = result.group(1, 2)
            host_ip = host_ip.strip()
            if (host_ip not in settings["ipv6"]) and (host_ip not in settings["whitelist"]):
                settings["ipv6"].add(host_ip)
                return host_ip
            else:
                settings["duplicates"] += 1
                return None

        """
                            6th try: adblock format
        """
        log.debug("[extract_hostname]:sixth try:")

        if re.search(r'^\|\||\^$|\^\$third-party$', rule_line.strip()):
            regex = r"^(\|\|)(([\w\.-]+[a-zA-Z])()(.*))(\/\w+\/)?(\^)*(\$third-party)?"
            result = re.search(regex, rule_line.strip())
            if result:
                hostname = result.group(3)
                hostname = get_domain_complement(hostname.strip())
                hostname = domain2idna(hostname.strip())
                if (hostname not in settings["hostnames"]) and (hostname not in settings["whitelist"]):
                    settings["hostnames"].add(hostname)
                    return hostname
                else:
                    settings["duplicates"] += 1
                    return None
            else:
                return None


        else:
            # if reach here, print / log the rule line for analysis
            log.warning("Unable to detect type for line %s", rule_line)
            return None
    else:
        return None


def unique(mylist):
    # insert the list to the set
    list_set = set(mylist)
    # convert the set to the list
    unique_list = (list(list_set))
    return unique_list


def get_domain_complement(domain):
    if re.search(r'^[w]{3}\.', domain.strip()):
        # strip www. from hostname as usually www hostname is alternate representation of domain
        # and blocking domain will effectivly block all subdomains and hosts including www
        domain = re.sub(r'^[w]{3}\.', "", domain).strip()
    return domain


def domain2idna(domain):
    try:
        return domain.strip().encode("IDNA").decode("UTF-8")
    except Exception as err:
        log.debug("Failed to encode domain [%s] with error %s", domain, err)
        return domain
        pass


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


def get_whitelist(url):
    global settings
    try:
        req = Request(url,
                      data=None,
                      headers={
                          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36'
                      }
                      )
        f = urlopen(req, timeout=60)
        if f.status == 200:
            lines = f.readlines()
            with open(settings["whitelistfile"], "wb") as whitelist_data:
                whitelist_data.writelines(lines)
            # log info
            log.info("Updating source %s from %s", settings["whitelistfile"], url)
            return True
    except Exception as err:
        log.error("Failed to Fetch file %s with error: %s", url, err)
        log.exception("Exception while fetching file %s", url)
        return False


def getfile(url, filepath):
    try:
        req = Request(url,
                      data=None,
                      headers={
                          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36'
                      }
                      )
        f = urlopen(req, timeout=60)
        if f.status == 200:
            lines = f.readlines()
            with open(filepath, "w",encoding="utf-8") as file_data:
                for line in lines:
                    if not re.search(r'^\s*#|^\s*$|^$', line.decode("utf-8")):
                        file_data.write(line.decode("utf-8"))


            log.info("Downloading file %s from %s", filepath, url)
            return True
    except Exception as err:
        log.error("Failed to download file %s with error: %s", url, err)
        log.exception("Exception while downloading file %s", url)
        return False


def checkipv4(ip):
    regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    if ip and re.search(regex, str(ip)):
        return True
    else:
        return False


def checkipv6(ip):
    regex = r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$"
    if ip and re.search(regex, str(ip)):
        return True
    else:
        return False


def checkdomain(domain):
    regex1 = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    regex2 = r"^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$"
    if re.search(regex1, str(domain)) or re.search(regex2, str(domain)) or (domain is None):
        return False
    else:
        return True


def randomString(stringLength=8):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


def getcompressesdfilecontent(req,filename=None):
    # get current working directory
    currentdir = os.getcwd()

    # create temporary directory
    tmpdir = os.path.join(tempfile.gettempdir(), "dl")
    log.debug("tempdir = %s", tmpdir)

    # clean up old temp dir
    if os.path.exists(tmpdir):
        shutil.rmtree(tmpdir)

    os.mkdir(tmpdir)
    os.chdir(tmpdir)

    # create a temporary file and write some data to it
    fp = tempfile.TemporaryFile()

    # Download the file from `url` and save it locally under tempfile `fp`:
    try:
        with urlopen(req, timeout=300) as response:
            shutil.copyfileobj(response, fp)


        try:
            if 'ftp://' in response.geturl():
                status = 200
            else:
                status = response.status
        except:
            pass


        if (status == 200 and response.headers['Content-Type'] == 'application/x-gzip'):
            log.info("Detected Content-Type: %s",response.headers['Content-Type'])
            fp.seek(0)
            with gzip.GzipFile(fileobj=fp) as fh:
                tp = tempfile.NamedTemporaryFile(delete=False)
                shutil.copyfileobj(fh, tp)
                fp.close()
                return status,tp.name

        elif (status ==200):
            log.info("Detected Content-Type: %s",response.headers['Content-Type'])
            fp.seek(0)
            filelist = set()
            for entry in libarchive.public.memory_pour(fp.read()):
                filelist.add(entry.pathname)
                fp.close()

            if filename is None:
                filepath = os.path.join(tmpdir, str(filelist.pop()))
            else:
                for file in filelist:
                    if filename in file:
                        filepath = os.path.join(tmpdir,file)
                        continue
            os.chdir(currentdir)
            return status, filepath
        else:
            log.error("Fail to Download compressed file from %s with status=%s", req.get_full_url(), str(status))
            return status, None
    except Exception as err:
        log.error("Failed to download file %s with error: %s", req.get_full_url(), err)
        log.exception("Exception while downloading file %s", req.get_full_url())
        return 404, None
        pass


def fetchurl(url,compressed,filename=None):
    try:
        if (compressed == True):
            req = Request(
                url,
                data=None,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36'
                })

            if filename is None:
                status, filepath = getcompressesdfilecontent(req)
            else:
                status, filepath = getcompressesdfilecontent(req,filename)

            log.debug("Fetch compressed file %s with status %s", filepath, str(status))

            f = open(filepath, "r", encoding="utf-8")

            log.debug("Opening uncompressed file %s", filepath)

        else:
            # create request with custom user-agent
            req = Request(
                url,
                data=None,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36'
                }
            )
            f = urlopen(req, timeout=300)
            status = f.status
        return status, f
    except Exception as err:
        log.error("Failed to Fetch file %s with error: %s", url, err)
        log.exception("Exception while fetching file %s", url)
        return 404,None

def rawincount(filename):
    f = open(filename, 'rb')
    bufgen = iter(partial(f.raw.read, 1024 * 1024), b'')
    return sum(buf.count(b'\n') for buf in bufgen)

if __name__ == "__main__":
    main()
