# verify domain and syntax
import os
from PyFunceble import load_config
from PyFunceble import test as PyFunceble
# from PyFunceble.cli_core import CLICore

from glob import glob
from timeit import default_timer as timer
from datetime import datetime
import updateSources
import json
import logger
import logging

# setup logger
logger.setup(__name__)
log = logging.getLogger(__name__)

# Project Settings
BASEDIR_PATH = os.path.dirname(os.path.realpath(__file__))
# load configuration file for PyFunceble
load_config(generate_directory_structure=False, custom={"idna": True, "iana": True})


# load_config(generate_directory_structure=True,custom={"api_file_generation":True,"idna":True,"iana":True})
##########################################
# Decorator
# decorator to calculate duration
# taken by any function.
##########################################
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
        log.info("Total Time taken %d", (end - begin))

    return inner1


settings = {}


def get_defaults():
    global settings
    settings = updateSources.get_defaults()
    settings["activedomainfilename"] = "ACTIVE"
    return settings


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


@calculate_time
def main():
    global settings
    settings = get_defaults()

    sources_path = settings["sourcespath"]
    source_data_filename = settings["sourcedatafilename"]  # update.json

    # list of all sub director of sources
    settings["sources"] = glob(sources_path + "/**/" + source_data_filename, recursive=True)
    # get list of all sources files sorted by number of rules. default source file name is update.json
    settings["sources"] = get_sources_sorted()

    domain_filename = settings["domainfilename"]
    active_domain_filename = settings["activedomainfilename"]
    ips_filename = settings["ipsfilename"]

    source_count = 0
    for source in settings["sources"]:
        source_count += 1
        print("Source: ", source)
        with open(os.path.join(os.path.dirname(source), domain_filename), "r", encoding="UTF-8") as domains_data:
            domains = domains_data.readlines()

        active_domains = [domain for domain in domains if PyFunceble(domain.strip()) == "ACTIVE"]
        active_domains = [domain2idna(domain) for domain in filter(None, active_domains)]

        with open(os.path.join(os.path.dirname(source), active_domain_filename), "w",
                  encoding="UTF-8") as active_domains_data:
            active_domains_data.writelines("\n".join(active_domains))

        # update source file with numberofrules
        try:
            with open(source, "r", encoding="UTF-8") as update_file:
                update_data = json.load(update_file)

            with open(source, "w", encoding="UTF-8") as update_file:
                update_data["activerules"] = len(domains)
                update_data["lastupdateactiverule"] = datetime.now().strftime("%d/%m/%Y %H:%M") + " UTC+8"
                update_file.write(json.dumps(update_data, indent=4))

        except Exception as err2:
            log.error("error updating source file ", err2)
            log.exception("error updating source file ", err2)

        if source_count > 0:
            break


def domain2idna(domain):
    try:
        return domain.strip().encode("IDNA").decode("UTF-8")
    except Exception as err:
        log.debug("Failed to encode domain [%s] with error %s", domain, err)
        return domain
        pass


if __name__ == "__main__":
    main()
