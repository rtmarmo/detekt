# Copyright (C) 2014 Claudio Guarnieri.
# This file is part of Detekt - https://github.com/botherder/detekt
# See the file 'LICENSE' for copying permission.

import os
import time
import yara
import psutil
import logging
import threading
from win32com.shell import shell

from utils import get_resource

class DetectorError(Exception): pass

# Configure logging for our main application.
log = logging.getLogger('detector')
log.propagate = 0
fh = logging.FileHandler(os.path.join(os.getcwd(), 'detekt.log'))
sh = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
sh.setFormatter(formatter)
log.addHandler(fh)
log.addHandler(sh)
log.setLevel(logging.DEBUG)

process_whitelist = [
    'avp.exe',
    'avguard.exe',
    'avira.oe.systr',
    'savservice.exe',
    'sbamsvc.exe',
    'housecall.bin',
    'avastui.exe',
    'dphostw.exe',
]

def scan(queue_results):
    # Find Yara signatures, if file is not available, we need to terminate.
    yara_path = os.path.join(os.getcwd(), 'signatures.yar')
    if not os.path.exists(yara_path):
        yara_path = get_resource(os.path.join('rules', 'signatures.yar'))
        if not os.path.exists(yara_path):
            raise DetectorError("Unable to find a valid Yara signatures file!")

    log.info("Selected Yara signature file at %s", yara_path)

    rules = yara.compile(yara_path)

    matched = []

    for process in psutil.process_iter():
        # Skip ourselves.
        if process.pid == os.getpid():
            continue

        try:
            process_name = process.name()
        except:
            process_name = ''

        # If there is a process name, let's match it against the whitelist
        # and skip if there is a match.
        # TODO: this is hacky, need to find a better solution to false positives
        # especially with security software.
        if process_name:
            if process_name.lower() in process_whitelist:
                continue

        try:
            try:
                log.debug("Scanning process %s, pid: %d, ppid: %d, exe: %s, cmdline: %s",
                          process_name, process.pid, process.ppid(), process.exe(), process.cmdline())
            except:
                log.debug("Scanning process %s, pid: %d", process_name, process.pid)

            for hit in rules.match(pid=process.pid):
                log.warning("Process %s (pid: %d) matched: %s, Values:", process_name, process.pid, hit.rule)

                for entry in hit.strings:
                    log.warning("\t%d, %s, %s", entry[0], entry[1], entry[2])

                # We only store unique results, it's pointless to store results
                # for the same rule.
                if not hit.rule in matched:
                    # Add rule to the list of unique matches.
                    matched.append(hit.rule)

                    # Add match to the list of results.
                    queue_results.put(dict(
                        rule=hit.rule,
                        detection=hit.meta.get('detection'),
                    ))
        except Exception as e:
            log.debug("Unable to scan process: %s", e)

def main(queue_results, queue_errors):
    log.info("Starting with process ID %d", os.getpid())

    # Check if the user is an Administrator.
    # If not, quit with an error message.
    if not shell.IsUserAnAdmin():
        log.error("The user is not an Administrator, aborting")
        queue_errors.put('NOT_AN_ADMIN')
        return

    # Launch the scanner.
    try:
        scan(queue_results)
    except DetectorError as e:
        log.critical("Yara scanning failed: %s", e)
        queue_errors.put('SCAN_FAILED')
    else:
        log.info("Scanning finished")

    log.info("Analysis finished")

if __name__ == '__main__':
    from Queue import Queue
    results = Queue()
    errors = Queue()
    main(results, errors)
