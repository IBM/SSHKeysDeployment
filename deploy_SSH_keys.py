#!/usr/bin/python3
import os
from getpass import getpass
import sys
import datetime
import platform
import time
import argparse
import subprocess
import logging
import csv
import ipaddress
import re
import socket
import shutil


PROGRAM_NAME = "SSHKeysDeployment"
VERSION = "1.1"

# Colorful constants
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
NOCOLOR = '\033[0m'

# GIT
GIT_URL = "https://github.com/IBM/SSHKeysDeployment"



class SSHKeysDeployment(object):
    def __init__ (self, hosts_csv, csv_is_file, verbose):
        self.missedNodes = False
        self.__check_os(False)
        self.__check_commands(False)
        self.__check_root_user(False)
        self.log_dir = "/var/log/SSHKeyDeployment"
        self.privateKey = "/root/.ssh/id_rsa"
        self.publicKey = self.privateKey + ".pub"
        self.hosts_csv = hosts_csv
        self.hosts_csv_is_file = csv_is_file
        self.verbose = verbose
        self.logFile = self.__create_log_file()
        self.log_this = self.__start_logger()
        # Log init completed


    def __convert_hosts_to_list(self):
        if self.hosts_csv_is_file:
            self.log_this.debug(
                "Hosts is passed as file parameter"
            )
            self.log_this.debug(
                "Going to check if file " +
                self.hosts_csv +
                " exists"
            )
            host_file_exists = os.path.isfile(self.hosts_csv)
            if host_file_exists:
                self.log_this.debug(
                    "host CSV file " +
                    self.hosts_csv +
                    " exists"
                )
                self.log_this.debug(
                    "Going to open the CSV file for read"
                )
                try:
                    csv_file_handler = open(self.hosts_csv,'r')
                    self.log_this.debug(
                        "Opened the CSV file for read"
                    )
                except BaseException:
                    self.log_this.error(
                        "Could not open file " +
                        self.hosts_csv +
                        " to read"
                    )
                    sys.exit(1)
                self.log_this.debug(
                    "Going to import contents of the CSV file"
                )
                try:
                    file_csv_content = csv.reader(csv_file_handler)
                    self.log_this.debug(
                        "Imported the CSV file as CSV content"
                    )
                except BaseException:
                    self.log_this.error(
                        "Could not import CSV file " +
                        self.hosts_csv +
                        " as CSV. Likely it is not in CSV format."
                    )
                    self.log_this.debug(
                        "Going to close the file"
                    )
                    csv_file_handler.close()
                    self.log_this.debug(
                        "CSV handler file is closed"
                    )
                    sys.exit(1)
                self.log_this.debug(
                    "Going to put in a list the CSV file contents"
                )
                for entry in file_csv_content:
                    self.all_hosts_list = entry
                self.log_this.debug(
                    "Contents added to list: " +
                    str(self.all_hosts_list)
                )
                self.log_this.debug(
                        "Going to close the file"
                    )
                csv_file_handler.close()
                self.log_this.debug(
                    "CSV handler file is closed"
                )
            else:
                self.log_this.error(
                    "Parameter hosts file " +
                    self.hosts_csv +
                    " does not exist"
                )
                sys.exit(1)
        else:
            # Parameter string
            self.log_this.debug(
                "Going to move input hosts string " +
                self.hosts_csv +
                " into python list"
            )
            try:
                self.all_hosts_list = self.hosts_csv.split(",")
                self.log_this.debug(
                    "Could convert CSV into list: " +
                    str(self.all_hosts_list)
                )
            except BaseException:
                self.log_this.error(
                    "Cannot process CSV hosts passed. Are you sure is in CSV format? Please check it and try again"
                )
                sys.exit(1)
        
        # Common regardless how hosts are passed
        self.log_this.debug(
            "All hosts added to " +
            str(self.all_hosts_list)
        )
        self.all_hosts_number = len(self.all_hosts_list)
        self.log_this.debug(
            "There are " +
            str(self.all_hosts_number) +
            " host[s] to process"
        )
        basicHostsCheckOK = self.__check_hosts_possible()
        if basicHostsCheckOK:
            self.log_this.debug(
                "All basic tests on hosts are passed"
            )
        else:
            self.log_this.error(
                "There had been issues with host[s] checks. Please fix it and try again"
            )
            sys.exit(1)

        reachableHosts = 0
        for host in self.all_hosts_list:
            self.log_this.debug(
                "Going to check if we can reach host " +
                str(host)
            )
            canReachThisHost = self.__can_reach(host)
            if canReachThisHost:
                self.log_this.debug(
                    "Can reach host " +
                    str(host)
                )
                reachableHosts = reachableHosts + 1
            else:
                self.log_this.error(
                    "Cannot reach host " +
                    str(host)
                )
        if reachableHosts == self.all_hosts_number:
            self.log_this.debug(
                "All hosts defined can be reached, we can continue"
            )
        else:
            self.log_this.error(
                "Not all hosts defined can be reached, address that and run this tool again"
            )
            sys.exit(1)


    def __check_hosts_possible(self):
        self.log_this.debug(
            "Going to check that the hosts passed are possible"
        )
        errors = 0
        for host in self.all_hosts_list:
            isIP = self.__is_IP(host)
            if isIP:
                self.log_this.debug(
                    "Host " +
                    host +
                    " is a possible IP address"
                )
            
            else:
                isHostname = self.__is_hostname(host)
                if isHostname:
                    self.log_this.debug(
                        "Host " +
                        host +
                        " is a possible hostname"
                    )
                else:
                    self.log_this.error(
                        "Host " +
                        host +
                        " is not a valid IP address nor hostname. "
                    )
                    errors = errors + 1
        self.log_this.debug(
            "All basic checks performed on host[s]"
        )
        if errors == 0:
            self.log_this.debug(
                "No errors found on basic checks on host[s]"
            )
            return True
        else:
            self.log_this.error(
                str(errors) +
                " error[s] found on basic check on host[s]. Check above output"
            )
            return False


    def __is_IP(self, IP_to_check):
        self.log_this.debug(
            "Going to check IP " +
            IP_to_check
        )
        try:
            IP_OK = True
            ipadd = ipaddress.ip_address(IP_to_check)
            self.log_this.debug(
                "IP has valid format"
            )
            if ipadd.version == 4:
                self.log_this.debug("IP has IPv4 format")
            elif ipadd.version == 6:
                self.log_this.debug("IP has IPv6 format")
            else:
                IP_OK = False
                self.log_this.debug("IP does not have IPv4 or IPv6 format")
        except ValueError:
            IP_OK = False
            self.log_this.debug("IP does not have a valid format")
        self.log_this.debug(
            "Ending check IP " +
            IP_to_check +
            " and we return IP_OK=" +
            str(IP_OK))
        return IP_OK


    def __is_hostname(self, hostname):
        # We check is RFC1035 + RFC3696 prefered options
        is_short_hostname = self.__check_is_short_hostname(hostname)
        if is_short_hostname:
            self.log_this.debug(
                "We are going to append '.local' to " +
                hostname +
                " to run the hostname check only"
            )
            
            long_hostname = hostname + ".local"
            self.log_this.debug(
            "hostname and domain merged as " +
            long_hostname
        )
        else:
            self.log_this.debug(
                "hostname seems to be a FQDN, we test it as is"
            )
            long_hostname = hostname
        
        RFC3696_pref = re.compile(
            r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z0-9][-.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
            r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
        )
        self.log_this.debug("Starting FQDN check for " + long_hostname)
        good_FQDN = RFC3696_pref.match(long_hostname)
        if good_FQDN:
            self.log_this.debug(
                "Completed FQDN check for " +
                long_hostname +
                " and it aligns with RFC1035 and RFC3696 prefered format"
            )
        else:
            self.log_this.error(
                "Completed FQDN check for " +
                long_hostname +
                " and it does not align with RFC1035 and " +
                "RFC3696 prefered format"
            )
        return(good_FQDN)


    def __check_is_short_hostname(self, hostname):
        self.log_this.debug(
            "Going to determine if " +
            hostname +
            " is a short hostname or a FQDN"
        )
        len_hostname = len(hostname.split("."))
        if len_hostname == 1:
            self.log_this.debug(
                "Hostname " +
                hostname +
                " seems to be a short hostname"
            )
            is_short_hostname = True
        else:
            self.log_this.debug(
                "Hostname " +
                hostname +
                " seems to be a long hostname"
            )
            is_short_hostname = False
        return is_short_hostname


    def __create_log_file(self):
        fullLogFile = (
                    self.log_dir + 
                    "/" + 
                    str(datetime.datetime.now().strftime('%Y_%m_%d_%H_%M_%S')) + 
                    '.log'
                )
        exists = os.path.exists(self.log_dir)
        if exists:
            isDir = os.path.isdir(self.log_dir)
            if isDir:
                # Directory already exists
                return fullLogFile
            else:
                # It exists and it is a file ... we stop here
                sys.exit(
                    RED + 
                    "QUIT: " + 
                    NOCOLOR + 
                    "Log directory " +
                    self.log_dir +
                    " is a file, not a directory\n")
        else:
            # Log dir does not exist, lets create it
            try:
                os.makedirs(self.log_dir)
                return fullLogFile
            except BaseException:
                sys.exit(
                    RED + 
                    "QUIT: " + 
                    NOCOLOR + 
                    "Cannot create directory " +
                    self.log_dir +
                    " \n"
                )


    def __start_logger(self):
        log_format = '%(asctime)s %(levelname)-4s:\t %(message)s'
        logging.basicConfig(level=logging.DEBUG,
                            format=log_format,
                            filename=self.logFile,
                            filemode='w')

        console = logging.StreamHandler()
        if self.verbose:
            console.setLevel(logging.DEBUG)
        else:
            console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter(log_format))
        logging.getLogger('').addHandler(console)
        log_anchor = logging.getLogger(self.logFile)
        return log_anchor


    def __show_header(self):
        # Say hello and give chance to disagree
        try:
            while True:
                print("")
                print(GREEN +
                    "Welcome to " +
                    PROGRAM_NAME +
                    ", version " +
                    str(VERSION) +
                    NOCOLOR)
                print("")
                print(
                    "Please use " + 
                    GIT_URL +
                    " to get latest versions and report issues about this tool."
                )
                print("")
                if self.check_only:
                    self.log_this.debug(
                        "This is a check only run. No changes to system[s] are going to happen"
                    )
                    print(
                        GREEN +
                        "This tool will check the SSH root keys from this node to all " +
                        "the nodes defined for root user" +
                        NOCOLOR
                    )
                else:
                    self.log_this.debug(
                        "This is a deploy run, changes to system[s] are going to happen"
                    )
                    print(
                        YELLOW +
                        "This tool will copy the SSH root keys from this node to all " +
                        "the nodes defined for root user" +
                        NOCOLOR
                    )
                print("")
                print(
                    "Debug logs are saved to " +
                    self.logFile
                )
                print("")
                print(
                    RED +
                    "This software comes with absolutely no warranty of any kind. " +
                    "Use it at your own risk" +
                    NOCOLOR)
                print("")
                run_this = input("Do you want to continue? (y/n): ")
                if run_this.lower() == 'y':
                    self.log_this.debug(
                        "User has accepted to run the tool"
                    )
                    break
                if run_this.lower() == 'n':
                    self.log_this.debug(
                        "User has not accepted to run the tool"
                    )
                    print("")
                    sys.exit("Have a nice day! Bye.\n")
        except KeyboardInterrupt:
            self.log_this.debug(
                "User cancelled agreeing to run the tool"
            )
            print("")
            sys.exit("Have a nice day! Bye.\n")
            

    def __check_commands(self, logON):
        commands_to_check = ['ssh', 'ssh-copy-id', 'sshpass']
        if logON:
            self.log_this.debug(
                "Going to check if required commands " +
                str(commands_to_check) +
                " are avaialble"
            )
        
        for command in commands_to_check:
            if shutil.which(command) is None:
                if logON:
                    self.log_this.error(
                        RED + "QUIT: " + NOCOLOR + "cannot find command " + command + ". Please install it."
                    )
                    sys.exit(1)
                sys.exit(RED + "QUIT: " + NOCOLOR + "cannot find command " + command + ". Please install it.\n")
            elif logON:
                self.log_this.debug(
                    "Command '" +
                    str(command) +
                    "' found in path"
                )


    def __check_os(self, logON):
        thisSystem = platform.system()
        if thisSystem == "Linux":
            if logON:
                self.log_this.debug(
                    "This is a Linux system"
                )
                thisDistribution = platform.dist()[0]
                thisUname = platform.uname()
                self.log_this.debug(str(thisUname))
                if thisDistribution == "redhat" or "centos":
                    self.log_this.debug(
                        "This is a RedHat based system"
                    )
                else:
                    self.log_this.warn(
                        "This is not a RedHat Linux, never tested ... good luck"
                    )
                    time.sleep(3)
        else:
            if logON:
                self.log_this.debug(
                    "This is not a Linux system"
                )
            sys.exit(RED +
                    "QUIT: " +
                    NOCOLOR +
                    "this tool needs to be run in a Linux system\n")


    def __check_root_user(self, logON):
        # We might need to relax this for SUDO environments, to be seen
        effective_uid = os.getuid()
        if logON:
            self.log_this.debug(
                "Got effective UID=" +
                str(effective_uid)
            )
        if effective_uid == 0:
            if logON:
                self.log_this.debug(
                    "The tool is being run as root or via sudo"
                )
        else:
            if logON:
                self.log_this.debug(
                    "The tool is not being run as root or via sudo"
                )
            sys.exit(RED +
                    "QUIT: " +
                    NOCOLOR +
                    "this tool needs to be run as root or via sudo\n")


    def __ask_password(self):
        while True:
            self.log_this.debug(
                "Going to ask user for password to use, we do NOT log it"
            )
            self.log_this.info(
                "Please type the password to try to connect. It does not get logged or printed"
            )
            p1 = getpass()
            self.log_this.info(
                "Please type the same password again"
            )
            p2 = getpass()
            if p1 == p2:
                self.log_this.debug(
                    "Passwords match, we continue"
                )
                break
            else:
                self.log_this.error(
                    "Passwords do not match, we ask you again."
                )
                continue
        return p1


    def __ask_key(self):
        try:
            while True:
                self.log_this.debug(
                    "Going to ask for the key file, we offer the default " +
                    self.privateKey
                )
                print("")
                print("Going to ask you which key to be used from this node, if not input passed the in between brakets file is used")
                print("")
                sshPrivateKey = input(
                    "Please type the SSH private key to use for deployment to the nodes [" +
                    self.privateKey +
                    "]: ")
                if sshPrivateKey == "":
                    self.log_this.debug(
                        "User selected to use the default key " +
                        self.privateKey
                    )
                    sshPrivateKey = self.privateKey
                    sshPublicKey = self.publicKey
                else:
                    self.log_this.debug(
                        "User has entered " +
                        sshPrivateKey +
                        "."
                    )
                privateKeyFileExists = self.__check_file_exists(sshPrivateKey)
                if privateKeyFileExists:
                    self.log_this.debug(
                        "Input private Key file exists we do standard SSH key checks"
                    )
                    sshPublicKey = sshPrivateKey + ".pub"
                else:
                    self.log_this.error(
                        "Entered SSH private key file " +
                        sshPrivateKey +
                        " does not exist"
                    )
                    continue
                self.log_this.debug(
                    "We have a file that we need to check if it is a SSH private key"
                )
                self.log_this.debug(
                    "Going to check if SSH public key " +
                    sshPublicKey + 
                    " exists"
                )
                publicKeyFileExists = self.__check_file_exists(sshPrivateKey)
                if publicKeyFileExists:
                    self.log_this.debug(
                        "SSH public key file " +
                        sshPublicKey +
                        " does exist. We need to check keys match"
                    )
                else:
                    self.log_this.error(
                        "Although the private key " +
                        sshPrivateKey +
                        " exists, there is no public file " +
                        sshPublicKey +
                        " pair file. We cannot continue"
                    )
                    self.log_this.info(
                        "You can try to generate the public key with a command similar to " +
                        "ssh-keygen -y -f " +
                        sshPrivateKey +
                        " > " +
                        sshPublicKey +
                        " and run this tool again"
                    )
                    sys.exit(1)
                self.log_this.debug(
                    "We have both SSH private and public key files, lets check if they match"
                )
                keysMatch = self.__verify_ssh_keys_match(sshPrivateKey,sshPublicKey)
                if keysMatch:
                    self.log_this.debug(
                        "We have the needed key information from user, we move on"
                    )
                    self.privateKey = sshPrivateKey
                    self.publicKey = sshPrivateKey + ".pub"
                    break
                else:
                    self.log_this.debug(
                        "Something did not go right, lets ask the user again for the SSH private key"
                    )
                    continue
        except KeyboardInterrupt:
            self.log_this.debug(
                "User cancelled input of SSH private key"
            )
            print("")
            print("Have a nice day")
            sys.exit(1)


    def __verify_ssh_keys_match(self,sshPrivateKey,sshPublicKey):
        self.log_this.debug(
            "Going to check if SSH private key " +
            sshPrivateKey +
            " matches public key " +
            sshPublicKey
        )
        try:
            public_key_file = open(sshPublicKey, "r")
            public_key_file_value = public_key_file.read().split(' ')[1]
            self.log_this.debug(
                "Successfully loaded content of public key into variable"
            )
            public_key_file.close()
        except BaseException:
            self.log_this.error(
                "Cannot read public key " +
                sshPublicKey +
                ". Please check keys are generated properly and run this tool again. You might need to regenerate your keys in this system"
            )
            sys.exit(1)
        try:
            public_key_calculated = (subprocess.check_output(
                "ssh-keygen -y -f " + sshPrivateKey,
                shell=True).strip()
            ).decode().split(' ')[1]
        except BaseException:
            self.run_log.error(
                "Could not load SSH private key " +
                sshPrivateKey +
                " with ssh-keygen"
            )
            sys.exit(1)

        self.log_this.debug(
            "Got both SSH public key content and calculated public key from private"
        )
        if public_key_file_value.strip() == public_key_calculated.strip():
            self.log_this.debug(
                "Both SSH public file content and calcualted public key from private match. We continue"
            )
        else:
            self.log_this.debug(
                "Although both SSH key files do exist. SSH public key file " +
                sshPublicKey +
                " is not a match to your private key file " +
                sshPrivateKey
            )
            self.log_this.info(
                    "You can try to generate the public key with a command similar to " +
                    "ssh-keygen -y -f " +
                    sshPrivateKey +
                    " > " +
                    sshPublicKey +
                    " and run this tool again"
                )
            sys.exit(1)
        self.log_this.debug(
            "We are done with SSH keys checks"
        )
        return True


    def __can_reach(self, dsthost):
        dstHostAlive = False
        # We do a quick port scan of IP, better than nothing
        # ARPPING needs scype or make it up from scratch
        self.log_this.debug(
            "Going to check if IP address / host " +
            dsthost +
            " has some defined TCP ports up"
        )
        ports_to_check = [22]

        for port in ports_to_check:
            port_probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            port_probe.settimeout(0.3)
            self.log_this.debug(
                "Going to check if IP address / host " +
                dsthost +
                " answers on TCP port " +
                str(port)
            )
            conn = port_probe.connect_ex((dsthost, port))
            if(conn == 0):
                self.log_this.debug(
                    "IP address / host  " +
                    dsthost +
                    " answers on TCP port " +
                    str(port)
                )
                dstHostAlive = True
            else:
                self.log_this.debug(
                    "IP address / host  " +
                    dsthost +
                    " does not answer on TCP port " +
                    str(port)
                )
            port_probe.close()
        if dstHostAlive:
            self.log_this.debug(
                "Port probing detetects that IP address / host " +
                dsthost +
                " is in use"
            )
        else:
            self.log_this.debug(
                "Port probing detetects that IP address / host  " +
                dsthost +
                " is not in use"
            )
        return dstHostAlive


    def __checkSSHPublicKey(self,dsthost):
        self.log_this.debug(
            "Going to attempt SSH passwordless command to host " +
            str(dsthost)
        )
        SSHcommand = "ssh -i " + \
            self.privateKey + \
            " -o ConnectTimeout=2 -o StrictHostKeyChecking=no -o PreferredAuthentications=publickey " + \
            dsthost + \
            " date"
        SSHcommandList = SSHcommand.split(" ")
        try:
            self.log_this.debug(
                "Going to run " + 
                SSHcommand
            )
            dateOutput = subprocess.check_output(
                SSHcommandList,
                stderr=subprocess.STDOUT
                ).strip().decode()
            self.log_this.debug(
                "Got output from try wihtout password for host " +
                dsthost +
                ": " +
                dateOutput
            )
        except BaseException:
            self.log_this.warning(
                "Connecting to host " +
                dsthost +
                " with passwordless has failed."
            )
            self.missedNodes = True


    def __copySSHPublicKey(self, dsthost):
        self.log_this.debug(
            "Going to attempt to add public key from this node into " +
            str(dsthost)
        )
        SSHcommand = "ssh-copy-id -f -i " + \
            self.publicKey + \
            " -o ConnectTimeout=2 -o StrictHostKeyChecking=no " + dsthost
        SSHPasscommand = "sshpass -p " + self.commonPassword + " " + SSHcommand
        SSHPasscommandList = SSHPasscommand.split(" ")
        try:
            self.log_this.debug(
                "Going to run " +
                "sshpass -p ********" + 
                " " + 
                SSHcommand
            )
            commonPasswordCopyOutput = subprocess.check_output(
                SSHPasscommandList,
                stderr=subprocess.STDOUT
                ).strip().decode()
            self.log_this.debug(
                "Got output from try wiht common password for host " +
                dsthost +
                ": " +
                commonPasswordCopyOutput
            )
        except BaseException:
            self.log_this.warning(
                "Connecting to host " +
                dsthost +
                " with the common password has failed. " +
                "We are going to ask for the password for this node to try again"
            )
            thisNodePass = self.__ask_password()
            thisSSHPasscommand = "sshpass -p " + thisNodePass + " " + SSHcommand
            thisSSHPasscommandList = SSHPasscommand.split(" ")
            try:
                self.log_this.debug(
                    "Going to run " +
                    "sshpass -p ********" + 
                    " " + 
                    thisSSHPasscommandList
                )
                thisPasswordCopyOutput = subprocess.check_output(
                    SSHPasscommandList,
                    stderr=subprocess.STDOUT
                    ).strip().decode()
                self.log_this.debug(
                    "Got output from try wiht common password for host " +
                    dsthost +
                    ": " +
                    thisPasswordCopyOutput
                )
            except BaseException:
                self.log_this.error(
                    "Connecting to host " +
                    dsthost +
                    " with the entered password has failed. " +
                    "We stop trying to process this node"
                )
                self.missedNodes = True
                
        
    def __check_file_exists(self, fileToCheck):
        self.log_this.debug(
            "Going to check if file " +
            fileToCheck +
            " exists and it is a file"
        )
        fileExists = os.path.isfile(fileToCheck)
        if fileExists:
            self.log_this.debug(
                "File exists check for " +
                fileToCheck +
                " completed and it does exist"
            )
        else:
            self.log_this.debug(
                "File exists check for " +
                fileToCheck +
                " completed and it does not exist"
            )
        return fileExists


    def check(self):
        self.check_only = True
        self.log_this.debug(
            "Check keys got called"
        )
        self.__check_os(True)
        self.__check_root_user(True)
        self.__check_commands(True)
        self.__show_header()
        self.__ask_key()
        self.__convert_hosts_to_list()
        self.log_this.info(
            "Going to check the public key " +
            self.publicKey +
            " into the nodes " +
            str(self.hosts_csv)
        )
        hostNumber = 0
        for host in self.all_hosts_list:
            hostNumber = hostNumber + 1
            self.log_this.info(
                "Going to process node " +
                host +
                ". This is node " +
                str(hostNumber) + 
                " of " +
                str(self.all_hosts_number) +
                " to test"
            )
            self.__checkSSHPublicKey(host)
            self.log_this.info(
                "Successfully tested node " +
                host 
            )
        if self.missedNodes:
            self.log_this.warning(
                "Some node[s] did not pass the check, check above ouptut"
            )
        else:
            self.log_this.info(
                "All nodes were successfully tested"
            )


    def deploy(self):
        self.check_only = False
        self.log_this.debug(
            "Deploy keys got called"
        )
        self.__check_os(True)
        self.__check_root_user(True)
        self.__check_commands(True)
        self.__show_header()
        self.__ask_key()
        self.__convert_hosts_to_list()
        self.log_this.info(
            "Going to deploy the public key " +
            self.publicKey +
            " into the nodes " +
            str(self.hosts_csv)
        )
        self.commonPassword = self.__ask_password()
        hostNumber = 0
        for host in self.all_hosts_list:
            hostNumber = hostNumber + 1
            self.log_this.info(
                "Going to process node " +
                host +
                ". This is node " +
                str(hostNumber) + 
                " of " +
                str(self.all_hosts_number) +
                " to process"
            )
            self.__copySSHPublicKey(host)
            self.log_this.info(
                "Successfully processed node " +
                host 
            )
        if self.missedNodes:
            self.log_this.warning(
                "Some node[s] was not properly processed, check above ouptut"
            )
        else:
            self.log_this.info(
                "All nodes were successfully processed"
            )


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description='SSH keys copy helper'
    )

    parser.add_argument(
    '-c',
    '--check',
    required=False,
    action='store_true',
    dest='is_check',
    help='Perform only a passwordless SSH connection from this node',
    default=False
    )

    parser.add_argument(
        '-d',
        '--debug',
        required=False,
        action='store_true',
        dest='be_verbose',
        help='Print verbose messages also to shell',
        default=False
    )
    hostCSV = parser.add_mutually_exclusive_group(required=True)

    hostCSV.add_argument(
        '--hosts',
        action='store',
        dest='hosts_csv_str',
        help='CSV list of hosts to deploy SSH keys',
        metavar='CSV_HOSTS',
        type=str)
    
    hostCSV.add_argument(
        '-f',
        '--hosts-file',
        action='store',
        dest='hosts_csv_file',
        help='CSV file of hosts to deploy SSH keys',
        metavar='CSV_HOSTS_FILE',
        type=str)

    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='SSH keys helper version ' + VERSION
    )

    args = parser.parse_args()

    # One mandatory argument does exists already
    if args.hosts_csv_file:
        hosts_csv = args.hosts_csv_file
        is_file = True
    elif args.hosts_csv_str:
        hosts_csv = args.hosts_csv_str
        is_file = False
    else:
        # We should not hit this
        sys.exit(RED + "QUIT: " + NOCOLOR + "Unexpected error parsing arguments\n")
    return hosts_csv,is_file,args.be_verbose,args.is_check


def main():
    hosts_csv, csv_is_file, be_verbose, only_check = parse_arguments()
    thisDeploySSHKeys = SSHKeysDeployment(hosts_csv,csv_is_file,be_verbose)
    if only_check:
        thisDeploySSHKeys.check()
    else:
        thisDeploySSHKeys.deploy()


if __name__ == '__main__':
    main()
