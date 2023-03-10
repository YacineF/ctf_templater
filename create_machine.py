#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = "Yacine Floret"
__version__ = "0.2.0"
__license__ = "MIT"

import argparse
import os
import glob
import subprocess
import jinja2
import datetime
import parse_nmap
from pathlib import Path
from logzero import logger

SCAN_PATH = "/home/yacine/Documents/autorecon_scans"
# import debugpy
# Allow other computers to attach to debugpy at this IP address and port.
# debugpy.listen(('127.0.0.1', 5678))

# Pause the program until a remote debugger is attached
# debugpy.wait_for_client()
class NmapFileNotFound(Exception):
    pass

class MarkdownTemplate:
    """Generating Markdown templates with :
    - XML nmap info
    - IP address
    - Machine name
    - SMBmap scripts
    - Guessing OS
    """

    def __init__(
        self,
        machine_name,
        force=False,
        note_path="OSCPmd/1 - Machine in progress",
        scan_path=SCAN_PATH,
    ):
        """Constructur of the Markdown Template with basic information

        Args:
            ip_address (str): IP address of the machine
            machine_name (str): Name of the machine
            force (bool, optional): Flag to override the files. Defaults to False.
        """
        self.machine_name = machine_name
        self.ip_address = ""
        self.config = {}
        self.force = force
        self.nmap_xml = None
        self.machines_path = (
            Path().absolute().joinpath(note_path).joinpath(machine_name)
        )
        self.nmap_path = Path(scan_path).joinpath(self.machine_name)
        self.config = {
            "creation_date": datetime.datetime.now(),
            "machine_name": machine_name,
            "OS": "",
            "services": [],
            "name": machine_name,
        }
        self.check_nmap()
        self.read_nmap()
        self.parse_nmap_xml()

        self.smbmap_enum()
        self.get_screenshots()

    @staticmethod
    def templates_list():
        """Static method looking for .template with glob

        Returns:
            iter: glob paths of templates
        """
        template_path = os.path.abspath(os.path.dirname(__file__))
        templates = glob.glob(f"{template_path}/*.template")
        logger.info(f"Templates files found : {templates}")
        return templates

    @property
    def machines_dir(self):
        """Return machine directory path and create it if it doesn't exist'

        Returns:
            str: Machine path
        """
        if not self.machines_path.exists():
            logger.info(f"Folder {self.machines_path} doesn't exist, creating it")
            self.machines_path.mkdir(parents=False, exist_ok=True)
        # else:
        # logger.info(f"Folder {self.machines_path} already exists")

        return self.machines_path

    def load_template(self, template_path="00 - Overview.template"):
        """Load Jinjaa template

        Args:
            template_path (str, optional): Jinjaa Template . Defaults to "00 - Overview.template".

        Returns:
            str: Text generated text from Jinjaa template
        """
        print(template_path)
        return jinja2.Environment(
            autoescape=True, loader=jinja2.FileSystemLoader(os.path.dirname(__file__))
        ).get_template(template_path)

    def get_screenshots(self):
        """Look for screenshots to include in the Web page"""
        # print(self.machines_dir / "screenshots")
        self.config["screenshots"] = [
            s for s in self.machines_dir.glob("screenshots/*png")
        ]
        # print(self.config["screenshots"])

    def smbmap_enum(self):
        for s in self.machines_dir.glob("scans/smbmap-*.txt"):
            logger.info("Including SMBmap results to report")
            logger.info(f"Found SMBMap file : {s.file}")
            with open(s, "r") as smbmap_file:
                self.config["smbmap"] = {"name": s, "content": smbmap_file.read()}

        # print(self.config["smbmap"])

    def generate_all(self):
        """Generate all markdown templates"""
        for template in MarkdownTemplate.templates_list():
            self.generate_template(Path(template).name)

    def generate_template(self, template_name):
        """Generate Jinjaa template with templates files

        Args:
            template_name (str): filename of the Jinjaa template

        """
        md_file = Path(template_name).stem + ".md"
        md_path = self.machines_dir.joinpath(md_file)
        if Path(md_path).exists():
            logger.debug(f"The {md_file} file already exists")
            if not self.force:
                logger.info(f"Force flag is set to False, skipping...")
                return False
        logger.info(f"Creating file {md_path}")
        with open(md_path, "w") as file:
            file.write(self.load_template(template_name).render(self.config))

    def check_nmap(self):
        """Check the basic nmap file to include it in the report"""
        if self.nmap_path.exists():
            return True
        raise NmapFileNotFound
        # self.run_autorecon()

    def run_autorecon(self):
        """[TODO] Run scan (not working now)"""
        cmd = f"sudo autorecon --heartbeat 5 --single-target {self.ip_address} -v -o ./ --exclude-tags dirbuster"
        subprocess.Popen()

    def read_nmap(self):
        """Read the basic nmap file to include it in the report"""
        with open(self.nmap_path.joinpath("scans/_full_tcp_nmap.txt"), "r") as nmap_file:
            self.config["nmap_results"] = nmap_file.read()

    def parse_nmap_xml(self):
        """Parse the XML file of nmap"""
        xml_parsed = parse_nmap.NmapXML(self.nmap_path.joinpath("scans/xml/_full_tcp_nmap.xml")).get_information_host()
        ip_addresses = list(xml_parsed.keys())
        logger.info(f"{len(ip_addresses)} identified : '{ip_addresses}'")
        if len(ip_addresses) > 1:
            logger.warn(
                "More than one ip address identified, reporting "
                "multiple hosts is not implemented yet"
            )
        self.ip_address = ip_addresses[0]
        self.nmap_xml = xml_parsed[self.ip_address]
        self.config["OS"] = self.nmap_xml["os"]
        self.config["services"] = self.nmap_xml["services"]
        self.config["scripts"] = self.nmap_xml["scripts"]
        logger.debug(self.nmap_xml)


def main(args):
    """Main entry point of the app"""
    logger.info("Running Markdown template generation")
    logger.info(args)
    if args.name is None:
        args.name = args.ip_address
    if args.action == "create":
        mt = MarkdownTemplate(
           args.name, force=args.force, note_path=args.path
        )
        mt.generate_all()


if __name__ == "__main__":
    """This is executed when run from the command line"""
    parser = argparse.ArgumentParser()

    # Required positional argument
    parser.add_argument("action", help="Action to perform (create, modify, delete)")
    # Optional argument which requires a parameter (eg. -d test)
    parser.add_argument("name", action="store")
    parser.add_argument(
        "-p",
        "--path",
        action="store",
        dest="path",
        default="OSCPmd/1 - Machine in progress",
    )
    parser.add_argument("-f", "--force", action="store_true", dest="force")

    # Optional verbosity counter (eg. -v, -vv, -vvv, etc.)
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="Verbosity (-v, -vv, etc)"
    )

    # Specify output of "--version"
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s (version {version})".format(version=__version__),
    )

    args = parser.parse_args()
    main(args)
