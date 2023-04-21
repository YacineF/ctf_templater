#!/usr/bin/env python3
"""
Module Docstring
"""

__author__ = "Yacine Floret"
__version__ = "0.4.0"
__license__ = "MIT"

import argparse
import os
import glob
import pprint
import shutil
import subprocess
import traceback
import jinja2
import datetime
from config import SCAN_PATH, MD_PATH, USING_AUTORECON
import parse_nmap
from pathlib import Path
from logzero import logger

BANNER = f"""  ____ _____ _____   _____                    _       _            
 / ___|_   _|  ___| |_   _|__ _ __ ___  _ __ | | __ _| |_ ___ _ __ 
| |     | | | |_      | |/ _ \ '_ ` _ \| '_ \| |/ _` | __/ _ \ '__|
| |___  | | |  _|     | |  __/ | | | | | |_) | | (_| | ||  __/ |   
 \____| |_| |_|       |_|\___|_| |_| |_| .__/|_|\__,_|\__\___|_|   
                                       |_|                      
                                                           v{__version__}"""
# import debugpy
# Allow other computers to attach to debugpy at this IP address and port.
# debugpy.listen(('127.0.0.1', 5678))

# Pause the program until a remote debugger is attached
# debugpy.wait_for_client()
class NmapFileNotFound(Exception):
    pass

# EMOJIS=(🥯  🦆 🦉 🥓 🦄 🦀 🖕 🍣 🍤 🍥 🍡 🥃 🥞 🤯  🤬 🤮 🤫 🤭 🧐 🐕 🦖 👾 🐉 🐓 🐋 🐌 🐢)

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
        note_path,
        force=False,
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
        self.nmap_scan_file = "scan.txt"
        self.xml_scan_file = "scan.xml"
        if USING_AUTORECON:
            self.xml_scan_file = "scans/xml/_full_tcp_nmap.xml"
            self.nmap_scan_file = "scans/_full_tcp_nmap.txt"
        self.machines_md_path = (
            Path(MD_PATH).absolute().joinpath(note_path).joinpath(machine_name)
        )
        self.nmap_path = Path(scan_path).joinpath(self.machine_name)
        self.config = {
            "creation_date": datetime.datetime.now(),
            "machine_name": machine_name,
            "OS": "",
            "services": [],
            "name": machine_name,
        }
        # We check and read the nmap scan files
        self.check_nmap()
        self.read_nmap()
        # Parsing the XML file, filling information in self.config
        self.parse_nmap_xml()
        # Parsing the XML file, filling information in self.config
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
        logger.debug(f"⚓ Markdown note path : {template_path}")
        for t in templates:
            md_name = t.split("/")[-1]
            logger.debug(f"🗄️ Templates files found : {md_name}")
        return templates

    @property
    def machines_dir(self):
        """Return machine directory path and create it if it doesn't exist'

        Returns:
            str: Machine path
        """
        if not self.machines_md_path.exists():
            logger.info(f"Folder {self.machines_md_path} doesn't exist, creating it 🧐")
            self.machines_md_path.mkdir(parents=False, exist_ok=True)

        return self.machines_md_path

    def load_template(self, template_path="00 - Overview.template"):
        """Load Jinjaa template

        Args:
            template_path (str, optional): Jinjaa Template . Defaults to "00 - Overview.template".

        Returns:
            str: Text generated text from Jinjaa template
        """
        return jinja2.Environment(
            autoescape=True, loader=jinja2.FileSystemLoader(os.path.dirname(__file__))
        ).get_template(template_path)

    def get_screenshots(self):
        """Look for screenshots to include in the Web page"""
        self.config["screenshots"] = {}
        for image in Path(self.nmap_path).rglob("*png"):
            img_name = image.name
            port = img_name.split("_")[1]
            logger.info("🖼️ Screenshots detected : {image}")
            logger.info("🖼️ 📦 Copying the screenshot to the current md path")
            logger.debug(
                "[*] mv " + str(image) + " -> " + str(self.machines_md_path / img_name)
            )
            shutil.copy(image, self.machines_md_path / img_name)
            self.config["screenshots"][port] = img_name

    def smbmap_enum(self):
        smbmap_content = []
        for s in self.machines_dir.glob("scans/smbmap-*.txt"):
            logger.info("📦 Including SMBmap results to report 📦")
            logger.info(f"🗄️ Found SMBMap file : {s.file}")
            with open(s, "r") as smbmap_file:
                smbmap_content.append(smbmap_file.read())
        self.config["smbmap"] = {"name": "SMBMAP", "content": "\n".join(smbmap_content)}

    def generate_all(self):
        """Generate all markdown templates"""
        for template in MarkdownTemplate.templates_list():
            self.generate_template(Path(template).name)

    def generate_template(self, template_name):
        """Generate Jinjaa template with templates files

        Args:
            template_name (str): filename of the Jinjaa template

        """
        prefix_num, page_name = Path(template_name).stem.split("-")
        md_file = f"{prefix_num} - {self.machine_name} - {page_name}.md"
        md_path = self.machines_dir.joinpath(md_file)
        if Path(md_path).exists():
            logger.info(f"🗄️ The {md_file} file already exists")
            if not self.force:
                logger.info(f"Force flag is set to False, skipping... 😵‍💫")
                return False
        logger.info(f"🧐 Creating file {md_path}")
        with open(md_path, "w") as file:
            file.write(self.load_template(template_name).render(self.config))

    def check_nmap(self):
        """Check the basic nmap file to include it in the report"""
        if self.nmap_path.exists():
            return True
        logger.error(f"⚠️⚠️ Nmap path : {self.nmap_path}")
        raise NmapFileNotFound("❌⚠️ The nmap file doesn't exist 😵‍💫")
        # self.run_autorecon()

    def run_autorecon(self):
        """[TODO] Run scan (not working now)"""
        cmd = f"sudo autorecon --heartbeat 5 --single-target {self.ip_address} -v -o ./ --exclude-tags dirbuster"
        subprocess.Popen()

    def read_nmap(self):
        """Read the basic nmap file to include it in the report"""
        with open(self.nmap_path.joinpath(self.nmap_scan_file), "r") as nmap_file:
            self.config["nmap_results"] = nmap_file.read()

    def parse_nmap_xml(self):
        """Parse the XML file of nmap"""
        xml_parsed = parse_nmap.NmapXML(
            self.nmap_path.joinpath(self.xml_scan_file)
        ).get_information_host()
        ip_addresses = list(xml_parsed.keys())
        logger.info(f"🔍 {len(ip_addresses)} IP addresses identified : {ip_addresses} 🔎")
        if len(ip_addresses) > 1:
            logger.warn(
                "⚠️ More than one ip address identified, reporting "
                "multiple hosts is not implemented yet ⚠️"
            )
        try:
            self.ip_address = ip_addresses[0]
            self.nmap_xml = xml_parsed[self.ip_address]
            self.config["OS"] = self.nmap_xml["os"]
            self.config["services"] = self.nmap_xml["services"]
            self.config["scripts"] = self.nmap_xml["scripts"]
            self.config["ip_address"] = self.ip_address
        except KeyError as e:
            logger.error(f"❌⚠️ One information is missing in the nmap file 🤪")
            print(traceback.format_exc())
        # logger.debug(self.nmap_xml)


def main(args):
    """Main entry point of the app"""
    print(BANNER)
    logger.info("📄 Running Markdown template generation ✔️")
    logger.debug(f"Arguments : {args}")
    if args.name is None:
        args.name = args.ip_address
    if args.action == "create":
        mt = MarkdownTemplate(args.name, force=args.force, note_path=args.path)
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
