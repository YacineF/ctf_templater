import sys
import collections
import xml.etree.ElementTree as ET
from logzero import logger

class HostStatusDownException(Exception):
    pass

class NmapXML:

    def __init__(self, inputfile):
        self.inputfile = inputfile
        self.results = {}
        self.root = self._parse_nmap_xml()
        # <address addr="X.X.X.X" addrtype="ipv4"/>
        self.host = self.root.find("host")
        self.host_status, self.ip, self.hostname = "", "", ""

    def _parse_nmap_xml(self):
        """Parse Nmap XML file

        Returns:
            str: Nmap XML root
        """        
        try:
            tree = ET.parse(self.inputfile)
            return tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Parsing error with file {self.inputfile}")
            logger.exception(e)
            sys.exit(1)
        except IOError as e:
            logger.error(f"IOerror with file {self.inputfile}")
            logger.exception(e)
            sys.exit(1)
        except Exception as e:
            logger.error(f"Unexpected error: {sys.exc_info()[0]}")
            logger.exception(e)
            sys.exit(1)

    
    def _gather_host_info(self):
        """Gather the information only directly 
        related to the host (status, ip, hostname) 

        Raises:
            HostStatusDownException: when the host is down
        """        
        self.ip = self.host.find("address").get("addr")
        self.host_status = self.host.find("status").get("state")
        if self.host_status == "down":
            raise HostStatusDownException
        self.hostname = ""
        if self.host.find("hostnames") is not None:
            if self.host.find("hostnames").find("hostname") is not None:
                self.hostname = self.host.find("hostnames").find("hostname").get("name")

    def get_information_host(self):
        """Dive in the XML file to collect information :
            - OS (Linux, Windows) and versions
            - Services (ports)

        Returns:
            dict: information gathered from nmap XML
        """        
        osmatchs = []
        # Gather basic host info before digging OS and services
        self._gather_host_info()
        self.results[self.ip] = {"hostname": self.hostname, "address": self.ip}
        services = []
        osmatchs = ["Linux"]
        if 'Windows' in self.root:
            osmatchs = ["Windows"]
        
        # Host match
        # for xml_os_matches in self.host.findall(".//os/osmatch"):
        #     osmatch = xml_os_matches.attrib["name"]
        #     osmatchs.append(osmatch)
        osmatchs2 = [match.attrib["name"] for match in self.host.findall(".//os/osmatch")]
        # Each services    
        all_scripts = {}
        for xml_port in self.host.findall(".//ports/port"):
            service = xml_port.find("service")
            port_number = xml_port.attrib["portid"]
            service_name = "?"
            if service:
                service_name = service.attrib.get("name", "?")
                ostype = service.attrib.get("ostype", "")
                if ostype:
                    osmatchs.append(ostype)
                # self.results[self.ip]["os"] = guess_os(osmatchs)
                
            services.append({"port": port_number, "name": service_name})
            self.results[self.ip]["os"] = guess_os(osmatchs)
            self.results[self.ip]["services"] = services
            # Nmap scripts
            for script in xml_port.findall("script"):
                all_scripts[script.attrib["id"]] = script.attrib["output"]
            self.results[self.ip]["scripts"] = all_scripts
            
        return self.results


    def get_information_hosts(self):
        """Dive in the XML file to collect information
        from many hosts:
            - OS (Linux, Windows) and versions
            - Services (ports)
        TO IMPLEMENT

        Returns:
            dict: information gathered from nmap XML
        """        
        results = {}
        for host in self.root.findall("host"):
            # <address addr="X.X.X.X" addrtype="ipv4"/>
            ip = self.host.find("address").get("addr")
            host_status = self.host.find("status").get("state")
            hostname = ""
        return results

def guess_os(osmatchs):
    """Guess Operating System from Nmap XML scan
    by counting the occurence of the word "Linux"
    or "Windows"
    Args:
        osmatchs (list): Nmap XML field "osmatch"

    Returns:
        str: OS name between Windows and Linux
    """    
    words_os = []
    for o in osmatchs:
        words_os.extend(o.split(" "))
            
    words_os_count = collections.Counter(words_os)
    if not "Windows" in words_os_count:
        return "Linux"
    elif not "Linux" in words_os_count:
        return "Windows"
    else:
        os = ["Linux", "Windows"]
        return os[words_os_count["Windows"] > words_os_count["Linux"]]
        
if __name__ == "__main__":
    n_xml = NmapXML("/home/yacine/Documents/autorecon_scans/Challenge 1 - VM4/scans/xml/_full_tcp_nmap.xml")
    res = n_xml.get_information_host()
    import pprint
    pprint.pprint(res)
