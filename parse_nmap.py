import sys
import collections
import xml.etree.ElementTree as ET


def parse_nmap_xml(input_file):
    inputfile = input_file

    try:
        tree = ET.parse(inputfile)
        root = tree.getroot()
    except ET.ParseError as e:
        print(e)
        # print("Parse error({0}): {1}".format(e.errno, e.strerror))
        sys.exit(2)
    except IOError as e:
        # print("IO error({0}): {1}".format(e.errno, e.strerror))
        sys.exit(2)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(2)
    results = {}
    for host in root.findall("host"):
        ip = host.find("address").get("addr")
        osver = ""
        isUp = host.find("status").get("state")
        hostname = ""
        osmatchs = []
        if isUp != "down":
            ipaddress = host.find("address").attrib['addr']
            if host.find("hostnames") is not None:
                # print(host.find("hostnames"))
                if host.find("hostnames").find("hostname") is not None:
                    # print(host.find("hostnames").find("hostname"))
                    hostname = host.find("hostnames").find("hostname").get("name")
                results[ip] = {"hostname": hostname, "address": ipaddress}
                # Each host
                for child in host:
                    services = []
                    # Host match
                    for children in host.findall(".//os/osmatch"):
                        osmatch = children.attrib["name"]
                        osmatchs.append(osmatch)
                    # Each services    
                    for children in host.findall(".//ports/port"):
                        service = children.find("service")
                        service_name = ""
                        port_number = children.attrib["portid"]
                        if service:
                            # print("->:", children, service)
                            service_name = service.attrib["name"]
                            services.append({"port": port_number, "name": service_name})
                    
                    results[ip]["os"] = guess_os(osmatchs)
                    results[ip]["services"] = services
                        
                # results[ip] = {"osmatchs": osmatchs}
        # print(collections.Counter(words_os))
    return results


def guess_os(osmatchs):
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
    res = parse_nmap_xml("../../1 - Machine/Master/scans/xml/_full_tcp_nmap.xml")
