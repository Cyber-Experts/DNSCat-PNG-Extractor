import re
import sys
from scapy.all import rdpcap, DNSQR, DNSRR


def extract_dns_queries(pcap_file):
    """ Extract DNS queries from a pcap file and concatenate them. """
    concatenated_queries = b''
    last_query = b''

    for packet in rdpcap(pcap_file):
        if packet.haslayer(DNSQR) and not packet.haslayer(DNSRR):
            query_name = packet[DNSQR].qname
            print("Qname: ", query_name)

            query = query_name.replace(b'.jz-n-bs.local.', b'').strip().split(b'.')
            print("Hex: ", query)

            query = b''.join(part for part in query)[18:]
            print("Concat: ", query)

            if last_query != query:
                print(query)
                concatenated_queries += query

            last_query = query

    return concatenated_queries


def hex_to_bytes(ascii_hex_data):
    """ Convert ASCII representation of hexadecimal data to bytes. """
    try:
        return bytes.fromhex(str(ascii_hex_data, "latin-1"))
    except ValueError:
        print("Invalid hexadecimal data")
        return None

def find_png_data(hex_data):
    """ Search for PNG data within a byte string. """
    png_regex = re.compile(rb'89504e470d0a1a0a(.*?)49454e44ae426082')
    matches = png_regex.search(hex_data)

    if matches:
        return b'89504e470d0a1a0a' + matches.group(1) + b'49454e44ae426082'
    else:
        return None


def write_png_file(png_data, filename):
    """ Write PNG data to a file in binary mode. """
    with open(filename, "wb") as png_file:
        png_file.write(png_data)


# Main process
try:
    pcap_filename = sys.argv[1]  # Get pcap filename from command-line argument
    hex_data = extract_dns_queries(pcap_filename)
    print("Hex version: ", hex_data)

    png_data = find_png_data(hex_data)

    byte_data = hex_to_bytes(png_data)

    if byte_data:
        write_png_file(byte_data, "result.png")
    else:
        print("No PNG images found in the data.")

except Exception as e:
    print("An error occurred:", e)
