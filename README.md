# DNSCat-PNG-Extractor

## Overview

DNSCat-PNG-Extractor is a Python tool designed to extract PNG images embedded within DNS queries in pcap files. It's particularly useful in scenarios involving DNS exfiltration using tools like `dnscat`. The script parses pcap files, identifies hidden PNG data within DNS queries, and reconstructs the images for analysis.

## Features

- **DNSCat Traffic Analysis**: Parses pcap files to detect and process `dnscat` communication patterns.
- **PNG Image Extraction**: Extracts PNG images from fragmented DNS query data.
- **Custom Domain Replacement**: Offers an option to specify a custom domain for filtering DNS queries.
- **Image Display**: Utilizes Python Imaging Library (PIL) to display the extracted PNG image.
- **Command-Line Interface**: Easy to use with command-line arguments for file processing and optional domain specification.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Cyber-Experts/DNSCat-PNG-Extractor.git
   ```
2. **Install Dependencies**:
   - Ensure you have Python installed on your system.
   - Install necessary Python packages:
     ```bash
     pip install -r requirements.txt
     ```

## Usage

Run the script by providing the pcap file as a required argument. Optionally, specify a domain to replace in DNS queries:

```bash
python dns_cat_png_extractor.py <pcap_file> -d <domain_to_replace>
```

- `<pcap_file>`: The path to the pcap file you want to analyze.
- `<domain_to_replace>`: Specify the domain to be replaced in DNS queries.

## Example

```bash
python dns_cat_png_extractor.py yourfile.pcap -d 'jz-n-bs.local'
```

## Output

The script processes the pcap file, identifies any PNG images within DNS queries, reconstructs the images, saves them as `result.png`, and displays the image using PIL.

## Contributing

Contributions are welcome! Feel free to fork the repository, make your changes, and submit a pull request. For significant changes, please open an issue first to discuss what you would like to change.

## License

DNSCat-PNG-Extractor is released under the [MIT License](LICENSE).

Certainly! Here's a "References" section for your README, including the provided links:

## References

The development of the DNSCat-PNG-Extractor tool was significantly informed and enriched by the following resources. These references provided crucial insights into DNS exfiltration, the workings of `dnscat`, and the PNG format, which were essential in shaping the tool's capabilities and functionalities:

- **HackTricks - DNSCat Exfiltration**: This resource provided a foundational understanding of pcap inspection and DNSCat exfiltration. [Read more](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/dnscat-exfiltration).
- **CTF Write-Ups - DNSCap**: The challenges and solutions detailed here, particularly from BSidesSF 2017 CTF involving `dnscap`, offered practical insights that helped guide the development process. [Explore the write-ups](https://github.com/jrmdev/ctf-writeups/tree/master/bsidessf-2017/dnscap).
- **DNSCat2 Protocol Documentation**: [View the documentation](https://github.com/iagox86/dnscat2/blob/master/doc/protocol.md).
- **Wikipedia - PNG (Portable Network Graphics)**: The detailed information about the PNG format. [Learn about PNG](https://en.wikipedia.org/wiki/PNG).


