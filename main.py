import argparse
import logging
import dns.resolver
import dns.zone
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the script.

    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Detects potential DNS zone transfer vulnerabilities by attempting an AXFR request.")
    parser.add_argument("domain", help="The domain to check for zone transfer vulnerability.")
    return parser

def attempt_zone_transfer(domain, nameserver):
    """
    Attempts a DNS zone transfer (AXFR) against the specified nameserver for the given domain.

    Args:
        domain (str): The domain to check.
        nameserver (str): The nameserver to target.

    Returns:
        str: The zone data if the transfer is successful, None otherwise.
    """
    try:
        logging.info(f"Attempting zone transfer from {nameserver} for {domain}...")
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]

        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10)) #timeout added for safety

        logging.info(f"Zone transfer successful from {nameserver} for {domain}.")
        return str(zone)
    except dns.exception.FormError as e: #Catch form error and log
        logging.error(f"FormError when attempting zone transfer from {nameserver} for {domain}: {e}")
        return None
    except dns.exception.Timeout as e: #Catch timout error and log
         logging.error(f"TimeoutError when attempting zone transfer from {nameserver} for {domain}: {e}")
         return None
    except dns.tsig.BadSig as e: #Catch bad signature error
        logging.error(f"TSIG Error: {e}")
        return None
    except dns.query.TransferError as e:  #Catch transfer errors
        logging.error(f"TransferError when attempting zone transfer from {nameserver} for {domain}: {e}")
        return None
    except Exception as e: #Catch other exceptions and log
        logging.error(f"An unexpected error occurred: {e}")
        return None

def get_nameservers(domain):
    """
    Retrieves the nameservers for a given domain.

    Args:
        domain (str): The domain to query.

    Returns:
        list: A list of nameserver IP addresses.  Returns None if no NS records are found.
    """
    try:
        resolver = dns.resolver.Resolver()
        nameservers = []
        answers = resolver.resolve(domain, 'NS')  # Resolve for NS records
        for rdata in answers:
            nameserver = str(rdata.target)
            # Resolve the nameserver's A record to get its IP address
            try:
                ip_answers = resolver.resolve(nameserver, 'A')
                for ip_rdata in ip_answers:
                    nameservers.append(str(ip_rdata.address))
            except dns.resolver.NXDOMAIN:
                logging.warning(f"Could not resolve IP address for nameserver: {nameserver}")
            except dns.exception.Timeout:
                logging.warning(f"Timeout resolving IP address for nameserver: {nameserver}")

        if not nameservers:
            logging.warning(f"No A records found for nameservers of domain: {domain}")
            return None

        return nameservers

    except dns.resolver.NXDOMAIN:
        logging.error(f"Domain not found: {domain}")
        return None
    except dns.resolver.NoAnswer:
        logging.warning(f"No NS records found for domain: {domain}")
        return None
    except dns.exception.Timeout:
        logging.error(f"Timeout resolving NS records for domain: {domain}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def main():
    """
    Main function to execute the zone transfer vulnerability scan.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    domain = args.domain

    # Input Validation
    if not domain:
        print("Error: Domain name is required.")
        sys.exit(1)

    nameservers = get_nameservers(domain)

    if not nameservers:
        print(f"Could not retrieve nameservers for {domain}.  Exiting.")
        sys.exit(1)

    logging.info(f"Found nameservers: {nameservers}")

    vulnerable = False
    for nameserver in nameservers:
        zone_data = attempt_zone_transfer(domain, nameserver)
        if zone_data:
            print(f"Zone transfer successful from {nameserver} for {domain}!")
            print("--------------------------------------------------")
            print(zone_data)
            print("--------------------------------------------------")
            vulnerable = True
            break  # Stop after first successful transfer

    if not vulnerable:
        print(f"Zone transfer failed for all nameservers of {domain}.  Vulnerability not detected.")

if __name__ == "__main__":
    main()