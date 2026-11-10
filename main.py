import argparse
import logging
import dns.resolver
import dns.zone
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

RESOLVE_LIFETIME = 5
XFR_TIMEOUT = 10

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
    Attempts a DNS zone transfer (AXFR) against the specified nameserver.

    Returns:
        tuple: (outcome, zone_text_or_None) where outcome is one of
        "success" (transfer allowed, zone text returned), "refused" (the
        nameserver was reached and definitively refused or failed the
        transfer, a real negative), or "unanswered" (timeout or a transport
        error, so no verdict about that server was earned).
    """
    try:
        logging.info(f"Attempting zone transfer from {nameserver} for {domain}...")
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=XFR_TIMEOUT, lifetime=XFR_TIMEOUT))
        logging.info(f"Zone transfer successful from {nameserver} for {domain}.")
        return "success", zone.to_text()
    except dns.query.TransferError as e:
        logging.error(f"Transfer refused by {nameserver} for {domain}: {e}")
        return "refused", None
    except dns.exception.FormError as e:
        logging.error(f"FormError when attempting zone transfer from {nameserver} for {domain}: {e}")
        return "refused", None
    except dns.tsig.BadSig as e:
        logging.error(f"TSIG Error from {nameserver} for {domain}: {e}")
        return "refused", None
    except dns.exception.Timeout as e:
        logging.error(f"Timeout when attempting zone transfer from {nameserver} for {domain}: {e}")
        return "unanswered", None
    except Exception as e:
        logging.error(f"No answer from {nameserver} for {domain}: {e}")
        return "unanswered", None

def get_nameservers(domain):
    """
    Retrieves the nameserver addresses for a given domain.

    Both A and AAAA records are resolved for each nameserver, through the
    configured resolver, with an explicit lifetime on every query. A
    nameserver that answers one record type and not the other is skipped
    for that type only, never allowed to abort the whole lookup.

    Returns:
        list: Nameserver IP addresses, or None if no NS records are found.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = RESOLVE_LIFETIME
    try:
        answers = resolver.resolve(domain, 'NS', lifetime=RESOLVE_LIFETIME)
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

    nameservers = []
    # Addresses are deduplicated below, nameserver hostnames are not. Two NS
    # names that resolve to the same address still earn one transfer attempt
    # each per distinct address only, since the list holds addresses.
    for rdata in answers:
        nameserver = str(rdata.target)
        for rdtype in ('A', 'AAAA'):
            try:
                ip_answers = resolver.resolve(nameserver, rdtype, lifetime=RESOLVE_LIFETIME)
                for ip_rdata in ip_answers:
                    address = str(ip_rdata.address)
                    if address not in nameservers:
                        nameservers.append(address)
            # Every resolver failure stays local to this one record type:
            # a nameserver failing one lookup must never abort the whole
            # scan or hide the remaining nameservers.
            except dns.resolver.NoAnswer:
                logging.warning(f"No {rdtype} record for nameserver: {nameserver} (continuing)")
            except dns.resolver.NXDOMAIN:
                logging.warning(f"Could not resolve IP address for nameserver: {nameserver}")
            except dns.exception.Timeout:
                logging.warning(f"Timeout resolving {rdtype} record for nameserver: {nameserver}")
            except dns.exception.DNSException as e:
                logging.warning(f"Could not resolve {rdtype} record for nameserver: {nameserver}: {e} (continuing)")

    if not nameservers:
        logging.warning(f"No A or AAAA records found for nameservers of domain: {domain}")
        return None

    return nameservers

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

    logging.info(f"Found nameserver addresses: {nameservers}")

    tested = 0
    refused = 0
    for nameserver in nameservers:
        tested += 1
        outcome, zone_data = attempt_zone_transfer(domain, nameserver)
        if outcome == "success":
            # First success ends the run. The remaining addresses are never
            # tried, and the count printed below says exactly how far I got.
            print(f"Zone transfer successful from {nameserver} for {domain}!")
            print("--------------------------------------------------")
            print(zone_data)
            print("--------------------------------------------------")
            print(f"Tested {tested} of {len(nameservers)} nameserver addresses before the successful transfer.")
            return
        if outcome == "refused":
            refused += 1

    # One definite refusal is enough for a negative verdict and exit 0,
    # even when the other addresses never answered. Unanswered alone is
    # not a negative; that case falls through to the exit 1 below.
    if refused:
        print(f"Zone transfer refused by {refused} of {tested} nameserver addresses tested for {domain}. Vulnerability not detected.")
        return

    print(f"Scan did not complete: none of the {tested} nameserver addresses tested for {domain} gave a definitive answer. No verdict is reported.")
    sys.exit(1)

if __name__ == "__main__":
    main()
