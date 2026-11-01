# vuln-DNS-Zone-Transfer-Scanner

I wrote this to ask a domain's own nameservers one question: will you hand me the whole zone? It resolves the NS records for the domain you name, resolves both A and AAAA addresses for each nameserver (one nameserver failing one record type never stops the rest), and tries an AXFR against each address with a set lifetime on every query.

The outcome states are kept apart, because they mean different things. A nameserver that answers and refuses is a real negative, and the final line says how many of the tested addresses refused. A run where no nameserver gives a definitive answer at all exits non-zero and reports no verdict. When a transfer succeeds, the report prints the zone records themselves from the zone's text form, not an object placeholder.

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-dns-zone-transfer-scanner`

Install the dependency with `dnspython` (the distribution that provides the `dns` import): the requirements file names it correctly.

## Usage
`python main.py <domain>`

Example: `python main.py example.com`

## Parameters
- `-h`: Show help message and exit
- `domain`: The domain to check (required, positional).

## License
Copyright (c) ShadowGuard-AI
