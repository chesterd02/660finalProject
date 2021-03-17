import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import csv

def query(domain):
    # get nameservers for target domain
    response = dns.resolver.resolve(domain, dns.rdatatype.NS)

    # we'll use the first nameserver in this example
    nsname = response.rrset[0].to_text()  # name
    response = dns.resolver.resolve(nsname, dns.rdatatype.A)
    nsaddr = response.rrset[0].to_text()  # IPv4

    # get DNSKEY for zone
    request = dns.message.make_query(domain,
                                     dns.rdatatype.DNSKEY,
                                     want_dnssec=True)
    # print("request: ", request)

    # send the query
    try:
        response = dns.query.udp(request, nsaddr, timeout=3)
    except:
        return False
    if response.rcode() != 0:
        print("HANDLE QUERY FAILED - SERVER ERROR OR NO DNSKEY RECORD")

    # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)

    answer = response.answer
    # print("answer: ", answer)
    if len(answer) != 2:
        #print("SOMETHING WENT WRONG THE ANSWER SHOULD HAVE 2 THINGS IN IT")
        return False

    # the DNSKEY should be self signed, validate it
    name = dns.name.from_text(domain)

    try:
        dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
    except dns.dnssec.ValidationFailure:
        print("BE SUSPICIOUS THIS DNSKEY IS NOT SELF SIGNED")
        return False
    else:
        print("WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR THE QUERY")
        return True

def parse_csv():
    with open('top-1m.csv', newline='') as csvfile:
        dialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        reader = csv.reader(csvfile, dialect)
        test_number_to_parse = 100                     # This number is used for testing on a smaller set of data
        domain = next(reader)

        # for row in reader:
        #     do stuff with row
        response = []

        while int(domain[0]) != test_number_to_parse:
            # print ("line: ", domain[0])
            response.append(query(domain[1]))
            domain = next(reader)
        return response


if __name__ == '__main__':
    list = parse_csv()
    total = sum(1 for x in list if x==True)
    print ("List: ", list)
    print ("Total DNSSEC: ", total)





