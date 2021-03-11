import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype

def query():
    # get nameservers for target domain
    response = dns.resolver.resolve('com.', dns.rdatatype.NS)

    # we'll use the first nameserver in this example
    nsname = response.rrset[0].to_text()  # name
    response = dns.resolver.resolve(nsname, dns.rdatatype.A)
    nsaddr = response.rrset[0].to_text()  # IPv4

    # get DNSKEY for zone
    request = dns.message.make_query('com.',
                                     dns.rdatatype.DNSKEY,
                                     want_dnssec=True)
    # print("request: ", request)

    # send the query
    response = dns.query.udp(request, nsaddr)
    if response.rcode() != 0:
        print("HANDLE QUERY FAILED - SERVER ERROR OR NO DNSKEY RECORD")

    # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
    answer = response.answer
    print("answer: ", answer)
    if len(answer) != 2:
        print("SOMETHING WENT WRONG THE ANSWER SHOULD HAVE 2 THINGS IN IT")

    # the DNSKEY should be self signed, validate it
    name = dns.name.from_text('com.')
    try:
        dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
    except dns.dnssec.ValidationFailure:
        print("BE SUSPICIOUS THIS DNSKEY IS NOT SELF SIGNED")
    else:
        print("WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR the query")

if __name__ == '__main__':
    query()


