import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import csv
import re
import json
import pickle

class myObject:
    def __init__(self,
                 domain,
                 ds_response,
                 soa_response,
                 a_response,
                 ns_response,
                 response,
                 ds_id,
                 answer,
                 algorithm_number,
                 algorithm,
                 key_id):
        self.domain = domain
        self.ds_response = ds_response
        self.soa_response = soa_response
        self.a_response = a_response
        self.ns_response = ns_response
        self.response = response
        self.ds_id = ds_id
        self.answer = answer
        self.algorithm_number = algorithm_number
        self.algorithm = algorithm
        self.key_id = key_id

def getquerydata(domain):
    # domain = 'salesforce.com'
    ds_response = dns.resolver.resolve(domain, dns.rdatatype.DS)
    soa_response = dns.resolver.resolve(domain, dns.rdatatype.SOA)
    a_response = dns.resolver.resolve(domain, dns.rdatatype.A)
    ns_response = dns.resolver.resolve(domain, dns.rdatatype.NS)

    nsname = ns_response.rrset[0].to_text()
    ds_id = str.split(ds_response.rrset[0].to_text(),' ')[0]

    response = dns.resolver.resolve(nsname, dns.rdatatype.A)
    nsaddr = response.rrset[0].to_text()  # IPv4

    # get DNSKEY for zone
    request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    try:
        response = dns.query.udp(request, nsaddr, timeout=10)
    except:
        #No DNSSEC data
        return None

    answer = response.answer
    name = dns.name.from_text(domain)
    if len(answer) != 2:
        #print("SOMETHING WENT WRONG THE ANSWER SHOULD HAVE 2 THINGS IN IT")
        return None

    # the DNSKEY should be self signed, validate it
    try:
        dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
    except dns.dnssec.ValidationFailure:
        print("BE SUSPICIOUS THIS DNSKEY IS NOT SELF SIGNED")
        return None
    print("WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR THE QUERY")

    keys = {name: answer[0]}
    for rrsigset in answer[1]:
        if isinstance(rrsigset, tuple):
            rrsigrdataset = rrsigset[1]
        else:
            rrsigrdataset = rrsigset

        algorithm_number = int(str.split(rrsigrdataset.to_text(), ' ')[1])
        algorithm = dns.dnssec.algorithm_to_text(algorithm_number)

        dns.dnssec.validate_rrsig(answer[0], rrsigrdataset, keys)
        candidate_key = dns.dnssec._find_candidate_keys(keys, rrsigrdataset)
        key_id = dns.dnssec.key_id(candidate_key[0])
        print ("KEYID****: ", key_id)

    #return an object to be put in a sqlite table?
    newObject = myObject(domain,
                        ds_response,
                        soa_response,
                        a_response,
                        ns_response,
                        response,
                        ds_id,
                        answer,
                        algorithm_number,
                        algorithm,
                        key_id)
    picklestring = pickle.dumps(newObject)
    # unpickle = pickle.loads(picklestring)

    return picklestring

def parse_csv():
    with open('top-1m.csv', newline='') as csvfile:
        dialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        reader = csv.reader(csvfile, dialect)
        test_number_to_parse = 100                    # This number is used for testing on a smaller set of data
        domain = next(reader)
        # for row in reader:
        #     do stuff with row
        responses = []

        while int(domain[0]) != test_number_to_parse:
            # print ("line: ", domain[0])
            if int(domain[0]) < 40:
                domain = next(reader)
                continue
            responses.append(getquerydata(domain[1]))
            domain = next(reader)
        return responses


if __name__ == '__main__':
    list = parse_csv()
    total = sum(1 for x in list if x==True)
    print ("List: ", list)
    print ("Total DNSSEC: ", total)




