import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import csv
import pickle

class myObject:
    def __init__(self,
                 domain,
                 ds_id,
                 soa_key,
                 key_id,
                 algorithm_number,
                 algorithm):
        self.domain = domain
        self.ds_id = ds_id
        self.soa_key = soa_key
        self.key_id = key_id
        self.algorithm_number = algorithm_number
        self.algorithm = algorithm

def getKey(soa_string, domain):
    i = 5
    while i != len(soa_string):
        test = soa_string[i]
        if soa_string[i] == domain + '.':
            soa_key = soa_string[i-1]
            return soa_key
        i+=1
    return None

def getquerydata(domain):
    # domain = 'salesforce.com'
    key_id = None
    algorithm_number = None
    algorithm = None
    response = None
    soa_response = None

    try:
        ds_response = dns.resolver.resolve(domain, dns.rdatatype.DS)  #Delegation Signer (KSK)
        ns_response = dns.resolver.resolve(domain, dns.rdatatype.NS)
    except:
        return None

    print ("****DOMAIN****:  ", domain)
    nsname = ns_response.rrset[0].to_text()
    ds_id = str.split(ds_response.rrset[0].to_text(),' ')[0]
    print ("**DS_ID: ", ds_id)
    # USE GOOGLE AS DEFAULT NSADDR ADDRESS 8.8.8.8
    response = dns.resolver.resolve(nsname, dns.rdatatype.A)
    nsaddr = response.rrset[0].to_text()  # IPv4
    # get DNSKEY for zone
    request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    soa_request = dns.message.make_query(domain, dns.rdatatype.SOA, want_dnssec=True)
    try:
        response = dns.query.udp(request, nsaddr, timeout=10)
        soa_response = dns.query.udp(soa_request, nsaddr, timeout=10)
    except:
        #No DNSSEC data
        return None

    answer = response.answer
    soa_answer = soa_response.answer
    soa_signer = soa_answer[1].to_text()
    soa_string = str.split(soa_signer, ' ')
    soa_key = getKey(soa_string, domain)
    print ("Key to sign SOA: ", soa_key)

    name = dns.name.from_text(domain)

    if len(answer) != 2:
        print ("DOMAIN AND NSNAME DIDNT HAVE 2 TINGS IN ANSWER: ", domain, " ", nsname)
        try:
            response = dns.query.tcp(request, nsaddr, timeout=10)
            soa_response = dns.query.tcp(soa_request, nsaddr, timeout=10)
            answer = response.answer
            soa_answer = soa_response.answer
            soa_signer = soa_answer[1].to_text()
            soa_string = str.split(soa_signer, ' ')
            soa_key = getKey(soa_string, domain)
            print("Key to sign SOA: ", soa_key)
        except:
            print("SOMETHING WENT WRONG THE ANSWER SHOULD HAVE 2 THINGS IN IT")
            return myObject(domain,
                     ds_id,
                     soa_key,
                     key_id,
                     algorithm_number,
                     algorithm)
    # the DNSKEY should be self signed, validate it
    try:
        dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
    except dns.dnssec.ValidationFailure:
        print("BE SUSPICIOUS THIS DNSKEY IS NOT SELF SIGNED")
        # return None
    # print("WE'RE GOOD, THERE'S A VALID DNSSEC SELF-SIGNED KEY FOR THE QUERY")
    # print("DOMAIN AND NSNAME WITH DNSSEC: ", domain, " ", nsname)
    keys = {name: answer[0]}
    for rrsigset in answer[1]:  # can i make this be answer[0]?
        if isinstance(rrsigset, tuple):
            rrsigrdataset = rrsigset[1]
        else:
            rrsigrdataset = rrsigset

        algorithm_number = int(str.split(rrsigrdataset.to_text(), ' ')[1])
        algorithm = dns.dnssec.algorithm_to_text(algorithm_number)

        dns.dnssec.validate_rrsig(answer[0], rrsigrdataset, keys)
        # willFail = dns.dnssec.key_id(answer[0])
        candidate_key = dns.dnssec._find_candidate_keys(keys, rrsigrdataset)
        key_id = dns.dnssec.key_id(candidate_key[0])
        print ("KEYID****: ", key_id)

    #return an object to be put in a sqlite table?
    # are these the things that we want?  Is this all the data that we need from the queries
    newObject = myObject(domain,
                        ds_id,
                        soa_key,
                        key_id,
                        algorithm_number,
                        algorithm)
    picklestring = pickle.dumps(newObject)
    # unpickle = pickle.loads(picklestring)

    return picklestring

def parse_csv():
    with open('top-1m.csv', newline='') as csvfile:
        dialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        reader = csv.reader(csvfile, dialect)
        test_number_to_parse = 1000                    # This number is used for testing on a smaller set of data
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
    total = sum(1 for x in list if x!=None)
    # print ("List: ", list)
    print ("Total DNSSEC: ", total)




