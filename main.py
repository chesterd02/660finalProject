import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import csv
import pickle
import sqlite3

class myObject:
    def __init__(self,
                 id,
                 domain,
                 ksk,
                 zsk,
                 multiple_ksk,
                 algorithm_number,
                 algorithm,
                 tcp):
        self.id = id
        self.domain = domain
        self.ksk = ksk
        self.zsk = zsk
        self.multiple_ksk = multiple_ksk
        self.algorithm_number = algorithm_number
        self.algorithm = algorithm
        self.tcp = tcp
def clear_table():
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    # sql = '''DROP TABLE IF EXISTS Alexa1M'''    #commented out to prevent accidental removal of the table
    cursor.execute(sql)
    connection.commit()
    connection.close()

def createTable():
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = '''CREATE TABLE Alexa1M
            (ID INT PRIMARY KEY,
            DOMAINNAME VARCHAR,
            KSK INT,
            ZSK VARCHAR,
            MULTIPLEKSK INT,
            ALGORITHMNUMBER INT,
            ALGORITHM VARCHAR,
            TCP INT)'''

    cursor.execute(sql)
    connection.commit()
    connection.close()

def insertToDatabase(object):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    myObject = object
    domain = myObject.domain
    ksk = myObject.ksk
    zsk = myObject.zsk
    multiple_ksk = myObject.multiple_ksk
    algorithm_number = myObject.algorithm_number
    algorithm = myObject.algorithm
    tcp = myObject.tcp
    id = myObject.id


    sql = "INSERT INTO Alexa1M (ID, DOMAINNAME, KSK, ZSK, MULTIPLEKSK, ALGORITHMNUMBER, ALGORITHM, TCP) " \
        f"VALUES ('{id}'," \
        f"'{domain}'," \
        f"'{ksk}'," \
        f"'{zsk}'," \
        f"'{multiple_ksk}'," \
        f"'{algorithm_number}'," \
        f"'{algorithm}'," \
        f"'{tcp}')"
    cursor.execute(sql)
    connection.commit()
    connection.close()

def checkDatabase():
  connection = sqlite3.connect('data.db')
  cursor = connection.cursor()

  sql = "SELECT * FROM Alexa1M"
  cursor.execute(sql)

  rows = cursor.fetchall()
  count = 0
  for row in rows:
    print(row)
    count +=1
  connection.close()
  return count

def getKey(soa_string, domain):
    i = 5
    while i != len(soa_string):
        test = soa_string[i]
        if soa_string[i] == domain + '.':
            soa_key = soa_string[i-1]
            return soa_key
        i+=1
    return None

def getquerydata(row):
    # domain = 'blackboard.com'
    domain = row[1]
    id = row[0]
    ksk = None
    zsk = None
    algorithm_number = None
    algorithm = None
    multiple_ksk = False
    tcp = False

    try:
        ds_response = dns.resolver.resolve(domain, dns.rdatatype.DS)  #Delegation Signer (KSK)
        ns_response = dns.resolver.resolve(domain, dns.rdatatype.NS)
    except:
        return

    nsname = ns_response.rrset[0].to_text()
    ksk = str.split(ds_response.rrset[0].to_text(),' ')[0]

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
        return

    answer = response.answer
    soa_answer = soa_response.answer
    if len(soa_answer) < 1:
        return
    soa_signer = soa_answer[0].to_text()
    if "RRSIG" not in soa_signer:
        try:
            soa_signer = soa_answer[1].to_text()
        except:
            return
    soa_string = str.split(soa_signer, ' ')
    zsk = getKey(soa_string, domain)

    if len(answer) != 2:
        print ("DOMAIN AND NSNAME DIDNT HAVE 2 THINGS IN ANSWER: ", domain, " ", nsname)
        try:
            response = dns.query.tcp(request, nsaddr, timeout=10)
            soa_response = dns.query.tcp(soa_request, nsaddr, timeout=10)
            answer = response.answer
            soa_answer = soa_response.answer
            soa_signer = soa_answer[1].to_text()
            soa_string = str.split(soa_signer, ' ')
            zsk = getKey(soa_string, domain)
            tcp = True

        except:
            print("SOMETHING WENT WRONG THE ANSWER SHOULD HAVE 2 THINGS IN IT")
            return myObject(id,
                     domain,
                     ksk,
                     zsk,
                     multiple_ksk,
                     algorithm_number,
                     algorithm,
                     tcp)

    count = 0
    for rrsigset in answer[1]:
        count += 1
        if count >= 2:
            multiple_ksk = True
            print ("multiple keys found for domain: " , domain)
        if isinstance(rrsigset, tuple):
            rrsigrdataset = rrsigset[1]
        else:
            rrsigrdataset = rrsigset

        algorithm_number = int(str.split(rrsigrdataset.to_text(), ' ')[1])
        algorithm = dns.dnssec.algorithm_to_text(algorithm_number)

    newObject = myObject(id,
                        domain,
                        ksk,
                        zsk,
                        multiple_ksk,
                        algorithm_number,
                        algorithm,
                        tcp)
    insertToDatabase(newObject)

    # picklestring = pickle.dumps(newObject)

    return

def parse_csv():
    with open('top-1m.csv', newline='') as csvfile:
        dialect = csv.Sniffer().sniff(csvfile.read(1024))
        csvfile.seek(0)
        reader = csv.reader(csvfile, dialect)
        # test_number_to_parse = 1000                    # This number is used for testing on a smaller set of data
        # domain = next(reader)
        # responses = []
        for row in reader:
            getquerydata(row)

        # while int(domain[0]) != test_number_to_parse:
        #     # print ("line: ", domain[0])
        #     if int(domain[0]) < 40:
        #         domain = next(reader)
        #         continue
        #     responses.append(getquerydata(domain[1]))
        #     domain = next(reader)
        return


if __name__ == '__main__':
    # clear_table()
    total = checkDatabase()
    # createTable()
    # parse_csv()
    print ("total", total)
    # # print ("List: ", list)
    # print ("Total DNSSEC: ", total)




