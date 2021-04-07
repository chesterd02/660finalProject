import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import csv
import pickle
import sqlite3
from datapackage import Package
import numpy as np
import matplotlib.pyplot as plt

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
    sql = '''CREATE TABLE Top500
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


    sql = "INSERT INTO Top500 (ID, DOMAINNAME, KSK, ZSK, MULTIPLEKSK, ALGORITHMNUMBER, ALGORITHM, TCP) " \
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
    domain = row[1]
    id = row[0]
    ksk = None
    zsk = None
    algorithm_number = None
    algorithm = None
    multiple_ksk = False
    tcp = False

    # request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    # response = dns.resolver.resolve(request, '8.8.8.8', timeout=3)

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
    with open('top500.csv', newline='') as csvfile:
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

def get_top_level_domains():
    package = Package('https://datahub.io/core/top-level-domain-names/datapackage.json')

    # print list of all resources:
    print(package.resource_names)

    # print processed tabular data (if exists any)
    count = 0
    for resource in package.resources:
        if resource.descriptor['datahub']['type'] == 'derived/csv':
            full_list = resource.read()
            for item in full_list:
                tuple = [count, item[0]]
                getquerydata(tuple)
                # print (item[0])
        count +=1
            # print(resource.read())

def getKSKCount(tableName, quantity):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT KSK, COUNT(KSK) FROM " + tableName + " GROUP BY KSK"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    sortedRows = sorted(rows, key=lambda k: k[1], reverse=True)
    return sortedRows[:quantity]

def graphKSKDistribution(data):
    ksk_id, score = zip(*data)
    x_pos = np.arange(len(ksk_id))
    plt.bar(x_pos, score)
    plt.xticks(x_pos, ksk_id)
    plt.show()

def getZSKCount(tableName, quantity):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT ZSK, COUNT(ZSK) FROM " + tableName + " GROUP BY ZSK"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    sortedRows = sorted(rows, key=lambda k: k[1], reverse=True)
    return sortedRows[:quantity]

def graphZSKDistribution(data):
    zsk_id, score = zip(*data)
    x_pos = np.arange(len(zsk_id))
    plt.bar(x_pos, score)
    plt.xticks(x_pos, zsk_id)
    plt.show()

def getMultipleKSKCount (tableName):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT COUNT(*) FROM " + tableName + " WHERE MULTIPLEKSK='True'"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    return rows[0]

def getTotalCount (tableName):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT COUNT(*) FROM " + tableName + " ORDER BY ID DESC LIMIT 1"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    return rows[0]

def pieChartMultipleKSKs(total, multi_ksks):
    data = [('singleKSK', (total-multi_ksks)), ('multipleKSK', multi_ksks)]
    name, amount = zip(*data)

    plt.pie(amount, startangle=90, autopct='%1.0f%%', pctdistance=0.5, textprops={'fontsize': 16})

    plt.legend(name, bbox_to_anchor=(1, 0.75), loc="upper right", fontsize=15,
               bbox_transform=plt.gcf().transFigure)

    plt.show()

def getAlgorithm(tableName, quantity):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT ALGORITHM, COUNT(ALGORITHM) FROM " + tableName + " GROUP BY ALGORITHM"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    sortedRows = sorted(rows, key=lambda k: k[1], reverse=True)
    return sortedRows[:quantity]

def graphAlgorithm(data):
    algorithm, score = zip(*data)
    x_pos = np.arange(len(algorithm))

    plt.bar(x_pos, score, align='center')
    plt.xticks(x_pos, algorithm, rotation=45)  # rotation=45?
    plt.ylabel('Popularity')
    plt.show()

def getAlgorithmNumber(tableName, quantity):
    connection = sqlite3.connect('data.db')
    cursor = connection.cursor()
    sql = "SELECT ALGORITHMNUMBER, COUNT(ALGORITHMNUMBER) FROM " + tableName + " GROUP BY ALGORITHMNUMBER"
    cursor.execute(sql)
    rows = cursor.fetchall()
    connection.close()
    sortedRows = sorted(rows, key=lambda k: k[1], reverse=True)
    return sortedRows[:quantity]

def graphOutdatedAlgorithms(data):
    algorithm, amount = zip(*data)

    plt.pie(amount, startangle=90, autopct='%1.0f%%', pctdistance=1.1, textprops={'fontsize': 11})

    plt.legend(algorithm, bbox_to_anchor=(1, 0.75), loc="upper right", fontsize=15,
               bbox_transform=plt.gcf().transFigure)

    plt.show()

if __name__ == '__main__':
    # clear_table()
    total = checkDatabase()
    # createTable()
    # parse_csv()
    # getquerydata([1, 'com.'])
    # print ("total", total)
    # # print ("List: ", list)
    # print ("Total DNSSEC: ", total)

    '''ANALYZE KSK'S'''
    # graphKSKDistribution(getKSKCount('top500', 10))

    '''ANALYZE ZSK'S'''
    # graphZSKDistribution(getZSKCount('Alexa1M', 10))

    '''ANALYZE MULTIPLE KSKS'''
    totalDNSSECDomains = getTotalCount('Alexa1M')[0]
    # totalDomainsWithMultipleKSKs = getMultipleKSKCount('top500')[0]
    # pieChartMultipleKSKs(totalDNSSECDomains, totalDomainsWithMultipleKSKs)
    print ("TOTAL DNSSEC DOMAINS: ", totalDNSSECDomains)

    '''ALGORITHM NUMBER'''
    # graphAlgorithm(getAlgorithm('Alexa1M', 6))

    '''OUTDATED ALGORITHMS'''
    # graphOutdatedAlgorithms(getAlgorithmNumber('Alexa1M', 6))

    # top_level_domains = get_top_level_domains()




