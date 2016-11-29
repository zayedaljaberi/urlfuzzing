import httplib
import sys
import os
import getopt
import string
import signal
import socket
from ipwhois import IPWhois


print('')
print('Advance Fuzzing v1.0, 2016 Development by Zayed AlJaberi')
print('zayed.aljaberi@gmail.com    |    http://wesecure.ae')


real_path = os.path.dirname(os.path.realpath(__file__))

def signal_handler(signal, frame):
    print("\nScan stopped by user.")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

class options:
    targetURL = None
    showRedirect = None
    listFile = None

def if_null(data):
    if data == None:
        return ""
    return data.replace('\n',' ')

def whois_site(site):
    if site.startswith('http'):
        site = site[7:].replace('/','')
    ip = socket.gethostbyname(site)
    obj = IPWhois(ip)
    data = obj.lookup_whois()
    print ('IP : '+if_null(data['query']) )
    print ('IP Location : '+ if_null( data['nets'][0]['country'])+" , "+if_null(data['nets'][0]['city'])+" , "+if_null(data['nets'][0]['address'].replace('\n',' ') ) )
    print ('postal_code : '+ if_null( data['nets'][0]['postal_code']) )
    print ('ASN : '+ if_null( data['asn'] )+" - "+if_null( data['nets'][0]['description'] ) )
    print ('created : '+if_null(data['nets'][0]['created'] )+" --> updated : "+if_null(data['nets'][0]['updated']) )

def cls():
    os.system('cls' if os.name=='nt' else 'clear')

def main():
    start = '''\n\nChoose the category ?\n\t1:   Automatic\n\t2:   CMS\n\t3:   WebServer\n\t4:   Others\n\t \n\n'''
    print (start)
    cmd_raw_input = raw_input("Please enter an option: ")
    if int(cmd_raw_input) == 1:
        file = real_path+"/Automatic/list.txt"
        site = raw_input("Enter Web Site: ")
    elif int(cmd_raw_input) == 2:
        cls()
        res = "\n\nCMS?\n\t"
        for i in os.listdir(real_path+"/CMS"):
            num = os.listdir(real_path+"/CMS").index(i) + 1
            try:
                i = i.split('.')[0]
            except:
                pass
            res = res+str(num)+": "+i+"\n\t"
        print (res)
        file = raw_input("Choose CMS : ")
        file = os.listdir(real_path+"/CMS")[int(file)-1]
        file = real_path+"/CMS/"+file
        site = raw_input("Enter Web Site: ")
        cls()
    elif int(cmd_raw_input) == 3:
        res = "\n\nWebServer?\n\t"
        for i in os.listdir(real_path+"/WebServer"):
            num = os.listdir(real_path+"/WebServer").index(i) + 1
            try:
                i = i.split('.')[0]
            except:
                pass
            res = res+str(num)+": "+i+"\n\t"
        print (res)
        file = raw_input("Choose WebServer : ")
        file = os.listdir(real_path+"/WebServer")[int(file)-1]
        file = real_path+"/WebServer/"+file
        site = raw_input("Enter Web Site: ")
    elif int(cmd_raw_input) == 4:
        res = "\n\nOthers Extension?\n\t"
        for i in os.listdir(real_path+"/Others"):
            num = os.listdir(real_path+"/Others").index(i) + 1
            try:
                i = i.split('.')[0]
            except:
                pass
            res = res+str(num)+": "+i+"\n\t"
        print (res)
        file = raw_input("Choose Extension : ")
        file = os.listdir(real_path+"/Others")[int(file)-1]
        file = real_path+"/Others/"+file
        site = raw_input("Enter Web Site: ")
    elif int(cmd_raw_input) == 5:
        file = raw_input("Please enter path to file:")
        site = raw_input("Enter Web Site: ")

    if site == "":
        print ("Site Is Empty")
        sys.exit()

    if not os.path.isfile(file):
        print("Error: File ("+file+") doesn't exist.")
        sys.exit()
    else:
        options.listFile = file
        options.targetURL = site

    if options.targetURL[-1] != "/":
        options.targetURL += "/"

    targetPro = ""

    if options.targetURL[:5].lower() == 'https':
        targetDomain = options.targetURL[8:].split("/",1)[0].lower()
        targetPath = "/" + options.targetURL[8:].split("/",1)[1]
        connection = httplib.HTTPSConnection(targetDomain)
        targetPro = "https://"
        print("Target: ", targetPro+targetDomain, "(over HTTPS)")
        print("Path: ", targetPath)
    elif options.targetURL[:5].lower() == 'http:':
        targetDomain = options.targetURL[7:].split("/",1)[0].lower()
        targetPath = "/"+options.targetURL[7:].split("/",1)[1]
        connection = httplib.HTTPConnection(targetDomain)
        targetPro = "http://"
        print("Target set: ", targetDomain)
        print("Path: ", targetPath)
    else:
        targetDomain = options.targetURL.split("/",1)[0].lower()
        targetPath = "/"+options.targetURL.split("/",1)[1]
        connection = httplib.HTTPConnection(targetDomain)
        targetPro = "http://"
        print("Target set: ", targetDomain)
        print("Path: ", targetPath)

    connection.request("HEAD", targetPath+"randomhy27dtwjwysg.txt")
    res = connection.getresponse()

    if res.status == 200:
        print("NOTE: Looks like the server is returning code 200 for all requests, there might be lots of false positive links.")

    if res.status >= 300 and res.status < 400 and options.showRedirect != None:
        print("NOTE: Looks like the server is returning code", res.status, "for all requests, there might be lots of false positive links. try to scan without the option -r")

    tpData = res.read()

    with open(options.listFile) as lFile:
        pathList = lFile.readlines()

    print ("Scanning (",len(pathList),") files...")
    countFound = 0

    for pathLine in pathList:
        pathLine = pathLine.strip("\n")
        pathLine = pathLine.strip("\r")

        if pathLine != "":
            if pathLine[:1] == "/":
                pathLine = pathLine[1:]

            connection.request("GET", targetPath+pathLine)
            try :
                res = connection.getresponse()
            except:
                pass

            if res.status == 200:
                print("Code", res.status,":",targetPro+targetDomain+targetPath+pathLine)
                countFound += 1

            if options.showRedirect != None:
                if res.status >= 300 and res.status < 400:
                    print("Code", res.status,":",targetPro+targetDomain+targetPath+pathLine, "(",res.getheader("location"),")")
                    countFound += 1

            tpData = res.read()

    connection.close()
    print ( "Total Pages found:",countFound )
    print (options.targetURL)
    whois_site(options.targetURL)


if __name__ == "__main__":
    main()
