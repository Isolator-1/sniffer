import re
from packetAnalyzer import getSummary

def itemCheck(package, description):
    
    if getSummary(package)[2] != None:
        print(description.lower() , getSummary(package)[2].lower())
        if description.lower() == getSummary(package)[2].lower():
            return True

    if "==" in description:
        left = description[:description.index("==")]
        right = description[description.index("==") + 2 :]
        if left == "ip":
            try:
                if package["IP"].src == right or package["IP"].dst == right:
                    return True
            except:
                pass
            try:
                if package["IPv6"].src == right or package["IPv6"].dst == right:
                    return True
            except:
                pass
        elif left == "ip.src":
            try:
                if package["IP"].src == right:
                    return True
            except:
                pass
            try:
                if package["IPv6"].src == right:
                    return True
            except:
                pass
        elif left == "right":
            try:
                if package["IP"].dst == right:
                    return True
            except:
                pass
            try:
                if package["IPv6"].dst == right:
                    return True
            except:
                pass
    elif description == "tcp" or description == "TCP":
        if "TCP" in package:
            return True
    elif description == "udp" or description == "UDP":
        if "UDP" in package:
            return True
    elif description == "arp" or description ==  "ARP":
        if "ARP" in package:
            return True
    elif description == "arp" or description ==  "ARP":
        if "ARP" in package:
            return True
    return False


def checkPackages(package, rule):
    if rule == "":
        return True
    rule = rule.replace(" ","")
    words = re.findall(r'\|\||&&|\w+\=\=\w+\.\w+\.\w+\.\w+|\w+\.\w+\=\=\w+\.\w+\.\w+\.\w+|\w+', rule)
    boolList = [None] * len(words)
    while True:
        try:
            pos = words.index("&&")
            if boolList[pos-1] == None and boolList[pos+1] == None:
                boolList[pos-1] = itemCheck(package,words[pos-1]) and itemCheck(package,words[pos+1])
            elif boolList[pos-1] != None and boolList[pos+1] == None:
                boolList[pos-1] = boolList[pos-1] and itemCheck(package,words[pos+1])
            elif boolList[pos-1] == None and boolList[pos+1] != None:
                boolList[pos-1] = itemCheck(package,words[pos-1]) and boolList[pos+1]
            else:
                boolList[pos-1] = boolList[pos-1] and boolList[pos+1]
            words[pos-1] = words[pos-1] + words[pos] + words[pos+1]
            del(words[pos])
            del(words[pos])
            del(boolList[pos])
            del(boolList[pos])
        except ValueError:
            break
    
    while True:
        try:
            pos = words.index("||")
            if boolList[pos-1] == None and boolList[pos+1] == None:
                boolList[pos-1] = itemCheck(package,words[pos-1]) or itemCheck(package,words[pos+1])
            elif boolList[pos-1] != None and boolList[pos+1] == None:
                boolList[pos-1] = boolList[pos-1] or itemCheck(package,words[pos+1])
            elif boolList[pos-1] == None and boolList[pos+1] != None:
                boolList[pos-1] = itemCheck(package,words[pos-1]) or boolList[pos+1]
            else:
                boolList[pos-1] = boolList[pos-1] or boolList[pos+1]
            words[pos-1] = words[pos-1] + words[pos] + words[pos+1]
            del(words[pos])
            del(words[pos])
            del(boolList[pos])
            del(boolList[pos])
        except ValueError:
            break
    if len(boolList) != 1 and len(words) != 1 and rule != words[0]:
        print("checkPackage Error", boolList, words)

    if boolList[0] == None:
        return itemCheck(package, words[0])

    return boolList[0]