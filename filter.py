import re

class RuleFilter:
    def __init__(self,rawRule):
        if rawRule == "":
            return self.allPackageList()
        self.protocol = ["tcp", "udp", "tls", "icmp"]
        self.rawRule = rawRule
        self.rawRule = rawRule.replace(" ","")
        self.words = re.findall(r'\|\||&&|\w+\.\w+\=\=\w+\.\w+\.\w+\.\w+|\w+', self.rawRule)
        self.packageList = [None] * len(self.words)
        while True:
            try:
                pos = self.words.index("&&")
                left = self.getPackageList(pos-1)
                right = self.getPackageList(pos+1)
                self.words[pos-1] = self.words[pos-1] + self.words[pos] + self.words[pos+1]
                self.packageList[pos-1] = self.andOperation(left,right)
                del(self.words[pos])
                del(self.words[pos])
                del(self.packageList[pos])
                del(self.packageList[pos])
            except ValueError:
                break
        while True:
            try:
                pos = self.words.index("||")
                left = self.getPackageList(pos-1)
                right = self.getPackageList(pos+1)
                self.words[pos-1] = self.words[pos-1] + self.words[pos] + self.words[pos+1]
                self.packageList[pos-1] = self.orOperation(left,right)
                del(self.words[pos])
                del(self.words[pos])
                del(self.packageList[pos])
                del(self.packageList[pos])
            except ValueError:
                break

        

    def getPackageList(self,index):
        if self.words[index] ==None:
            pass
        else:
            if self.words[index] in self.protocol:
                pass
            elif "==" in self.words[index]:
                pass
            pass

    def allPackageList(self):
        pass

    def andOperation(self,left,right):
        pass

    def orOperation(self,left,right):
        pass