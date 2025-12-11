import datetime
from .logs import log, log_http
class Alarm:
    def __init__(self, reason: str, ipdst: str, ipsrc: str, is_prot: bool):
        self.reason = reason
        self.ipdst = ipdst
        self.ipsrc = ipsrc
        self.message = f"{datetime.datetime.now()} || {reason} || {ipdst} -> {ipsrc} || {is_prot}"
    
    def __str__(self):
        return self.message
    
    def log(self,logfile: str,logtypes: list[str]) -> list[str]:    
        #["PRINT","LOG","example.domain.com"]
        errors = []

        logtypes = [x.lower() for x in logtypes.copy()]
        logtypes = set(logtypes)

        if "print" in logtypes:
            print(self.message)
            errors.append(False)

        if "log" in logtypes:
            try:
                log(self.message,logfile)
                errors.append(False)
            except:
                print(Exception)
                errors.append(Exception)

        if len(logtypes) > len(errors):
            try:
                log_http(self.message,[x for x in logtypes if x not in ["print","log"]])
                errors.append(False)
            except:
                errors.append(Exception)
        return errors


        

        


