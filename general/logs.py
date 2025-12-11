import requests
import json
import re


def is_valid_domain(domain_string: str) -> bool:
    """
    Проверяет, соответствует ли строка формату валидного доменного имени.
    
    Args:
        domain_string: Строка для проверки.
        
    Returns:
        True, если строка является валидным доменом, иначе False.
    """
    
    regex_pattern = r"^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$"
    
    pattern = re.compile(regex_pattern, re.IGNORECASE)
    
    if pattern.search(domain_string):
        return True
    else:
        return False


def log(msg: str, pathtofile: str) -> None:
    print(pathtofile)
    with open(pathtofile,"a",encoding="utf-8") as f:
        f.write(msg + "\n")
        f.flush()

def log_http(msg: str, domens: list[str]) -> None:
    for domen in domens:
        if is_valid_domain(domen):
            r = requests.post(f"http://{domen}",data=json.dumps({"msg": msg}))
            if r.status_code not in list(range(200,300)): print(f"WARNING!! request to {domen} {r.status_code}")
        else:
            raise ValueError(f"{domen} not is valid")



