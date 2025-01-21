import asyncio
from msldap.commons.factory import LDAPConnectionFactory
import argparse
import os
from smbclient import listdir
from smbclient.path import isdir
import smbclient
import registrypol

async def make_query(url,query,attributes):
    conn_url = LDAPConnectionFactory.from_url(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err

    #user = await ldap_client.get_user(user)
    
    entries = []
    async for entry, err in ldap_client.pagedsearch(
        query,
        attributes=attributes
    ):
        if err is not None:
            print(f"Error: {err}")
            break
        
        entries.append(entry)

    await ldap_client.disconnect()
    return entries

async def get_acl(url,dn):
    conn_url = LDAPConnectionFactory.from_url(url)
    ldap_client = conn_url.get_client()
    _, err = await ldap_client.connect()
    if err is not None:
        raise err
  
    entries = []
    async for entry, err in ldap_client.get_objectacl_by_dn(dn):
        if err is not None:
            print(f"Error: {err}")
            break
        
        entries.append(entry)

    await ldap_client.disconnect()
    return entries

async def main():
    result = await make_query("ldap+ntlm-password://domain\\administrator:Password01@192.168.245.155","(sAMAccountName=bhorseman)","distinguishedName")
    
    print(result)

if __name__ == "__main__":
    asyncio.run(main())

#ldap+ntlm-password://TEST\\victim:<password>@10.10.10.2