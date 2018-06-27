#! /bin/env python
# 
# USAGE
# $ python activedirectory_pop.py "My Group Name"
#
# Author: # Sumod Madhavan
# sumadh@microsoft.com
# Organization : Microsoft

import sys
import ldap


ACTIVEDIRECTORY_SERVERS = [ '<dc ip address>', 'dc ip address']
ACTIVEDIRECTORY_USER_BASEDN = "<BASE DN. E.g. OU=Users,DC=Example,DC=Com>"
ACTIVEDIRECTORY_USER_FILTER = '(&(objectClass=USER)(sAMAccountName={username}))'
ACTIVEDIRECTORY_USER_FILTER2 = '(&(objectClass=USER)(dn={userdn}))'
ACTIVEDIRECTORY_GROUP_FILTER = '(&(objectClass=GROUP)(cn={group_name}))'
ACTIVEDIRECTORY_BIND_USER = '<foobar>' #Pipe in UserName
ACTIVEDIRECTORY_BIND_PWD = '<foobar>' #Pipe in Password



# ldap connection
def activedirectory_authentication(username=ACTIVEDIRECTORY_BIND_USER, password=ACTIVEDIRECTORY_BIND_PWD, address=ACTIVEDIRECTORY_SERVERS[0]):
	conn = ldap.initialize('ldap://' + address)
	conn.protocol_version = 3
	conn.set_option(ldap.OPT_REFERRALS, 0)

	result = True

	try:
		conn.simple_bind_s(username, password)
		print "Succesfully authenticated"
	except ldap.INVALID_CREDENTIALS:
		return "Invalid credentials", False
	except ldap.SERVER_DOWN:
		return "Server down", False
	except ldap.LDAPError, e:
		if type(e.message) == dict and e.message.has_key('desc'):
			return "Other LDAP error: " + e.message['desc'], False
		else:
			return "Other LDAP error: " + e, False

	return conn, result

def get_dn_by_username(username, activedirectory_conn, basedn=ACTIVEDIRECTORY_USER_BASEDN):
	return_dn = ''
	activedirectory_filter = ACTIVEDIRECTORY_USER_FILTER.replace('{username}', username)
	results = activedirectory_conn.search_s(basedn, ldap.SCOPE_SUBTREE, activedirectory_filter)
	if results:
		for dn, others in results:
			return_dn = dn
	return return_dn

#
# query only enabled users with the following filter
# (!(userAccountControl:1.2.840.113556.1.4.803:=2))
#
def get_email_by_dn(dn, activedirectory_conn):
	email = ''
	result = activedirectory_conn.search_s(dn, ldap.SCOPE_BASE, \
		'(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))')
	if result:
		for dn, attrb in result:
			if 'mail' in attrb and attrb['mail']:
				email = attrb['mail'][0].lower()
				break
	return email


def get_group_members(group_name, activedirectory_conn, basedn=ACTIVEDIRECTORY_USER_BASEDN):
	members = []
	activedirectory_filter = ACTIVEDIRECTORY_GROUP_FILTER.replace('{group_name}', group_name)
	result = activedirectory_conn.search_s(basedn, ldap.SCOPE_SUBTREE, activedirectory_filter)
	if result:
		if len(result[0]) >= 2 and 'member' in result[0][1]:
			members_tmp = result[0][1]['member']
			for m in members_tmp:
				email = get_email_by_dn(m, activedirectory_conn)
				if email:
					members.append(email)
	return members
	
#Main Begins
if __name__ == "__main__":
  group_name = sys.argv[1]
  activedirectory_conn, result = activedirectory_authentication()
  if result:
    group_members = get_group_members(group_name, activedirectory_conn)
    for groupMember in group_members:
      print groupMember
#Main Ends