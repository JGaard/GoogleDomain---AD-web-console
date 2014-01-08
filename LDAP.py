import ldap, sys
import ldap.modlist as modlist
import settings
import base64
    
import datetime, time


ADMIN_LOGIN = base64.b64decode(settings.encoded_admin_serverlogin)
ADMIN_PASS = base64.b64decode(settings.encoded_admin_pass)
AD_SERVER = base64.b64decode(settings.encode_AD_server)
LOCAL_DC = settings.local_DC
LOCAL_DC_PATH = settings.local_DC_path

def LDAPauthorize():
    ldap.set_option(ldap.OPT_DEBUG_LEVEL,0)
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

    server = AD_SERVER
    
    l = ldap.initialize(server)
    l.protocol_version=ldap.VERSION3
    l.start_tls_s()
    
    l.bind_s(ADMIN_LOGIN, ADMIN_PASS)
    
    return l
    
def addUser(username, firstname, surname, email, password, organization):
    
    l = LDAPauthorize()

    dn = 'CN=' +firstname + ' ' + surname + ',OU=' + organization + ',' + LOCAL_DC
    password_value = unicode_pass.encode('utf-16-le')
    
    attrs = {}
    attrs['objectclass'] = "user"
    attrs['uid'] = username
    attrs['sAMAccountname'] = username
    attrs['sn'] = surname
    attrs['givenName'] = firstname
    attrs['cn'] = firstname + ' ' + surname
    attrs['displayName'] = firstname + ' ' + surname
    attrs['mail'] = email
    attrs['company'] = organization
    attrs['userPrincipalName'] = username + LOCAL_DC_PATH
    attrs['unicodePwd'] = password_value
    attrs['userAccountControl'] = '66048' #<-- SUBJECT TO CHANGE BASED ON NEW USER REQUIREMENTS; SEE ARTICLE ON AD FLAGS 
    
    ldif = modlist.addModlist(attrs)
    l.add_s(dn, ldif)

def retrieveADGroups():
    domain_groups = {}
    
    l = LDAPauthorize()

    for org in settings.list_of_local_domains:
        base_dn = 'OU=' + str(org) + ',' + LOCAL_DC
        filter = '(objectclass=group)'
        attrs = ['name']
        domain_groups[org] = []
    
        for i in l.search_s( base_dn, ldap.SCOPE_SUBTREE, filter, attrs ):
            domain_groups[org].append(i)
    
    return domain_groups

def addUsertoGroups(group_dn, user_dn):
    l = LDAPauthorize()
    
    mod_attrs = [( ldap.MOD_ADD, 'member', user_dn )]
    l.modify_s(group_dn, mod_attrs)
    

def deactivateLastLogonPriorTo(year, month, day):
    l = LDAPauthorize()
    
    for org in settings.list_of_local_domains:
        base_dn = 'OU=' + str(org) + ',DC=9thStreet,DC=internal' 
        filter = '(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<=' + str(dateTimetoLargeInt(year, month, day)) + '))'
        attrs = []

    for i in l.search_s( base_dn, ldap.SCOPE_SUBTREE, filter, attrs ):
        mod_attrs = [( ldap.MOD_REPLACE, 'userAccountControl', '514')]
        l.modify_s(i[0], mod_attrs)

def dateTimetoLargeInt(year, month, day):
    seconds_in_year = 31556900
    epoch_time_no_subseconds = int(convertDate(year, month, day))
    LargeIntTime = (seconds_in_year * (1969 - 1600) + (epoch_time_no_subseconds - 22500)) * 10000000
    return LargeIntTime

def convertDate(year, month, day):
    date = datetime.datetime(year, month, day)
    return time.mktime(date.timetuple())
