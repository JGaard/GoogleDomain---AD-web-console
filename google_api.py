# -*- coding: utf-8 -*-

import gdata.apps.client
import gdata.contacts.client
import gdata.apps.service
import gdata.apps.emailsettings.client
import gdata.apps.groups.client
import settings
import base64

SOURCE = settings.webapp_name
LOCAL_DC = settings.local_DC
LOCAL_DC_PATH = settings.local_DC_path

class gAPI(object):
    def __init__(self, org_domain, username, userpassword):
        self.org_domain = org_domain
        self.username = username
        self.admin_domain = self.set_admin_domain()
        self.admin_password = self.set_admin_password()
        self.userpassword = userpassword

        self.client = gdata.apps.client.AppsClient(domain=self.org_domain)
        self.client.ssl = True
        self.client.ClientLogin(email=self.admin_domain, password=self.admin_password, source=SOURCE)
        
    def set_admin_domain(self):
        if self.org_domain in settings.domain_login_exception_one:
            return settings.domain_login_exception_one[self.org_domain]
        else:
            return 'support' + '@' + self.org_domain #<--SUBJECT TO CHANGE, GOOGLE DOMAIN ADMIN LOGIN
        
    def set_admin_password(self):
        if self.org_domain == settings.domain_pass_exception_one:
            return base64.b64decode(settings.encoded_admin_pass_two)
        else:
            return base64.b64decode(settings.encoded_admin_pass)
    
    def utf_decode(self, data):
        return data.decode('utf-8')
    
    def _admin_service_login(self):
        service = gdata.apps.service.AppsService(email=self.admin_domain, domain=self.org_domain, password=self.admin_password)
        service.ProgrammaticLogin()
        return service
    
    def _admin_client_login(self, client_id):
        if client_id == "groups":
            groupClient = gdata.apps.groups.client.GroupsProvisioningClient(domain=self.org_domain)
            groupClient.ClientLogin(email=self.admin_domain, password=self.admin_password, source=SOURCE)
            return groupClient
        if client_id == "emailsettings":
            emailClient = gdata.apps.emailsettings.client.EmailSettingsClient(domain=self.org_domain)
            emailClient.ClientLogin(email=self.admin_domain, password=self.admin_password, source=SOURCE)
            return emailClient
    
    def create_new_user(self, given_name, family_name):
        self.client.CreateUser(self.username, family_name, given_name, self.userpassword, suspended=False,
                          admin=None, quota_limit=None, password_hash_function=None, change_password=None)
    
    def retrieve_user(self):
         return self.client.RetrieveUser(self.username)
    
    def update_user_password(self, password):
        user_entry = self.retrieve_user()
        user_entry.login.password = password
        self.client.UpdateUser(self.username, user_entry)
    
    def update_user_username(self, username):
        user_entry = self.retrieve_user()
        user_entry.login.user_name = username
        self.client.UpdateUser(self.username, user_entry)
    
    def update_user_givenname(self, givenname):
        user_entry = self.retrieve_user()
        user_entry.name.given_name = givenname
        self.client.UpdateUser(self.username, user_entry)
    
    def update_user_familyname(self, familyname):
        user_entry = self.retrieve_user()
        user_entry.name.family_name = familyname
        self.client.UpdateUser(self.username, user_entry)
        
    def create_nickname(self, nickname):
        self.client.CreateNickname(self.username, nickname)
    
    def update_user(self, username, user_entry):
        self.client.UpdateUser(username, user_entry)
        
    def delete_user(self):
        self.client.DeleteUser(self.username)
    
    def suspend_user(self):
        user_entry = self.client.RetrieveUser(self.username)
        user_entry.login.suspended = 'true'
        self.client.UpdateUser(self.username, user_entry)
    
    def unsuspend_user(self):
        user_entry = self.client.RetrieveUser(self.username)
        user_entry.login.suspended = 'false'
        self.client.UpdateUser(self.username, user_entry)
    
    def delete_nickname(self, nickname):
        self.client.DeleteNickname(nickname)
    
    def delete_all_user_nicknames(self):
        user_nicknames = self.retrieve_nicknames()
        for nickname in user_nicknames:
            self.delete_nickname(nickname)
    
    def retrieveAllDomainAddresses(self, ):
        domainAddresses=[]
        for user in self.retrieve_domain_usernames():
            domainAddresses.append(user + '@' + self.org_domain)
        return domainAddresses
          
    def retrieve_domain_usernames(self):
        domain_usernames=[]
        users = self._admin_service_login().RetrieveAllUsers()

        for u in users.entry:
            domain_usernames.append(self.utf_decode(u.login.user_name))
        return domain_usernames
        
    
    def retrieve_domain_givennames(self):
        domain_givennames=[]
        users = self._admin_service_login().RetrieveAllUsers()

        for u in users.entry:
            domain_givennames.append(self.utf_decode(u.name.given_name))
        return domain_givennames
    
    def retrieve_domain_familynames(self):
        domain_familynames=[]
        users = self._admin_service_login().RetrieveAllUsers()
        
        for u in users.entry:
            domain_familynames.append(self.utf_decode(u.name.family_name)) 
        return domain_familynames
    
    def retrieve_nicknames(self):
        user_nicknames = []
        nicknames = self._admin_service_login().RetrieveNicknames(self.username)
        
        for u in nicknames.entry:
            user_nicknames.append(self.utf_decode(u.nickname.name))
        return user_nicknames
    
    def retriveUserGroups(self):
        userGroups = []
        client = self._admin_client_login('groups').RetrieveGroups(self.username + '@' + self.org_domain)

        for u in client.entry:
            userGroups.append(u)
        return userGroups

    def retrieveDomainGroups(self):
        domainGroups = []
        client = self._admin_client_login('groups').RetrieveAllGroups()
        
        for u in client.entry:
            domainGroups.append(u)
        return domainGroups
    
    def setGroupRelation(self):
        groupRelations={}
        for i in self.retrieveDomainGroups():
            groupRelations[i.GetGroupName()] = i.GetGroupId()
        return groupRelations
        
    
    def retriveUserGroupIds(self):
        userGroupIds = []
        client = self._admin_client_login().RetrieveGroups(self.username + '@' + self.org_domain)

        for u in client.entry:
            user_groups = u.GetGroupId()
            userGroupIds.append(self.utf_decode(user_groups))
        return userGroupIds

    def retrieveDomainGroupIds(self):
        domainGroupIds = []
        client = self._admin_client_login('groups').RetrieveAllGroups()
        
        for u in client.entry:
            domain_groups = u.GetGroupName()
            domainGroupIds.append(self.utf_decode(domain_groups))
        return domainGroupIds
    
    
    def retriveUserGroupNames(self):
        userGroupNames = []
        client = self._admin_client_login('groups').RetrieveGroups(self.username + '@' + self.org_domain)

        for u in client.entry:
            user_groups = u.GetGroupName()
            userGroupNames.append(self.utf_decode(user_groups))
        return userGroupNames

    def retrieveDomainGroupNames(self):
        domainGroupNames = []
        client = self._admin_client_login('groups').RetrieveAllGroups()
        
        for u in client.entry:
            domain_groups = u.GetGroupName()
            domainGroupNames.append(self.utf_decode(domain_groups))
        return domainGroupNames
    
    def addToGroup(self, group_id):
        groupClient = gdata.apps.groups.client.GroupsProvisioningClient(domain=self.org_domain)
        groupClient.ClientLogin(email=self.admin_domain, password=self.admin_password, source=SOURCE)
        groupClient.AddMemberToGroup(group_id, self.username + '@' + self.org_domain)   
    
    def removeFromGroup(self, group_id):
        groupClient = gdata.apps.groups.client.GroupsProvisioningClient(domain=self.org_domain)
        groupClient.ClientLogin(email=self.admin_domain, password=self.admin_password, source=SOURCE)
        groupClient.RemoveMemberFromGroup(group_id, self.username + '@' + self.org_domain)   
    
    def retrieveUserForwarding(self):
        emailClient = self._admin_client_login('emailsettings')
        emailClient = emailClient.RetrieveForwarding(self.username)
        return emailClient.GetForwardTo()
    
    def setForwardingSettings(self, forwarding_status, forwarding_address):
        emailClient = self._admin_client_login('emailsettings')
        emailClient.UpdateForwarding(username=self.username, enable=forwarding_status, forward_to=forwarding_address, action='KEEP')
        
    def createNewFilter(self, from_address=None,
                    to_address=None,
                    subject=None,
                    has_the_word=None,
                    does_not_have_the_word=None,
                    has_attachments=None,
                    label=None,
                    mark_as_read=None,
                    archive=None,
                    **kwargs):
        emailClient = self._admin_client_login('emailsettings')
        emailClient.CreateFilter(username=self.username,
                                from_address=from_address,
                                to_address=to_address,
                                subject=subject,
                                has_the_word=has_the_word,
                                does_not_have_the_word=does_not_have_the_word,
                                has_attachments=has_attachments,
                                label=label,
                                mark_as_read=mark_as_read,
                                archive=archive)
    
    
    def get_username(self):
        if self.username == "":
            return ""
        u = self.retrieve_user()
        return self.utf_decode(u.login.user_name)

    def get_firstname(self):
        if self.username == "":
            return ""
        u= self.retrieve_user()
        return self.utf_decode(u.name.given_name)
            
    def get_lastname(self):
        if self.username == "":
            return ""
        u = self.retrieve_user()
        return self.utf_decode(u.name.family_name)
    
    def get_password(self):
        u = self.retrieve_user()
        return self.utf_decode(u.login.password)
    
    def get_nickname(self, nickname):
        self.client.RetrieveNickname(nickname)
            
