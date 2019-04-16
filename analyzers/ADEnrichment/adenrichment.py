#!/usr/bin/python2
# -*- coding: utf-8 -*-

import ldap
import json
import datetime
import unidecode
import base64

from cortexutils.analyzer import Analyzer

class ADEnrichment(Analyzer):
	def __init__(self):
		Analyzer.__init__(self)
		self.adurl=self.get_param('config.ldapsurl', None, 'LDAPS URL parameter is missing')
		self.domain = self.get_param('config.domain', None, 'Domain parameter is missing')
		self.computer_basedn = self.get_param('config.computer_basedn', None, 'computer_basedn parameter is missing. This should be a semicolon separated list of base distinguished names such as ",OU=Mycompany,OU=Workstations,DC=corp,DC=local"')
		self.person_basedn = self.get_param('config.person_basedn', None, 'person_basedn parameter is missing. This should be a semicolon separated list of base distinguished names such as ",OU=Branch,OU=UserAccounts,DC=corp,DC=local;,OU=HQ,OU=UserAccounts,DC=corp,DC=local"')
		self.service_account = self.get_param('config.serviceaccount', None, 'serviceaccount parameter is missing. This account is used to bind to LDAP')
		self.service_account_password  = self.get_param('config.serviceaccount_password', None, 'serviceaccount_password parameter is missing')
	def asciionly(self,txt):
		result= ''.join([i if ord(i) < 128 else ' ' for i in txt])
		if not result.strip:
			return txt
		return result

	def getFiletime(self,dt):
	    microseconds = dt / 10
	    seconds, microseconds = divmod(microseconds, 1000000)
	    days, seconds = divmod(seconds, 86400)
	    return datetime.datetime(1601, 1, 1) + datetime.timedelta(days, seconds, microseconds)
	
	def parse(self,key,val):
		bl=["logonHours","msExchSafeSendersHash","msExchBlockedSendersHash","mS-DS-ConsistencyGuid","protocolSettings","msExchMailboxSecurityDescriptor","msExchPoliciesIncluded","userCertificate","objectSid","msExchMailboxGuid","msDS-ExternalDirectoryObjectIdprotoco	lSettings","mS-DS-ConsistencyGuid ","objectGUID"]
		wl={"thumbnailPhoto":"base64","lastLogon":"time","badPasswordTime":"time","lastLogonTimestamp":"time","pwdLastSet":"time","	ms-Mcs-AdmPwdExpirationTime":"time"}
		if key in bl:
			return None
				
		if not key in wl:
			for i in range(0,len(val)):
				val[i]=self.asciionly(val[i])

			if type(val) is list and len(val) == 1:
				return (key,val[0])
			elif type(val) is list:
				return (key,','.join(val).strip(","))
		else:
			if wl[key] is "time":
				return (key,format(self.getFiletime(int(val[0])), '%a, %d %B %Y %H:%M:%S %Z'))
			if wl[key] is "base64":
				return (key,str(base64.b64encode(val[0])))
		return (key,val)

	def adlookup(self,subject,otype):
		ldap_obj = ldap.initialize(self.adurl)
		ldap_obj.protocol_version = ldap.VERSION3
		ldap_obj.set_option(ldap.OPT_REFERRALS, 0)
		result=ldap_obj.simple_bind_s(self.service_account+"@"+self.domain, self.service_account_password)
		basedns=None
		if otype=="computer":
			basedns=self.computer_basedn.split(";")
		elif otype=="person" or otype=="mail":
			basedns=self.person_basedn.split(";")
		else:
			return

		if result[0]== 97 and result[2]==1:
		        #ldap bind worked
		        results={}
			for basedn in basedns:
				try:
					m=None
					if otype=="person":
						m=ldap_obj.search_ext_s(basedn.strip(","),ldap.SCOPE_SUBTREE,"(SamAccountName="+subject+")")[0][1]
					elif otype=="mail":
						m=ldap_obj.search_ext_s(basedn.strip(","),ldap.SCOPE_SUBTREE,"(mail="+subject+")")[0][1]
					elif otype=="computer":
						m=ldap_obj.search_ext_s(basedn.strip(","),ldap.SCOPE_SUBTREE,"(Name="+subject+")")[0][1]
					for i in m:
						try:
							parsed=self.parse(i,m[i])

							if parsed:
								results[parsed[0]]=parsed[1]
							else:
								results[i]=self.asciionly(m[i])
						except:
							continue
					break
				except Exception as e:
					#print(str(e))
					continue
					return None
			kv=[]
			for r in results:
				kv.append({"key":r,"value":results[r]})
			res={}
			if "distinguishedName" in results:
				res= {"adobject":kv,"Name":results["distinguishedName"]}
			else:
				res= {"adobject":kv,"Name":subject}
			if 'thumbnailPhoto' in results:
				res["thumbnail"]=results['thumbnailPhoto']
			return res
		return None

	def summary(self,raw):
   		return {"taxonomies": [{"predicate": "ActieDirectory Object","namespace": "ActiveDirectory","value":raw["Name"],"level": "info"}]}


	def run(self):
		data = self.get_param('data',None,"Data is missing")
		data = data.replace("[.]",".")
		if self.data_type in ['upn','mail']:
			result = self.adlookup(data.strip("<").strip(">"),'mail')
			self.report(result)
		elif self.data_type in ['computer','hostname','fqdn','domain']:
			result = self.adlookup(data,'computer')
			self.report(result)
		elif self.data_type in ['user','name','person','givenname','samid','ntid','account','samaccountname']:
			result = self.adlookup(data,'person')
			self.report(result)
		else:
			self.error('invalid data type')

if __name__ == '__main__':
	ADEnrichment().run()
