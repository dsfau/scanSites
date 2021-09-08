import requests
import ssl
from Certificate import Certificate
import urllib
import time
from datetime import datetime
import re
class Site():
    def __init__(self, url, proto="https://", port=443):
        self.url = url
        self.proto = proto
        self.port = port
        try:
            user_agent = {'User-agent': 'Mozilla/5.0'}
            self.__requests = requests.get(self.proto+self.url+":"+str(self.port),headers = user_agent, allow_redirects=False)
        except:
            pass
        self.__getCodStatus()
        self.__getServerHeader()
        self.__getContentSecurityPolicy()
        self.__getHSTS()
        self.__getCookieFlags()
        self.__getHttpMethods()
        self.__etractHtmlTitle()
#        self.timestampscan = datetime.strptime(str(time.time()), '%Y%m%d%H%M%SZ')
        if self.proto == "https://":
            try:
                self.__certificate = ssl.get_server_certificate((self.url, self.port))
            except:
                self.__certificate = None
            self.__getCertificateInfo()
            self.__checkValidProtocolsTLS()

    def __getCodStatus(self):
        try:
            self.statusCode = self.__requests.status_code
        except:
            self.statusCode = '-1'

    def __getServerHeader(self):
        try:
            if len(self.__requests.headers['Server']) < 2 :
                self.serverHeader = 'Desconocido'
            else:
                self.serverHeader = self.__requests.headers['Server']
        except:
            self.serverHeader = 'Desconocido'

    def __getContentSecurityPolicy(self):
        try:
            self.contentSecurityPolicyHeader = self.__requests.headers['Content-Security-Policy']
        except:
            self.contentSecurityPolicyHeader = 'Desconocido'

    def __getHSTS(self):
        try:
            self.hstsHeader = self.__requests.headers['Strict-Transport-Security']
        except:
            self.hstsHeader = 'Desconocido'

    def __getCookieFlags(self):
        try:
            cookie=self.__requests.headers['Set-Cookie'].split(';')
            if 'Secure' in cookie:
                self.secureFlag = True
            else:
                self.secureFlag = False
            if 'HttpOnly' in cookie:
                self.HttpOnlyFlag = True
            else:
                self.HttpOnlyFlag = False
        except:
            self.HttpOnlyFlag = False
            self.secureFlag = False

    def __getCertificateInfo(self):
        certificateI = Certificate(self.__certificate)
        self.certificateNotAfter = certificateI.notAfterDate
        self.certificateNotBefore = certificateI.notBeforeDate
        self.certificateSubjectNameFull = certificateI.subjectNameFull
        self.certificateIssuerFull = certificateI.issuerFull
        self.certificateIssuerCommonName = certificateI.issuerCommonName
        self.certificateSubjectNameCommonName = certificateI.subjectNameCommonName
        self.certificateSignatureHash = certificateI.signatureHash
        self.certificateSerialNumber = certificateI.serialNumber

    def __checkValidProtocolsTLS(self):
        protocolsSSL={'SSLv2': 'no_tested', 'SSLv3': 'no_tested', 'TLSv1': 'no_tested', 'TLSv11': 'no_tested', 'TLSv12': 'no_tested', 'TLSv13': 'no_tested'}
        for i in protocolsSSL.keys():
            try:
                if i == 'SSLv2':
                    ssl.get_server_certificate((self.url, self.port), ssl.PROTOCOL_SSLv2)
                    protocolsSSL[i] = 'Active'
            except Exception as e:
                if str(e).find('error') > 0:
                    protocolsSSL[i] = 'Inactive'
                pass
            try:
                if i == 'SSLv3':
                    ssl.get_server_certificate((self.url, self.port), ssl.PROTOCOL_SSLv3)
                    protocolsSSL[i] = 'Active'
            except Exception as e:
                if str(e).find('error') > 0:
                    protocolsSSL[i] = 'Inactive'
                pass
            try:
                if i == 'TLSv1':
                    ssl.get_server_certificate((self.url, self.port), ssl.PROTOCOL_TLSv1)
                    protocolsSSL[i] = 'Active'
            except Exception as e:
                if str(e).find('error') > 0:
                    protocolsSSL[i] = 'Inactive'
                pass
            try:
                if i == 'TLSv11':
                    ssl.get_server_certificate((self.url, self.port), ssl.PROTOCOL_TLSv1_1)
                    protocolsSSL[i] = 'Active'
            except Exception as e:
                if str(e).find('error') > 0:
                    protocolsSSL[i] = 'Inactive'
                pass
            try:
                if i == 'TLSv12':
                    ssl.get_server_certificate((self.url, self.port), ssl.PROTOCOL_TLSv1_2)
                    protocolsSSL[i] = 'Active'
            except Exception as e:
                if str(e).find('error') > 0:
                    protocolsSSL[i] = 'Inactive'
                pass
            try:
                if i == 'TLSv13':
                    ssl.get_server_certificate((self.url, self.port), ssl.PROTOCOL_TLSv1_3)
                    protocolsSSL[i] = 'Active'
            except Exception as e:
                if str(e).find('error') > 0:
                    protocolsSSL[i] = 'Inactive'
                pass
            self.protocolsSSL = protocolsSSL
    def __getHttpMethods(self):
        listverbs = {'PUT', 'OPTIONS', 'GET','HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'TRACE', 'PATCH'}
        dic = {}
        for i in listverbs:
            try:
                urllib.request.urlopen(urllib.request.Request(url=self.proto + self.url + ":" + str(self.port), method=i))
                dic[i] = 'Active'
            except:
                dic[i] = 'Inactive'
        self.httpMethods = dic

    def __etractHtmlTitle(self):
        title_re = re.compile(r'<title>(.*?)</title>', re.UNICODE)
        try:
            match = title_re.search(self.__requests.text)
            if match:
                self.HtmlTitlePage = match.group(1)
            else:
                self.HtmlTitlePage = 'N/A'
        except:
            self.HtmlTitlePage = 'N/A'

    def generateJson(self):
        out={}
        out['site'] = self.url
        out['proto'] = self.proto
        out['port'] = self.port
        out['StatusCode'] = self.statusCode
        out['ServerHeader'] = self.serverHeader
        out['HstsHeader'] = self.hstsHeader
        out['SecureFlag'] = self.secureFlag
        out['HttpOnlyFlag'] = self.HttpOnlyFlag
        out['Certificate'] = {}
        try:
            out['Certificate']['NotAfter'] = self.certificateNotAfter
            out['Certificate']['NotBefore'] = self.certificateNotBefore
            out['Certificate']['SubjectNameFull'] = self.certificateSubjectNameFull
            out['Certificate']['IssuerFull'] = self.certificateIssuerFull
            out['Certificate']['IssuerCN'] = self.certificateIssuerCommonName
            out['Certificate']['SubjectNameCN'] = self.certificateSubjectNameCommonName
            out['Certificate']['SignatureHash'] = self.certificateSignatureHash
            out['Certificate']['SerialNumber'] = self.certificateSerialNumber
            out['ProtocolsSSL'] = self.protocolsSSL
        except:
            pass
        out['HttpMethods'] = self.httpMethods
        out['HTMLTitle'] = self.HtmlTitlePage
        return out
