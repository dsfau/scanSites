import OpenSSL
from datetime import datetime
class Certificate():
    def __init__(self, certificate):
        self.certificate = certificate
        try:
            self.x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.certificate)
        except:
            pass
        self.__getSubjectName()
        self.__getValidDate()
        self.__getIssuer()
        self.__getSignatureHash()
        self.__getSerialNumber()
    def __getSubjectName(self):
        dcomponents = {}
        try:
            components = self.x509.get_subject().get_components()
            for i in components:
                dcomponents[i[0].decode()]=i[1].decode()
            self.subjectNameFull = dcomponents
            self.subjectNameCommonName = dcomponents['CN']
        except:
            self.subjectNameFull = 'None'
            self.subjectNameCommonName = 'None'

    def __getValidDate(self):
        try:
            self.notAfterDate = str(datetime.strptime(self.x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'))
            self.notBeforeDate = str(datetime.strptime(self.x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'))
        except:
            self.notAfterDate = '0000'
            self.notBeforeDate = '0000'

    def __getIssuer(self):
        try:
            dcomponents = {}
            components = self.x509.get_issuer().get_components()
            for i in components:
                dcomponents[i[0].decode()] = i[1].decode()
            self.issuerFull = dcomponents
            self.issuerCommonName = dcomponents['CN']
        except:
            self.issuerFull = 'None'
            self.issuerCommonName = 'None'

    def __getSignatureHash(self):
        try:
            self.signatureHash = self.x509.get_signature_algorithm().decode()
        except:
            self.signatureHash = 'None'

    def __getSerialNumber(self):
        try:
            self.serialNumber = self.x509.get_serial_number()
        except:
            self.serialNumber = 'None'