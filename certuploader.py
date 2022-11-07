#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from urllib.parse import unquote
from pathlib import Path
from os import path, makedirs, rename
from datetime import datetime
from dns import resolver, rdatatype
import getpass
import ldap3
import json
import sys
import os

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.backends import default_backend

# gtk2 theme is more convenient when it comes to
# selecting files from network shares using QFileDialog (on linux)
if os.environ.get('QT_QPA_PLATFORMTHEME') == 'qt5ct':
	os.environ['QT_QPA_PLATFORMTHEME'] = 'gtk2'
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from locale import getdefaultlocale


class CertUploaderAboutWindow(QDialog):
	def __init__(self, *args, **kwargs):
		super(CertUploaderAboutWindow, self).__init__(*args, **kwargs)
		self.InitUI()

	def InitUI(self):
		self.buttonBox = QDialogButtonBox(QDialogButtonBox.Ok)
		self.buttonBox.accepted.connect(self.accept)

		self.layout = QVBoxLayout(self)

		labelAppName = QLabel(self)
		labelAppName.setText(self.parentWidget().PRODUCT_NAME + ' v' + self.parentWidget().PRODUCT_VERSION)
		labelAppName.setStyleSheet('font-weight:bold')
		labelAppName.setAlignment(Qt.AlignCenter)
		self.layout.addWidget(labelAppName)

		labelCopyright = QLabel(self)
		labelCopyright.setText(
			'<br>'
			'© 2021-2022 <a href=\'https://georg-sieber.de\'>Georg Sieber</a>'
			'<br>'
			'<br>'
			'GNU General Public License v3.0'
			'<br>'
			'<a href=\''+self.parentWidget().PRODUCT_WEBSITE+'\'>'+self.parentWidget().PRODUCT_WEBSITE+'</a>'
			'<br>'
			'<br>'
			+ QApplication.translate('CertUploader', 'If you like CertUploader please consider<br>making a donation to support further development.') +
			'<br>'
		)
		labelCopyright.setOpenExternalLinks(True)
		labelCopyright.setAlignment(Qt.AlignCenter)
		self.layout.addWidget(labelCopyright)

		labelDescription = QLabel(self)
		labelDescription.setText(
			QApplication.translate('CertUploader', 'The CertUploader enables you to upload/publish your personal (email) certificate into your companies LDAP directory (e.g. Active Directory). Other employees need the public key from your certificate in order to send encrypted emails to you (using Outlook, Evolution or other SMIME compatible mail clients).')
		)
		labelDescription.setStyleSheet("opacity:0.8")
		labelDescription.setFixedWidth(450)
		labelDescription.setWordWrap(True)
		self.layout.addWidget(labelDescription)

		self.layout.addWidget(self.buttonBox)

		self.setLayout(self.layout)
		self.setWindowTitle('About')

class CertTableView(QTableWidget):
	def __init__(self, *args):
		QTableWidget.__init__(self, *args)
		self.setSelectionBehavior(QAbstractItemView.SelectRows)
		self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
 
	def setData(self, certs):
		self.tmpCerts = certs

		self.setRowCount(len(self.tmpCerts))
		self.setColumnCount(4)

		counter = 0
		for binaryCert in self.tmpCerts:
			try:
				cert = x509.load_der_x509_certificate(binaryCert, default_backend())
				certIssuedFor = str(cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
				certIssuer = str(cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value)
				certUsage = str(self.GetExtendedKeyUsages(cert))
				certExpiry = str(cert.not_valid_after)
			except Exception as e:
				certIssuedFor = QApplication.translate('CertUploader', 'INVALID CERTIFICATE')
				certIssuer = str(e)
				certUsage = ''
				certExpiry = ''

			newItem = QTableWidgetItem(certIssuedFor)
			self.setItem(counter, 0, newItem)
			newItem = QTableWidgetItem(certIssuer)
			self.setItem(counter, 1, newItem)
			newItem = QTableWidgetItem(certUsage)
			self.setItem(counter, 2, newItem)
			newItem = QTableWidgetItem(certExpiry)
			self.setItem(counter, 3, newItem)
			counter += 1

		self.setHorizontalHeaderLabels([
			QApplication.translate('CertUploader', 'Issued for'),
			QApplication.translate('CertUploader', 'Issuer'),
			QApplication.translate('CertUploader', 'Usage'),
			QApplication.translate('CertUploader', 'Expiry')
		])
		self.resizeColumnsToContents()
		self.resizeRowsToContents()

	def GetExtendedKeyUsages(self, cert):
		try:
			ext = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
			for usage in ext.value:
				return str(usage.dotted_string if usage._name == 'Unknown OID' else usage._name)
		except x509.ExtensionNotFound:
			return ''

class CertUploaderMainWindow(QMainWindow):
	PLATFORM          = sys.platform.lower()

	PRODUCT_NAME      = 'CertUploader'
	PRODUCT_VERSION   = '1.0.0'
	PRODUCT_WEBSITE   = 'https://github.com/schorschii/certuploader'

	useKerberos = True
	server      = None
	connection  = None
	tmpDn       = ''
	tmpCerts    = []

	cfgPresetDirWindows = path.dirname(sys.executable) if getattr(sys, 'frozen', False) else sys.path[0]
	cfgPresetDirUnix    = '/etc'
	cfgPresetFile       = 'certuploader.json'
	cfgPresetPath       = (cfgPresetDirWindows if PLATFORM=='win32' else cfgPresetDirUnix)+'/'+cfgPresetFile

	cfgDir           = str(Path.home())+'/.config/certuploader'
	cfgPath          = cfgDir+'/settings.json'
	cfgServer        = []
	cfgDomain        = ''
	cfgUsername      = ''
	cfgPassword      = ''
	cfgQueryUsername = ''
	cfgLdapAttributeCertificates = 'userCertificate'


	def __init__(self):
		super(CertUploaderMainWindow, self).__init__()
		self.LoadSettings()
		self.InitUI()

	def InitUI(self):
		# Menubar
		mainMenu = self.menuBar()

		# File Menu
		fileMenu = mainMenu.addMenu(QApplication.translate('CertUploader', '&File'))

		queryAction = QAction(QApplication.translate('CertUploader', '&Query Certificates'), self)
		queryAction.setShortcut('F2')
		queryAction.triggered.connect(self.OnClickQuery)
		fileMenu.addAction(queryAction)
		queryAction2 = QAction(QApplication.translate('CertUploader', 'Query &Other User Certificates'), self)
		queryAction2.setShortcut('F3')
		queryAction2.triggered.connect(self.OnClickQueryOtherUser)
		fileMenu.addAction(queryAction2)
		fileMenu.addSeparator()
		uploadAction = QAction(QApplication.translate('CertUploader', '&Upload'), self)
		uploadAction.setShortcut('F5')
		uploadAction.triggered.connect(self.OnClickUpload)
		fileMenu.addAction(uploadAction)
		saveAction = QAction(QApplication.translate('CertUploader', '&Save'), self)
		saveAction.setShortcut('F6')
		saveAction.triggered.connect(self.OnClickSave)
		fileMenu.addAction(saveAction)
		deleteAction = QAction(QApplication.translate('CertUploader', '&Delete'), self)
		deleteAction.setShortcut('F7')
		deleteAction.triggered.connect(self.OnClickDelete)
		fileMenu.addAction(deleteAction)
		fileMenu.addSeparator()
		quitAction = QAction(QApplication.translate('CertUploader', '&Quit'), self)
		quitAction.setShortcut('Ctrl+Q')
		quitAction.triggered.connect(self.OnQuit)
		fileMenu.addAction(quitAction)

		# Help Menu
		helpMenu = mainMenu.addMenu(QApplication.translate('CertUploader', '&Help'))

		aboutAction = QAction(QApplication.translate('CertUploader', '&About'), self)
		aboutAction.setShortcut('F1')
		aboutAction.triggered.connect(self.OnOpenAboutDialog)
		helpMenu.addAction(aboutAction)

		# Statusbar
		self.statusBar = self.statusBar()

		# Window Content
		grid = QGridLayout()
		gridLine = 0

		self.lblMyCertificates = QLabel(QApplication.translate('CertUploader', 'Certificates, published in global address list (GAL)'))
		grid.addWidget(self.lblMyCertificates, gridLine, 0)

		gridLine += 1
		self.lstMyCertificates = CertTableView()
		grid.addWidget(self.lstMyCertificates, gridLine, 0)

		buttonBox = QVBoxLayout()
		self.btnQuery = QPushButton(QApplication.translate('CertUploader', 'Query'))
		self.btnQuery.clicked.connect(self.OnClickQuery)
		buttonBox.addWidget(self.btnQuery)
		self.btnUpload = QPushButton(QApplication.translate('CertUploader', 'Upload'))
		self.btnUpload.setEnabled(False)
		self.btnUpload.clicked.connect(self.OnClickUpload)
		buttonBox.addWidget(self.btnUpload)
		self.btnSave = QPushButton(QApplication.translate('CertUploader', 'Save'))
		self.btnSave.setEnabled(False)
		self.btnSave.clicked.connect(self.OnClickSave)
		buttonBox.addWidget(self.btnSave)
		self.btnDelete = QPushButton(QApplication.translate('CertUploader', 'Delete'))
		self.btnDelete.setEnabled(False)
		self.btnDelete.clicked.connect(self.OnClickDelete)
		buttonBox.addWidget(self.btnDelete)
		buttonBox.addStretch(1)
		grid.addLayout(buttonBox, gridLine, 1)

		widget = QWidget(self)
		widget.setLayout(grid)
		self.setCentralWidget(widget)

		# Window Settings
		self.setMinimumSize(480, 300)
		self.setWindowTitle(self.PRODUCT_NAME+ ' v' + self.PRODUCT_VERSION)
		self.statusBar.showMessage(QApplication.translate('CertUploader', 'Settings file:')+' '+self.cfgPath)

	def OnQuit(self, e):
		sys.exit()

	def OnOpenAboutDialog(self, e):
		dlg = CertUploaderAboutWindow(self)
		dlg.exec_()

	def OnReturnSearch(self):
		self.OnClickUpload(None)

	def OpenFileDialog(self, title, filter):
		fileName, _ = QFileDialog.getOpenFileName(self, title, None, filter)
		return fileName

	def SaveFileDialog(self, title, default, filter):
		fileName, _ = QFileDialog.getSaveFileName(self, title, default, filter)
		return fileName

	def OnClickQueryOtherUser(self, e):
		# ask for credentials
		if not self.checkCredentialsAndConnect():
			return

		# set custom query username
		item, ok = QInputDialog.getText(self, QApplication.translate('CertUploader', 'Other Username'), QApplication.translate('CertUploader', 'Please enter the SAMAccountname of the user to query.'))
		if ok and item:
			self.cfgQueryUsername = item
		else: return
		self.OnClickQuery(None)

	def OnClickQuery(self, e):
		# ask for credentials
		if not self.checkCredentialsAndConnect():
			return

		try:
			# start LDAP search
			self.connection.search(
				search_base=self.createLdapBase(self.cfgDomain),
				search_filter='(&(objectCategory=user)(samaccountname='+self.cfgQueryUsername+'))',
				attributes=['SAMAccountname', 'distinguishedName', self.cfgLdapAttributeCertificates]
			)
			for entry in self.connection.entries:
				self.statusBar.showMessage(QApplication.translate('CertUploader', 'Found:')+' '+str(entry['distinguishedName'])+' ('+str(self.connection.server)+')')
				self.tmpDn = str(entry['distinguishedName'])
				self.btnUpload.setEnabled(True)
				self.btnSave.setEnabled(True)
				self.btnDelete.setEnabled(True)
				self.lstMyCertificates.setData(entry[self.cfgLdapAttributeCertificates])
				return

			# no result found
			self.btnUpload.setEnabled(False)
			self.btnSave.setEnabled(False)
			self.btnDelete.setEnabled(False)
			self.lstMyCertificates.setRowCount(0)
			self.statusBar.showMessage(QApplication.translate('CertUploader', 'No results for »%s«') % self.cfgQueryUsername + ' ('+str(self.connection.server)+')')
		except Exception as e:
			# display error
			self.statusBar.showMessage(str(e))
			self.showErrorDialog(QApplication.translate('CertUploader', 'Error'),
				str(e),
				self.tmpDn+' ('+str(self.connection.server)+')'
			)
			# reset connection
			self.server = None
			self.connection = None

		self.tmpDn = ''

	def OnClickUpload(self, e):
		if self.tmpDn == '': return

		# choose file
		fileName = self.OpenFileDialog(QApplication.translate('CertUploader', 'Certificate File'), 'Certificate Files (*.cer *.p12);;All Files (*.*)')
		if not fileName: return
		with open(fileName, 'rb') as f: certContent = f.read()

		# check certificate
		try:
			_, fileExtension = path.splitext(fileName)
			if fileExtension == '.cer':
				x509.load_der_x509_certificate(certContent, default_backend())
			elif fileExtension == '.p12':
				item, ok = QInputDialog.getText(self, QApplication.translate('CertUploader', 'Certificate Password'), QApplication.translate('CertUploader', 'Please enter the password to decrypt the .p12 certificate file (only the public key will be uploaded).'), QLineEdit.Password)
				if ok:
					p12Data = pkcs12.load_key_and_certificates(certContent, str.encode(item), default_backend())
					certContent = p12Data[1].public_bytes(Encoding.DER)
				else: return
		except Exception as e:
			self.showErrorDialog(QApplication.translate('CertUploader', 'Error'),
				str(e),
				self.tmpDn+' ('+str(self.connection.server)+')'
			)
			return

		# ask for credentials
		if not self.checkCredentialsAndConnect():
			return

		# start LDAP modify
		self.connection.modify(self.tmpDn, { self.cfgLdapAttributeCertificates: [(ldap3.MODIFY_ADD, [certContent])] })
		if self.connection.result['result'] == 0:
			self.showInfoDialog('Success',
				QApplication.translate('CertUploader', 'Certificate successfully uploaded'),
				self.tmpDn+' ('+str(self.connection.server)+')'
			)
			self.OnClickQuery(None)
		else:
			self.showErrorDialog(QApplication.translate('CertUploader', 'Error'),
				str(self.connection.result),
				self.tmpDn+' ('+str(self.connection.server)+')'
			)
		return

	def OnClickSave(self, e):
		# get selected cert binary content
		binaryCerts = []
		for row in sorted(self.lstMyCertificates.selectionModel().selectedRows()):
			binaryCerts.append(self.lstMyCertificates.tmpCerts[row.row()])
		if self.tmpDn == '' or len(binaryCerts) != 1:
			msg = QMessageBox()
			msg.setIcon(QMessageBox.Warning)
			msg.setWindowTitle(QApplication.translate('CertUploader', 'Save'))
			msg.setText(QApplication.translate('CertUploader', 'Please select exactly 1 certificate from the list.'))
			msg.setStandardButtons(QMessageBox.Ok)
			msg.exec_()
			return

		# save file
		try:
			fileName = self.SaveFileDialog(QApplication.translate('CertUploader', 'Save Certificate Into File'), None, 'Certificate Files (*.cer);;All Files (*.*)')
			if not fileName: return
			with open(fileName, 'wb') as f:
				f.write(binaryCerts[0])
				f.close()
			self.showInfoDialog('Success',
				QApplication.translate('CertUploader', 'Certificate successfully saved'),
				self.tmpDn+' ('+str(self.connection.server)+')'
			)
		except Exception as e:
			# display error
			self.showErrorDialog(QApplication.translate('CertUploader', 'Error'),
				str(e),
				self.tmpDn+' ('+str(self.connection.server)+')'
			)

	def OnClickDelete(self, e):
		# get selected cert binary content
		binaryCerts = []
		for row in sorted(self.lstMyCertificates.selectionModel().selectedRows()):
			binaryCerts.append(self.lstMyCertificates.tmpCerts[row.row()])
		if self.tmpDn == '' or len(binaryCerts) == 0: return

		# ask for credentials
		if not self.checkCredentialsAndConnect():
			return

		# confirm
		msg = QMessageBox()
		msg.setIcon(QMessageBox.Warning)
		msg.setWindowTitle(QApplication.translate('CertUploader', 'Delete'))
		msg.setText(QApplication.translate('CertUploader', 'Are you sure you want to delete %s cert(s) from the global address list?') % str(len(binaryCerts)))
		msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
		if(msg.exec_() == QMessageBox.Cancel): return

		# start LDAP modify
		self.connection.modify(self.tmpDn, { self.cfgLdapAttributeCertificates: [(ldap3.MODIFY_DELETE, binaryCerts)] })
		if self.connection.result['result'] == 0:
			self.showInfoDialog('Success',
				QApplication.translate('CertUploader', 'Certificate(s) successfully deleted'),
				self.tmpDn+' ('+str(self.connection.server)+')'
			)
			self.OnClickQuery(None)
		else:
			self.showErrorDialog(QApplication.translate('CertUploader', 'Error'),
				str(self.connection.result),
				self.tmpDn+' ('+str(self.connection.server)+')'
			)
		return

	def checkCredentialsAndConnect(self):
		# ask for server address and domain name if not already set via config file
		if self.cfgDomain == '':
			item, ok = QInputDialog.getText(self, '♕ '+QApplication.translate('CertUploader', 'Domain'), QApplication.translate('CertUploader', 'Please enter your Domain name (e.g. example.com).'))
			if ok and item:
				self.cfgDomain = item
				self.server = None
			else: return False
		if len(self.cfgServer) == 0:
			# query domain controllers by dns lookup
			try:
				res = resolver.query(qname=f"_ldap._tcp.{self.cfgDomain}", rdtype=rdatatype.SRV, lifetime=10)
				for srv in res.rrset:
					serverEntry = {
						'address': str(srv.target),
						'port': srv.port,
						'ssl': (srv.port == 636)
					}
					print('DNS auto discovery found server: '+json.dumps(serverEntry))
					self.cfgServer.append(serverEntry)
			except Exception as e: print('DNS auto discovery failed: '+str(e))
			# ask user to enter server names if auto discovery was not successful
			if len(self.cfgServer) == 0:
				item, ok = QInputDialog.getText(self, '💻'+QApplication.translate('CertUploader', 'Server Address'), QApplication.translate('CertUploader', 'Please enter your LDAP server IP address or DNS name.'))
				if ok and item:
					self.cfgServer.append({
						'address': item,
						'port': 389,
						'ssl': False
					})
					self.server = None
		self.SaveSettings()

		# establish server connection
		if self.server == None:
			try:
				serverArray = []
				for server in self.cfgServer:
					port = server['port']
					if('gc-port' in server):
						port = server['gc-port']
						self.gcModeOn = True
					serverArray.append(ldap3.Server(server['address'], port=port, use_ssl=server['ssl'], get_info=ldap3.ALL, connect_timeout=5))
				self.server = ldap3.ServerPool(serverArray, ldap3.ROUND_ROBIN, active=1, exhaust=True)
			except Exception as e:
				self.showErrorDialog(QApplication.translate('CertUploader', 'Error connecting to LDAP server'), str(e))
				return False

		# try to bind to server via Kerberos
		try:
			if(self.useKerberos):
				self.connection = ldap3.Connection(
					self.server,
					authentication=ldap3.SASL,
					sasl_mechanism=ldap3.KERBEROS,
					auto_referrals=True,
					auto_bind=True
				)
				if(self.cfgQueryUsername == ''):
					self.cfgQueryUsername = getpass.getuser()
				#self.connection.bind()
				return True # return if connection created successfully
		except Exception as e:
			print('Unable to connect via Kerberos: '+str(e))

		# ask for username and password for NTLM bind
		sslHint = ''
		if len(self.cfgServer) > 0 and self.cfgServer[0]['ssl'] == False:
			sslHint = '\n\n'+QApplication.translate('CertUploader', 'Please consider enabling SSL in the config file (~/.config/certuploader/settings.json).')
		if self.cfgUsername == '':
			item, ok = QInputDialog.getText(self, '👤 '+QApplication.translate('CertUploader', 'Username'), QApplication.translate('CertUploader', 'Please enter the username which should be used to connect to:')+'\n'+str(self.cfgServer), QLineEdit.Normal, getpass.getuser())
			if ok and item:
				self.cfgUsername = item
				if(self.cfgQueryUsername == ''):
					self.cfgQueryUsername = item
				self.connection = None
			else: return False
		if self.cfgPassword == '':
			item, ok = QInputDialog.getText(self, '🔑 '+QApplication.translate('CertUploader', 'Password for »%s«') % self.cfgUsername, QApplication.translate('CertUploader', 'Please enter the password which should be used to connect to:')+'\n'+str(self.cfgServer)+sslHint, QLineEdit.Password)
			if ok and item:
				self.cfgPassword = item
				self.connection = None
			else: return False
		self.SaveSettings()

		# try to bind to server with username and password
		try:
			self.connection = ldap3.Connection(
				self.server,
				user=self.cfgUsername+'@'+self.cfgDomain,
				password=self.cfgPassword,
				authentication=ldap3.SIMPLE,
				auto_referrals=True,
				auto_bind=True
			)
			#self.connection.bind()
		except Exception as e:
			self.cfgUsername = ''
			self.cfgPassword = ''
			self.showErrorDialog(QApplication.translate('CertUploader', 'Error binding to LDAP server'), str(e))
			return False

		return True # return if connection created successfully

	def createLdapBase(self, domain):
		# convert FQDN 'example.com' to LDAP path notation 'DC=example,DC=com'
		search_base = ''
		base = domain.split('.')
		for b in base:
			search_base += 'DC=' + b + ','
		return search_base[:-1]

	def LoadSettings(self):
		if(not path.isdir(self.cfgDir)):
			makedirs(self.cfgDir, exist_ok=True)

		if(path.isfile(self.cfgPath)): cfgPath = self.cfgPath
		elif(path.isfile(self.cfgPresetPath)): cfgPath = self.cfgPresetPath
		else: return

		try:
			with open(cfgPath) as f:
				cfgJson = json.load(f)
				self.cfgServer = cfgJson.get('server', '')
				self.cfgDomain = cfgJson.get('domain', '')
				self.cfgUsername = cfgJson.get('username', '')
				self.cfgQueryUsername = self.cfgUsername
				self.cfgLdapAttributeCertificates = str(cfgJson.get('ldap-attribute-certificates', self.cfgLdapAttributeCertificates))
		except Exception as e:
			self.showErrorDialog(QApplication.translate('CertUploader', 'Error loading settings file'), str(e))

	def SaveSettings(self):
		try:
			with open(self.cfgPath, 'w') as json_file:
				json.dump({
					'server': self.cfgServer,
					'domain': self.cfgDomain,
					'username': self.cfgUsername,
					'ldap-attribute-certificates': self.cfgLdapAttributeCertificates
				}, json_file, indent=4)
		except Exception as e:
			self.showErrorDialog(QApplication.translate('CertUploader', 'Error saving settings file'), str(e))

	def showErrorDialog(self, title, text, additionalText=''):
		print('Error: '+text)
		msg = QMessageBox()
		msg.setIcon(QMessageBox.Critical)
		msg.setWindowTitle(title)
		msg.setText(text)
		msg.setDetailedText(additionalText)
		msg.setStandardButtons(QMessageBox.Ok)
		retval = msg.exec_()
	def showInfoDialog(self, title, text, additionalText=''):
		print('Info: '+text)
		msg = QMessageBox()
		msg.setIcon(QMessageBox.Information)
		msg.setWindowTitle(title)
		msg.setText(text)
		msg.setDetailedText(additionalText)
		msg.setStandardButtons(QMessageBox.Ok)
		retval = msg.exec_()

def main():
	app = QApplication(sys.argv)
	translator = QTranslator(app)
	if getattr(sys, 'frozen', False):
		translator.load(os.path.join(sys._MEIPASS, 'lang/%s.qm' % getdefaultlocale()[0]))
	elif os.path.isdir('lang'):
		translator.load('lang/%s.qm' % getdefaultlocale()[0])
	else:
		translator.load('/usr/share/certuploader/lang/%s.qm' % getdefaultlocale()[0])
	app.installTranslator(translator)

	window = CertUploaderMainWindow()
	window.show()
	sys.exit(app.exec_())

if __name__ == '__main__':
	main()
