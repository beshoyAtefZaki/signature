import json 
import hashlib
from asn1crypto import cms, util, algos, x509, core, pem
import pkcs11
from pkcs11 import Attribute, ObjectClass, KeyType





def concenate_dict(dic) :
	concate_v = ''
	if type(dic) != dict :

		try :
			dic = json.loads(dic)
		except :
			return "Error Accourd"

	for key , value in dic.items() :
		if key == 'documents' : 
			dictt = dic.get('documents')[0]
			concenate_dict(dictt)
		else :
			concate_v = concate_v + '"' + key.upper() +'"' + check_value_type(value)
	return concate_v



def check_value_type (value) :
	value_str = ''
	if type(value) == str :
		value_str = '"' + value +'"'
	if type(value) == dict  :
		for key , val in value.items() :
			value_str = value_str +'"' + key.upper() +'"' + check_value_type(val)
	if type(value) == list :
		for item in value :
			for key , val in item.items():
				value_str = value_str +'"' + key.upper() +'"' + check_value_type(val)


	return value_str

form = """{'issuer': {'name': 'اﻻبيض اوتوموتيف لتجارة السيارات', 'id': '432950923', 'type': 'B', 'address': {'branchID': '0', 'country': 'EG', 'governate': 'Giza', 'regionCity': 'Giza', 'street': 'Fessal', 'buildingNumber': '1000'}}, 'receiver': {'name': 'نيو شيرين كار', 'id': '726547662', 'type': 'B', 'address': {'branchID': '0', 'country': 'EG', 'governate': 'Giza', 'regionCity': 'Giza', 'street': 'haran', 'buildingNumber': '12323'}}, 'documentType': 'I', 'documentTypeVersion': '1.0', 'dateTimeIssued': '2021-06-02T09:37:05Z', 'taxpayerActivityCode': '4510', 'internalID': 'detest_pro-A-BN-cerereffjjfddsss', 'purchaseOrderReference': '', 'purchaseOrderDescription': '', 'salesOrderReference': '', 'salesOrderDescription': '', 'proformaInvoiceNumber': '', 'invoiceLines': [{'description': 'Car Chevrolet', 'itemType': 'EGS', 'itemCode': 'EG-432950923-1107', 'unitType': 'CTL', 'quantity': 1.0, 'internalCode': 'EG-432950923-1107', 'salesTotal': 10000.15, 'total': 11628.171, 'valueDifference': 0.0, 'totalTaxableFees': 200.0, 'netTotal': 10000.15, 'itemsDiscount': 0.0, 'unitValue': {'currencySold': 'EGP', 'amountEGP': 10000.15, 'amountSold': 0.0, 'currencyExchangeRate': 0.0}, 'discount': {'rate': 0.0, 'amount': 0.0}, 'taxableItems': [{'taxType': 'T1', 'amount': 1428.021, 'subType': 'V001', 'rate': 14}, {'taxType': 'T8', 'amount': 200.0, 'subType': 'RD02', 'rate': 0}]}], 'totalDiscountAmount': 0, 'totalSalesAmount': 10000.15, 'netAmount': 10000.15, 'taxTotals': [{'taxType': 'T1', 'amount': 1428.021}, {'taxType': 'T8', 'amount': 200.0}], 'totalAmount': 11628.171, 'extraDiscountAmount': 0, 'totalItemsDiscountAmount': 0}"""

form2 = form.replace("'" , '"')
a = concenate_dict(form2)



# hsa_45 =  hashlib.sha256(bytes(a , 'utf-8'))
# print (hsa_45.hexdigest())


def create_signuture(dic, token_pass) :
	val = concenate_dict(dic)
	str_sha256 =  hashlib.sha256(bytes(val , 'utf-8'))
	lib = pkcs11.lib('libcastle.so.1.0.0')

	SignedData = cms.SignedData()
	SignedData['version']='v3'

	            
	SignedData['digest_algorithms']=[ util.OrderedDict([
	        ('algorithm', 'sha256'),
	        ('parameters', None) ])]



	SignedData['encap_content_info']= util.OrderedDict([
	        ('content_type', 'data'),
        ('content', None)
         ])

	signer_info = cms.SignerInfo()

	signer_info['version']='v1'
	signer_info['digest_algorithm']=util.OrderedDict([
	                ('algorithm', 'sha256'),
	                ('parameters', None) ])
	signer_info['signature_algorithm']=util.OrderedDict([
	                ('algorithm', 'sha256_rsa'),
	                ('parameters', None) ])

	token = lib.get_token(token_label='Egypt Trust')
	session = token.open(user_pin=token_pass)

	privateKey = next(session.get_objects({
        Attribute.CLASS: ObjectClass.PRIVATE_KEY,
        })


	certObj = next(session.get_objects({
        Attribute.CLASS: ObjectClass.CERTIFICATE,
        Attribute.LABEL: 'Certificate for Digital Signature' })

	cert = x509.Certificate.load(certObj[Attribute.VALUE])
	SignedData['certificates'] = [cert]
	signer_info['signature'] = privateKey.sign(
        str_sha256, 
        mechanism=pkcs11.mechanisms.Mechanism.SHA256_RSA_PKCS )

	







