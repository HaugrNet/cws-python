from zeep import Client
import hashlib
import datetime
import base64
# Usage Examples

# Connect to the two main webservices, system and share

ADM_USER = "admin"
ADM_PASSWORD = "secret"


def createUser(uid, pw, creds):
    DATA = creds.copy()
    DATA.update(dict(action='CREATE', memberId='',
                     newAccountName=uid, newCredential=pw))
    result = syscli.service.processMember(DATA)
    if result.returnCode == "SUCCESS":
        return result.memberId
    elif result.returnCode == "CONSTRAINT_ERROR":
        return None
    else:
        return None  # XXX

syscli = Client('http://localhost:8080/cws/system?wsdl')
sharecli = Client('http://localhost:8080/cws/share?wsdl')

print "Set an initial password for your administrator"
# We do this by sending an arbitrary initial authenticated request which
# will set the so far unset password

# We fetch all existing circles, which should be an empty list now.
CRED = dict(accountName=ADM_USER, credential=ADM_PASSWORD,
            credentialType="PASSPHRASE")
result = syscli.service.fetchCircles(CRED)

assert result.returnCode == "SUCCESS"
print "Connection successful"
# assert result.circles == []
assert result.trustees == []

# By now the password is set, we can use it.
print "Next is creation of a normal users account"
member_id = createUser(uid='pilz', pw='secret', creds=CRED)

print "Member ID: %s" % member_id

print "Now we need to create a circle"

DATA = CRED.copy()
DATA.update(dict(action="CREATE", circleId="",
                 circleName="MyNewCircle", memberId=member_id,
                 trustLevel="ADMIN"))
# Trustlevel is irrelevant here, the first one is always admin
result = syscli.service.processCircle(DATA)
if result.returnCode == "SUCCESS":
    circle_id = result.circleId

print "Circle ID: %s" % circle_id

print "Now we need a second user and add it to the same circle"

jensen_id = createUser(uid='jensen', pw='secret', creds=CRED)

print "Jensen ID: %s" % jensen_id

print "Now we add jensen to the circle"
# This time, we do it as the circle admin user, not the sysadmin
DATA = dict(accountName="pilz", credential="secret",
            credentialType="PASSPHRASE", action="ADD", circleId=circle_id,
            circleName="", memberId=jensen_id, trustLevel="WRITE")
result = syscli.service.processCircle(DATA)
print result

print "Check the circle"

DATA = CRED.copy()
DATA.update(dict(circleId=circle_id))
result = syscli.service.fetchCircles(CRED)

print result

print "Let's put a file in / Note that we use sharecli now"

print "Upload file"
BLOB = open('test/plone.pdf', 'rb').read()  # Add a real blob here
BLOB = base64.b64encode(BLOB)
UUID = hashlib.md5(BLOB).hexdigest()

DATA = dict(accountName="pilz", credential="secret",
            credentialType="PASSPHRASE", action="ADD", circleId=circle_id,
            dataId='', typeName='data', folderId=None,
            dataName=UUID, data=BLOB
            )
result = sharecli.service.processData(DATA)
data_id = result.dataId
print result

print "Read the file again"
DATA = dict(accountName="jensen", credential="secret",
            credentialType="PASSPHRASE", circleId=circle_id,
            dataId=data_id, folderId=None, pageSize=1, pageNumber=1
            )
result = sharecli.service.fetchData(DATA)
data_out = base64.b64decode(result.data)
open('out.pdf', 'wb').write(data_out)
print result


print "Sign a document"

DATA = dict(accountName="pilz", credential="secret",
            credentialType="PASSPHRASE", data=BLOB,
            expires=datetime.date(datetime.MAXYEAR, 12, 31)
            )
result = sharecli.service.sign(DATA)
print result
signature = result.signature
# signature = 'B0AEfotILqPDLS6TTjiRvaWH68H4rqbpeajv3nPxE8exknKSQbFPsT+juqIWS29JYZb+3V/zdV5zFcr7/0FFsdsmBJkOBLGr1VN4a9xiPabL6XoVgmyQzKrFy6FMnh7U4k9Rv7UfVv4lMoNQzGy0ZfgtOvqpQ/sVoUVySQXnsxddqvgtzGjmT1wOsgYVtbUb/93BDdEBtJWSQqJlXQC20WTmd8KnzDm/0fi5xq1a51gOh6Lhb9+WiWFK4oLGUcSq3AGTnDx0R1xxxvKIw3KS07i9SbE99OF5ePSzSzdgjVC+kQ7o1Zqvo5PKmqcYtfYgFndk3bJRTyvT6q7UjTu1Mw=='

DATA = dict(accountName="jensen", credential="secret",
            credentialType="PASSPHRASE", data=BLOB, signature=signature
            )

result = sharecli.service.verify(DATA)

print result

assert result.verified == True

print "Verify the signature"
DATA = dict(accountName="jensen", credential="secret",
            credentialType="PASSPHRASE", data=BLOB+'x', signature=signature
            )

result = sharecli.service.verify(DATA)
print result
assert result.verified == False
