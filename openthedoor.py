#!/usr/bin/python
# coding=utf-8


import nmap
import datetime
import requests
import json
import argparse
import socket
import os
import re
import IPy
requests.packages.urllib3.disable_warnings()
import sys 
reload(sys) 
sys.setdefaultencoding('utf-8')



dstdir=os.getcwd()+os.path.sep+'dst'+os.path.sep
resultdir=os.getcwd()+os.path.sep+'result'+os.path.sep


#调用masscan
def massscan_scan(scan_ip):
    ports = [] #设定一个临时端口列表
    #LINUX
    #cmd='masscan ' + scan_ip + ' -p 1-65535 -oJ '+dstdir+scan_ip+'.json --rate 1000'
    cmd='masscan.exe ' + scan_ip + ' -p 1-65535 -oJ '+dstdir+scan_ip+'.json --rate 1000'
    os.system(cmd)
    #提取json文件中的端口
    with open(dstdir+scan_ip+'.json', 'r') as f:
        content=f.read()
        if content:
            data=json.loads(content)
            for port in data:
                ports.append(port['ports'][0]['port'])


    if len(ports) > 50:
        pass      #如果端口数量大于50，说明可能存在防火墙，属于误报，清空列表
    else:
        nmap_scan(scan_ip,ports) 

#调用nmap识别服务
def nmap_scan(scan_ip,ports):
    nm = nmap.PortScanner()
    try:

        with open(resultdir+scan_ip+'.txt', 'wb+') as f:
            for port in ports:
                ret = nm.scan(scan_ip,str(port),arguments='-Pn,-sS')
                service_name = ret['scan'][scan_ip]['tcp'][port]['name']
                print '[+]host ' + scan_ip + ' : ' + str(port) + ' --server==' + service_name
                f.write(scan_ip+'\t\t'+str(port)+'\t\t'+service_name+'\n')
    except Exception as e:
       print e
       pass

def getIPs(target):
    iplist=[]
    try:
        if is_valid_domain(target):
            iplist.append(socket.gethostbyname(target))
        else:
            ips=IPy.IP(target)
            if ips:
                if len(ips)>1:
                    for ip in ips:
                        iplist.append(str(ip))
                else:
                    iplist.append(str(ips))
        return iplist
    except Exception, e:
        print 'IP is not legal'
        sys.exit()
        
def IPsScan(target):
    try:
        for ip in target:
            print '[+]start scan:'+ip
            massscan_scan(ip)

    except Exception as e:
        print e
        pass

def is_valid_domain(value):
    pattern = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    return True if pattern.match(value) else False

def readFile():
    try:
        with open('ip.txt', 'r') as f:
            for line in f.readlines():
                ip = line.strip()
                print '[+]start scan:'+ip
                massscan_scan(ip)

    except Exception as e:
        print e
        pass

def usage():
    usage = '''
        python openthedoor.py  -t ip
        
        exp: python openthedoor.py -t 192.168.1.1
             python openthedoor.py -t 192.168.1.1/24
             python openthedoor.py -t domain
             python openthedoor.py -f 

        '''
    print usage

if __name__ =='__main__':
        
    start_time = datetime.datetime.now()
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="IP address.")
    parser.add_argument("-f", "--file",action='store_true', default=False, help="use ip.txt.")
    args = parser.parse_args()

    if args.target != None:
        IPsScan(getIPs(args.target))
    elif args.file:
        readFile()
    else:
        usage()
        sys.exit()

    spend_time = (datetime.datetime.now() - start_time).seconds
    print u'total time： ' + str(spend_time) + u'秒'


