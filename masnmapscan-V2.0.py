#!/usr/bin/python
# coding=utf-8


import nmap
import datetime
import threading
import requests
import chardet
import re
import json
import os
requests.packages.urllib3.disable_warnings()
import Queue
import sys 
reload(sys) 
sys.setdefaultencoding('utf-8')



dstdir=os.getcwd()+os.path.sep+'dst'+os.path.sep
resultdir=os.getcwd()+os.path.sep+'result'+os.path.sep

class PortScan(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self._queue = queue

    def run(self):
        while not self._queue.empty():
            scan_ip = self._queue.get()
            try:
                portscan(scan_ip)
            except Exception as e:
                print e
                pass

#调用masscan
def portscan(scan_ip):
    ports = [] #设定一个临时端口列表
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
        Scan(scan_ip,ports) #小于50则进一步侦查

#调用nmap识别服务
def Scan(scan_ip,ports):
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

#启用多线程扫描
def main():
    queue = Queue.Queue()
    try:
        f = open(r'ip.txt', 'rb')
        for line in f.readlines():
            final_ip = line.strip()
            queue.put(final_ip)
        threads = []
        thread_count = 20
        for i in range(thread_count):
            threads.append(PortScan(queue))
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        f.close()
    except Exception as e:
        print e
        pass


if __name__ =='__main__':
    start_time = datetime.datetime.now()
    main()
    spend_time = (datetime.datetime.now() - start_time).seconds
    print u'total time： ' + str(spend_time) + u'秒'
