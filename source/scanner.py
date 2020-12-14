import tkinter
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import re
import os
import time
import platform
import random
import threading

#snmp
#get ip and build the chart
def getip(ipisr,iposr,array):
    # get present ip flow
    ipis = os.popen('snmpwalk -v 2c -c public 127.0.0.1 ipInReceives').read()[36:-1]
    ipos = os.popen('snmpwalk -v 2c -c public 127.0.0.1 ipOutRequests').read()[37:-1]
    ipis = int(ipis)
    ipos = int(ipos)
    tmp,tmp2 = ipis,ipos
    ipis = ipis - ipisr
    ipos = ipos - iposr
    yi = ipis/12
    yo = ipos/12
    ipis,ipos = str(ipis),str(ipos)
    ipis ='ipInReceives: '+ipis+'packages'
    ipos ='ipOutRequests: '+ipos+'packages'
    listb.delete(0,END)
    listb.insert(0,ipis,ipos)
    ipisr,iposr = tmp,tmp2

    #build the flow chart
    cv.delete(ALL)
    if yi >150:
        yi=150
    if yo >150:
        yo =150
    cv.create_text(200, 20, text='ip_input',fill = 'blue')
    cv.create_text(195, 170, text='ip_output',fill = 'red')
    cv.create_line(0,150,300,150,width = 2)
    cv.create_line(0,(300-yi),30,array[0][0],60,array[0][1],90,array[0][2],120,array[0][3],150,array[0][4],180,array[0][5],210,array[0][6],240,array[0][7],width = 3,fill = 'red')
    cv.create_line(0,(150-yo),30,array[1][0],60,array[1][1],90,array[1][2],120,array[1][3],150,array[1][4],180,array[1][5],210,array[1][6],240,array[1][7],width = 3,fill = 'blue')
    for i in range(8):
        if i == 7:
            array[0][0] = 300-yi
            array[1][0] = 150-yo
        else:
            array[0][7-i] =array[0][6-i]
            array[1][7-i] =array[1][6-i]
    return (ipisr,iposr,array)

#get tcp and build the chart
def gettcp(tcpisr,tcposr,array):
    tcpis = os.popen('snmpwalk -v 2c -c public 127.0.0.1 tcpInSegs').read()[34:-1]
    tcpos = os.popen('snmpwalk -v 2c -c public 127.0.0.1 tcpOutSegs').read()[35:-1]
    tcpis = int(tcpis)
    tcpos = int(tcpos)
    tmp,tmp2 = tcpis,tcpos
    tcpis = tcpis - tcpisr
    tcpos = tcpos - tcposr
    yi = tcpis/12
    yo = tcpos/12
    tcpis,tcpos = str(tcpis),str(tcpos)
    tcpis ='tcpInSegs: '+tcpis+'packages'
    tcpos ='tcpOutSegs: '+tcpos+'packages'
    listb1.delete(0,END)
    listb1.insert(0,tcpis,tcpos)
    tcpisr,tcposr = tmp,tmp2

    cv1.delete(ALL)
    if yi >150:
        yi=150
    if yo >150:
        yo =150
    cv1.create_text(195, 20, text='tcp_input',fill = 'blue')
    cv1.create_text(190, 170, text='tcp_output',fill = 'red')
    cv1.create_line(0,150,300,150,width = 2)
    cv1.create_line(0,(300-yi),30,array[0][0],60,array[0][1],90,array[0][2],120,array[0][3],150,array[0][4],180,array[0][5],210,array[0][6],240,array[0][7],width = 3,fill = 'red')
    cv1.create_line(0,(150-yo),30,array[1][0],60,array[1][1],90,array[1][2],120,array[1][3],150,array[1][4],180,array[1][5],210,array[1][6],240,array[1][7],width = 3,fill = 'blue')
    for i in range(8):
        if i == 7:
            array[0][0] = 300-yi
            array[1][0] = 150-yo
        else:
            array[0][7-i] =array[0][6-i]
            array[1][7-i] =array[1][6-i]
    return (tcpisr,tcposr,array)
    
#get udp and build the chart
def getudp(udpisr,udposr,array):
    udpis = os.popen('snmpwalk -v 2c -c public 127.0.0.1 udpInDatagrams').read()[39:-1]
    udpos = os.popen('snmpwalk -v 2c -c public 127.0.0.1 udpOutDatagrams').read()[40:-1]
    udpis = int(udpis)
    udpos = int(udpos)
    tmp,tmp2 = udpis,udpos
    udpis = udpis - udpisr
    udpos = udpos - udposr
    yi = udpis/12
    yo = udpos/12
    udpis,udpos = str(udpis),str(udpos)
    udpis ='udpInDatagrams: '+udpis+'packages'
    udpos ='udpOutDatagrams: '+udpos+'packages'
    listb2.delete(0,END)
    listb2.insert(0,udpis,udpos)
    udpisr,udposr = tmp,tmp2

    cv2.delete(ALL)
    if yi >150:
        yi=150
    if yo >150:
        yo =150
    cv2.create_text(195, 20, text='udp_input',fill = 'blue')
    cv2.create_text(190, 170, text='udp_output',fill = 'red')
    cv2.create_line(0,150,300,150,width = 2)
    cv2.create_line(0,(300-yi),30,array[0][0],60,array[0][1],90,array[0][2],120,array[0][3],150,array[0][4],180,array[0][5],210,array[0][6],240,array[0][7],width = 3,fill = 'red')
    cv2.create_line(0,(150-yo),30,array[1][0],60,array[1][1],90,array[1][2],120,array[1][3],150,array[1][4],180,array[1][5],210,array[1][6],240,array[1][7],width = 3,fill = 'blue')
    for i in range(8):
        if i == 7:
            array[0][0] = 300-yi
            array[1][0] = 150-yo
        else:
            array[0][7-i] =array[0][6-i]
            array[1][7-i] =array[1][6-i]
    return (udpisr,udposr,array)

def si():
    #get system information
    s = os.popen('snmpwalk -v 2c -c public 127.0.0.1 .1.3.6.1.2.1.1.1.0').read()[32:]
    tkinter.messagebox.showinfo( "system information", s)


def getv():
    #get nic information
    flag0 = 0
    out =''
    tmp = os.popen('snmpwalk -v 2c -c public 127.0.0.1 ifDescr').read()[:-1]
    while(len(tmp) != 0):
        if tmp[0:6] == 'STRING':
            flag0 = 1
            tmp = tmp[8:]
        if tmp[0:6] == 'IF-MIB':
            flag0 = 0
        if flag0 == 1:
            out = out + tmp[0:1]
        tmp = tmp[1:]
    out = 'NIC information:\n'+out
    #get memorysize
    tmp = os.popen('snmpwalk -v 2c -c public 127.0.0.1 .1.3.6.1.2.1.25.2.2').read()[45:-1]
    out = out + '\n Memory Size:\n' +tmp
    #get ipaddress
    flag0 = 0
    out1 =''
    tmp = os.popen('snmpwalk -v 2c -c public 127.0.0.1 ipAdEntAddr').read()[:-1]
    while(len(tmp) != 0):
        if tmp[0:9] == 'IpAddress':
            flag0 = 1
            tmp = tmp[10:]
        if tmp[0:6] == 'IP-MIB':
            flag0 = 0
        if flag0 == 1:
            out1 = out1 + tmp[0:1]
        tmp = tmp[1:]
    out = out + '\n IPAddress:\n' +out1
    return out


#load mib
#ls  = os.popen('snmpwalk -v 2c -c public 127.0.0.1 ').read()

#gui
#initialize values
root = Tk()
root.title("scanner")
flag = 0
listb  = Listbox(root,width =30,height =3)
cv = Canvas(root,bg = 'white',width =240,height = 300)
listb1 = Listbox(root,width =30,height =3)
cv1 = Canvas(root,bg = 'white',width =240,height = 300)
listb2 = Listbox(root,width =30,height =3)
cv2 = Canvas(root,bg = 'white',width =240,height = 300)
v = getv()
v2 = "HELP:\n1.the three part are showing you\n the network data flow at present.\n2.the table refresh every 5 seconds.\nscanner V 1.0.2\ncopyright 2020 jdxccz"

ipisr = int(os.popen('snmpwalk -v 2c -c public 127.0.0.1 ipInReceives').read()[36:-1])
iposr = int(os.popen('snmpwalk -v 2c -c public 127.0.0.1 ipOutRequests').read()[37:-1])
tcpisr = int(os.popen('snmpwalk -v 2c -c public 127.0.0.1 tcpInSegs').read()[34:-1])
tcposr = int(os.popen('snmpwalk -v 2c -c public 127.0.0.1 tcpOutSegs').read()[35:-1])
udpisr = int(os.popen('snmpwalk -v 2c -c public 127.0.0.1 udpInDatagrams').read()[39:-1])
udposr = int(os.popen('snmpwalk -v 2c -c public 127.0.0.1 udpOutDatagrams').read()[40:-1])
array1 = [[300,300,300,300,300,300,300,300],[150,150,150,150,150,150,150,150]]
array2 = [[300,300,300,300,300,300,300,300],[150,150,150,150,150,150,150,150]]
array3 = [[300,300,300,300,300,300,300,300],[150,150,150,150,150,150,150,150]]

#build loop and user interface
while True:
    time.sleep(0.5)
    bt1 = tkinter.Button(root, text ="system information", command = si)
    bt1.grid(row=2,column=1)
    
    w = tkinter.Label(root, text=v)
    w2 = tkinter.Label(root, text=v2)

    flag =flag+1

    if flag == 10:
        (ipisr,iposr,array1) = getip(ipisr,iposr,array1)
        (tcpisr,tcposr,array2)=gettcp(tcpisr,tcposr,array2)
        (udpisr,udposr,array3)=getudp(udpisr,udposr,array3)

        listb.grid(row=0,column=0)
        cv.grid(row=1,column=0)
        listb1.grid(row=0,column=1)
        cv1.grid(row=1,column=1)
        listb2.grid(row=2,column=0)
        cv2.grid(row=3,column=0)
        w.grid(row=3,column=1,sticky = N)
        w2.grid(row=3,column=1,sticky = S)
        
        flag = 0
    
    root.update()
