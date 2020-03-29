#!/usr/bin/python3 
import subprocess
from tkinter import *
from threading import Thread

ipDataSet = set()

def windowThread():
    mainWindow = Tk()
    mainWindow.mainloop()

def readFromSubProc():
    capture = subprocess.Popen(['./cap'], stdout=subprocess.PIPE)

    #Iterate over all the packet info from capture proc and show do some analysis
    while True:
        line = capture.stdout.readline()
        if not line:
            exit(0)

        ipData = line.decode('ascii')
        if ipData not in ipDataSet:
            ipDataSet.add(ipData)
            print(ipData)


Thread(target=windowThread).start()
Thread(target=readFromSubProc).start()
