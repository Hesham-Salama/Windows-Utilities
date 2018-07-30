import platform
import os
import subprocess
from _winreg import *
import _winreg
import re
import io

# Downloaded Libraries
# 1- psutil , to install: CMD: C:\Python27\python.exe -m pip install psutil
import psutil
import ctypes

class disable_file_system_redirection:
    _disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
    _revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
    def __enter__(self):
        self.old_value = ctypes.c_long()
        self.success = self._disable(ctypes.byref(self.old_value))
    def __exit__(self, type, value, traceback):
        if self.success:
            self._revert(self.old_value)


class SystemInfo:
    dictOfPids = {}
    listHKLM1 = [r'Software\Microsoft\Windows\CurrentVersion\Run',
                 r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                 r'Software\Microsoft\Windows\CurrentVersion\RunOnceEx',
                 r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
                 r'Software\Microsoft\Windows\CurrentVersion\RunServices',
                 r'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
                 r'Software\CLASSES\batfile\shell\open\command',
                 r'Software\CLASSES\comfile\shell\open\command',
                 r'Software\CLASSES\exefile\shell\open\command',
                 r'Software\CLASSES\htafile\Shell\Open\Command',
                 r'Software\CLASSES\piffile\shell\open\command',
                 r'Software\Mirabilis\ICQ\Agent\Apps\test',
                 r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell']
    listHKLM2 = [ r'SOFTWARE\Microsoft\Active Setup\Installed Components',
                  r'System\CurrentControlSet\Services']
    listHKCU1 = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                 r'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce',
                 r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
                 r'Software\Microsoft\Windows NT\CurrentVersion\Windows\Run']
    listHKCU2 = [r'SOFTWARE\Microsoft\Active Setup\Installed Components']
    listHKCR = [r'exefile\shell\open\command',
                r'comfile\shell\open\command',
                r'batfile\shell\open\command',
                r'htafile\Shell\Open\Command',
                r'piffile\shell\open\command']

    def __init__(self):
        self.directory = os.path.join(os.path.expandvars("%userprofile%"), "Desktop") + "\\Statistics"
        if not os.path.exists(self.directory):
            os.makedirs(self.directory)
        self.fileAutostart = open(self.directory + "\\Autostart_Apps.txt", "w")
        self.fileSystemInfo = open(self.directory + "\\System_Information.txt", "w")
        # self.fileProcesses = open(self.directory+"\\processes.txt", "w")
        self.autostart_string = self.systemInfo_string = self.processes_string = ""

    def displayVersionOS(self):
        line = "Operating System: " + platform.platform()
        line = line.replace('-', ' ')
        #printline
        self.fileSystemInfo.write(line+"\n")
        self.systemInfo_string+=(line+"\n")

    def is_windows_64bit(self):
        if 'PROCESSOR_ARCHITEW6432' in os.environ:
            return True
        return os.environ['PROCESSOR_ARCHITECTURE'].endswith('64')

    def displaySystemType(self):
        if self.is_windows_64bit():
            string = "Architecture: "+ "64 bits."
        else:
            string = "Architecture: " + "32 bits."
        #printstring
        self.fileSystemInfo.write(string+"\n")
        self.systemInfo_string +=(string+"\n")

    def printProcessesStatisticsImproved(self):
        for pid in psutil.pids():
            try:
                p = psutil.Process(pid)
                mainString = "{ProcessName"
                arguments = p.name()
                try:
                    mainString += "||AccessPath"
                    arguments += "||" + p.exe()
                except psutil.AccessDenied:
                    arguments += "||Access Path Denied"
                try:
                    tempStr = ""
                    for commandline in p.cmdline():
                        tempStr += commandline+" "
                    if tempStr:
                        tempStr = tempStr[:-1]
                    if tempStr:
                        arguments += "||" + tempStr
                        mainString += "||Arguments"
                        #printp.memory_full_info()
                except psutil.AccessDenied:
                    pass
                try:
                    mainString += "||Username"
                    arguments += "||" + p.username()
                except psutil.AccessDenied:
                    arguments += "||SYSTEM"
                mainString += "}:"
                self.dictOfPids[pid] = arguments
                outputString = str(pid)+" "+mainString +" "+self.dictOfPids[pid]
                #printoutputString
                # self.fileProcesses.write(outputString + "\n")
                self.processes_string += (outputString + "\n")
            except psutil.NoSuchProcess:
                pass

    def traverseLevelZeroRegistry(self,hkey,regPath):
        try:
            flag = False
            key = _winreg.OpenKey(hkey, regPath,0,
                                  _winreg.KEY_READ | _winreg.KEY_WOW64_64KEY)
            for i in xrange(0, _winreg.QueryInfoKey(key)[1]):
                name,value,_ =  _winreg.EnumValue(key, i)
                value = str(value)
                if ".exe" in value or ".sys" in value:
                    if not flag:
                        if hkey==_winreg.HKEY_LOCAL_MACHINE:
                            temp = "HKLM\\"+regPath
                        elif hkey==_winreg.HKEY_CURRENT_USER:
                            temp = "HKCU\\" + regPath
                        else:
                            temp = "HKCR\\"+regPath
                        flag = True
                        #printtemp
                        # self.fileAutostart.write(temp+"\n")
                        # self.autostart_string+=(temp+"\n")
                    #print"{Name||Value}: "+name+"||"+value
                    to_be_written = name+"||"+temp+"||"+value+"\n"
                    to_be_written = to_be_written.replace("\"", "")
                    self.fileAutostart.write(to_be_written)
                    # self.autostart_string += (name+"||"+value+"\n")
        except WindowsError:
            pass

    def specialTraverseLevelZeroRegistry(self, hkey, regPath):
        try:
            key = _winreg.OpenKey(hkey, regPath, 0,
                                  _winreg.KEY_READ | _winreg.KEY_WOW64_64KEY)
            for i in xrange(0, _winreg.QueryInfoKey(key)[1]):
                name, value, _ = _winreg.EnumValue(key, i)
                value = str(value)
                if ".exe" in value or ".sys" in value:
                    return value
        except WindowsError:
            pass
        return ""

    def traverseLevelOneRegistry(self,hkey,regPath):
        list = []
        try:
            parentKey = _winreg.OpenKey(hkey, regPath)
            i = 0
            while True:
                try:
                    key = _winreg.EnumKey(parentKey, i)
                    list.append(key)
                    i += 1
                except WindowsError:
                    break
        except WindowsError:
            pass
        return list

    def killASignal(self,pid):
        try:
            p = psutil.Process(pid)
            p.kill()
            flag = False
            for process in psutil.process_iter():
                if process.pid == pid:
                    # print"Failed to kill the process"
                    # # flag = True
                    # # break
                    # return False
                    return "Unable to stop."
            if not flag:
                # print"Process id "+str(pid)+" terminated"
                # return True
                # pass
                return "OK"
        except psutil.NoSuchProcess:
            # print"No process with id "+str(pid)
            return "No such process with pid "+str(pid)
        except psutil.AccessDenied:
            return "Access Denied for pid: "+str(pid)
        except Exception,e:
            return str(e)

    def suspendASignal(self,pid):
        try:
            p = psutil.Process(pid)
            p.suspend()
            print "pid ",pid,"suspended\n"
        except psutil.NoSuchProcess:
            print"No process with id "+str(pid)
            pass

    def resumeASignal(self,pid):
        try:
            p = psutil.Process(pid)
            p.resume()
        except psutil.NoSuchProcess:
            print"No process with id "+str(pid)
            pass

    def checkStartupFiles(self):
        listLocations = ['C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp',
                         os.path.join(os.path.expandvars("%userprofile%"), "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
                         "C:\windows\start menu\programs\startup"]
        for location in listLocations:
            if os.path.isdir(location):
                #printlocation
                # self.fileAutostart.write(location+"\n")
                # self.autostart_string +=(location+"\n")
                filenames = next(os.walk(location))[2]
                for fileName in filenames:
                    #printfileName
                    to_be_written = fileName+"||"+location+"\n"
                    to_be_written = to_be_written.replace("\"", "")
                    self.fileAutostart.write(to_be_written)
                    # self.autostart_string+=(fileName+"\n")

    # name||regpath||filepath
    # name||filepath
    def traverseRegistryHelper(self,hkey,regPath):
        keys = self.traverseLevelOneRegistry(hkey, regPath)
        for key in keys:
            valueExtracted = self.specialTraverseLevelZeroRegistry(hkey, regPath+"\\"+key)
            if valueExtracted != "":
                if hkey==HKEY_CURRENT_USER:
                    tempo = "HKCU\\"
                elif hkey==HKEY_LOCAL_MACHINE:
                    tempo = "HKLM\\"
                else:
                    tempo = "HKCR\\"
                #printtempo+regPath+"\\"+key
                # self.fileAutostart.write(tempo+regPath+"\\"+key + "\n")
                # self.autostart_string+=(tempo+regPath+"\\"+key + "\n")
                tempString =   valueExtracted
                #printtempString
                # tt=tempo+regPath+"\\"+key+"||"+tempString
                to_be_written = key+"||"+tempo+regPath+"\\"+key+"||"+tempString + "\n"
                to_be_written = to_be_written.replace("\"", "")
                self.fileAutostart.write(to_be_written)
                # self.autostart_string +=(tempString + "\n")

    def traverseStartup(self):
        for regPath in self.listHKLM1:
            self.traverseLevelZeroRegistry(_winreg.HKEY_LOCAL_MACHINE,regPath)
        for regPath in self.listHKCU1:
            self.traverseLevelZeroRegistry(_winreg.HKEY_CURRENT_USER, regPath)
        for regPath in self.listHKLM2:
            self.traverseRegistryHelper(_winreg.HKEY_LOCAL_MACHINE,regPath)
        for regPath in self.listHKCU2:
            self.traverseRegistryHelper(_winreg.HKEY_CURRENT_USER, regPath)
        for regPath in self.listHKCR:
            self.traverseLevelZeroRegistry(_winreg.HKEY_CLASSES_ROOT,regPath)
        self.checkStartupFiles()

    def parse_scheduler(self):
        Alllists = set()
        tasklist = subprocess.check_output(["schtasks.exe", "/FO", "CSV"])
        for line in tasklist.splitlines()[1:]:
            if not line.startswith('"\\'):
                continue
            folder = line.rsplit("\\", 1)[0][1:]
            taskname = line.rsplit("\\", 1)[1].split('"')[0]
            nextrun = line.rsplit("\\", 1)[1].split(",")[1].replace('"', '')
            status = line.rsplit("\\", 1)[1].split(",")[2].replace('"', '')
            if folder == "":
                folder = "\\"
            Alllists.add(folder + "||" + taskname + "||" + nextrun + "||" + status)
        return Alllists

    def traverseTaskScheduler(self):
        PATH = r'C:\Windows\System32\Tasks'
        flag = False
        tasksSet = self.parse_scheduler()
        for task in tasksSet:
            parts = task.split("||")
            try:
                file = io.open(PATH+parts[0]+"\\"+parts[1], 'r', encoding='utf16')
                lines = file.readlines()
                for line in lines:
                    m = re.search('<Command>(.+?)</Command>', line)
                    if m:
                        found = m.group(1)
                        found = found.replace("\"", "")
                        if not flag:
                            #print"Task Scheduler"
                            self.fileAutostart.write("Task Scheduler\n")
                            self.autostart_string+=("Task Scheduler\n")
                            flag = True
                        temp = "{Name||Path||Status||Next run}: "+parts[1]+"||"+found+"||"+parts[3]+"||"+parts[2]
                        #printtemp
                        self.fileAutostart.write(temp+"\n")
                        self.autostart_string+=(temp+"\n")
                        break
            except IOError:
                pass

    def agentStartWork(self):
        self.displayVersionOS()
        self.displaySystemType()
        # self.printProcessesStatisticsImproved()
        self.traverseStartup()
        # self.traverseTaskScheduler()

    def closeFiles(self):
        self.fileAutostart.close()
        self.fileSystemInfo.close()
        # self.fileProcesses.close()

#
# agent = SystemInfo()
# agent.agentStartWork()
# agent.closeFiles()


# # agent.killASignal(6588)