#Author: Subhash
#Linkedin: https://www.linkedin.com/in/subhash-thapa-8670b1115/
#Github: https://github.com/erSubhashThapa

import time
import tkinter as tk
from tkinter import ttk #Optional new theamed widget
from tkinter import filedialog as fd
from threading import * #threading
import tkinter.messagebox
import webbrowser,time
import subprocess

root = tk.Tk()
root.title("Allin1Tab-(By Subhash)")

ipVar= tk.StringVar()         #Fill if Applicable
urlVar= tk.StringVar()            #Fill if Applicable
filehashVar= tk.StringVar()         #Fill if Applicable
filenameVar= tk.StringVar()           #Fill if Applicable

#Main frame
window_width = 500
window_height = 220
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()

center_x = int(screen_width/2 - window_width/2)
center_y = int(screen_height/2 - window_height/2)

root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
root.resizable(False, False)

ttk.Label(root, text="Enter the IP Address: (Optional)").pack()
ttk.Entry(root, textvariable=ipVar).pack(ipadx=3,ipady=3,fill=tk.X)

ttk.Label(root, text="Enter the URL/Domain: (Optional)").pack()
ttk.Entry(root, textvariable=urlVar).pack(ipadx=3,ipady=3,fill=tk.X)

ttk.Label(root, text="Enter the File Hash Value: (Optional)").pack()
ttk.Entry(root, textvariable=filehashVar).pack(ipadx=3,ipady=3,fill=tk.X)

ttk.Label(root, text="Enter the Suspicious File Name: (Optional)").pack()
ttk.Entry(root, textvariable=filenameVar).pack(ipadx=3,ipady=3,fill=tk.X)

chrome = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
#chrome = "C:\Program Files (x86)\Google\Chrome\Application/chrome.exe %s"
#dge_path = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
#webbrowser.register('chrome', None, webbrowser.BackgroundBrowser(chrome_path))
#webbrowser.register('edge', None, webbrowser.BackgroundBrowser(edge_path))
#Just simple threading

def threading():
    # Call work function
    t1=Thread(target=startProcess)
    t1.start()
    
#We can skip this if it's multiple time use
#def show_finish_message():
#    tkinter.messagebox.showinfo("Success","Output will be displayed in Browser")
#    root.after(1000,lambda:root.destroy())
    
def show_finish_message():
    tkinter.messagebox.showinfo("Success","Result will be displayed in Browser")

def startProcess():
    ip= ipVar.get()         #Fill if Applicable
    url= urlVar.get()            #Fill if Applicable
    filehash= filehashVar.get()         #Fill if Applicable
    filename= filenameVar.get()           #Fill if Applicable

    #AbuseP
    AbuseIP = f"https://www.abuseipdb.com/check/{ip}"
    AbusePURL = f"https://www.abuseipdb.com/check/{url}"
    
    #ShodanIP
    ShodanIp = f"https://www.shodan.io/host/{ip}"
    ShoURL = f"https://www.shodan.io/search?query={url}"
    
    #VirusTotal
    VTIp = f"https://www.virustotal.com/gui/ip-address/{ip}"
    VTurl = f"https://www.virustotal.com/gui/domain/{url}"
    VTHash = f"https://www.virustotal.com/gui/file/{filehash}"
    
    #AlienVault
    AlienIP = f"https://otx.alienvault.com/indicator/ip/{ip}"
    AlienHash = f"https://otx.alienvault.com/indicator/file/{filehash}"
    
    #ArinIntel
    ArinIp = f"https://search.arin.net/rdap/?query={ip}"
    
    #CensysIP
    CensysIP = f"https://search.censys.io/hosts/{ip}"
    CensysURL = f"https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=INCLUDE&q={url}"
    
    #GreyNoise
    GreyNoise = f"https://viz.greynoise.io/ip/{ip}"
    GreyURL = f"https://viz.greynoise.io/query?gnql={url}"
      
    #Fortinet
    FortinetIp = f"https://www.fortiguard.com/search?q={ip}&engine=8"
    FortinetURL = f"https://www.fortiguard.com/search?q={url}&engine=1"
    
    #IpInfo
    IpInfor = f"https://ipinfo.io/{ip}"
    
    #IPQualityScore
    IpQSip = f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}"
    
    #HackerTarget
    HackTarIP = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
    
    #IPVoid
    ipvoid= "https://www.ipvoid.com/ip-blacklist-check"
    
    #MXToolBoxARN
    MXArnIP = f"https://mxtoolbox.com/SuperTool.aspx?action=arin%3a{ip}"
    MXUrl = f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{url}&run=toolpage"
    
    #PulseDriveIP 
    PulseIP = f"https://pulsedive.com/indicator/{ip}"
    PulseUrl = f"https://pulsedive.com/indicator/{url}"
    
    #TaloscISCO
    Talso = f"https://talosintelligence.com/reputation_center/lookup?search={ip}"
    TalosURL = f"https://talosintelligence.com/reputation_center/lookup?search={url}"
    
    #TorRelaySearch
    TorIp = f"https://metrics.torproject.org/rs.html#search/{ip}"
    Torurl = f"https://metrics.torproject.org/rs.html#search/{url}"
    
    #UrlHashAbuse
    AbuseCh = f"https://urlhaus.abuse.ch/browse.php?search={ip}"
    AbuseURL = f"https://urlhaus.abuse.ch/browse.php?search={url}"
    
    #IBM Cloud
    IbmIp = f"https://exchange.xforce.ibmcloud.com/ip/{ip}"
    IbmUrl = f"https://exchange.xforce.ibmcloud.com/url/{url}"
    IbmURL = f"https://exchange.xforce.ibmcloud.com/malware/{filehash}"
    
    #Browsling URl
    broIP = f"https://www.browserling.com/browse/win/7/chrome/92/http%3A%2F%2F{ip}"
    broURL = "https://www.browserling.com/browse/win/7/chrome/92/http%3A%2F%2F{url}"

    #Symantec
    SyURL = f"https://sitereview.bluecoat.com/#/lookup-result/{url}"
    
    #Host Io
    HostURL = f"https://host.io/{url}"
    
    #SecurityTrail
    SecURL = f"https://securitytrails.com/domain/{url}/dns"
    
    #ThreatMiner
    ThreatURL = f"https://www.threatminer.org/domain.php?q={url}#gsc.tab=0&gsc.q={url}&gsc.page=1"
    ThreatHash = f"https://www.threatminer.org/sample.php?q={filehash}#gsc.tab=0&gsc.q={filehash}&gsc.page=1"
    
    #Googe Search
    gsquery= f"https://www.google.com/search?q=what+is+{filename}"
    
    #Echotrail
    echosearch = f"https://www.echotrail.io/insights/search/?q={filename}"
    
    #Strontic
    indexall = "https://strontic.github.io/xcyclopedia/index"
    
    #URLVoid
    URLVoid = f"https://www.urlvoid.com/scan/{url}"
    
    #HybridAnalysys
    HybridHash = f"https://www.hybrid-analysis.com/search?query={filehash}"
    
    child  = subprocess.Popen(chrome, shell=True)
    #webbrowser.get('chrome').open('google.com')
    time.sleep(2)

    if ip:
        webbrowser.open_new(AbuseIP)
        webbrowser.open(ShodanIp)
        webbrowser.open(VTIp)
        webbrowser.open(AlienIP)
        webbrowser.open_new(ArinIp)
        webbrowser.open_new(CensysIP)
        webbrowser.open_new(GreyNoise)
        webbrowser.open_new(FortinetIp)
        webbrowser.open(IpInfor)
        webbrowser.open(IpQSip)
        webbrowser.open_new(HackTarIP)
        webbrowser.open_new(ipvoid)
        webbrowser.open_new(MXArnIP)
        webbrowser.open_new(PulseIP)
        webbrowser.open_new(Talso)
        webbrowser.open(TorIp)
        webbrowser.open(AbuseCh)
        webbrowser.open_new(IbmIp)
        webbrowser.open_new(broIP)

    if url:
        webbrowser.open_new(CensysURL)
        webbrowser.open_new(VTurl)
        webbrowser.open_new(ShoURL)
        webbrowser.open(SyURL)
        webbrowser.open(FortinetURL)
        webbrowser.open(HostURL)
        webbrowser.open_new(PulseUrl)
        webbrowser.open_new(MXUrl)
        webbrowser.open_new(SecURL)
        webbrowser.open_new(TalosURL)
        webbrowser.open_new(Torurl)
        webbrowser.open_new(ThreatURL)
        webbrowser.open_new(AbusePURL)
        webbrowser.open_new(IbmUrl)
        webbrowser.open_new(URLVoid)
        webbrowser.open_new(AbuseURL)
        webbrowser.open_new(GreyURL)
        webbrowser.open_new(broURL)
        
    if filehash:
        webbrowser.open_new(VTHash)
        webbrowser.open_new(AlienHash)
        webbrowser.open_new(HybridHash)
        webbrowser.open_new(ThreatHash)
        webbrowser.open_new(IbmURL)

    if filename:
        webbrowser.open_new(gsquery)  
        webbrowser.open_new(echosearch)  
        webbrowser.open_new(indexall)  

    print("Executed")

    show_finish_message()
    
btn_start_process = ttk.Button(root,text="Start",command=threading).pack(ipadx=10,ipady=20,fill=tk.X)
root.mainloop()