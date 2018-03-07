import sys
import os
import yaml
from operator import itemgetter, attrgetter


ffd_num = ['5000','5001','5002','5003','5004','5005','5006','5007','5010','5011','5012','5013','5014','5015','5016','5017','5018','5019','5021','5022','5026','5028','5029','8102','8103']

ffd_case_num = {
'5000':{'5000':'5000xx for TR fix','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5001':{'5001':'RBS Auto-Integration','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5002':{'5002':'Single IP','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5003':{'5003':'IPSec VPN Responder','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5004':{'5004':'CM','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5005':{'5005':'FM','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5006':{'5006':'PM','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5007':{'5007':'Show Command','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5010':{'5010':'IKEv2 per RFC4306/5996/7296','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5011':{'5011':'IPSEC ACL and TS','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5012':{'5012':'Certificate Management','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5013':{'5013':'Dead Peer Detection (DPD)','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5014':{'5014':'ESP per RFC 4303','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5015':{'5015':'BGP based ICR','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5016':{'5016':'BGP based ISSU','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5017':{'5017':'Certificate Enroll','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5018':{'5018':'Multi-IPSEC interface','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5019':{'5019':'IKEv2-Frag per RFC7383','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5021':{'5021':'Scale without N+1','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5022':{'5022':'Shared IP Pool','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5026':{'5026':'Intelligent load balance','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5028':{'5028':'malicious attack','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'5029':{'5029':'flow control','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'8102':{'8102':'legacy IKE','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0},
'8103':{'8103':'legacy ESP','Total':0,'Passed':0,'Failed':0,'NotRun':0,'TotalTime':0}
}

caseyaml = {}

case0time = []
case1time = []
case2time = []
case3time = []

total_time = 0
total_case = 0
total_pass = 0
total_fail = 0
total_nrun = 0

if len(sys.argv) != 2:
    print 'useage: python checkcase.py <filename>'
    sys.exit()
if not os.path.isfile(sys.argv[1]):
    print 'file not exist!'
    sys.exit()

yamlfile = open(sys.argv[1],'r')

caseyaml = yaml.load(yamlfile)

for line,detail in caseyaml.items():
    tmp = line[0:4]
    ffd_case_num[tmp]['Total']=ffd_case_num[tmp]['Total'] + 1
    if detail['results'] == 'pass':
        ffd_case_num[tmp]['Passed'] = ffd_case_num[tmp]['Passed'] + 1
    if detail['results'] == 'empty':
        ffd_case_num[tmp]['NotRun'] = ffd_case_num[tmp]['NotRun'] + 1 
    if detail['results'] != 'pass' and detail['results'] != 'empty':
        ffd_case_num[tmp]['Failed'] = ffd_case_num[tmp]['Failed'] + 1
    
    if detail ['run_times'] == 1:
        time_str = detail['run_time_duration']
        time = float(time_str[0])
        case1time.append([line, time])
        ffd_case_num[tmp]['TotalTime'] = ffd_case_num[tmp]['TotalTime'] + time 
        
    if detail ['run_times'] == 2:
        time_str = detail['run_time_duration']
        time1 = float(time_str[0])
        time2 = float(time_str[1])
        case2time.append([line, time1, time2])
        ffd_case_num[tmp]['TotalTime'] = ffd_case_num[tmp]['TotalTime'] + time

    if detail ['run_times'] == 3:
        time_str = detail['run_time_duration']
        time1 = float(time_str[0])
        time2 = float(time_str[1])
        time3 = float(time_str[2])
        case3time.append([line, detail['results'], time1, time2, time3])
        ffd_case_num[tmp]['TotalTime'] = ffd_case_num[tmp]['TotalTime'] + time

    if detail ['run_times'] == 0:
        case0time.append([line, 0])

case0time = sorted(case0time, key=itemgetter(0))
case1time = sorted(case1time, key=itemgetter(1))
case2time = sorted(case2time, key=itemgetter(1))
case3time = sorted(case3time, key=itemgetter(1,2))

print ("=============passed in 1 time, duration greater than 300s============")
print ("  CaseID        Time")
for i in case1time:
    if i[1] >= 300:
        print ("%10s, %8d"%(i[0],i[1]))

print ("============passed in 2 times, duration greater than 300s============")
print ("  CaseID        Time1     Time2     Total")
for i in case2time:
    if i[1] >= 300 or i[2] >= 300:
        print ("%10s, %8d, %8d, %8d"%(i[0],i[1],i[2],i[1]+i[2]))

print ("======================the cases that run 3 times=====================")
print ("  CaseID              Status      Time1     Time2     Time3     Total")
for i in case3time:
    print ("%10s, %16s, %8d, %8d, %8d, %8d"%(i[0], i[1], i[2],i[3],i[4],i[2]+i[3]+i[4]))

print ("========================the cases that NOT run=======================")
print ("  CaseID")
for i in case0time:
    print ("%10s"%(i[0]))
print ("=====================================================================")

caseyaml = yaml.dump(ffd_case_num)

print
print("FFD Name                          Total Passed Failed NotRun TotalTime Avg.Time")
print("--------------------------------------------------------------------------------")
for ff in ffd_num:
    total_time = total_time + ffd_case_num[ff]['TotalTime']
    total_case = total_case + ffd_case_num[ff]['Total']
    total_pass = total_pass + ffd_case_num[ff]['Passed']
    total_fail = total_fail + ffd_case_num[ff]['Failed']
    total_nrun = total_nrun + ffd_case_num[ff]['NotRun']
    if int(ffd_case_num[ff]['Total']) == 0:
        print("%4d%28s%7d%7d%7d%7d%10d%10d"%(int(ff),ffd_case_num[ff][ff],ffd_case_num[ff]['Total'],ffd_case_num[ff]['Passed'],ffd_case_num[ff]['Failed'],ffd_case_num[ff]['NotRun'],ffd_case_num[ff]['TotalTime'],0))
    else:
        print("%4d%28s%7d%7d%7d%7d%10d%10.2f"%(int(ff),ffd_case_num[ff][ff],ffd_case_num[ff]['Total'],ffd_case_num[ff]['Passed'],ffd_case_num[ff]['Failed'],ffd_case_num[ff]['NotRun'],ffd_case_num[ff]['TotalTime'],float(ffd_case_num[ff]['TotalTime'])/float(ffd_case_num[ff]['Total'])))
print("--------------------------------------------------------------------------------")
print("%32s%7d%7d%7d%7d%10d%10.2f"%('Total:',total_case,total_pass,total_fail,total_nrun,total_time,float(total_time/total_case)))



