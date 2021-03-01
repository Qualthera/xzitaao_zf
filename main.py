#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021 Qualthera, Inc. All Rights Reserved 
#
# @Time    : 3/1/2021 3:17 PM
# @Author  : Howie Hye
# @Email   : howiehye@163.com
# @File    : main.py
# @Software: PyCharm

import base64
import binascii
import datetime
import time
import json
import os
import re
from urllib import parse

import requests
import rsa
import lxml

# from Crypto.Cipher import PKCS1_V1_5
# from Crypto.PublicKey import RSA
from bs4 import BeautifulSoup
from requests import exceptions

U_ID = ''
U_PASSWD = ''

BASE_URL = r'http://117.80.117.100:81/jwglxt/'
INIT_URL = parse.urljoin(BASE_URL, 'xtgl/index_initMenu.html')
KEY_URL = parse.urljoin(BASE_URL, 'xtgl/login_getPublicKey.html')
LOGIN_URL = parse.urljoin(BASE_URL, 'xtgl/login_slogin.html')
Headers = {
    'Host': '117.80.117.100:81',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
}


def test(r, name):
    data = r.content
    with open(name + '_test.html', 'wb') as f:
        f.write(data)


def get_rsa(pwd, n, e):
    """对密码base64编码"""
    message = str(pwd).encode()
    rsa_n = binascii.b2a_hex(binascii.a2b_base64(n))
    rsa_e = binascii.b2a_hex(binascii.a2b_base64(e))
    key = rsa.PublicKey(int(rsa_n, 16), int(rsa_e, 16))
    encropy_pwd = rsa.encrypt(message, key)
    result = binascii.b2a_base64(encropy_pwd)
    return result


def main():
    Headers['Referer'] = parse.urljoin(LOGIN_URL, '?jsdm=xs&_t=' + str(int(round(time.time() * 1000))))
    # print(int(round(time.time() * 1000)))
    session = requests.Session()

    req = session.get(LOGIN_URL, headers=Headers, timeout=3)
    # print(req.text)
    soup = BeautifulSoup(req.text, 'lxml')
    tokens = soup.find(id='csrftoken').get('value')
    print(tokens)
    Headers['Referer'] = LOGIN_URL
    res = session.get(KEY_URL + '?time=' + str(int(round(time.time() * 1000))), headers=Headers, timeout=3).json()
    print(res)
    n = res['modulus']
    e = res['exponent']
    print(n)
    print(e)
    hmm = get_rsa(U_PASSWD, n, e)
    print(hmm)
    login_data = {
        'csrftoken': tokens,
        'language': 'zh_CN',
        'yhm': '20170502127',
        'mm': hmm,
        'mm': hmm
    }
    session.post(LOGIN_URL + '?time=' + str(int(round(time.time() * 1000))), headers=Headers, data=login_data,
                 timeout=3)
    login_req = session.get(INIT_URL, headers=Headers, timeout=3)
    test(login_req, U_ID)


if __name__ == '__main__':
    main()
