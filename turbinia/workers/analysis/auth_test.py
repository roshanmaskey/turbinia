# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""AuthAnalyzer test class"""

import json
import pandas as pd
import unittest
import logging

from turbinia.workers.analysis.auth import AuthAnalyzer
from turbinia.workers.analysis.auth import BruteForceAnalyzer
from turbinia.workers.analysis.auth import LastXDaysAnalyzer

log = logging.getLogger('auth_analyzer')
log.setLevel(logging.DEBUG)


class TestAuthAnalyzer(unittest.TestCase):

  def test_get_ip_summary(self):
    aa = AuthAnalyzer(
        name='analyzer.auth', display_name='Auth Analyzer',
        description='Authentication analyzer')
    df = pd.read_csv('test_data/ssh_auth_data.csv')
    aa.set_dataframe(df)
    summary = aa.get_ip_summary('102.25.103.232')
    print(summary)
    print(json.dumps(summary.__dict__, indent=4))

  def test_get_user_summary(self):
    aa = AuthAnalyzer(
        name='analyzer.auth', display_name='Auth Analyzer',
        description='Authentication analyzer')
    df = pd.read_csv('test_data/ssh_auth_data.csv')
    aa.set_dataframe(df)
    summary = aa.get_user_summary(domain='', username='spiderman')
    print(summary)
    print(json.dumps(summary.__dict__, indent=4))


class TestBruteForceAnalyzer(unittest.TestCase):

  def test_run(self):
    bfa = BruteForceAnalyzer()

    df = pd.read_csv('test_data/ssh_auth_data.csv')
    result = bfa.run(df)
    print(result)
    print(json.dumps(result, indent=4))


class TestLastXDaysAnalyzer(unittest.TestCase):

  def test_run(self):
    a = LastXDaysAnalyzer()
    df = pd.read_csv('test_data/ssh_auth_data.csv')
    result = a.run(df)
    print(result)
    print(json.dumps(result, indent=4))


if __name__ == '__main__':
  unittest.main()
