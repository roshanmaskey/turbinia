# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Task for analyzing Linux SSH authentication."""

import gzip
import hashlib
import logging
import os
import pandas as pd
import re

from datetime import datetime
from typing import Any, List

from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask
from turbinia.workers.analysis.auth import BruteForceAnalyzer
from turbinia.workers.analysis.auth import LastXDaysAnalyzer

log = logging.getLogger('turbinia')

SSH_CONNECTION_PATTERN = {
    'accepted':
        re.compile(
            r'(\w+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+sshd\[(\d+)\]:\s+Accepted\s+([^\s]+)\s+for\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)\s+ssh?'
        ),
    'failed':
        re.compile(
            r'(\w+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+sshd\[(\d+)\]:\s+Failed\s+([^\s]+)\s+for\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)\s+ssh?'
        ),
    'invalid_user':
        re.compile(
            r'(\w+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+sshd\[(\d+)\]:\s+Failed\s+([^\s]+)\s+for\s+invalid\s+user\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)\s+ssh'
        ),
    'disconnected':
        re.compile(
            r'(\w+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+sshd\[(\d+)\]:\s+Disconnected\s+from\s+user\s+([^\s]+)\s+([^\s]+)\s+port\s+(\d+)'
        ),
}


class SSHEventData:
  """SSH authentication event."""

  def __init__(
      self, timestamp: int, date: str, time: str, hostname: str, pid: int,
      event_key: str, event_type: str, auth_method: str, auth_result: str,
      username: str, source_ip: str, source_port: int):
    self.timestamp = timestamp
    self.date = date
    self.time = time
    self.hostname = hostname
    self.pid = pid
    self.event_key = event_key
    self.event_type = event_type
    self.auth_method = auth_method
    self.auth_result = auth_result
    self.domain = ''  # Required for consistency with Windows
    self.username = username
    self.source_ip = source_ip
    self.source_port = source_port
    self.session_hash = None

  def calculate_session_hash(self) -> None:
    hash_data = (
        f'{self.date}|{self.hostname}|{self.username}|{self.source_ip}|'
        f'{self.source_port}')

    h = hashlib.new('sha256')
    h.update(str.encode(hash_data))
    self.session_hash = h.hexdigest()


class LinuxSSHAuthAnalysisTask(TurbiniaTask):
  """Task to analyze Linux SSH authentication."""

  REQUIRED_STATES = [state.MOUNTED, state.CONTAINER_MOUNTED]

  TASK_CONFIG = {
      # This is the length of secons that the collected data will be processed.
      'ssh_analyzer_timeout': 600
  }

  # Log year validation
  # The minimum supported log year
  # NOTE: Python supports 1 as minimum year in datetime
  MIN_LOG_YEAR = 1970

  # Maximum supported valid log year
  # NOTE: Python datetime supports 9999 as maximum year
  MAX_LOG_YEAR = 9999

  def read_logs(self, log_dir: str) -> pd.DataFrame:
    """Read SSH authentication logs."""
    ssh_records = []

    for log_filename in os.listdir(log_dir):
      if not log_filename.startswith(
          'auth.log') and not log_filename.startswith('secure'):
        continue
      log_file = os.path.join(log_dir, log_filename)
      log.debug(f'log direcotry {log_dir}')

      # Handle log archive
      if log_filename.endswith('.gz'):
        with gzip.open(log_file, 'rt') as fh:
          log_data = fh.read()
          records = self.read_log_data(log_data)
          if not records:
            log.info(f'no ssh events in {log_filename}')
            continue
          ssh_records += records

      # Handle standard log file
      try:
        with open(log_file, 'r') as fh:
          log_data = fh.read()
          records = self.read_log_data(log_data)
          if not records:
            log.info(f'no ssh events in {log_filename}')
            continue
          ssh_records += records
      except FileNotFoundError:
        log.error(f'log {log_file} does not exist')
        continue

    if not ssh_records:
      return pd.DataFrame()

    ssh_data = []
    for ssh_record in ssh_records:
      ssh_data.append(ssh_record.__dict__)
    df = pd.DataFrame(ssh_data)
    return df

  def read_log_data(self, data, log_year: int = None) -> List:
    """ Parses SSH authentication log."""
    # check valid year is provided
    # If valid year isn't provided raise error
    return []

  def run(self, evidence, result):
    """Run the SSH Auth Analyzer worker.

    Args:
      evidence (Evidence object): The evidence of process
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      TurbiniaTaskResult object.
    """

    # Output file and evidence
    output_file_name = 'linux_ssh_auth_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    output_evidence = ReportText(source_path=output_file_path)

    # Analyzer outputs
    analyzer_output_priority = Priority.LOW
    analyzer_output_summary = ''
    analyzer_output_report = ''
    output_summary_list = []
    output_report_list = []

    mount_path = evidence.mount_path
    log_dir = os.path.join(mount_path, 'var', 'log')

    df = self.read_logs(log_dir=log_dir)
    if not df.empty:
      # Check for brute force
      bfa = BruteForceAnalyzer()
      bfa_result = bfa.run(df)

      bfa_result_summary = bfa_result['result_summary']
      if bfa_result_summary:
        output_summary_list.append(bfa_result_summary)

      bfa_result_markdown = bfa_result['result_markdown']
      if bfa_result_markdown:
        output_report_list.append(
            fmt.heading4(fmt.bold(bfa_result['analyzer_name'])))
        output_report_list.append(bfa_result_markdown)
        # TODO(rmaskey): add attributes

      # Check last x-days events
      lxd = LastXDaysAnalyzer()
      lxd_result = lxd.run(df)
      lxd_result_summary = lxd_result['result_summary']
      if lxd_result_summary:
        output_summary_list.append(lxd_result_summary)

      lxd_result_markdown = lxd_result['result_markdown']
      if lxd_result_markdown:
        output_report_list.append(
            fmt.heading4(fmt.bold(lxd_result['analyzer_name'])))
        output_report_list.append(lxd_result_markdown)
        # TODO(rmaskey): add attributes

    # Handling result
    if output_summary_list:
      analyzer_output_summary = '. '.join(output_summary_list)
    else:
      analyzer_output_summary = 'No findings'

    if output_report_list:
      analyzer_output_report = '\n'.join(output_report_list)

    result.report_priority = analyzer_output_priority
    result.report_data = analyzer_output_report

    # Write the report to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf-8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=analyzer_output_summary)
    return result
