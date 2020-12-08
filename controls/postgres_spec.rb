# encoding: utf-8

# Copyright 2016, Patrick Muench
# Copyright 2016-2019 DevSec Hardening Framework Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Christoph Hartmann
# author: Dominik Richter
# author: Patrick Muench

title 'PostgreSQL Server Configuration'

# attributes


USER = attribute(
  'user',
  description: 'define the postgresql user to access the database',
  default: 'postgres'
  
)


PASSWORD = attribute(
  'password',
  description: 'define the postgresql password to access the database'
  
)

HOST = attribute(
  'host',
  description: 'define the postgresql host where it is listening',
  default: 'localhost'
)

sql = postgres_session(USER, PASSWORD, HOST)


POSTGRES_DATA = attribute(
  'postgres_data',
  description: 'define the postgresql data directory',
  default: '/var/lib/postgresql/12/main'
  
)

POSTGRES_CONF_DIR = attribute(
  'postgres_conf_dir',
  description: 'define the postgresql configuration directory',
  default: '/etc/postgresql'
 
)

POSTGRES_CONF_PATH = attribute(
  'postgres_conf_path',
  description: 'define path for the postgresql configuration file',
  default: '/etc/postgresql/12/main/postgresql.conf'
  
).to_s

POSTGRES_HBA_CONF_FILE = attribute(
  'postgres_hba_conf_file',
  description: 'define path for the postgresql configuration file',
  default: '/etc/postgresql/12/main/pg_hba.conf'
)



only_if do
  command('psql').exist?
end

control 'postgres-01' do
  impact 1.0
  title 'Postgresql should be running and enabled'
  desc 'Postgresql should be running and enabled. When system restarts apruptly postgres should be started and loaded automatically'
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  # describe service(postgres.service) do
  #   it { should be_installed }
  #   it { should be_running }
  #   it { should be_enabled }
  # end
  case os[:name]
  when 'ubuntu'
    case os[:release]
    when '12.04'
      describe command('/etc/init.d/postgresql status') do
        its('stdout') { should include 'online' }
      end
    when '14.04'
      describe command('service postgresql status') do
        its('stdout') { should include 'online' }
      end
    when '16.04'
      describe systemd_service(postgres.service) do
        it { should be_installed }
        it { should be_running }
        it { should be_enabled }
      end
    # Added for ubuntu 18.04 
    when '18.04'
      describe command('service postgresql status') do
        its('stdout') { should include 'active' }
      end
      describe command('systemctl list-unit-files | grep postgresql.service') do
        its('stdout') { should include 'enabled' }
      end
    
      
    end
  when 'debian'
    case os[:release]
    when /7\./
      describe command('/etc/init.d/postgresql status') do
        its('stdout') { should include 'Running' }
      end
    end
  when 'redhat', 'centos', 'oracle', 'fedora'
    case os[:release]
    when /6\./
      describe command('/etc/init.d/postgresql-9.4 status') do
        its('stdout') { should include 'running' }
      end
    when /7\./
      describe command('ps aux | awk /\'bin\/postgres\'/ | wc -l') do
        its('stdout') { should include '1' }
      end
    end
  end
end

control 'postgres-02' do
  impact 1.0
  title 'Use stable postgresql version'
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  desc 'Use only community or commercially supported version of the PostgreSQL software. Do not use RC, DEVEL oder BETA versions in a production environment.'
  # describe command('psql -V') do
  #   its('stdout') { should match(/^psql\s\(PostgreSQL\)\s([9 10 11 12]\.[3-6]|10\.5).*/) }
  # end
  describe command('psql -V') do
    its('stdout') { should_not match(/RC/) }
    its('stdout') { should_not match(/DEVEL/) }
    its('stdout') { should_not match(/BETA/) }
  end
end

control 'postgres-03' do
  impact 1.0
  title 'Run one postgresql instance per operating system'
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  desc 'Only one postgresql database instance must be running on an operating system instance (both physical HW or virtualized).'
  pg_command = 'postgres'
  pg_command = 'postmaster' if os.redhat? && os.release.include?('6.')
  describe processes(pg_command) do
    its('entries.length') { should eq 1 }
  end
end

# control 'postgres-04' do
#   impact 1.0
#   tag Vulnerability: 'Medium'
#   tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
#   title 'Only "c" and "internal" should be used as non-trusted procedural languages'
#   desc 'If additional programming languages (e.g. plperl) are installed with non-trust mode, then it is possible to gain OS-level access permissions.'
#   describe postgres_session(USER, PASSWORD, HOST).query('SELECT count (*) FROM pg_language WHERE lanpltrusted = \'f\' AND lanname!=\'internal\' AND lanname!=\'c\';') do
#     its('output') { should eq '0' }
#   end
# end

control 'postgres-05' do
  impact 1.0
  title 'Set a password for each user'
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  desc 'It tests for usernames which does not set a password. '
  describe sql.query('SELECT count(*) FROM pg_shadow WHERE passwd IS NULL;', ['postgres']) do
    its('output') { should eq '0' }
  end
  # describe postgres_session(USER, PASSWORD,HOST).query('SELECT count(*) FROM pg_shadow WHERE passwd IS NULL;') do
  #   its('output') { should eq '0' }
  # end
end

control 'postgres-06' do
  impact 1.0
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  title 'Use salted hash to store postgresql passwords'
  desc 'Store postgresql passwords in salted hash format (e.g. salted MD5).'
  case postgres.version
  when /^9/
    # describe postgres_session(USER, PASSWORD, HOST).query('SELECT passwd FROM pg_shadow;') do
    #   its('output') { should match(/^md5.*$/) }
    # end
    describe sql.query('SELECT passwd FROM pg_shadow;', ['postgres']) do
      its('output') { should match(/^md5.*$/) }
    end
    # describe postgres_conf(POSTGRES_CONF_PATH) do
    #   its('password_encryption') { should eq 'on' }
    # end
  when /^10/
    # describe postgres_session(USER, PASSWORD, HOST).query('SELECT passwd FROM pg_shadow;') do
    #   its('output') { should match(/^scram-sha-256\S*$/) }
    # end
    describe sql.query('SELECT passwd FROM pg_shadow;', ['postgres']) do
      its('output') { should match(/^scram-sha-256\S*$/) }
    end
    # describe postgres_conf(POSTGRES_CONF_PATH) do
    #   its('password_encryption') { should eq 'scram-sha-256' }
    # end
  end
end

control 'postgres-07' do
  impact 1.0
  tag Vulnerability: 'Critical'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  title 'Only the postgresql database administrator should have SUPERUSER, CREATEDB or CREATEROLE privileges.'
  desc 'Granting extensive privileges to ordinary users can cause various security problems, such as: intentional/ unintentional access, modification or destroying data'
  # describe postgres_session(USER, PASSWORD, HOST).query('SELECT count(*) FROM pg_roles WHERE rolsuper IS TRUE OR rolcreaterole IS TRUE or rolcreatedb IS TRUE;') do
  #   its('output') { should eq '1' }
  describe sql.query('SELECT count(*) FROM pg_roles WHERE rolsuper IS TRUE OR rolcreaterole IS TRUE or rolcreatedb IS TRUE;', ['postgres']) do
    its('output') { should eq '1' }
  end
end

control 'postgres-08' do
  impact 1.0
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  title 'Only the DBA should have privileges on pg_catalog.pg_authid table.'
  desc 'In pg_catalog.pg_authid table there are stored credentials such as username and password. If hacker has access to the table, then he can extract these credentials.'
  # describe postgres_session(USER, PASSWORD, HOST).query('\dp pg_catalog.pg_authid') do
  #   its('output') { should eq 'pg_catalog | pg_authid | table | postgres=arwdDxt/postgres |' }
  # end
  describe sql.query('\dp pg_catalog.pg_authid', ['postgres']) do
    its('output') { should eq 'pg_catalog | pg_authid | table | postgres=arwdDxt/postgres |' }
  end
end

control 'postgres-09' do
  impact 1.0
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  title 'The PostgreSQL "data_directory" should be assigned exclusively to the database account (such as "postgres").'
  desc 'If file permissions on data are not property defined, other users may read, modify or delete those files.'
  find_command = 'find ' + POSTGRES_DATA.to_s + ' -user ' + USER + ' -group ' + USER + ' -perm /go=rwx'
  describe command(find_command) do
    its('stdout') { should eq '' }
  end
end

control 'postgres-10' do
  impact 1.0
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  title 'The PostgreSQL config directory and file should be assigned exclusively to the database account (such as "postgres").'
  desc 'If file permissions on config files are not property defined, other users may read, modify or delete those files.'
  describe file(POSTGRES_CONF_DIR) do
    it { should be_directory }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
  describe file(POSTGRES_CONF_PATH) do
    it { should be_file }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
  describe file(POSTGRES_HBA_CONF_FILE) do
    it { should be_file }
    it { should be_owned_by USER }
    it { should be_readable.by('owner') }
    it { should_not be_readable.by('group') }
    it { should_not be_readable.by('other') }
    it { should be_writable.by('owner') }
    it { should_not be_writable.by('group') }
    it { should_not be_writable.by('other') }
    it { should_not be_executable.by('owner') }
    it { should_not be_executable.by('group') }
    it { should_not be_executable.by('other') }
  end
end

control 'postgres-11' do
  impact 1.0
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  title 'SSL is deactivated just for testing the chef-hardening-cookbook. It is recommended to activate ssl communication.'
  desc 'The hardening-cookbook will delete the links from #var/lib/postgresql/%postgresql-version%/main/server.crt to etc/ssl/certs/ssl-cert-snakeoil.pem and #var/lib/postgresql/%postgresql-version%/main/server.key to etc/ssl/private/ssl-cert-snakeoil.key on Debian systems. This certificates are self-signed (see http://en.wikipedia.org/wiki/Snake_oil_%28cryptography%29) and therefore not trusted. You have to #provide our own trusted certificates for SSL.'
  describe postgres_conf(POSTGRES_CONF_PATH) do
    its('ssl') { should eq 'off' }
  end
end

control 'postgres-12' do
  impact 1.0
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  title 'Use strong chiphers for ssl communication'
  desc 'The following categories of SSL Ciphers must not be used: ADH, LOW, EXP and MD5. A very good description for secure postgres installation / configuration can be found at: https://bettercrypto.org'
  # This is entirely incorrect way to test 
  # Initially postgres default is HIGH:MEDIUM:+3DES:!aNULL which is upto CIS benchmark
  # So it will fail this case even though cipers strategy is good
  # describe postgres_conf(POSTGRES_CONF_PATH) do
  #   its('ssl_ciphers') { should eq 'ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH' }
  # end
  # So we should check LOW ADH and EXP MD5 should not be present in ssl ciphers
  # describe postgres_session(USER, PASSWORD, HOST).query('show ssl_ciphers ;') do
  #   its('output') { should_not match (/ADH/) }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query('show ssl_ciphers ;') do
  #   its('output') { should_not match (/LOW/) }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query('show ssl_ciphers ;') do
  #   its('output') { should_not match (/EXP/) }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query('show ssl_ciphers ;') do
  #   its('output') { should_not match (/MD5/) }
  # end
  describe sql.query('show ssl_ciphers ;', ['postgres']) do
    its('output') { should_not match (/EXP/) }
  end
  describe sql.query('show ssl_ciphers ;', ['postgres']) do
    its('output') { should_not match (/ADH/) }
  end
  describe sql.query('show ssl_ciphers ;', ['postgres']) do
    its('output') { should_not match (/LOW/) }
  end  
  describe sql.query('show ssl_ciphers ;', ['postgres']) do
    its('output') { should_not match (/MD5/) }
  end
  
end

control 'postgres-13' do
  impact 1.0
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  title 'Require MD5 for ALL users, peers in pg_hba.conf'
  desc 'Require MD5 for ALL users, peers in pg_hba.conf and do not allow untrusted authentication methods.'
  # describe file(POSTGRES_HBA_CONF_FILE) do
  #   its('content') { should match(/local\s.*?all\s.*?all\s.*?md5/) }
  #   its('content') { should match(%r{host\s.*?all\s.*?all\s.*?127.0.0.1\/32\s.*?md5}) }
  #   its('content') { should match(%r{host\s.*?all\s.*?all\s.*?::1\/128\s.*?md5}) }
  #   its('content') { should_not match(/.*password/) }
  #   its('content') { should_not match(/.*trust/) }
  #   its('content') { should_not match(/.*crypt/) }
  # end
  # Here we are executing query and fetching exact details more robust and no chance of getting false data

  # describe postgres_session(USER, PASSWORD, HOST).query('select auth_method  from pg_hba_file_rules where type=\'local\' AND database=\'{all}\' AND user_name=\'{all}\';') do
  #   its('output') { should eq "md5" }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query(' select auth_method  from pg_hba_file_rules where type=\'host\' AND database=\'{all}\' AND user_name=\'{all}\' AND address=\'127.0.0.1\';') do
  #   its('output') { should eq "md5" }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query('select auth_method  from pg_hba_file_rules where type=\'host\' AND database=\'{all}\' AND user_name=\'{all}\' AND address=\'::1\'; ;') do
  #   its('output') { should eq "md5" }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query('select auth_method from  pg_hba_file_rules ;') do
  #   its('output') { should_not match(/.*password/) }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query('select auth_method from  pg_hba_file_rules ;') do
  #   its('output') { should_not match(/.*trust/) }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query('select auth_method from  pg_hba_file_rules ;') do
  #   its('output') { should_not match(/.*crypt/) }
  # end
  
  describe sql.query('select auth_method  from pg_hba_file_rules where type=\'local\' AND database=\'{all}\' AND user_name=\'{all}\';', ['postgres']) do
    its('output') { should match (/md5|peer/) }
  end
  describe sql.query('select auth_method  from pg_hba_file_rules where type=\'host\' AND database=\'{all}\' AND user_name=\'{all}\' AND address=\'127.0.0.1\';', ['postgres']) do
    its('output') { should eq "md5" }
  end
  describe sql.query('select auth_method  from pg_hba_file_rules where type=\'host\' AND database=\'{all}\' AND user_name=\'{all}\' AND address=\'::1\'; ', ['postgres']) do
    its('output') { should eq "md5" }
  end
  describe sql.query('select auth_method from  pg_hba_file_rules ;', ['postgres']) do
    its('output') { should_not match(/.*password/) }
  end
  describe sql.query('select auth_method from  pg_hba_file_rules ;', ['postgres']) do
    its('output') { should_not match(/.*trust/) }
  end
  describe sql.query('select auth_method from  pg_hba_file_rules ;', ['postgres']) do
    its('output') { should_not match(/.*crypt/) }
  end
end

# control 'postgres-14' do
#   impact 1.0
#   tag Vulnerability: 'Low'
#   tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
#   title 'We accept one peer and one ident for now (chef automation)'
#   desc 'We accept one peer and one ident for now (chef automation)'
#   # This code fails as commented line words peer is also being grep and giving false data
#   # describe command('cat ' + POSTGRES_HBA_CONF_FILE.to_s + ' | egrep \'peer|ident\' | wc -l') do
#   #   its('stdout') { should match(/^[2|1]/) }
#   # end
#   describe postgres_session(USER, PASSWORD, HOST).query('select count(*) auth_method from  pg_hba_file_rules where auth_method=\'peer\' ;') do
#     its('output') { should <= "1"  }
#   end
#   describe postgres_session(USER, PASSWORD, HOST).query('select count(*) auth_method from  pg_hba_file_rules where auth_method=\'ident\' ;') do
#     its('output') { should <= "1"  }
#   end
#   describe sql.query('select auth_method from  pg_hba_file_rules ;', ['postgres']) do
#     its('output') { should <= "1" }
#   end
#   describe sql.query('select auth_method from  pg_hba_file_rules ;', ['postgres']) do
#     its('output') { should <= "1" }
#   end

#

control 'postgres-15' do
  impact 1.0
  title "Ensure SSL is enabled and configured correctly"
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Edit the PostgreSQL configuration file postgresql.conf to ensure the following items are
  set.; i.e ssl = on"
  ref 'Postgres ssl', url: 'https://www.postgresql.org/docs/12/static/ssl-tcp.html'
  desc "SSL on a PostgreSQL server should be enabled (set to on ) and configured to encrypt TCP
  traffic to and from the server.
  If SSL is not enabled and configured correctly, this increases the risk of data being
  compromised in transit."
#   describe postgres_session(USER, PASSWORD, HOST).query('show log_rotation_size;') do
#     its('output') { should_not eq '0' }
#  end
  describe sql.query('show ssl;', ['postgres']) do
    its('output') { should match (/on/) }
  end
end

control 'postgres-16' do
  impact 1.0
  title "Ensure the maximum log file size is set correctly"
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "To alter it execute following psql command. \n 
              alter system set log_rotation_size = '1GB';"
  ref 'Postgres Logging if you are curious to know', url: 'https://www.postgresql.org/docs/9.3/runtime-config-logging.html'
  desc "If this is set to zero.Then all logs is appended to same file and its size consistently increases.\n
        We should always set it to any value other than 0"
#   describe postgres_session(USER, PASSWORD, HOST).query('show log_rotation_size;') do
#     its('output') { should_not eq '0' }
#  end
  describe sql.query('show log_rotation_size ;', ['postgres']) do
    its('output') {  should_not eq '0' }
  end
end

control 'postgres-17' do
  impact 1.0
  title 'Ensure the maximum log age is set correctly'
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "To alter it execute following psql command. \n 
              alter system set log_rotation_age='1h';"
  ref 'Postgres Logging if you are curious to know', url: 'https://www.postgresql.org/docs/9.3/runtime-config-logging.html'
  desc "If this is not set or set to default value which is 1 day.Then new log file will be created on daily basis e.g log.monday log.tuesday.\n
        Lets say some bad event happend on monday. Then  you will have to go through overall log.monday to get that interested event.\n 
        We should set it to hour basis e.g 1 hour."
  
#   describe postgres_session(USER, PASSWORD, HOST).query('show log_rotation_age;') do
#     its('output') { should_not match 'd|y|m' }
#  end
  describe sql.query('show log_rotation_age;', ['postgres']) do
    its('output') {  should_not match 'd|y|m'  }
  end
end

control 'postgres-18' do
  impact 1.0
  title 'Ensure the log file permissions are set correctly'
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "To alter it execute following psql command. \n 
              alter system set log_file_mode = '0600';"
  ref 'Postgres Logging if you are curious to know', url: 'https://www.postgresql.org/docs/9.3/runtime-config-logging.html'
  
  desc "Our logs contain the event or action we have performed.\n
        If a new database is created or modified, any sql statement taking much time than defined one are also logged.This is only one such example\n 
        We should set it to 600 so that only  user postgres can read or write it"

#   describe postgres_session(USER, PASSWORD, HOST).query('show log_file_mode;') do
#     its('output') { should  eq '0600' }
#  end
  describe sql.query('show log_file_mode;', ['postgres']) do
    its('output') {  should  eq '0600'  }
  end
end

control 'postgres-19' do
  impact 1.0
  title 'Ensure log_checkpoints is enabled'
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "To alter it execute following psql command. \n 
              alter system set log_checkpoints = 'on';"
  ref 'Postgres Logging if you are curious to know', url: 'https://www.postgresql.org/docs/9.3/runtime-config-logging.html'
  
  desc "A checkpoint is a point in the transaction log sequence at which all data files have been updated to reflect the information in the log. All data files will be flushed to disk.\n
        Enabling the log_checkpoints setting causes checkpoints and restartpoints to be logged in the server log.\n
        Checkpoints"
  # describe postgres_session(USER, PASSWORD, HOST).query('show log_checkpoints ;') do
  #   its('output') { should  eq 'on' }
  # end
  describe sql.query('show log_checkpoints ;', ['postgres']) do
    its('output') {  should  eq 'on' }
  end
end

# control 'postgres-20' do
#   impact 1.0
#   title 'Ensure log_checkpoints is enabled'
#   tag Vulnerability: 'Medium'
#   tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
#   tag Remedy: "To alter it execute following psql command. \n 
#               alter system set log_checkpoints = 'on';"
#   ref 'Postgres Logging if you are curious to know', url: 'https://www.postgresql.org/docs/9.3/runtime-config-logging.html'
  
#   desc "A checkpoint is a point in the transaction log sequence at which all data files have been updated to reflect the information in the log. All data files will be flushed to disk.\n
#         Enabling the log_checkpoints setting causes checkpoints and restartpoints to be logged in the server log.\n
#         Checkpoints"

#   describe postgres_session(USER, PASSWORD, HOST).query('show log_checkpoints ;') do
#     its('output') { should  eq 'on' }
#  end
# end

control 'postgres-21' do
  impact 1.0
  title 'Ensure log_lock_waits is enabled'
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "To alter it execute following psql command. \n 
              alter system set log_lock_waits = 'on';"
  ref 'Postgres Logging if you are curious to know', url: 'https://www.postgresql.org/docs/9.3/runtime-config-logging.html'
  
  desc "The log_lock_waits setting specifies whether a log message is produced when a session waits longer than deadlock_timeout to acquire a lock.\n
        The setting should be enabled (set to on ) unless otherwise directed by your organization's logging policy."

#   describe postgres_session(USER, PASSWORD, HOST).query('show log_lock_waits ;') do
#     its('output') { should  eq 'on' }
#  end
  describe sql.query('show log_lock_waits ;', ['postgres']) do
    its('output') {  should  eq 'on' }
  end
end

control 'postgres-22' do
  impact 1.0
  title 'Ensure FIPS 140-2 OpenSSL Cryptography Is Used'
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Install fips e.g for redhat execute  yum -y install dracut-fips"
  ref 'Install Fips Ubuntu', url: 'https://security-certs.docs.ubuntu.com/en/fips'
  ref 'About FIPS', url: 'https://d2iq.com/blog/why-we-care-about-fips-and-you-should-too'
  
  desc "Federal Information Processing Standard (FIPS) Publication 140-2 is a computer security standard developed by a U.S. Government and industry working group for validating the quality of cryptographic modules. Use of weak, or untested, encryption algorithms \n
        undermine the purposes of utilizing encryption to protect data"

  describe command('openssl version | grep \'fips\' | wc -l') do
    its('stdout') { should cmp "1" }
  end
end

control 'postgres-23' do
  impact 1.0
  title 'Ensure log_statement_stats is disabled'
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Execute following psql command, alter system set log_statement_stats = 'off';"
  ref 'About log statement stats', url: 'https://postgresqlco.nf/en/doc/param/log_statement_stats/'
  desc "Enabling the log_statement_stats setting causes cumulative performance statistics to be written to the server log for each query.\n
        The logging of these additional statistics when not mandated by your organization's logging policy greatly reduces the signal-to-noise ratio of the PostgreSQL logs."
  # describe postgres_session(USER, PASSWORD, HOST).query('show log_statement_stats ;') do
  # its('output') { should   eq 'off' }
  # end
  describe sql.query('show log_statement_stats ;', ['postgres']) do
    its('output') {  should  eq 'off' }
  end
end

control 'postgres-24' do
  impact 1.0
  title 'Ensure log_executor_stats is disabled'
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Execute following psql command,alter system set log_executor_stats = 'off';"
  ref 'About log executor stats', url: 'https://postgresqlco.nf/en/doc/param/log_executor_stats/'
  desc "Any Postgres sql query goes through \'parser\' which checks for syntax of given sql statement followed by \'planner\' which checks for optimal way to execute that statement and that result is passed to executor. Executor execute the instruction as planned by planner.\n
        Enabling the log_executor_stats setting causes executor performance statistics to be written to the server log.\n
        The logging of these additional statistics when not mandated by your organization's logging policy greatly reduces the signal-to-noise ratio of the PostgreSQL logs."
  # describe postgres_session(USER, PASSWORD, HOST).query('show log_executor_stats ;') do
  # its('output') { should   eq 'off' }
  # end
  describe sql.query('show log_executor_stats ;', ['postgres']) do
    its('output') {  should  eq 'off' }
  end
end

control 'postgres-25' do
  impact 1.0
  title 'Ensure log_planner_stats is disabled'
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Execute following psql command,alter system set log_planner_stats = 'off';"
  ref 'About log_planner_stats', url: 'https://postgresqlco.nf/en/doc/param/log_planner_stats/'
  desc "Any Postgres sql query goes through \'parser\' which checks for syntax of given sql statement followed by \'planner\' which checks for optimal way to execute that statement and that result is passed to executor. Executor execute the instruction as planned by planner.\n
        Enabling the log_planner_stats setting causes planner performance statistics to be written to the server log.\n
        The logging of these additional statistics when not mandated by your organization's logging policy greatly reduces the signal-to-noise ratio of the PostgreSQL logs."
  # describe postgres_session(USER, PASSWORD, HOST).query('show log_planner_stats ;') do
  # its('output') { should   eq 'off' }
  # end
  describe sql.query('show log_planner_stats ;', ['postgres']) do
    its('output') {  should  eq 'off' }
  end
end

control 'postgres-26' do
  impact 1.0
  title 'Ensure log_parser_stats is disabled'
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Execute following psql command,alter system set log_parser_stats = 'off';"
  ref 'About log_parser_stats', url: 'https://postgresqlco.nf/en/doc/param/log_parser_stats/'
  desc "Any Postgres sql query goes through \'parser\' which checks for syntax of given sql statement followed by \'planner\' which checks for optimal way to execute that statement and that result is passed to executor. Executor execute the instruction as planned by planner.\n
        Enabling the log_parser_stats setting causes parser performance statistics to be written to the server log.\n
        The logging of these additional statistics when not mandated by your organization's logging policy greatly reduces the signal-to-noise ratio of the PostgreSQL logs."
  # describe postgres_session(USER, PASSWORD, HOST).query('show log_parser_stats ;') do
  # its('output') { should   eq 'off' }
  # end
  describe sql.query('show log_parser_stats ;', ['postgres']) do
    its('output') {  should  eq 'off' }
  end
end

control 'postgres-27' do
  impact 1.0
  title 'Ensure debug_print_parse is disabled'
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Execute following psql command,alter system set debug_print_parse='off';"
  ref 'About debug_print_parse', url: 'https://postgresqlco.nf/en/doc/param/debug_print_parse/'
  desc "The debug_print_parse setting enables printing the resulting parse tree for each executed query. These messages are emitted at the LOG message level. Unless directed otherwise by \n
        your organization's logging policy, it is recommended this setting be disabled by setting it to off ."
  # describe postgres_session(USER, PASSWORD, HOST).query('show debug_print_parse;') do
  # its('output') { should   eq 'off' }
  # end
  describe sql.query('show debug_print_parse;', ['postgres']) do
    its('output') {  should  eq 'off' }
  end
end

control 'postgres-28' do
  impact 1.0
  title 'Ensure debug_print_plan is disabled'
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Execute following psql command,alter system set debug_print_plan = 'off';"
  ref 'About debug_print_plan', url: 'https://postgresqlco.nf/en/doc/param/debug_print_plan/'
  desc "The debug_print_plan setting enables printing the execution plan for each executed query.\n
        These messages are emitted at the LOG message level. Unless directed otherwise by your \n
        organization's logging policy, it is recommended this setting be disabled by setting it to off ."
  # describe postgres_session(USER, PASSWORD, HOST).query('show debug_print_plan ;') do
  # its('output') { should   eq 'off' }
  # end
  describe sql.query('show debug_print_plan ;', ['postgres']) do
    its('output') {  should  eq 'off' }
  end
end

control 'postgres-29' do
  impact 1.0
  title 'Ensure WAL archiving is configured and functional'
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "You need to enable archiving mode see attached references to correct it"
  ref 'About Archive and how to set it', url: 'https://www.tutorialdba.com/p/postgresql-archivelog.html#:~:text=%2D%2Dswitch%20to%20postgres%20user,Archive%2Dlog%20mode%20requires%20RESTART.&text=%2D%2DAfter%20the%20server%20start,or%20not%20using%20psql%20terminal.'
  desc "Write Ahead Log (WAL) Archiving, or Log Shipping, is the process of sending transaction
        log files from the PRIMARY host either to one or more STANDBY hosts or to be archived on
        a remote storage device for later use."
  # describe postgres_session(USER, PASSWORD, HOST).query('show archive_mode;') do
  # its('output') { should   eq 'on' }
  # end
  describe sql.query('show archive_mode;', ['postgres']) do
    its('output') {  should  cmp 'on' }
  end
  # describe postgres_session(USER, PASSWORD, HOST).query('show archive_command;') do
  # its('output') { should_not   eq 'disabled' }
  # end
  describe sql.query('show archive_mode;', ['postgres']) do
    its('output') {  should  cmp 'on' }
  end
end

control 'postgres-30' do
  impact 1.0
  title 'Ensure SSL Certificates are properly Configured For Replication'
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Generate a self-signed certificate and add its name into postgresql conf"
  ref 'Generate self signed certificate', url: 'https://www.rosehosting.com/blog/how-to-generate-a-self-signed-ssl-certificate-on-linux/'
  ref 'Postgres generate certificate and its parameter to use in postresqlconf', url: 'https://www.postgresql.org/docs/9.5/ssl-tcp.html#:~:text=With%20SSL%20support%20compiled%20in,on%20whether%20to%20use%20SSL%20.'
  desc "Secure Sockets Layer (SSL) certificates enable encrypted communications between the PRIMARY and STANDBY hosts. SSL certificates can also be used to authenticate the identity of the host.\n 
        The use of SSL certificates mitigates against sniffing of what would otherwise be sensitive information that's being transmitted in the clear."
  # describe postgres_session(USER, PASSWORD, HOST).query('show ssl_cert_file;') do
  # its('output') { should_not   eq 'disabled' }
  # end
  # describe postgres_session(USER, PASSWORD, HOST).query('show ssl_key_file;') do
  # its('output') { should_not   eq 'disabled' }
  # end
  describe sql.query('show ssl_cert_file;', ['postgres']) do
    its('output') {  should_not  match 'disabled' }
  end
  describe sql.query('show ssl_key_file;', ['postgres']) do
    its('output') {  should_not  match 'disabled' }
  end
end

control 'postgres-31' do
  impact 1.0
  title 'Ensure a replication-only user is created and used for replication'
  tag Vulnerability: 'High'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "It will be necessary to create a new role for replication purposes: create user replication_user REPLICATION encrypted password 'XXX';"
  ref 'Set up replication and how to create user in postgres', url: 'https://www.percona.com/blog/2019/10/11/how-to-set-up-streaming-replication-in-postgresql-12/'
  desc "Create a new user specifically for use by replication instead of using the superuser account."
  # describe postgres_session(USER, PASSWORD, HOST).query('select count(*) rolname from pg_roles where rolreplication is true;') do
  # its('output') { should_not   eq '1' }
  # end
  describe sql.query('select count(*) rolname from pg_roles where rolreplication is true;', ['postgres']) do
    its('output') { should_not   cmp '1' }
  end
end

control 'postgres-32' do
  impact 1.0
  title 'Ensure debug_print_rewritten is disabled'
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Execute the following SQL statement(s) to disable this setting: alter system set debug_print_rewritten = 'off';"
  ref 'About debug_print_rewritten', url: 'https://postgresqlco.nf/en/doc/param/debug_print_rewritten/'
  desc "These parameters enable various debugging output to be emitted. When set, they print the resulting parse tree, the query rewriter output, or the execution plan for each executed query."
  # describe postgres_session(USER, PASSWORD, HOST).query('show debug_print_rewritten;') do
  # its('output') { should   eq 'off' }
  # end
  describe sql.query('show debug_print_rewritten;', ['postgres']) do
    its('output') {  should   eq 'off' }
  end
end

control 'postgres-33' do
  impact 1.0
  title 'Ensure the PostgreSQL Audit Extension (pgAudit) is enabled'
  tag Vulnerability: 'Medium'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "To install and enable pgAudit, simply install the appropriate rpm from the PGDG repo: yum -y install pgaudit_95"
  ref 'Official Pgaudit repo , see Readme file', url: 'https://github.com/pgaudit/pgaudit#:~:text=The%20PostgreSQL%20Audit%20Extension%20(pgAudit,the%20standard%20PostgreSQL%20logging%20facility.&text=An%20audit%20is%20an%20official,typically%20by%20an%20independent%20body.'
  ref 'Pgaudit Package for ubuntu', url: 'https://ubuntu.pkgs.org/18.04/ubuntu-universe-amd64/postgresql-10-pgaudit_1.2.0-1_amd64.deb.html'
  desc "It is not enough to have a list of all the operations performed against the database, it must also be possible to find particular statements that are of interest to an auditor.
        The standard logging facility shows what the user requested, while pgAudit focuses on the details of what happened while the database was satisfying the request.
        e.g while creating a table what standard loggings logs it and what pgaudit 
        EXECUTE 'CREATE TABLE import' || 'ant_table (id INT)';
        Standard Logging 
        LOG:  statement:  EXECUTE 'CREATE TABLE import' || 'ant_table (id INT)';
        pgaudit 
        AUDIT: SESSION,33,2,DDL,CREATE TABLE,TABLE,public.important_table,CREATE TABLE important_table (id INT)"
  # describe postgres_session(USER, PASSWORD, HOST).query('show shared_preload_libraries ;') do
  # its('output') { should  match 'pgaudit' }
  # end
  describe sql.query('show shared_preload_libraries ;', ['postgres']) do
    its('output') {  should  match 'pgaudit' }
  end
end

control 'postgres-34' do
  impact 1.0
  title 'Ensure all temporary files are logged'
  tag Vulnerability: 'Low'
  tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
  tag Remedy: "Execute Following psql statement: alter system set log_temp_files = 0;"
  ref 'About work_mem', url: 'https://www.citusdata.com/blog/2018/06/12/configuring-work-mem-on-postgres/#:~:text=work_mem%20is%20a%20configuration%20within,before%20writing%20data%20to%20disk.'
  desc "Temporary files are created for sorts, hashes, and temporary query results when these
        operations exceed work_mem . A log entry is made for each temporary file when it is deleted.
        Setting log_temp_files to 0 causes all temporary file information to be logged, while
        positive values log only files whose size is greater than or equal to the specified number of
        kilobytes. A value of -1 disables temporary file information logging."
  # describe postgres_session(USER, PASSWORD, HOST).query('show log_temp_files ;') do
  # its('output') { should  eq '0' }
  # end
  describe sql.query('show log_temp_files ;', ['postgres']) do
    its('output') {  should  eq '0' }
  end
end
