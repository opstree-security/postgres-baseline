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

control 'postgres-logging-collector' do
    impact 1.0
    title 'Ensure the logging collector is enabled'
    tag Vulnerability: 'High'
    tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
    tag Remedy: "Execute the following SQL statement(s) to remediate this setting:
    postgres=# alter system set logging_collector = 'on';"
    ref 'Postgres logging config', url: 'https://www.postgresql.org/docs/12/static/runtime-config-logging.html'
    desc "The logging collector is a background process that captures log messages sent to stderr
    and redirects them into log files. The logging_collector setting must be enabled in order
    for this process to run. It can only be set at server start."
    # describe postgres_session(USER, PASSWORD, HOST).query('show logging_collector;') do
    #   its('output') { should eq 'on' }
    # end
    describe sql.query('show logging_collector;', ['postgres']) do
        its('output') { should match (/on/) }
    end
end

control 'postgres-logging-connections' do
    impact 1.0
    title 'Ensure log_connections is enabled'
    tag Vulnerability: 'Medium'
    tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
    tag Remedy: "Execute the following SQL statement(s) to remediate this setting:
    postgres=# alter system set log_connections = 'on';"
    ref 'Postgres logging config', url: 'https://www.postgresql.org/docs/12/static/runtime-config-logging.html'
    desc "Enabling the log_connections setting causes each attempted connection to the server to
    be logged, as well as successful completion of client authentication.
    PostgreSQL does not maintain an internal record of attempted connections to the database
    for later auditing. It is only by enabling the logging of these attempts that one can
    determine if unexpected attempts are being made."
    # describe postgres_session(USER, PASSWORD, HOST).query('show log_connections;') do
    #   its('output') { should eq 'on' }
    # end
    describe sql.query('show log_connections;', ['postgres']) do
        its('output') { should match (/on/) }
    end
end

control 'postgres-logging-disconnections' do
    impact 1.0
    title 'Ensure log_disconnections is enabled'
    tag Vulnerability: 'Medium'
    tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
    tag Remedy: "Execute the following SQL statement(s) to remediate this setting:
    postgres=# alter system set log_disconnections = 'on';"
    ref 'Postgres logging config', url: 'https://www.postgresql.org/docs/12/static/runtime-config-logging.html'
    desc "Enabling the log_disconnections setting logs the end of each session, including session
    duration.PostgreSQL does not maintain the beginning or ending of a connection internally for later
    review. It is only by enabling the logging of these that one can examine connections for
    failed attempts, 'over long' duration, or other anomalies.
    "
    # describe postgres_session(USER, PASSWORD, HOST).query('show log_disconnections;') do
    #   its('output') { should eq 'on' }
    # end
    describe sql.query('show log_disconnections;', ['postgres']) do
        its('output') { should match (/on/) }
    end
end

control 'postgres-logging-duration' do
    impact 1.0
    title 'Ensure log_duration is enabled'
    tag Vulnerability: 'Medium'
    tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
    tag Remedy: "Execute the following SQL statement(s) to remediate this setting:
    postgres=# alter system set log_duration = 'on';"
    ref 'Postgres logging config', url: 'https://www.postgresql.org/docs/12/static/runtime-config-logging.html'
    desc "By logging the duration of statements, it is easy to identify both non-performant queries as well as possible DoS attempts (excessively long running queries may be attempts at resource starvation)."
    # describe postgres_session(USER, PASSWORD, HOST).query('show log_disconnections;') do
    #   its('output') { should eq 'on' }
    # end
    describe sql.query('show log_duration;', ['postgres']) do
        its('output') { should match (/on/) }
    end
end

control 'postgres-logging-hostname' do
    impact 1.0
    title 'Ensure log_hostname is set correctly'
    tag Vulnerability: 'Low'
    tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
    tag Remedy: "Execute the following SQL statement(s) to remediate this setting:
    postgres=# alter system set log_hostname='off';"
    ref 'Postgres logging config', url: 'https://www.postgresql.org/docs/12/static/runtime-config-logging.html'
    desc "Enabling the log_hostname setting causes the hostname of the connecting host to be logged
    in addition to the host's IP address for connection log messages. Disabling the setting
    causes only the connecting host's IP address to be logged, and not the hostname. Unless
    your organization's logging policy requires hostname logging, it is best to disable this
    setting so as not to incur the overhead of DNS resolution for each statement that is logged."
    describe sql.query('show log_hostname;', ['postgres']) do
        its('output') { should match (/off/) }
    end
end

control 'postgres-logging-directory-set' do
    impact 1.0
    title 'Ensure log_directory is set'
    tag Vulnerability: 'Medium'
    tag Version: 'PostgreSQL 9.5 Benchmark v1.1.0'
    ref 'Postgres logging config', url: 'https://www.postgresql.org/docs/12/static/runtime-config-logging.html'
    desc "If log_directory is not set, it is interpreted as the absolute path '/' and PostgreSQL will attempt to write its logs there (and typically fail due to a lack of permissions to that directory).
    This parameter should be set to direct the logs into the appropriate directory location as defined by your organization's logging policy."
    describe sql.query('show log_directory;', ['postgres']) do
        its('output') { should_not match (/''/) }
    end
end