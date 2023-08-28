import json
import os
import shutil

import jsonschema
import paramiko
from jsonschema import validate


# Function to copy file
def copy_file(source, target):
    try:
        shutil.copy2(source, target)
        print(f"File copied from {source} to {target}")
    except Exception as e:
        print(f"Error copying file from {source} to {target}: {e}")


# Function to copy certificate
def copy_certificate(cert_entry, current_hostname, current_username):
    cert_file = cert_entry.get('cert_file')
    source_location = cert_entry.get('source_location')
    target_location = cert_entry.get('target_location')
    target_filename = cert_entry.get('target_filename')
    ssh_key = cert_entry.get('ssh_key')
    ssh_username = cert_entry.get('ssh_username')
    ssh_hostname = cert_entry.get('ssh_hostname')

    if source_location and target_location and target_filename:
        source_path = os.path.join(source_location, cert_file)
        target_path = os.path.join(target_location, target_filename)

        if ssh_username == current_username and ssh_hostname == current_hostname:
            # Copy locally
            shutil.copy(source_path, target_path)
            print(f'Certificate copied locally to {target_path}')
        else:
            # Copy using SSH
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_key = paramiko.RSAKey.from_private_key_file(ssh_key)

            try:
                ssh_client.connect(ssh_hostname, username=ssh_username, pkey=ssh_key)
                sftp = ssh_client.open_sftp()
                sftp.put(source_path, target_path)
                sftp.close()
                ssh_client.close()
                print(f'Certificate copied remotely to {target_path}')
            except Exception as e:
                print(f'Error copying certificate via SSH: {e}')


# Function to execute command
def execute_cert_command(cert_entry, current_hostname, current_username, ssh_client=None):
    command = cert_entry.get('command')
    ssh_username = cert_entry.get('ssh_username')
    ssh_hostname = cert_entry.get('ssh_hostname')
    ssh_key_filename = cert_entry.get('ssh_key_filename')

    if command:
        if ssh_username == current_username and ssh_hostname == current_hostname:
            os.system(command)
        else:
            execute_remote_command(command, ssh_username, ssh_hostname, ssh_key_filename, ssh_client)


# Function to execute remote command using SSH
def execute_remote_command(command, ssh_username, ssh_hostname, ssh_key_filename, ssh_client):
    try:
        if not ssh_client:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_key = paramiko.RSAKey(filename=ssh_key_filename)
            ssh_client.connect(ssh_hostname, username=ssh_username, pkey=ssh_key)

        stdin, stdout, stderr = ssh_client.exec_command(command)
        print(stdout.read().decode('utf-8'))
        print(stderr.read().decode('utf-8'))
    except Exception as e:
        print(f"Error executing remote command: {e}")


def main():
    # Load certificate manager configuration
    with open('config/certificate_manager_config.json') as cert_manager_config_file:
        cert_manager_config = json.load(cert_manager_config_file)

    # Load certificate manager schema
    with open('config/manager_schema.json') as manager_schema_file:
        manager_schema = json.load(manager_schema_file)

    # Validate configuration against schema
    try:
        validate(instance=cert_manager_config, schema=manager_schema)
    except jsonschema.ValidationError as e:
        print(f"Certificate manager configuration validation failed: {e}")
        return

    # Get the current hostname and username
    current_hostname = os.uname().nodename
    current_username = os.getlogin()

    ssh_client = None
    for cert_entry in cert_manager_config.get('certificates', []):
        copy_certificate(cert_entry, current_hostname, current_username)
        execute_cert_command(cert_entry, current_hostname, current_username, ssh_client)

    if ssh_client:
        ssh_client.close()


if __name__ == '__main__':
    main()
