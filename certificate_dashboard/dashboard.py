from flask import Flask, render_template
import json
import requests
import ssl
from datetime import datetime
import logging
import jsonschema
from jsonschema import validate
from OpenSSL import crypto
import socket

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load dashboard configuration
with open('config/dashboard_config.json') as dashboard_config_file:
    dashboard_config = json.load(dashboard_config_file)

# Load dashboard schema
with open('config/dashboard_schema.json') as dashboard_schema_file:
    dashboard_schema = json.load(dashboard_schema_file)


def check_ssl_cert(endpoint):
    try:
        response = requests.get(endpoint, verify=True)
        response_cert_info = response.content
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, response_cert_info)
        cert_expiry_date = datetime.strptime(x509.get_notAfter().decode('utf-8'), '%Y%m%d%H%M%SZ')
        days_until_expiry = (cert_expiry_date - datetime.utcnow()).days

        common_name = x509.get_subject().commonName  # Extract the Common Name

        if days_until_expiry <= 30:
            return 'Red', common_name, cert_expiry_date
        elif days_until_expiry <= 90:
            return 'Amber', common_name, cert_expiry_date
        else:
            return 'Green', common_name, cert_expiry_date

    except requests.exceptions.RequestException as e:
        logger.error("Error while connecting to endpoint %s: %s", endpoint, e)
        return 'Unknown', '', None
    except ssl.SSLError as e:
        logger.error("SSL Error while checking certificate for endpoint %s: %s", endpoint, e)
        return 'Unknown', '', None
    except Exception as e:
        logger.error("Error while checking certificate for endpoint %s: %s", endpoint, e)
        return 'Unknown', '', None


@app.route('/')
def dashboard():
    results = []

    try:
        # Validate the dashboard configuration against the schema
        validate(instance=dashboard_config, schema=dashboard_schema)

        for app_name, app_config in dashboard_config['applications'].items():
            for config in app_config:
                server_type = config['server_type']
                for server in config['servers']:
                    if server['cert_type'] == 'pem':
                        endpoint = server['endpoint']
                        cert_status, common_name, cert_expiry_date = check_ssl_cert(endpoint)

                        results.append({
                            'application': app_name,
                            'server_type': server_type,
                            'server': server['server_name'],
                            'endpoint': endpoint,
                            'cert_status': cert_status,
                            'common_name': common_name,
                            'cert_expiry_date': cert_expiry_date
                        })

    except jsonschema.ValidationError as e:
        logger.error("Dashboard configuration validation failed: %s", e)

    return render_template('dashboard.html', results=results)


if __name__ == '__main__':
    app.run(debug=True)
