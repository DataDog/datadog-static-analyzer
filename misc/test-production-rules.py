# This script is used only for CI/CD purposes
# We assume that everything is correctly built and available in the `target` directory.
import base64
import json
import optparse
import os.path
import random
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

import requests
import sys

parser = optparse.OptionParser()
parser.add_option(
    "-r", "--ruleset", dest="ruleset", help="ruleset to test",
)
parser.add_option(
    "-c", "--cli-bin", dest="clibin", help="path to cli binary",
)
parser.add_option(
    "-s", "--server-bin", dest="serverbin", help="path to server binary",
)
parser.add_option(
    "-d", "--debug", dest="debug", help="use debug (true/false)",
)

(options, args) = parser.parse_args()

use_debug = False

if not options.ruleset:
    print("please specify a rule to test with option -r ")
    sys.exit(1)

if not options.clibin:
    print("please specify cli binary with option -c")
    sys.exit(1)

if not options.serverbin:
    print("please specify cli binary with option -s")
    sys.exit(1)

if options.debug and options.debug == "true":
    use_debug = True

if not os.path.isfile(options.clibin):
    print(f"file {options.clibin} does not exists")
    sys.exit(1)

if not os.path.isfile(options.serverbin):
    print(f"file {options.serverbin} does not exists")
    sys.exit(1)

def fetch_ruleset(ruleset_name: str):
    """
    Fetch a ruleset from the datadog public API
    :param ruleset_name:
    :param site:
    :return:
    """
    url: str = f"https://api.datadoghq.com/api/v2/static-analysis/rulesets/{ruleset_name}"


    response = requests.get(url, timeout=10)

    if response.status_code != 200:
        print(f"ruleset {ruleset_name} not found")
        sys.exit(1)

    return response.json()


def ping_server(port):
    try:
        r = requests.get(f"http://localhost:{port}/version")
        if r.status_code != 200:
            return False
        return True
    except requests.exceptions.ConnectionError:
        return False

def start_server(port):
    pid = os.spawnl(os.P_NOWAIT, options.serverbin, options.serverbin, "-p", str(port))
    while True:
        if ping_server(port):
            break
        time.sleep(1.0)
        print(f"waiting for server to start on port {port}")
    return pid

def stop_server(server_pid):
    os.kill(server_pid, signal.SIGKILL)

def test_ruleset_server(ruleset, port):
    print(f"Testing ruleset {ruleset['data']['id']} on the server")
    rules = ruleset['data']['attributes']['rules']

    for rule in rules:
        print(f"   Testing rule {rule['name']}")

        # for each test of the rule
        for test in rule['tests']:
            test_code = test['code']
            test_file = test['filename']
            test_annotations_count = int(test['annotation_count'])

            payload = {
                "code": test_code,
                "file_encoding": "utf-8",
                "filename": test_file,
                "language": rule['language'],
                "rules": [transform_rule(rule)]
            }

            req = requests.post(f"http://localhost:{port}/analyze", json=payload)

            response = req.json()

            test_results = response['rule_responses']
            if len(test_results) == 0:
                results_annotations_count = 0
            else:
                results_annotations_count = len(test_results[0]['violations'])

            if results_annotations_count != test_annotations_count:
                print(f"number of annotations mistmatch for rule {rule['name']}")
                print(f"Expected number of annotations: {test_annotations_count}")
                print(f"Got number of annotations: {results_annotations_count}")
                sys.exit(1)


def transform_rule(rule):
    """
    Make sure we adapt the rule and put the right elements in the JSON file before passing it
    to the analyzer
    """
    return {
        "id": rule['name'],
        "name": rule['name'],
        "description": rule['description'],
        "category": rule['category'],
        "severity": rule['severity'],
        "rule_type": rule['type'],
        "type": rule['type'],
        "language": rule['language'],
        "tests": [],
        "tree_sitter_query": rule['tree_sitter_query'],
        'code': rule['code'],
        'variables': {},
        'checksum': rule['checksum']
    }

def test_ruleset_cli(ruleset):
    """
    Test a ruleset for the CLI.

    For each test of each rule, write the test, invoke the rule and compare the number of violations
    with the number of expected violations.

    If there is a violation mismatch (e.g. what is detected does not match what is expected, exit the process)

    :param ruleset:
    :return:
    """
    print(f"Testing ruleset {ruleset['data']['id']} on the CLI")
    rules = ruleset['data']['attributes']['rules']

    # Temporary directory to test, we will remove at the end
    testdir = tempfile.mkdtemp()
    for rule in rules:
        print(f"   Testing rule {rule['name']}")
        ruledir = os.path.join(testdir, rule['name'])
        os.makedirs(ruledir)

        # for each test of the rule
        for test in rule['tests']:
            test_code = test['code']
            test_file = test['filename']
            test_annotations_count = int(test['annotation_count'])
            test_file_path = os.path.join(ruledir, test_file)
            test_dirname = os.path.dirname(test_file_path)

            # make sure all directories for the test file are created in case there is a test
            # file with a directory inside
            if not os.path.exists(test_dirname):
                os.makedirs(os.path.dirname(test_file_path))
            test_results_file = os.path.join(ruledir, f"{test_file}.results")
            test_rules_file = os.path.join(ruledir, f"{test_file}.datadog.rules")
            with open(test_file_path, "w") as f:
                f.write(base64.b64decode(test_code).decode('utf-8'))

            # Write the rule as a JSON object
            with open(test_rules_file, "w") as f:
                r = {
                    'name': ruleset['data']['id'],
                    'description': ruleset['data']['attributes']['description'],
                    'rules': [transform_rule(rule)],
                }
                rulesets = [r]
                f.write(json.dumps(rulesets))

            # Invoke the tool, do not print anything
            cmd = f"{options.clibin} -r {test_rules_file} -i {ruledir} -o {test_results_file} -f json"
            if use_debug:
                # rust-gdb -ex run --args ./target/release/datadog-static-analyzer -i /home/ubuntu/cloud-tf-ci/ -o plop.json -f sarif
                cmd = f"{os.environ['HOME']}/.cargo/bin/rust-gdb -ex run --args {options.clibin} -r {test_rules_file} -i {ruledir} -o {test_results_file} -f json"

            subprocess.run(shlex.split(cmd), check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # check that the number of violations match the number of expected annotations
            with open(test_results_file) as results_file:
                results = results_file.read()
                test_results = json.loads(results)
                if len(test_results) == 0:
                    print(f"rule {rule['name']}, test {test_file} does not create results")
                    sys.exit(1)

                results_annotations_count = len(test_results[0]['violations'])

                if results_annotations_count != test_annotations_count:
                    print(f"number of annotations mistmatch for rule {rule['name']}")
                    print(f"Expected number of annotations: {test_annotations_count}")
                    print(f"Got number of annotations: {results_annotations_count}")
                    print(f"Command executed: {cmd}")
                    sys.exit(1)
            os.remove(test_file_path)


    # remove directory to test
    shutil.rmtree(testdir)


ruleset = fetch_ruleset(options.ruleset)

if ruleset is None:
    print("ruleset not found")
    sys.exit(1)


# First, get all the tests running on the CLI
test_ruleset_cli(ruleset)

# Then, get all the tests running on the server
# Get a post to run the server
port = random.randint(4000, 9000)
print(f"testing server on port {port}")

# Start the server
server_pid = start_server(port)

# Execute all tests
test_ruleset_server(ruleset, port)


# The server should still be running and respond to ping requests
if not ping_server(port):
    print("server not active after testing")
    sys.exit(1)

stop_server(server_pid)

sys.exit(0)
