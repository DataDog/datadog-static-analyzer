# This script is used only for CI/CD purposes
# We assume that everything is correctly built and available in the `target` directory.

# If you want to try this locally
# 1. Build the binary locally (e.g. cargo build --profile release-dev)
# 2. Bootstrap a Python environment with requests (e.g python -mvenv venv && source venv/bin/activate && pip install requests)
# 3. Execute the script: python misc/test-rules.py -l <LANGUAGE> -c target/release-dev/datadog-static-analyzer -s target/release-dev/datadog-static-analyzer-server
# Example: python misc/test-rules.py -l python -c target/release-dev/datadog-static-analyzer -s target/release-dev/datadog-static-analyzer-server

import base64
import json
import optparse
import os.path
import os
import shlex
import shutil
import signal
import subprocess
import tempfile
import time

import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

RETRY_DELAY = 1

parser = optparse.OptionParser()
parser.add_option(
    "-l", "--language", dest="language", help="language to test",
)
parser.add_option(
    "-c", "--cli-bin", dest="clibin", help="path to cli binary",
)
parser.add_option(
    "-s", "--server-bin", dest="serverbin", help="path to server binary",
)

(options, args) = parser.parse_args()

if not options.language:
    print("please specify a language to test with option -l")
    sys.exit(1)

if not options.clibin:
    print("please specify cli binary with option -c")
    sys.exit(1)

if not options.serverbin:
    print("please specify cli binary with option -s")
    sys.exit(1)

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
    :return:
    """

    if "DD_SITE" not in os.environ:
        print("DD_SITE environment variable not set")
        sys.exit(1)
    dd_site = os.environ["DD_SITE"]

    url: str = f"https://api.{dd_site}/api/v2/static-analysis/rulesets/{ruleset_name}"

    for _ in range(5):
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        time.sleep(RETRY_DELAY)

    print(f"[{response.status_code} failed to get ruleset {ruleset_name}")
    sys.exit(1)


def fetch_default_ruleset(language: str):
    """
    Fetch the default rulesets for a language
    :param language:
    :return:
    """

    if 'DD_SITE' not in os.environ:
        print("DD_SITE environment variable not set")
        sys.exit(1)
    dd_site = os.environ["DD_SITE"]

    url = f"https://api.{dd_site}/api/v2/static-analysis/default-rulesets/{language}"

    for _ in range(5):
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return response.json()
        time.sleep(RETRY_DELAY)

    print(f"[{response.status_code}] failed to get default ruleset for language {language}")
    sys.exit(1)


def ping_server(port: int):
    try:
        r = requests.get(f"http://localhost:{port}/version")
        if r.status_code != 200:
            return False
        return True
    except requests.exceptions.ConnectionError:
        return False


# Gets a currently free port. (note: this is subject to race conditions, and so isn't guaranteed)
def get_free_port() -> int | None:
    import socket

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            port: int = s.getsockname()[1]
            return port
    except OSError:
        return None


def start_server():
    # The maximum number of times to try to find a port
    MAX_STARTS = 10
    # The maximum number of times to try to ping a server
    MAX_PINGS = 5
    port = -1
    pid = -1
    for _ in range(MAX_STARTS):
        port = get_free_port()
        if port is None:
            continue
        try:
            pid = os.spawnl(
                os.P_NOWAIT, options.serverbin, options.serverbin, "-p", str(port)
            )
            break
        except:
            time.sleep(0.1)
    if port == -1 or port is None:
        print(f"Error: unable to find a free port after {MAX_STARTS} attempts")
        sys.exit(1)
    for ping_attempt in range(MAX_PINGS):
        if ping_server(port):
            return port, pid
        time.sleep(1.0)
        print(f"waiting for server to start on port {port}")
    print(f"Error: unable start a server after {MAX_STARTS} attempts")
    sys.exit(1)

def stop_server(server_pid: int):
    os.kill(server_pid, signal.SIGKILL)

def test_ruleset_server(ruleset, port: int):
    def post_request(payload):
        req = requests.post(f"http://localhost:{port}/analyze", json=payload)
        return req.json()

    print(f"Testing ruleset {ruleset['data']['id']} on the server")
    rules = ruleset['data']['attributes']['rules']

    with ThreadPoolExecutor() as executor:
        futures = []

        for rule in rules:
            print(f"   [{rule['name']}] Testing rule")

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

                futures.append((executor.submit(post_request, payload), rule['name'], test_annotations_count))

        for future, rule_name, test_annotations_count in futures:
            response = future.result()
            test_results = response['rule_responses']
            if len(test_results) == 0:
                results_annotations_count = 0
            else:
                results_annotations_count = len(test_results[0]['violations'])

            if results_annotations_count != test_annotations_count:
                print(f"[{rule['name']}] number of annotations mismatch (expected: {test_annotations_count}, got: {results_annotations_count})")
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
        'checksum': rule['checksum'],
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
            # TODO: There should be a cleaner way to be able to parse the output of the error
            try:
                subprocess.run(shlex.split(cmd), check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                raise RuntimeError("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))
            
            # check that the number of violations match the number of expected annotations
            with open(test_results_file) as results_file:
                results = results_file.read()
                test_results = json.loads(results)

                try:
                    results_annotations_count = len(test_results[0]['violations'])
                except IndexError:
                    # A rule result entry will only be created for a scan that produced at least one violation
                    results_annotations_count = 0

                if results_annotations_count != test_annotations_count:
                    print(f"number of annotations mismatch for rule {rule['name']}")
                    print(f"Expected number of annotations: {test_annotations_count}")
                    print(f"Got number of annotations: {results_annotations_count}")
                    print(f"Command executed: {cmd}")
                    sys.exit(1)
            os.remove(test_file_path)


    # remove directory to test
    shutil.rmtree(testdir)

rulesets_response = fetch_default_ruleset(options.language)

if not rulesets_response:
    print(f"cannot fetch default rulesets for language {options.language}")
    sys.exit(1)

rulesets = rulesets_response['data']['attributes']['rulesets']

for ruleset_name in rulesets:
    print(f"==== Starting testing ruleset {ruleset_name} ====")
    ruleset = fetch_ruleset(ruleset_name)

    if ruleset is None:
        print("ruleset not found")
        sys.exit(1)


    # First, get all the tests running on the CLI
    test_ruleset_cli(ruleset)

    # Start the server
    port, server_pid = start_server()
    print(f"testing server on port {port}")

    # Execute all tests
    test_ruleset_server(ruleset, port)


    # The server should still be running and respond to ping requests
    if not ping_server(port):
        print("server not active after testing")
        sys.exit(1)
    print(f"==== Done testing ruleset {ruleset_name} ====")
    stop_server(server_pid)

sys.exit(0)
