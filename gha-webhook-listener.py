#!/usr/bin/env python
#
# auto-deploy listener script
#
# Listens for Github webhook pokes. When it gets one, downloads the artifact
# from Github and unpacks it.
#
# Copyright 2019 New Vector Ltd
# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from __future__ import print_function

import argparse
from dateutil import parser as dateparser
import errno
import logging
import glob
import hashlib
import hmac
from io import BytesIO
import os
import re
import shutil
import tarfile
import threading
import zipfile

from flask import Flask, abort, jsonify, request
import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

app = Flask(__name__)

arg_extract_path = None
arg_symlink = None
arg_webhook_token = None
arg_api_token = None
arg_artifact_pattern = None
arg_keep_versions = None

deploy_lock = threading.Lock()


def create_symlink(source, linkname):
    try:
        logger.info("Symlinking %s->%s", linkname, source)
        os.symlink(source, linkname)
    except OSError as e:
        if e.errno == errno.EEXIST:
            # atomic modification
            os.symlink(source, linkname + ".tmp")
            os.rename(linkname + ".tmp", linkname)
        else:
            raise e


def req_headers():
    return {
        "Authorization": "token %s" % (arg_api_token,),
    }


def validate_signature(data, signature, token):
    github_secret = bytes(token, 'utf-8')
    expected_signature = hmac.new(key=github_secret, msg=data, digestmod=hashlib.sha256).hexdigest()
    signature = signature.split('sha256=')[-1].strip()
    return hmac.compare_digest(signature, expected_signature)


@app.route("/", methods=["POST"])
def on_receive_poke():
    incoming_signature = request.headers.get('X-Hub-Signature-256')
    incoming_data = request.data

    if not validate_signature(incoming_data, incoming_signature, arg_webhook_token):
        logger.info("Denying request with incorrect webhook token: %s", got_webhook_token)
        abort(400, "Incorrect webhook token")
        return

    required_api_prefix = None
    if arg_github_org is not None:
        required_api_prefix = f'https://api.github.com/repos/{arg_github_org}/matrix.org/actions/artifacts'

    incoming_json = request.get_json()
    if not incoming_json:
        abort(400, "No JSON provided!")
        return
    logger.debug("Incoming JSON: %s", incoming_json)

    action = incoming_json.get("action")
    if action is None:
        abort(400, "No 'action' specified")
        return

    if action == "completed":
        logger.info("Workflow completed")
    else:
        abort(400, "Not a suitable event")
        return

    workflow_status = incoming_json["workflow_run"]["conclusion"]
    if workflow_status == "success":
        logger.info("Workflow succeeded")
    else:
        logger.info("Rejecting '%s' event", event)
        abort(400, "Unrecognised event")
        return

    build_id = incoming_json["workflow_run"]["id"]
    if build_id is None:
        abort(400, "No 'id' specified")
        return

    workflow_id = incoming_json["workflow_run"]["workflow_id"]
    if workflow_id is None:
        abort(400, "No 'workflow_id' specified")
        return

    artifacts_url = incoming_json["workflow_run"]["artifacts_url"]
    if artifacts_url is None:
        abort(400, "No 'artifacts_url' specified")
        return

    logger.info("Fetching %s", artifacts_url)
    artifacts_resp = requests.get(artifacts_url, headers=req_headers())
    artifacts_resp.raise_for_status()
    artifacts_array = artifacts_resp.json()['artifacts']

    artifact_to_deploy = None
    for artifact in artifacts_array:
        logging.info("Artifact name is %s", artifact['name'])
        if re.match(arg_artifact_pattern, artifact['name']):
            artifact_to_deploy = artifact

    if artifact_to_deploy is None:
        logger.info("No suitable artifacts found")
        return jsonify({})

    # double paranoia check: make sure the artifact is on the right org too
    url = artifact_to_deploy['archive_download_url']
    if required_api_prefix is not None and not url.startswith(required_api_prefix):
        logger.info("Denying poke for build url with incorrect prefix: %s", url)
        abort(400, "Refusing to deploy artifact from URL %s", url)
        return

    # we extract into a directory based on the build number. This avoids the
    # problem of multiple builds building the same git version and thus having
    # the same tarball name. That would lead to two potential problems:
    #   (a) if we only get half the tarball, we'd replace
    #       a good deploy with a bad one
    #   (b) we'll be overwriting the live deployment, which means people might
    #       see half-written files.
    target_dir = os.path.join(arg_extract_path, "%s-#%i" % (workflow_id, build_id))
    if os.path.exists(target_dir):
        abort(400, "Not deploying. We have previously deployed this build.")

    # Github might time out the request if it takes longer than 10s, and fetching
    # the tarball may take some time, so we return success now and run the
    # download and deployment in the background.
    versions_to_keep = arg_keep_versions
    cleanup_dir = arg_extract_path
    def deploy():
        logger.info("awaiting deploy lock")
        with deploy_lock:
            logger.info("Got deploy lock; deploying to %s", target_dir)
            deploy_tarball(url, target_dir)
            if versions_to_keep is not None:
                tidy_extract_directory(target_dir, cleanup_dir, versions_to_keep)

    threading.Thread(target=deploy).start()

    return jsonify({})


def deploy_tarball(artifact_url, target_dir):
    """Download a tarball from Github and unpack it

    Returns:
        (str) the path to the unpacked deployment
    """

    os.mkdir(target_dir)

    logger.info("Fetching artifact %s -> %s...", artifact_url, target_dir)

    resp = requests.get(artifact_url, stream=True, headers=req_headers())
    resp.raise_for_status()

    # GHA artifacts are wrapped in a zip file, so we extract it to get our tarball
    # See https://github.com/actions/upload-artifact/issues/109
    zipped_artifact = zipfile.ZipFile(BytesIO(resp.content))
    tarball = zipped_artifact.open('content.tar.gz')

    # TODO: make the compression type depend on the filename
    # (or copy it to a temporary file so that tarfile can autodetect)
    with tarfile.open(fileobj=tarball, mode="r:gz") as tar:
        tar.extractall(path=target_dir)
    logger.info("...download complete.")

    create_symlink(source=target_dir, linkname=arg_symlink)
    

def tidy_extract_directory(target_dir, cleanup_dir, versions_to_keep):
    """
    Remove all but the last arg_keep_versions in the directory.
    Will never remove the target_dir that we just deployed.
    Will only consider directories that match the pattern.

    Args:
       target_dir: absolute path to where the most recent deployment was unpacked
       cleanup_dir: absolute path to the directory where files are unpacked
       versions_to_keep: count of versions to keep
    """
    directories = glob.glob(cleanup_dir + "/*-#*")
    directories.sort(key = lambda x: os.path.getmtime(x))
    to_delete = directories[:-versions_to_keep]
    logger.info("Deleting %i of %i directories", len(to_delete), len(directories))
    for target in to_delete:
        if target != target_dir:
            logger.info("Deleting %s", target)
            shutil.rmtree(target)
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Runs a redeployment server.")
    parser.add_argument(
        "-p", "--port", dest="port", default=4000, type=int, help=(
            "The port to listen on for requests from Github. "
            "Default: %(default)i"
        )
    )
    parser.add_argument(
        "-e", "--extract", dest="extract", default="./extracted", help=(
            "The location to extract .tar.gz files to. "
            "Default: %(default)s"
        )
    )

    parser.add_argument(
        "-s", "--symlink", dest="symlink", default="./latest", help=(
            "Write a symlink to this location pointing to the extracted "
            "tarball. New builds will keep overwriting this symlink. "
            "Default: %(default)s"
        )
    )

    parser.add_argument(
        "--webhook-token", dest="webhook_token", help=(
            "Only accept pokes with this Github token."
        ), required=True,
    )

    parser.add_argument(
        "--api-token", dest="api_token", help=(
            "API access token for Github. Requires repo scope."
        ), required=True,
    )

    # We require a matching webhook token, but because we take everything else
    # about what to deploy from the poke body, we can be a little more paranoid
    # and only accept builds / artifacts from a specific Github org
    parser.add_argument(
        "--org", dest="github_org", help=(
            "Lock down to this Github org"
        )
    )

    parser.add_argument(
        "--artifact-pattern", default="merged-content-artifact", help=(
            "Define a regex which artifact names must match. "
            "Default: %(default)s"
        )
    )

    parser.add_argument(
        "--keep-versions", type=int, help=(
            "Retain only this number of versions on disk. Set to a positive "
            "integer. Defaults to keeping all versions."
        )
    )

    args = parser.parse_args()

    if args.keep_versions is not None and args.keep_versions < 1:
        parser.error("keep-versions should be unset or > 0")

    arg_extract_path = args.extract
    arg_symlink = args.symlink
    arg_webhook_token = args.webhook_token
    arg_api_token = args.api_token
    arg_github_org = args.github_org
    arg_artifact_pattern = args.artifact_pattern
    arg_keep_versions = args.keep_versions

    if not os.path.isdir(arg_extract_path):
        os.mkdir(arg_extract_path)

    print(
        "Listening on port %s. Extracting to %s. Symlinking to %s" %
        (
            args.port,
            arg_extract_path,
            arg_symlink,
        ),
        flush=True,
    )
    if arg_keep_versions is not None:
        print(
            "Keeping only previous %i versions." % (arg_keep_versions, ),
            flush=True,
        )
    else:
        print("Keeping all versions") 

    app.run(port=args.port, debug=False)
