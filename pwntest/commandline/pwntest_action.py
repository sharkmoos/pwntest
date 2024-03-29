"""
TODO:
    - Add cmdline option to add an action that generates actions on push
    - Create more veritile "runs-on" logic, to allow for github or self-hosted runners
    as a cmdline argument
"""
import argparse
import logging
import pathlib
import datetime
import jinja2
import os

import pathlib
from ruamel.yaml import YAML

import pwnlib.log

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class ActionBuilder:
    def __init__(self, manifest_file):
        self.run_on_changed = None
        self.manifest_file = manifest_file
        self.file_path = ".github/workflows/pwntest.yml"
        self.backup_file_path = ".github/workflows/pwntest.yml.bak"
        self.environment: jinja2.environment.Environment = jinja2.Environment(
            loader=jinja2.FileSystemLoader("."))

        self.template_file = "pwntest/commandline/test_action.jinja"
        self.template = self.environment.get_template(self.template_file)

    def save_old_action(self):
        with open(self.file_path, "rb") as f:
            with open(self.backup_file_path, "wb") as b:
                b.write(f.read())

    def create_action(self, challenge_name: str, challenge_data: dict, runs_on: str = "self-hosted"):
        """
        Create a GitHub action for a challenge

        :param challenge_name:
        :param challenge_data:
        :return:
        """

        challenge_author: str = challenge_data.get("author")
        challenge_path: str = challenge_data.get("directory")
        uses_poetry: bool = False
        challenge_reqs = None
        docker_path = None

        if "requirements" in challenge_data:
            if "poetry" not in challenge_data.get("requirements")[0]:
                reqs: list = []
                if os.path.isfile(challenge_data.get("requirements")[0]):
                    req_file = challenge_data.get("requirements")[0]
                    with open(req_file, "r") as f:
                        requirements = f.readlines()
                    for req in requirements:
                        reqs.append(req.strip())
                else:
                    reqs = challenge_data.get("requirements")

                challenge_reqs: str = " " + " ".join(reqs)
            else:
                uses_poetry = True
                # get path to directory from path to file
                challenge_reqs = pathlib.Path(challenge_data.get("requirements")[0]).parent

        if "docker" in challenge_data:
            ports: str = challenge_data.get("docker").get("ports")
            inline_ports: str = "".join(
                " -p '%s'" % port.replace("'", "".replace('"', ""))
                for port in ports
            )

            docker_path: str = challenge_data.get("docker").get("docker_path")
            is_docker: bool = True
        else:
            inline_ports = ""
            challenge_ports = None
            docker_path = ""
            is_docker = False

        log.debug("Creating action for %s", challenge_name)
        log.debug("Author: %s", challenge_author)
        log.debug("Path: %s", challenge_path)
        log.debug("Port: %s", inline_ports)
        log.debug("Docker Path: %s", docker_path)
        log.debug("Requirements: %s\n\n", challenge_reqs)

        with open(f".github/workflows/{challenge_name}.yml", "wt") as out_file:
            out_file.write(
                self.template.render(
                    {
                        "DATETIME": datetime.datetime.now(),
                        "TEST_CASE_NAME": challenge_name,
                        "AUTHOR": challenge_author,
                        # "PORT": challenge_ports,
                        "TEST_CASE_NAME_PATH": docker_path,
                        "CHALLENGE_PATH": challenge_path if challenge_path.endswith("/") else challenge_path + "/",
                        "DOCKER": is_docker,
                        "RUNS_ON": runs_on,
                        "INLINE_PORTS": inline_ports,
                        "REQUIREMENTS": challenge_reqs,
                        "POETRY": uses_poetry,
                        "RUN_ON_CHANGE": self.run_on_changed
                    }
                ))

    def auto_regen(self, runs_on: str = "self-hosted"):
        """
        Action to regenerate actions
        :return:
        """

        template = self.environment.get_template(
            "pwntest/commandline/repeat_action.jinja"
        )

        log.info("Creating auto regen action with manifest: '%s'", self.manifest_file)
        with open(f".github/workflows/rebuild_tests.yml", "wt") as out_file:
            out_file.write(
                template.render(
                    {
                        "MANIFEST_PATH": self.manifest_file,
                        "RUN_ON_CHANGED": self.run_on_changed,
                        "RUNS_ON": runs_on,
                    }
                ))
    def get_challenge_objects(self):
        yaml = YAML()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.preserve_quotes = True

        try:
            with open(self.manifest_file, "r") as f:
                manifest = yaml.load(f)
        except AttributeError:
            print("Error: Manifest file is not a valid YAML file")
            exit(1)
        return manifest


def main(args):
    if not os.path.isfile(args.manifest):
        print("Error: Manifest file does not exist")
        exit(1)

    # the manifest describes the challenges
    mapper: ActionBuilder = ActionBuilder(args.manifest)
    # additional setting for how to run the action
    mapper.run_on_changed = args.run_on_changed
    # mapper.save_old_action()
    manifest: dict = mapper.get_challenge_objects()

    for item in manifest:
        # log.debug("Item: %s", item)
        challenge_data = manifest.get(item)
        mapper.create_action(item, challenge_data)

    if args.auto_regen:
        # TODO: make the autoregen code
        mapper.auto_regen()
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='build_action',
        description='Build a GitHub action from a YML manifest',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("-r", "--run_on_changed", action="store_true",
                        default=False,
                        help="Run only on changed files. By default, all tests run")

    parser.add_argument("-a", "--auto_regen", action="store_true",
                        default=False,
                        help="Automatically actions using this script")

    parser.add_argument("-m", '--manifest', type=str,
                        required=True, help='Path to the manifest file')

    arguments = parser.parse_args()
    main(arguments)
