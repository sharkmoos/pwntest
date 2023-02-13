import argparse
import logging
import pathlib
import datetime
import jinja2

from ruamel.yaml import YAML

import pwnlib.log

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


class ActionBuilder:
    def __init__(self, manifest_file):
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

    def create_action(self, challenge_name: str, challenge_data: dict):
        """
        Create a GitHub action for a challenge

        :param challenge_name:
        :param challenge_data:
        :return:
        """
        challenge_author = challenge_data.get("author")
        challenge_path = challenge_data.get("directory")

        if "docker" in challenge_data:
            ports = challenge_data.get("docker").get("ports")
            inline_ports = " -p ".join(ports)

            docker_path = challenge_data.get("docker").get("docker_path")
            is_docker = True
        else:
            inline_ports = None
            challenge_ports = None
            docker_path = None
            is_docker = False

        log.debug("Creating action for %s", challenge_name)
        log.debug("Author: %s", challenge_author)
        log.debug("Path: %s", challenge_path)
        log.debug("Port: %s", inline_ports)
        log.debug("Docker Path: %s\n\n", docker_path)

        if "runs_on" in challenge_data:
            runs_on = challenge_data.get("runs_on")
        else:
            runs_on = "self-hosted"

        with open(f".github/workflows/{challenge_name}.yml", "wt") as out_file:
            out_file.write(
                self.template.render(
                    {
                        "TEST_CASE_NAME": challenge_name,
                        # "PORT": challenge_ports,
                        "TEST_CASE_NAME_PATH": docker_path,
                        "DOCKER": is_docker,
                        "RUNS_ON": runs_on,
                        "INLINE_PORTS": inline_ports
                    }
                ))

    def get_challenge_objects(self):
        yaml = YAML()
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.preserve_quotes = True

        with open(self.manifest_file, "r") as f:
            manifest = yaml.load(f)

        manifest.yaml_set_start_comment(f"This file is automatically generated by"
                                        f" pwntest on {datetime.datetime.now()}")

        for item in manifest:
            # log.debug("Item: %s", item)
            challenge_data = manifest.get(item)
            self.create_action(item, challenge_data)


def main(args):
    mapper = ActionBuilder(args.manifest)
    # mapper.save_old_action()
    mapper.get_challenge_objects()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='build_action',
        description='Build a GitHub action from a YML manifest',
        epilog='Text at the bottom of help')

    parser.add_argument("-m", '--manifest', type=str, help='The manifest '
                                                           'file to build the '
                                                           'github action from')

    args = parser.parse_args()
    main(args)
