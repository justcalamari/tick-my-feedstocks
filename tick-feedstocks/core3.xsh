from base64 import b64encode
from base64 import b64decode
import codecs
import os
from collections import defaultdict
from collections import namedtuple
import github3
from pkg_resources import parse_version
import re
import requests
import subprocess
import yaml
from jinja2 import UndefinedError
from jinja2 import Template


def pypi_version(meta_yaml, package_name, gh):
    splitter = '-{}.'.format(meta_yaml['package']['version'])

    r = requests.get('https://pypi.python.org/pypi/{}/json'.format(
        package_name))
    if not r.ok:
        print('Could not find version on pypi', package_name)
        return False
    return r.json()['info']['version'].strip()


def gh_version(meta_yaml, package_name, gh):
    splitter = '-{}.'.format(meta_yaml['package']['version'])

    split_url = meta_yaml['source']['url'].lower().split('/')
    package_owner = split_url[split_url.index('github.com') + 1]
    # get all the tags
    repo = gh.repository(package_owner, package_name)
    if not repo:
        print("could not find repo", package_name)
        return False

    rels = [r.tag_name for r in repo.iter_releases()]
    if len(rels) == 0:
        print("no releases found", package_name)
        return False

    return max(rels)

def parsed_meta_yaml(text):
    """
    :param str text: The raw text in conda-forge feedstock meta.yaml file
    :return: `dict|None` -- parsed YAML dict if successful, None if not
    """
    try:
        yaml_dict = yaml.load(Template(text).render())
    except UndefinedError:
        # assume we hit a RECIPE_DIR reference in the vars and can't parse it.
        # just erase for now
        try:
            yaml_dict = yaml.load(
                Template(
                    re.sub('{{ (environ\[")?RECIPE_DIR("])? }}/', '',
                           text)
                ).render())
        except:
            return None
    except:
        return None

    return yaml_dict

def source_location(meta_yaml):
    try:
        if 'github.com' in meta_yaml['source']['url']:
            return 'github'
        elif 'pypi.python.org' in meta_yaml['source']['url']:
            return 'pypi'
        else: return None
    except KeyError:
        return None

sl_map = {'pypi': {'version': pypi_version},
          'github': {'version': gh_version}}

def get_latest_version(meta_yaml, feedstock, gh):
    sl = source_location(meta_yaml)
    if sl is None:
        print('Not on GitHub or pypi', feedstock.full_name)
        return False
    rv = sl_map[sl]['version'](meta_yaml, feedstock.full_name[12:-10], gh)
    return rv

def get_versions(feedstock, gh):
    meta_yaml = feedstock.contents('recipe/meta.yaml')
    if meta_yaml is None:
        return None

    text = codecs.decode(b64decode(meta_yaml.content))
    yaml_dict = parsed_meta_yaml(text)
    if yaml_dict is None:
        return None

    try:
        version = str(yaml_dict['package']['version']).strip()
    except KeyError:
        return None

    latest_version = get_latest_version(yaml_dict, feedstock, gh)
    if latest_version is False:
        return None

    return version, latest_version

def main():
    user = os.environ.get('GH_USER')
    password = os.environ.get('GH_PASSWORD')
    
    gh = github3.login(user, password)
    org = gh.organization('conda-forge')
    for repo in org.iter_repos():
        if repo.full_name[:12] == 'conda-forge/' and repo.full_name[-10:] == '-feedstock':
            ver = get_versions(repo, gh)
            if ver: print(repo.full_name, ver[0], ver[1])


if __name__ == "__main__":
    main()
