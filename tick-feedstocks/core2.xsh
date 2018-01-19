import codecs
import hashlib
import re
import urllib
from base64 import b64decode

import requests
import yaml
from jinja2 import Template
from jinja2 import UndefinedError
from pkg_resources import parse_version
from rever.github import login
from tqdm import tqdm

from .rever import update_feedstock

source_bundle_types = ["tar.gz", "tar.bz2", "zip", "bz2"]


def user_feedstocks(user):
    """
    :param github.AuthenticatedUser.AutheticatedUser user:
    :return: `list` -- list of conda-forge feedstocks the user maintains
    """
    feedstocks = []
    for team in tqdm(user.get_teams()):

        # Each conda-forge team manages one feedstock
        # If a team has more than one repo, skip it.
        if team.repos_count != 1:
            continue

        repo = list(team.get_repos())[0]
        if (repo.full_name[:12] == 'conda-forge/' and
                repo.full_name[-10:] == '-feedstock'):
            feedstocks.append(repo)

    return feedstocks


def stream_url_progress(url, verb='downloading', chunksize=1024):
    """Generator yielding successive bytes from a URL.

    Parameters
    ----------
    url : str
        URL to open and stream
    verb : str
        Verb to prefix the url downloading with, default 'downloading'
    chunksize : int
        Number of bytes to return, defaults to 1 kb.

    Returns
    -------
    yields the bytes which is at most chunksize in length.
    """
    nbytes = 0
    print(verb + ' ' + url)
    with urllib.request.urlopen(url) as f:
        totalbytes = f.length
        while True:
            b = f.read(chunksize)
            lenbytes = len(b)
            nbytes += lenbytes
            if lenbytes == 0:
                break
            else:
                yield b
            if totalbytes is None:
                totalbytes = f.length


def hash_url(url, hash='sha256'):
    """Hashes a URL, with a progress bar, and returns the hex representation"""
    hasher = getattr(hashlib, hash)()
    for b in stream_url_progress(url, verb='Hashing'):
        hasher.update(b)
    return hasher.hexdigest()


def source_location(meta_yaml):
    if 'github' in meta_yaml['source']['url']:
        return 'github'
    else:
        return 'pypi'


def pypi_legacy_json_sha(package_name, version):
    """
    Use PyPI's legacy JSON API to get the SHA256 of the source bundle
    :param str package_name: Name of package (PROPER case)
    :param str version: version for which to get sha
    :return: `tpl(str,str)|tpl(None,None)` -- bundle_type,SHA or None,None
    """
    r = requests.get('https://pypi.org/pypi/{}/json'.format(package_name))
    if not r.ok:
        return None, None
    jsn = r.json()

    if version not in jsn['releases']:
        return None, None

    release = None
    for bundle_type in source_bundle_types:
        try:
            release = next(x for x
                           in jsn['releases'][version]
                           if x['filename'].endswith('.' + bundle_type))
            return bundle_type, release['digests']['sha256']
        except StopIteration:
            # No bundle of target type
            continue
        except KeyError:
            # No key  for the sha.
            release = None

    if release is None:
        return None, None


def pypi_org_sha(package_name, version):
    """
    Scrape pypi.org for SHA256 of the source bundle
    :param str package_name: Name of package (PROPER case)
    :param str version: version for which to get sha
    :return: `str,str|None,None` -- bundle type,SHA for source, None,None if
    can't be found
    """
    import warnings
    from bs4 import BeautifulSoup
    warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

    r = requests.get('https://pypi.org/project/{}/{}/#files'.format(
        package_name,
        version))

    bs = BeautifulSoup(r.text)
    for bundle_type in source_bundle_types:
        try:
            url_pattern = re.compile(
                'https://files.pythonhosted.org.*{}-{}.{}'.format(package_name,
                                                                  version,
                                                                  bundle_type))
            sha_val = bs.find('a', {'href': url_pattern}
                              ).next.next.next['data-clipboard-text']
            return bundle_type, sha_val
        except AttributeError:
            # Bad parsing of page, couldn't get SHA256
            continue

    return None, None


def pypi_checksum(meta_yaml, version):
    splitter = '-{}.'.format(meta_yaml['package']['version'])
    package, _ = meta_yaml['source']['fn'].split(splitter)
    bundle_type, sha = pypi_legacy_json_sha(package, version)
    if bundle_type is not None and sha is not None:
        return sha
    return pypi_org_sha(package, version)[1]


def pypi_version(meta_yaml):
    splitter = '-{}.'.format(meta_yaml['package']['version'])
    package_name, _ = meta_yaml['source']['fn'].split(splitter)
    r = requests.get('https://pypi.python.org/pypi/{}/json'.format(
        package_name))
    if not r.ok:
        return False
    return r.json()['info']['version'].strip()


def gh_version(meta_yaml):
    splitter = '-{}.'.format(meta_yaml['package']['version'])
    package_name, _ = meta_yaml['source']['fn'].split(splitter)

    split_url = meta_yaml['source']['url'].lower().split('/')
    package_owner = split_url[split_url.index('github.com') + 1]
    # get all the tags
    refs = requests.get('https://api.github.com/repos/{owner}/'
                        '{repo}/git/refs/tags'.format(owner=package_owner,
                                                      repo=package_name))
    if not refs.ok:
        return False
    # Extract all the non rc tags
    tags = [parse_version(r['ref'].split('/')[-1]) for r in refs if
            'rc' not in r['ref']]
    # return the most recent tag
    return max(tags)


def gh_checksum(meta_yaml, version):
    package_url = meta_yaml['source']['url']
    package_url = package_url.replace(meta_yaml['source']['version'], version)
    if 'sha256' in meta_yaml['source']:
        hash = 'sha256'
    elif 'md5' in meta_yaml['source']:
        hash = 'md5'
    else:
        raise KeyError('Missing meta.yaml key for checksum')
    return hash_url(package_url, hash=hash)


sl_map = {'pypi': {'version': pypi_version, 'checksum': pypi_checksum},
          'github': {'version': gh_version, 'checksum': gh_checksum}}


def get_latest_version(meta_yaml):
    sl = source_location(meta_yaml)
    rv = sl_map[sl]['version'](meta_yaml)
    return rv


def get_checksum(meta_yaml, version):
    sl = source_location(meta_yaml)

    rv = sl_map[sl]['checksum'](meta_yaml, version)
    return rv


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


def parse_meta_yaml(feedstock):
    meta_yaml = feedstock.get_contents('recipe/meta.yaml')

    # yaml_dict = parsed_meta_yaml(meta_yaml.decoded_content)
    text = codecs.decode(b64decode(meta_yaml.content))
    yaml_dict = parsed_meta_yaml(text)
    return yaml_dict


def two_factor():
    """2 Factor Authentication callback function, called by
    ``github3.authorize()`` as needed.
    """
    code = ''
    while not code:
        code = input('Enter 2FA code: ')
    return code


def main():
    # Get credentialed github (potentially writing credfile if needed)
    gh, username = login(return_username=True)
    # get associated feedstocks
    feedstocks = user_feedstocks(gh.user)
    for feedstock in feedstocks:
        meta_yaml = parse_meta_yaml(feedstock)
        meta_yaml_version = meta_yaml['source']['version']
        if 'sha256' in meta_yaml['source']:
            hash_type = 'sha256'
        elif 'md5' in meta_yaml['source']:
            hash_type = 'md5'
        else:
            raise KeyError('Missing meta.yaml key for checksum')

        # get latest version
        latest_version = get_latest_version(meta_yaml)

        if parse_version(meta_yaml_version) < parse_version(latest_version):
            print(feedstock.full_name[-10:], latest_version, meta_yaml_version)
            new_checksum = get_checksum(meta_yaml, latest_version)

            # Pulled from rever
            # $VERSION = latest_version
            # $PROJECT = feedstock.full_name[-10:]
            # update_feedstock(gh, username, feedstock.full_name[-10:],
            #                  new_checksum,
            #                  hash_type=hash_type)
