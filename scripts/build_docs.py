#!/usr/bin/env python3
"""Build the manual and static Python reference, validating local HTML links."""
import shutil
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.targets = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ('id', 'name'):
            if attrs.get(key):
                self.targets.add(attrs[key])
        for key in ('href', 'src'):
            if attrs.get(key):
                self.links.append(attrs[key])


def check_links(site):
    pages = {}
    for path in site.rglob('*.html'):
        parser = Links()
        parser.feed(path.read_text(encoding='utf-8'))
        pages[path.resolve()] = parser
    errors = []
    for path, parser in pages.items():
        for link in parser.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            target = ((site / unquote(url.path).lstrip('/')) if url.path.startswith('/')
                      else (path.parent / unquote(url.path)) if url.path else path).resolve()
            if target.is_dir():
                target /= 'index.html'
            if not target.is_relative_to(site.resolve()) or not target.is_file():
                errors.append(f'{path.relative_to(site)}: missing {link}')
            elif url.fragment and target in pages and unquote(url.fragment) not in pages[target].targets:
                errors.append(f'{path.relative_to(site)}: missing anchor {link}')
    if errors:
        raise RuntimeError('\n'.join(errors))
    return len(pages)


def run(*args):
    subprocess.run([sys.executable, '-m', *args], cwd=ROOT, check=True)


def main():
    output = ROOT / 'documentation'
    if output.is_symlink():
        raise RuntimeError('documentation must be a regular directory')
    with tempfile.TemporaryDirectory(prefix='.docs-build-', dir=ROOT) as temporary:
        site = Path(temporary) / 'site'
        run('mkdocs', 'build', '--strict', '--clean', '--config-file', str(ROOT / 'mkdocs.yml'),
            '--site-dir', str(site))
        run('pydoctor', '--make-html', '--project-name', 'NFDetector',
            '--project-url', '../index.html', '--project-base-dir', str(ROOT),
            '--docformat', 'google', '--warnings-as-errors', '--html-output', str(site / 'api'),
            '--intersphinx-file', str(ROOT / 'scripts/vendor/python-3.12.inv') + '::https://docs.python.org/3.12/',
            str(ROOT / 'distributed'), str(ROOT / 'general'), str(ROOT / 'nfdetect.py'))
        # Normalize generator whitespace, without manual edits of output pages.
        for page in site.rglob('*.html'):
            page.write_text('\n'.join(line.rstrip() for line in page.read_text().splitlines()) + '\n')
        count = check_links(site)
        # Keep the previous generated tree intact until both generators and checks pass.
        backup = Path(temporary) / 'previous'
        if output.exists():
            output.rename(backup)
        try:
            site.rename(output)
        except BaseException:
            if backup.exists():
                backup.rename(output)
            raise
    print(f'Built {count} HTML pages; local links and anchors OK: {output / "index.html"}')


if __name__ == '__main__':
    main()
