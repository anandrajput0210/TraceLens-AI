import json
import re
import urllib.request
from pathlib import Path

MAX_DOWNLOAD_SIZE = 50_000_000  # 50 MB
REQUEST_TIMEOUT = 20

GITHUB_URL_PATTERN = re.compile(
    r"^https?://github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/?$"
)


def parse_github_url(url: str) -> tuple[str, str]:
    url = url.strip()

    match = GITHUB_URL_PATTERN.match(url)

    if not match:
        raise ValueError("Invalid GitHub repository URL.")

    owner = match.group("owner")
    repo = match.group("repo")

    if repo.endswith(".git"):
        repo = repo[:-4]

    if not owner or not repo:
        raise ValueError("Invalid GitHub repository URL.")

    return owner, repo


def get_default_branch(owner: str, repo: str) -> str:
    api_url = f"https://api.github.com/repos/{owner}/{repo}"

    request = urllib.request.Request(
        api_url,
        headers={
            "User-Agent": "TraceLens-AI",
            "Accept": "application/vnd.github+json",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
        ) as response:
            data = json.loads(response.read().decode("utf-8"))

    except Exception as error:
        raise ValueError(
            f"Unable to access GitHub repository: {error}"
        ) from error

    default_branch = data.get("default_branch")

    if not default_branch:
        raise ValueError("Unable to determine repository default branch.")

    return default_branch


def download_github_repository(
    github_url: str,
    destination_zip: str,
) -> str:

    owner, repo = parse_github_url(github_url)

    default_branch = get_default_branch(owner, repo)

    archive_url = (
        f"https://codeload.github.com/"
        f"{owner}/{repo}/zip/refs/heads/{default_branch}"
    )

    request = urllib.request.Request(
        archive_url,
        headers={
            "User-Agent": "TraceLens-AI",
        },
    )

    destination = Path(destination_zip)

    try:
        with urllib.request.urlopen(
            request,
            timeout=REQUEST_TIMEOUT,
        ) as response:

            content_length = response.headers.get("Content-Length")

            if content_length:
                if int(content_length) > MAX_DOWNLOAD_SIZE:
                    raise ValueError(
                        "GitHub repository download exceeds the 50 MB limit."
                    )

            downloaded = 0

            with destination.open("wb") as output:
                while True:
                    chunk = response.read(1024 * 1024)

                    if not chunk:
                        break

                    downloaded += len(chunk)

                    if downloaded > MAX_DOWNLOAD_SIZE:
                        raise ValueError(
                            "GitHub repository download exceeds the 50 MB limit."
                        )

                    output.write(chunk)

    except ValueError:
        raise

    except Exception as error:
        raise ValueError(
            f"Unable to download GitHub repository: {error}"
        ) from error

    return str(destination)