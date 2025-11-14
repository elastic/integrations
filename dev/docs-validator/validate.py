import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from pydantic import BaseModel
from pydantic_ai import Agent
import requests

from rich import print
from rich.console import Console
from rich.progress import track

console = Console()

# Load env vars
load_dotenv()

# ----------------------------------
# Shared Dependencies
# ----------------------------------
model = os.getenv("MODEL", "google-gla:gemini-2.5-flash")


@dataclass
class SystemInfoDeps:
    markdown: str
    urls: list[str]


@dataclass
class MarkdownReaderOutput:
    urls: list[str]
    text: str


@dataclass
class URLValidatorOutput:
    is_valid: bool
    url: str
    text: str
    error: Optional[str] = None


@dataclass
class FormatTemplateDeps:
    text: str
    format_template: str


@dataclass
class FormatTemplateOutput:
    is_valid: bool
    format_template: str
    text: str
    error: Optional[str] = None

# ----------------------------------
# Shared Data Passed Through the Chain
# ----------------------------------


class MarkdownContext(BaseModel):
    path: Path
    urls: Optional[list[str]] = None
    text: Optional[str] = None
    format_template: Optional[str] = None

# ----------------------------------
# Step 1: Read in the markdown
# ----------------------------------


markdown_reader_agent = Agent(
    model=model,
    deps_type=SystemInfoDeps,
    output_type=MarkdownReaderOutput,
    system_prompt=(
        "You are a markdown reader. "
        "You read the markdown and return the text and URLs."
    ),

)

url_agent = Agent(
    model=model,
    deps_type=SystemInfoDeps,
    output_type=URLValidatorOutput,
    system_prompt=(
        "You are a URL validator. "
        "You validate the URL and return the is_valid, url, text, and error."
    ),
)

format_template_agent = Agent(
    model=model,
    deps_type=SystemInfoDeps,
    output_type=FormatTemplateOutput,
    system_prompt=(
        "You are a format template validator."
        "You validate the format template and return the is_valid, \
        format_template, text, and error."
    ),
)


# ----------------------------------
# Chain Execution Logic
# ----------------------------------

async def handle_markdown(
    deps: SystemInfoDeps, ctx: MarkdownContext
) -> None:

    console.rule("[bold green]Reading markdown file[/bold green]")

    markdown_result = await markdown_reader_agent.run(deps.markdown, deps=deps)
    ctx.urls = markdown_result.output.urls
    ctx.text = markdown_result.output.text
    print(f"📄 Retrieved {len(ctx.urls)} URLs from the markdown file")


async def handle_urls(
    deps: SystemInfoDeps, ctx: MarkdownContext
) -> None:

    console.rule("[bold green]Validating URLs[/bold green]")
    valid_urls: list[str] = []
    invalid_urls: list[str] = []

    for url in track(ctx.urls, description="Validating URLs"):
        result = requests.get(url)
        if result.status_code == 200 or result.status_code == 300:
            url_prompt = (
                f"The content of the URL at {url} is: {result.text}."
                "Verify it has positive sentiment ."
                "Verify the page is not an invalid URL."
                "If the page is invalid, return the error."
            )
            # might want to just use requests to validate the URL
            print(f"📄 Validating URL: {url}")
            url_result = await url_agent.run(url_prompt, deps=deps)
            if url_result.output.is_valid:
                valid_urls.append(url)
        else:
            invalid_urls.append(url)
            print(f"❌ Invalid URL: {url}")
            continue

    ctx.urls = valid_urls
    if len(invalid_urls) > 0:
        print(f"📍 Invalid URLs: {invalid_urls}")
        print(f"📍 Total URLs: {len(ctx.urls)}")
        print(f"📍 Valid URLs: {len(valid_urls)}")
        print(f"📍 Invalid URLs: {len(invalid_urls)}")
    else:
        print("📍 All URLs are valid")


async def validate_format(
                          deps: SystemInfoDeps,
                          ctx: MarkdownContext,
) -> None:

    console.rule("[bold green]Validating format template[/bold green]")

    # read in the format template file
    format_template_file = os.path.join(
        os.path.dirname(__file__), "_static", "system_info_template.md")

    print(f"📄 Reading format template file {format_template_file}")

    try:
        with open(format_template_file, "r") as file:
            ctx.format_template = file.read()
    except FileNotFoundError:
        raise ValueError(
            f"Format template file not found: {format_template_file}")
    except Exception as e:
        raise ValueError(f"Error reading format template file: {e}")

    deps = FormatTemplateDeps(
        text=ctx.text,
        format_template=ctx.format_template)
    # ask the model to validate the text against the format template
    format_template_prompt = (
        f"The format template is: {deps.format_template}."
        f"The text to validate is: {deps.text}."
        f"Validate the text against the format template."
        "If valid, return the is_valid, format_template, text, and error."
        "If it is not valid, return the error."
    )
    format_template_result = await format_template_agent.run(
        format_template_prompt, deps=deps)
    if format_template_result.output.is_valid:
        print("📍 Format template is valid")
    else:
        print("❌ Format template is invalid")
        print(f"📍 Error: {format_template_result.output.error}")


async def verify_markdown(
        user_input: str, deps: SystemInfoDeps) -> MarkdownContext:
    print(f"\n👤 Verifying markdown: {user_input}")
    ctx = MarkdownContext(path=Path(user_input))

    # refactor this:
    # need a manager keeping track of how many rounds
    # need a tester to throw things back to be redone
    # need a URL validator
    # need a format validator

    chain = [
        handle_markdown,
        handle_urls,
        validate_format,
    ]
    """
        handle_hotel,
        handle_activities,
    ]
"""
    for step in chain:
        await step(deps, ctx)


# ----------------------------------
# Main Execution
# ----------------------------------


async def main():

    # we are at path/to/integrations/dev/docs-validator
    here = os.path.dirname(__file__)
    parent_dir = os.path.dirname(os.path.dirname(here))
    repo = os.path.expanduser(os.getenv("INTEGRATIONS_REPO_PATH", parent_dir))
    package_name = os.getenv("PACKAGE_NAME", "cisco_ftd")

    # given our current directory, find the markdown file
    markdown_file = os.path.join(
        repo,
        "packages",
        package_name,
        "docs",
        "knowledge_base",
        "system_info.md")

    # read in the markdown file
    try:
        with open(markdown_file, "r") as file:
            markdown = file.read()
    except FileNotFoundError:
        raise ValueError(f"Markdown file not found: {markdown_file}")
    except Exception as e:
        raise ValueError(f"Error reading markdown file: {e}")

    deps = SystemInfoDeps(markdown=markdown, urls=[])

    _ = await verify_markdown(markdown_file, deps)


if __name__ == "__main__":
    asyncio.run(main())
