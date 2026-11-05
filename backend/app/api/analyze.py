import logging
import shutil
import tempfile
from pathlib import Path
from zipfile import BadZipFile

from fastapi import (
    APIRouter,
    BackgroundTasks,
    File,
    Form,
    HTTPException,
    UploadFile,
)

from app.services.archive_service import safe_extract_zip
from app.services.analysis_service import (
    ANALYSES,
    create_analysis,
    run_analysis,
)
from app.services.github_service import download_github_repository


logger = logging.getLogger(__name__)

MAX_UPLOAD_SIZE = 50_000_000  # 50 MB
UPLOAD_CHUNK_SIZE = 1024 * 1024  # 1 MB

router = APIRouter(
    prefix="/api/analyze",
    tags=["Analysis"],
)

def _run_analysis_and_cleanup(
    analysis_id: str,
    repository_path: str,
    repository_name: str,
    temp_root: str,
) -> None:
    """Run the analysis and remove its entire temporary workspace."""
    try:
        run_analysis(
            analysis_id,
            repository_path,
            repository_name,
        )
    finally:
        shutil.rmtree(
            temp_root,
            ignore_errors=True,
        )

@router.post("")
async def start_analysis(
    background_tasks: BackgroundTasks,
    repository: UploadFile | None = File(None),
    github_url: str | None = Form(None),
):
    """
    Analyze a repository from either:

    1. Uploaded ZIP file
    2. Public GitHub repository URL

    Repository source code is treated as data.
    It is never executed.
    """

    # ---------------------------------------------------------
    # Validate repository source
    # ---------------------------------------------------------

    has_zip = repository is not None
    has_github = bool(github_url and github_url.strip())

    if not has_zip and not has_github:
        raise HTTPException(
            status_code=400,
            detail="Provide either a repository ZIP or a GitHub repository URL.",
        )

    if has_zip and has_github:
        raise HTTPException(
            status_code=400,
            detail="Provide either a repository ZIP or a GitHub repository URL, not both.",
        )

    # ---------------------------------------------------------
    # Create temporary workspace
    # ---------------------------------------------------------

    temp_root = Path(
        tempfile.mkdtemp(
            prefix="tracelens_"
        )
    )

    zip_path = temp_root / "repository.zip"

    try:

        # =====================================================
        # SOURCE 1: Uploaded ZIP
        # =====================================================

        if has_zip:

            filename = repository.filename or ""

            if not filename.lower().endswith(".zip"):
                raise HTTPException(
                    status_code=400,
                    detail="Only ZIP repositories are supported.",
                )

            total_uploaded = 0

            with zip_path.open("wb") as output:
                while True:
                    chunk = await repository.read(UPLOAD_CHUNK_SIZE)

                    if not chunk:
                        break

                    total_uploaded += len(chunk)

                    if total_uploaded > MAX_UPLOAD_SIZE:
                        raise HTTPException(
                            status_code=413,
                            detail=(
                                "Uploaded ZIP exceeds the maximum "
                                "allowed upload size."
                            ),
                        )
                    output.write(chunk)

        # =====================================================
        # SOURCE 2: GitHub repository
        # =====================================================

        else:

            download_github_repository(
                github_url.strip(),
                str(zip_path),
            )

        # -----------------------------------------------------
        # Extract repository safely
        # -----------------------------------------------------

        extraction_dir = temp_root / "repository"

        extraction_dir.mkdir()

        repository_path = safe_extract_zip(
            str(zip_path),
            str(extraction_dir),
        )

        # -----------------------------------------------------
        # Create analysis
        # -----------------------------------------------------

        analysis_id = create_analysis(
            repository_path
        )

        # -----------------------------------------------------
        # Run existing TraceLens pipeline
        # -----------------------------------------------------

        background_tasks.add_task(
            _run_analysis_and_cleanup,
            analysis_id,
            repository_path,
            Path(repository_path).name,
            str(temp_root),
        )
        return {
            "analysis_id": analysis_id,
            "status": "queued",
            "message": "Repository analysis started.",
        }

    except HTTPException:
        shutil.rmtree(
            temp_root,
            ignore_errors=True,
        )
        raise
    except BadZipFile as error:
        shutil.rmtree(
            temp_root,
            ignore_errors=True,
        )

        raise HTTPException(
            status_code=400,
            detail="The supplied archive is not a valid ZIP file.",
        ) from error
    except ValueError as error:

        shutil.rmtree(
            temp_root,
            ignore_errors=True,
        )

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )

    except Exception as error:
        logger.exception("Unexpected repository ingestion failure")

        shutil.rmtree(
            temp_root,
            ignore_errors=True,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to process the repository. "
                "Check the ZIP file or GitHub URL and try again."
            ),
        ) from error

@router.get("/{analysis_id}")
def get_analysis(analysis_id: str):

    analysis = ANALYSES.get(analysis_id)

    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return analysis