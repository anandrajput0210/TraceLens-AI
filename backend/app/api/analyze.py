import shutil
import tempfile
from pathlib import Path

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


router = APIRouter(
    prefix="/api/analyze",
    tags=["Analysis"],
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

            with zip_path.open("wb") as output:

                shutil.copyfileobj(
                    repository.file,
                    output,
                )

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
            run_analysis,
            analysis_id,
            repository_path,
            Path(repository_path).name,
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

        shutil.rmtree(
            temp_root,
            ignore_errors=True,
        )

        raise HTTPException(
            status_code=500,
            detail=f"Unable to process repository: {error}",
        )


@router.get("/{analysis_id}")
def get_analysis(analysis_id: str):

    analysis = ANALYSES.get(analysis_id)

    if analysis is None:

        raise HTTPException(
            status_code=404,
            detail="Analysis not found.",
        )

    return analysis