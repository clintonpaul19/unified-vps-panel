from pathlib import Path


def main() -> None:
    index = Path("platform/web/index.html").read_text(encoding="utf-8")
    main_py = Path("platform/api/app/main.py").read_text(encoding="utf-8")
    required = [
        Path("platform/web/assets/css/app.css"),
        Path("platform/web/assets/js/api.js"),
        Path("platform/web/assets/js/state.js"),
        Path("platform/web/assets/js/format.js"),
        Path("platform/web/assets/js/components.js"),
        Path("platform/web/assets/js/views.js"),
        Path("platform/web/assets/js/app.js"),
        Path("docs/FRONTEND_UI_SYSTEM.md"),
    ]
    if not all(path.exists() for path in required):
        raise SystemExit("frontend asset invariant failed")
    if 'src="/assets/js/app.js"' not in index:
        raise SystemExit("frontend JS asset is not referenced by index.html")
    if 'href="/assets/css/app.css"' not in index:
        raise SystemExit("frontend CSS asset is not referenced by index.html")
    if 'app.mount("/assets", StaticFiles' not in main_py:
        raise SystemExit("FastAPI frontend asset mount is missing")
    if 'WEB_DIR / "index.html"' not in main_py:
        raise SystemExit("FastAPI frontend entrypoint is missing")
    middleware = Path("platform/api/app/middleware.py").read_text(encoding="utf-8")
    if "Content-Security-Policy" not in middleware:
        raise SystemExit("CSP header invariant failed")
    if "Permissions-Policy" not in middleware:
        raise SystemExit("Permissions-Policy header invariant failed")
    print("Control-plane frontend invariants passed")


if __name__ == "__main__":
    main()
