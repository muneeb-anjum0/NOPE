import json
from pathlib import Path

from nope_api.models import Confidence, StackEvidence


def _has_file(root: Path, name: str) -> list[str]:
    return [str(path.relative_to(root)) for path in root.rglob(name) if path.is_file()]


def detect_stack(root: Path) -> list[StackEvidence]:
    evidence: list[StackEvidence] = []
    files = [path for path in root.rglob("*") if path.is_file() and ".git" not in path.parts]
    suffixes = {path.suffix.lower() for path in files}

    language_map = {
        ".js": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript",
        ".tsx": "TypeScript",
        ".py": "Python",
        ".go": "Go",
        ".java": "Java",
        ".cs": "C#",
        ".php": "PHP",
        ".rb": "Ruby",
        ".rs": "Rust",
        ".sh": "Shell",
        ".sql": "SQL",
    }
    for suffix, technology in language_map.items():
        matches = [str(p.relative_to(root)) for p in files if p.suffix.lower() == suffix][:5]
        if suffix in suffixes:
            evidence.append(
                StackEvidence(
                    technology=technology,
                    category="language",
                    confidence=Confidence.high,
                    evidence=matches,
                )
            )

    package_files = _has_file(root, "package.json")
    for package_file in package_files:
        data = json.loads((root / package_file).read_text(encoding="utf-8", errors="ignore"))
        deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        dependency_map = {
            "next": ("Next.js", "frontend"),
            "react": ("React", "frontend"),
            "vue": ("Vue", "frontend"),
            "nuxt": ("Nuxt", "frontend"),
            "@angular/core": ("Angular", "frontend"),
            "svelte": ("Svelte", "frontend"),
            "@sveltejs/kit": ("SvelteKit", "frontend"),
            "@remix-run/react": ("Remix", "frontend"),
            "astro": ("Astro", "frontend"),
            "express": ("Express", "backend"),
            "@nestjs/core": ("NestJS", "backend"),
            "fastify": ("Fastify", "backend"),
            "prisma": ("Prisma", "data"),
            "drizzle-orm": ("Drizzle", "data"),
            "typeorm": ("TypeORM", "data"),
            "sequelize": ("Sequelize", "data"),
            "mongoose": ("Mongoose", "data"),
            "graphql": ("GraphQL", "api"),
            "ws": ("WebSockets", "api"),
            "@supabase/supabase-js": ("Supabase", "data"),
            "firebase": ("Firebase", "data"),
            "stripe": ("Payment systems", "external"),
            "openai": ("AI APIs", "external"),
        }
        for dep, (technology, category) in dependency_map.items():
            if dep in deps:
                evidence.append(
                    StackEvidence(
                        technology=technology,
                        category=category,
                        confidence=Confidence.high,
                        evidence=[f"{package_file}: dependency {dep}"],
                    )
                )

    python_markers = {
        "requirements.txt": [("FastAPI", "backend", "fastapi"), ("Flask", "backend", "flask"), ("Django", "backend", "django")],
        "pyproject.toml": [("FastAPI", "backend", "fastapi"), ("SQLAlchemy", "data", "sqlalchemy")],
    }
    for marker, candidates in python_markers.items():
        for file in _has_file(root, marker):
            text = (root / file).read_text(encoding="utf-8", errors="ignore").lower()
            for technology, category, needle in candidates:
                if needle in text:
                    evidence.append(StackEvidence(technology=technology, category=category, confidence=Confidence.high, evidence=[file]))

    deployment_files = {
        "Dockerfile": "Docker",
        "docker-compose.yml": "Docker Compose",
        "kubernetes.yaml": "Kubernetes",
        "vercel.json": "Vercel",
        "netlify.toml": "Netlify",
        "firebase.json": "Firebase Hosting",
        "wrangler.toml": "Cloudflare",
    }
    for marker, technology in deployment_files.items():
        matches = _has_file(root, marker)
        if matches:
            evidence.append(StackEvidence(technology=technology, category="deployment", confidence=Confidence.high, evidence=matches))

    if _has_file(root, "supabase"):
        evidence.append(StackEvidence(technology="Supabase", category="data", confidence=Confidence.medium, evidence=["supabase directory"]))

    return evidence
