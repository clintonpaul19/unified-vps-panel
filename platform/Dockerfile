FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY platform/api/pyproject.toml /app/pyproject.toml
RUN pip install --no-cache-dir "fastapi>=0.115,<1" "uvicorn[standard]>=0.34,<1" "sqlalchemy>=2.0,<3" "asyncpg>=0.30,<1" "argon2-cffi>=23,<26" "itsdangerous>=2.2,<3" "pydantic-settings>=2.7,<3" "email-validator>=2.2,<3" "email-validator>=2.2,<3"
COPY platform/api/app /app/app
COPY platform/web /app/web
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--proxy-headers"]
