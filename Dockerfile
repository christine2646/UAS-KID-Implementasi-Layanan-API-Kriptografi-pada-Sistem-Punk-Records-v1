FROM python:3.11-slim

WORKDIR /app

# install dependencies dasar
RUN pip install --upgrade pip

# copy project
COPY . .

# install dependency langsung (tanpa uv)
RUN pip install fastapi uvicorn cryptography python-multipart pydantic

EXPOSE 8000

CMD ["python", "main.py"]
