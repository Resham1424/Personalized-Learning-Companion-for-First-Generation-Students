# LearnMate — AI-Powered Personalized Learning Companion for First-Generation Students

LearnMate is a full-stack web application that helps first-generation students with AI-driven learning guidance, resume feedback, skill gap analysis, habit tracking, and personalized study roadmaps.

Built for students who lack traditional mentorship, LearnMate acts as an always-available AI companion that identifies weak areas, suggests what to learn next, and keeps learners on track.

---

## Features

- **AI Mentor Chatbot** — Powered by Groq LLM for personalized learning guidance, study plans, and skill-building advice.
- **Resume Analyzer** — Upload PDF/DOCX resumes and get an ATS score, weak skill identification, and actionable improvement suggestions.
- **Skill Gap Analyzer** — Compares student skills against industry standards and highlights missing or underdeveloped areas.
- **Personalized Roadmap Generator** — Auto-generates a week-by-week learning plan with topics, practice ideas, mini projects, and resources.
- **Habit Tracker** — Build daily study habits with a visual streak and completion tracker for consistency.
- **Learning Progress Dashboard** — View learning readiness score, leaderboard standings, and overall progress.
- **Admin Panel** — Full admin interface with user management, database explorer, and analytics.
- **Auth System** — Registration, login, password reset via email with secure token links.

---

## Tech Stack

| Layer        | Technology                          |
| ------------ | ----------------------------------- |
| Backend      | Python, Flask                       |
| Database     | SQLite                              |
| AI / LLM     | Groq API (LLaMA 3.1)               |
| Frontend     | HTML, CSS, JavaScript (vanilla)     |
| Email        | SMTP (Gmail or any provider)        |
| Resume Parse | PyPDF2, python-docx                 |

---

## Project Structure

```
LearnMate/
├── run.py                  # Application entry point
├── requirements.txt        # Python dependencies
├── .env                    # Environment variables (API keys, secrets)
├── app/
│   ├── __init__.py         # Flask app factory & config
│   ├── db.py               # SQLite database layer (schema + CRUD)
│   ├── email_utils.py      # SMTP email helper
│   ├── routes.py           # All route handlers & API endpoints
│   ├── scheduler_service.py# Background task scheduler
│   ├── static/
│   │   ├── css/            # Stylesheets (auth, dashboard, resume, admin, etc.)
│   │   └── js/             # Client-side scripts (chatbot, resume analyzer, etc.)
│   └── templates/          # Jinja2 HTML templates
└── data/
    └── resumes/            # Uploaded user resumes (per-email folders)
```

---

## Getting Started

### Prerequisites

- Python 3.9+
- A Groq API key (for AI chatbot, resume analysis & skill gap detection)
- SMTP credentials (for password reset emails — optional for local dev)

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd Personalized-Learning-Companion-for-First-Generation-Students

# Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

# Install dependencies
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the project root:

```env
SECRET_KEY=your-secret-key
GROQ_API_KEY=gsk_your-groq-api-key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
```

### Run the App

```bash
python run.py
```

The server starts at **http://127.0.0.1:5000**.

---

## API Overview

| Endpoint                        | Method       | Description                           |
| ------------------------------- | ------------ | ------------------------------------- |
| `/`                             | GET          | Landing page                          |
| `/login`                        | GET / POST   | User login                            |
| `/register`                     | GET / POST   | User registration                     |
| `/forgot-password`              | GET / POST   | Request password reset email          |
| `/reset-password/<token>`       | GET / POST   | Reset password via token              |
| `/onboarding`                   | GET / POST   | First-login self-assessment           |
| `/dashboard`                    | GET          | Main dashboard with AI companion      |
| `/chat`                         | POST         | AI mentor chatbot conversation        |
| `/mock-tests`                   | GET          | Mock tests page                       |
| `/api/mock-tests`               | GET / POST   | CRUD for mock test records            |
| `/api/mock-tests/<id>`          | PUT / DELETE | Update or delete a mock test          |
| `/progress`                     | GET          | Progress & habits page                |
| `/api/habits`                   | GET / POST   | Habit CRUD                            |
| `/api/habits/toggle`            | POST         | Toggle daily habit completion         |
| `/api/habits/logs`              | GET          | Retrieve habit log history            |
| `/api/leaderboard`              | GET          | Leaderboard data                      |
| `/resume`                       | GET          | Resume analyzer page                  |
| `/api/resume/upload`            | POST         | Upload a resume file                  |
| `/api/resume/analyze`           | POST         | AI resume analysis + skill gap        |
| `/api/resume/smart-roadmap`     | POST         | Generate personalized learning roadmap|
| `/api/resume/latest`            | GET          | Get latest resume & analysis          |
| `/admin`                        | GET          | Admin panel                           |
| `/api/admin/*`                  | Various      | Admin user/table management           |
| `/api/health`                   | GET          | Health check                          |

---

## How It Works

1. **Sign Up & Onboard** — New users complete a guided self-assessment to personalize their experience.
2. **Get AI Guidance** — The AI Mentor chatbot answers questions, suggests study strategies, and builds confidence.
3. **Analyze Your Resume** — Upload a resume to get an ATS score, extracted skills, weak areas, and improvement suggestions with resources.
4. **Follow Your Roadmap** — A personalized week-by-week plan with topics, practice exercises, and mini projects.
5. **Build Habits & Track Progress** — Daily habit tracker and a progress dashboard keep motivation high.

---

## Deployment

### Option A: Ubuntu VPS (recommended for SQLite + scheduler)

This app uses SQLite and an in-process APScheduler job, so a **single server instance** is recommended.

1. Clone and prepare environment:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip nginx

git clone <repo-url> /var/www/learnmate
cd /var/www/learnmate

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Create `.env` in project root:

```env
SECRET_KEY=change-this-to-a-strong-random-value
GROQ_API_KEY=gsk_your-groq-api-key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_USE_TLS=true
```

3. Start with Gunicorn (quick check):

```bash
mkdir -p data
source .venv/bin/activate
gunicorn run:app --workers 2 --bind 127.0.0.1:8000
```

4. Configure `systemd` service:

```bash
sudo cp deploy/systemd/learnmate.service /etc/systemd/system/learnmate.service
sudo systemctl daemon-reload
sudo systemctl enable learnmate
sudo systemctl start learnmate
sudo systemctl status learnmate
```

5. Configure Nginx reverse proxy:

```bash
sudo cp deploy/nginx/learnmate.conf /etc/nginx/sites-available/learnmate
sudo ln -s /etc/nginx/sites-available/learnmate /etc/nginx/sites-enabled/learnmate
sudo nginx -t
sudo systemctl reload nginx
```

6. Enable HTTPS (Let's Encrypt):

```bash
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
```

### Option B: Render

This repository now includes `render.yaml` for Blueprint deploy.

1. Push your code to GitHub.
2. In Render: **New +** → **Blueprint** → select your repo.
3. Render will detect `render.yaml` and create the web service automatically.
4. In service settings, add secret env values:
    - `GROQ_API_KEY`
    - `SMTP_USER`
    - `SMTP_PASSWORD`
5. Deploy.

Important:
- Keep `numInstances: 1` for SQLite and in-process scheduler consistency.
- Persistent disk is preconfigured in `render.yaml` and mounted at `/var/data`.
- The app uses `DATABASE_PATH=/var/data/preppulse.db` on Render.

Manual (without Blueprint):
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn run:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120`
- Add a persistent disk mounted to `/var/data`
- Set `DATABASE_PATH=/var/data/preppulse.db`

### Option C: Windows server (without Gunicorn)

Gunicorn is Linux-focused. On Windows, run with Waitress:

```bash
waitress-serve --listen=0.0.0.0:8000 run:app
```

---

## License

This project was built for a hackathon. All rights reserved.
