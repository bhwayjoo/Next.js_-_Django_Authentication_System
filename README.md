# Account

A modern web application built with Next.js and Django, featuring secure account management .

## Features

- 🔐 Secure Authentication System

  - Email/Password Registration and Login
  - Google OAuth Integration
  - Email Verification
  - Password Reset
  - JWT Token Authentication

- 👤 User Management

  - User Profile Information
  - Change Username
  - Change Password
  - Email Verification Status
  - Account Status Tracking

## Tech Stack

### Frontend

- Next.js 13+ (React Framework)
- Tailwind CSS (Styling)
- Shadcn/ui (UI Components)
- React Context (State Management)
- Google OAuth Integration

### Backend

- Django 4+ (Python Web Framework)
- Django REST Framework (API)
- Simple JWT (Authentication)
- PostgreSQL (Database)
- Google OAuth2 (Social Authentication)

## Getting Started

### Prerequisites

- Python 3.8+
- Node.js 16+
- Git

### Backend Setup

1. Clone the repository

```bash
git clone <repository-url>
cd <project-name>
```

2. Create and activate a virtual environment

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

4. Set up environment variables

```bash
# Create .env file in backend directory
cp .env.example .env
# Edit .env with your settings
```

5. Run migrations

```bash
python manage.py migrate
```

6. Start the development server

```bash
python manage.py runserver
```

### Frontend Setup

1. Install dependencies

```bash
cd frontend
npm install
```

2. Set up environment variables

```bash
# Create .env.local file in frontend directory
cp .env.example .env.local
# Edit .env.local with your settings
```

3. Start the development server

```bash
npm run dev
```

## Environment Variables

### Backend (.env)

```
DEBUG=True
SECRET_KEY=your-secret-key
DATABASE_URL=postgresql://user:password@localhost:5432/dbname
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_HOST_USER=your-email@gmail.com
EMAIL_HOST_PASSWORD=your-app-password
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
```

### Frontend (.env.local)

```
NEXT_PUBLIC_API_URL=http://localhost:8000/api
NEXT_PUBLIC_GOOGLE_CLIENT_ID=your-google-client-id
```

## API Endpoints

### Authentication

- `POST /api/accounts/register/` - User registration
- `POST /api/accounts/login/` - User login
- `POST /api/accounts/logout/` - User logout
- `POST /api/accounts/google-login/` - Google OAuth login
- `GET /api/accounts/user-info/` - Get user information

### Account Management

- `POST /api/accounts/change-username/` - Change username
- `POST /api/accounts/change-password/` - Change password
- `POST /api/accounts/password/reset/` - Request password reset
- `POST /api/accounts/password/reset/confirm/<token>/` - Confirm password reset
- `GET /api/accounts/verifyEmail/<token>/` - Verify email

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Next.js](https://nextjs.org/)
- [Django](https://www.djangoproject.com/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Shadcn/ui](https://ui.shadcn.com/)
- [Google OAuth](https://developers.google.com/identity/protocols/oauth2)
