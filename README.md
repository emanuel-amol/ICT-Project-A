# ElderSafe Connect

```
Show Image
```
## 🔒 Identity and Access Management System for Aged Care

ElderSafe Connect is a comprehensive Identity and Access Management (IAM) system designed
specifically for aged care facilities. The platform implements robust security features to protect sensitive
health information while providing role-based access control for administrators, nursing staff, and
caregivers.

## 🎓 Academic Project Information

```
University : Swinburne University of Technology
Unit Code : ICT
Unit Name : ICT Project A
Submission Date : May 18, 2025
Instructor : [Instructor Name]
```
## 📋 Project Overview

ElderSafe Connect was developed to address security and access management challenges faced by aged
care facilities. The system implements a layered security approach to protect sensitive resident data while
ensuring appropriate staff members can access the information required for their roles.

### Key Features

```
Multi-Factor Authentication (MFA) : Time-based One-Time Password (TOTP) integration with QR
code setup
Role-Based Access Control (RBAC) : Granular access permissions for administrators, nurses, and
carers
JWT Authentication : Secure session management using JSON Web Tokens
Password Security : Strong password policies with bcrypt hashing and HIBP verification
Honeypot System : Deceptive security mechanism to detect and track potential intruders
Activity Logging : Comprehensive monitoring of user actions and security events
Supabase Integration : Secure database and authentication backend
Resident Care Plans : Role-appropriate access to health information
```

```
Responsive Design : Mobile-friendly interface for use across devices
```
## 👥 Team Members

```
 
```
```
Student Name Student ID
Emanuel Singh 104515032
Sahil Amin 104501837
Aryan Singla 104329631
Yehan Sooriarachchi 103449800
Chayan Kapoor 104202680
Kajal Dhanjal 104224600
```
## 🔧 Technology Stack

```
Backend : Python with Flask
Database : PostgreSQL via Supabase
Authentication : Supabase Auth with JWT tokens
Frontend : HTML, CSS, JavaScript
Security : bcrypt, PyOTP, JWT, HIBP API
Email : SMTP integration for notifications and password resets
```
## 🚀 Installation and Setup

### Prerequisites

```
Python 3.8 or higher
Supabase account
SMTP-enabled email account for system notifications
```
### Environment Setup

1. Clone the repository:
2. Create a virtual environment:

```
bash
gitgit clone https://github.com/your-username/eldersafe-connect.git clone https://github.com/your-username/eldersafe-connect.git
cdcd eldersafe-connect eldersafe-connect
```
```
bash
python -m venv venvpython -m venv venv
sourcesource venv/bin/activate venv/bin/activate # On Windows: venv\Scripts\activate# On Windows: venv\Scripts\activate
```

3. Install dependencies:
4. Create a .env file with the following variables:
5. Create the required certificates for HTTPS:

### Running the Application

1. Start the main application:
2. Access the application:
    Main application: https://localhost:
    Honeypot system: [http://localhost:](http://localhost:)

## 💼 Usage

1. **Admin Functions** :
    Invite new staff members
    Create resident profiles
    Assign staff to residents
    Monitor system logs
2. **Nurse Functions** :
    Create and update care plans
    Record resident vitals
    Upload and access medical documents
3. **Carer Functions** :

```
bash
pip pip installinstall -r requirements.txt -r requirements.txt
```
```
SUPABASE_URL=your_supabase_urlSUPABASE_URL=your_supabase_url
SUPABASE_SERVICE_ROLE_KEY=your_supabase_keySUPABASE_SERVICE_ROLE_KEY=your_supabase_key
SUPABASE_JWT_SECRET=your_jwt_secretSUPABASE_JWT_SECRET=your_jwt_secret
FLASK_SECRET_KEY=your_flask_secretFLASK_SECRET_KEY=your_flask_secret
JWT_SECRET=your_jwt_signing_keyJWT_SECRET=your_jwt_signing_key
```
```
bash
mkdirmkdir -p security_protocols/TLS/cert -p security_protocols/TLS/cert
cdcd security_protocols/TLS/cert security_protocols/TLS/cert
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365365
```
```
bash
python app.pypython app.py
```

```
View assigned resident information
Access care plans (read-only)
```
## 🔄 Development Workflow

The project was developed using an Agile-inspired approach with two major sprints:

```
Sprint 1 : Core security infrastructure (JWT, MFA, RBAC, Honeypot)
Sprint 2 : User experience enhancements, password reset functionality, and visual refinements
```
## 🔒 Security Features

### Multi-Factor Authentication (MFA)

Users are required to set up MFA using authenticator apps that implement Time-based One-Time
Passwords (TOTP). This provides an additional layer of security beyond password authentication.

### Password Security

```
Strong password requirements (length, complexity)
Bcrypt hashing with salting
Integration with Have I Been Pwned API to prevent use of compromised passwords
Secure password reset functionality
```
### Honeypot System

A decoy system designed to detect unauthorized access attempts. Triggers email alerts to administrators
when potential intrusions are detected.

### Access Control

Granular role-based access control ensures users can only access information relevant to their
responsibilities:

```
Admins: full system access
Nurses: write access to assigned residents
Carers: read-only access to assigned residents
```
## 📊 Monitoring

The system includes comprehensive logging for:

```
Authentication attempts
JWT token issuance and validation
Honeypot triggers
```

```
User activities (care plan submissions, etc.)
```
## ⚖ License

```
Show Image
```
This project is licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.
International License (CC BY-NC-ND 4.0).

### You are free to:

```
Share — copy and redistribute the material in any medium or format
View — examine the code and documentation for educational purposes
```
### Under the following terms:

```
Attribution — You must give appropriate credit to the original authors (ElderSafe Connect Team -
Swinburne University of Technology), provide a link to the license, and indicate if changes were made.
NonCommercial — You may not use the material for commercial purposes.
NoDerivatives — If you remix, transform, or build upon the material, you may not distribute the
modified material.
Academic Integrity — You may not submit this work, in whole or in part, as your own academic
assessment or project.
```
### Additional Restrictions:

```
This software may not be used, in whole or in part, for submission as academic coursework or
assessment.
You may fork this repository and suggest contributions via pull requests, but distribution of
derivatives is prohibited.
```
Copyright (c) 2025 ElderSafe Connect Team - Swinburne University of Technology

View Full License

## 🙏 Acknowledgments

```
We respectfully acknowledge the Wurundjeri People of the Kulin Nation, who are the Traditional
Owners of the land on which Swinburne's Australian campuses are located in Melbourne's east and
outer-east, and pay our respect to their Elders past, present and emerging.
Thanks to [Instructor Name] for guidance throughout the project
```

```
Thanks to Supabase for providing the backend infrastructure
Special thanks to the aged care professionals who provided domain expertise
```
**Note** : This project was developed for educational purposes as part of ICT30017 (ICT Project A) at
Swinburne University of Technology. It is not intended for production use without further security
auditing and enhancements.


