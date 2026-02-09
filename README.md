# Transaction Review Tool

## Project Overview
A comprehensive transaction monitoring and review application designed for AML (Anti-Money Laundering) compliance operations.

**Public URL**: https://3000-ityh4czoo2i191gah9jw7-2b54fc91.sandbox.novita.ai

## Features

### Authentication & Role-Based Access
- **Login System**: Session-based authentication with secure password hashing
- **Role Profiles**:
  - **Admin**: Full access including configuration management, user management, and customer population upload
  - **Reviewer**: Can view dashboards, alerts, upload statements for customers, and use AI analysis tools
- **Default Admin Credentials**: username: `admin`, password: `admin123` (change in production!)

### Core Functionality

#### Dashboard (All Users)
- KPI overview: total transactions, alerts, alert rate, critical alerts
- Volume metrics: total in/out, cash in/out, high-risk volume
- Charts: transaction volume trends, country distribution
- Filter by customer and time period (3m, 6m, 12m, YTD, monthly)

#### Alerts (All Users)
- View triggered risk alerts with severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Filter by severity, customer, and rule tags
- Alert details include transaction data, rule explanations, and risk scores

#### Explore (All Users)
- Search and filter raw transaction data
- Export to CSV
- Filter by customer, direction, channel, risk level, date range

#### AI Outreach (All Users)
- Generate intelligent outreach questions based on customer alerts
- Build question bank from triggered rules
- Optional LLM integration (OpenAI) for natural language question generation

#### AI Rationale (All Users)
- Generate compliance rationales for customer activity
- Period-based analysis with business context

#### Upload Statements (All Users)
- Customer-specific statement upload
- Select customer from population dropdown
- Upload transaction CSV files per customer
- View statement history per customer
- Multiple statements can be uploaded per customer

### Admin-Only Features

#### Customer Management (`/admin/customers`)
- **Upload Customer Population**: Bulk upload via CSV
- **Add Single Customer**: Manual entry
- **View/Edit/Delete Customers**: Full CRUD operations
- CSV format: `customer_id,customer_name,business_type,onboarded_date,status`

#### User Management (`/admin/users`)
- Create new users (admin or reviewer)
- Edit user roles
- Delete users
- Reset passwords

#### Rules & Settings (`/admin`)
- Configure risk rule parameters (thresholds, multipliers)
- Toggle built-in rules on/off
- Manage risky keywords for narrative scanning
- Configure AI settings (LLM model, enable/disable)
- Country risk level management
- Severity threshold configuration

## Data Model

### Core Tables
- **users**: Authentication and role management
- **customers**: Customer population master list
- **statements**: Track uploaded statement files per customer
- **transactions**: Transaction data with statement linkage
- **alerts**: Generated risk alerts
- **ref_country_risk**: Country risk classification
- **ref_sort_codes**: UK/Ireland bank sort codes
- **kyc_profile**: Customer KYC data (expected monthly volumes)
- **customer_cash_limits**: Per-customer cash limits

### Storage
- **SQLite Database**: `tx.db` in application directory

## Transaction Upload Schema

| Column | Type | Required | Notes |
|--------|------|----------|-------|
| id | TEXT | Yes | Unique transaction identifier |
| txn_date | DATE | Yes | Formats: DD/MM/YYYY, YYYY-MM-DD, MM/DD/YYYY, Excel serial |
| customer_id | TEXT | Yes | Must match selected customer |
| direction | TEXT | Yes | "in" or "out" |
| amount | DECIMAL | Yes | Transaction amount |
| currency | TEXT | No | Default: GBP |
| base_amount | DECIMAL | Yes | Amount in base currency |
| country_iso2 | TEXT | No | ISO2 country code |
| payer_sort_code | TEXT | No | Payer bank sort code |
| payee_sort_code | TEXT | No | Payee bank sort code |
| channel | TEXT | No | e.g., "cash", "wire", "card" |
| narrative | TEXT | No | Transaction description |

## Built-in Risk Rules
- **Jurisdiction Risk**: Prohibited/high-risk country detection
- **Cash Activity**: Daily cash limit breaches
- **Behavioral Deviation**: Outliers vs median, expected vs actual
- **Wolfsberg Patterns**: Structuring, flow-through, dormancy, velocity
- **NLP Detection**: Risky keyword scanning in narratives

## User Guide

### For Admins
1. Log in with admin credentials
2. Navigate to **Configuration > Customers** to upload customer population
3. Navigate to **Configuration > Users** to create reviewer accounts
4. Configure risk rules and parameters in **Configuration > Rules & Settings**

### For Reviewers
1. Log in with reviewer credentials
2. Navigate to **Data & Ingest > Upload Statements**
3. Select a customer from the dropdown
4. Upload transaction CSV file for that customer
5. Use **Dashboard**, **Alerts**, and **AI tools** to analyze customer activity

## Deployment

- **Platform**: Python Flask application
- **Runtime**: Development server (Werkzeug)
- **Port**: 3000
- **Status**: Active

**Note**: This is a development server. For production deployment, use a WSGI server (Gunicorn, uWSGI) behind a reverse proxy (Nginx).

## Technology Stack
- Python 3.12
- Flask 3.x
- SQLite 3
- Bootstrap 5.3
- Chart.js 4.4
- Pandas (for data processing)

## Last Updated
2026-02-04
